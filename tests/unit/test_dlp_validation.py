from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import attack_campaigns, dlp_validation, telemetry_feedback


NOW = datetime(2026, 7, 8, 23, 30, tzinfo=timezone.utc)


def dataset(**overrides: object) -> dlp_validation.CanaryDataset:
    values = {
        "dataset_id": "canary-dataset-1",
        "data_classes": (dlp_validation.CanaryDataClass.SYNTHETIC, dlp_validation.CanaryDataClass.CANARY),
        "canary_markers": ("canary-marker-1",),
        "synthetic_generation_note": "Generated synthetic records with non-sensitive markers.",
    }
    values.update(overrides)
    return dlp_validation.CanaryDataset(**values)  # type: ignore[arg-type]


def roe(**overrides: object) -> dlp_validation.DlpRulesOfEngagement:
    values = {
        "roe_id": "dlp-roe-1",
        "source_systems": ("source-lab-1",),
        "destination_systems": ("sink-lab-1",),
        "data_labels": ("synthetic-canary",),
        "max_volume_bytes": 1024,
        "max_record_count": 10,
        "allowed_protocols": (dlp_validation.DlpProtocol.HTTPS,),
        "window_start": NOW,
        "window_end": NOW + timedelta(hours=1),
        "timezone_label": "UTC",
        "detection_stakeholders": ("dlp-owner", "soc-lead"),
        "emergency_stop_conditions": ("operator_stop", "unexpected_sensitive_data"),
    }
    values.update(overrides)
    return dlp_validation.DlpRulesOfEngagement(**values)  # type: ignore[arg-type]


def approval(**overrides: object) -> dlp_validation.PurpleTeamApproval:
    values = {
        "approved_by_user_id": "purple-lead",
        "approval_ticket_id": "approval-1",
        "monitoring_owner_user_id": "monitoring-owner",
        "approved_at": NOW,
    }
    values.update(overrides)
    return dlp_validation.PurpleTeamApproval(**values)  # type: ignore[arg-type]


def monitoring(**overrides: object) -> dlp_validation.MonitoringReadiness:
    values = {
        "monitoring_owner_user_id": "monitoring-owner",
        "telemetry_sources": (attack_campaigns.TelemetrySource.SIEM,),
        "alert_route_id": "alert-route-1",
        "control_owner_user_id": "dlp-owner",
        "ready": True,
    }
    values.update(overrides)
    return dlp_validation.MonitoringReadiness(**values)  # type: ignore[arg-type]


def target_scope(**overrides: object) -> dlp_validation.DlpTargetScope:
    values = {
        "source_system_id": "source-lab-1",
        "destination_system_id": "sink-lab-1",
        "protocol": dlp_validation.DlpProtocol.HTTPS,
        "volume_bytes": 512,
        "record_count": 5,
    }
    values.update(overrides)
    return dlp_validation.DlpTargetScope(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> dlp_validation.DlpValidationRequest:
    values = {
        "validation_id": "dlp-validation-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "dataset": dataset(),
        "roe": roe(),
        "approval": approval(),
        "monitoring": monitoring(),
        "target_scope": target_scope(),
        "requested_at": NOW,
    }
    values.update(overrides)
    return dlp_validation.DlpValidationRequest(**values)  # type: ignore[arg-type]


def test_only_synthetic_canary_data_is_allowed_and_sensitive_classes_are_forbidden() -> None:
    dlp_validation.validate_canary_dataset(dataset())

    with pytest.raises(ValueError, match="sensitive_data_forbidden:personal_data,production_credential,real_sensitive_value"):
        dlp_validation.validate_canary_dataset(
            dataset(
                data_classes=(
                    dlp_validation.CanaryDataClass.REAL_SENSITIVE_VALUE,
                    dlp_validation.CanaryDataClass.PERSONAL_DATA,
                    dlp_validation.CanaryDataClass.PRODUCTION_CREDENTIAL,
                )
            )
        )


def test_roe_requires_scope_labels_caps_protocol_window_stakeholders_and_stop_conditions() -> None:
    dlp_validation.validate_roe(roe())

    with pytest.raises(ValueError, match="source_systems_required"):
        dlp_validation.validate_roe(roe(source_systems=()))
    with pytest.raises(ValueError, match="invalid_volume_cap"):
        dlp_validation.validate_roe(roe(max_volume_bytes=0))
    with pytest.raises(ValueError, match="protocol_limits_required"):
        dlp_validation.validate_roe(roe(allowed_protocols=()))
    with pytest.raises(ValueError, match="emergency_stop_conditions_required"):
        dlp_validation.validate_roe(roe(emergency_stop_conditions=()))


def test_simulation_is_disabled_until_purple_team_approval_and_monitoring_readiness_are_recorded() -> None:
    missing_approval = dlp_validation.evaluate_dlp_validation_request(request(approval=None))
    missing_monitoring = dlp_validation.evaluate_dlp_validation_request(request(monitoring=monitoring(ready=False)))
    allowed = dlp_validation.evaluate_dlp_validation_request(request())

    assert not missing_approval.allowed
    assert missing_approval.reason is dlp_validation.DlpDecisionReason.MISSING_APPROVAL
    assert not missing_monitoring.allowed
    assert missing_monitoring.reason is dlp_validation.DlpDecisionReason.MONITORING_NOT_READY
    assert allowed.allowed
    assert allowed.reason is dlp_validation.DlpDecisionReason.APPROVED_FOR_REVIEW_QUEUE
    assert not allowed.execution_enabled
    assert allowed.details == ("simulation_disabled_until_runner_policy_approved",)
    assert not hasattr(dlp_validation, "execute_exfiltration")
    assert not hasattr(dlp_validation, "transfer_data")


def test_negative_paths_fail_closed_for_missing_dataset_target_monitoring_owner_and_stop_condition() -> None:
    missing_dataset = dlp_validation.evaluate_dlp_validation_request(request(dataset=None))
    missing_target = dlp_validation.evaluate_dlp_validation_request(request(target_scope=None))
    missing_owner = dlp_validation.evaluate_dlp_validation_request(
        request(monitoring=monitoring(monitoring_owner_user_id=None))
    )
    missing_stop = dlp_validation.evaluate_dlp_validation_request(request(roe=roe(emergency_stop_conditions=("",))))

    assert not missing_dataset.allowed
    assert missing_dataset.reason is dlp_validation.DlpDecisionReason.MISSING_CANARY_DATASET
    assert not missing_target.allowed
    assert missing_target.reason is dlp_validation.DlpDecisionReason.MISSING_TARGET_SCOPE
    assert not missing_owner.allowed
    assert missing_owner.reason is dlp_validation.DlpDecisionReason.MISSING_MONITORING_OWNER
    assert not missing_stop.allowed
    assert missing_stop.reason is dlp_validation.DlpDecisionReason.MISSING_STOP_CONDITION


def test_target_scope_must_stay_within_roe_caps_and_protocol_limits() -> None:
    outside = dlp_validation.evaluate_dlp_validation_request(
        request(
            target_scope=target_scope(
                destination_system_id="outside-sink",
                protocol=dlp_validation.DlpProtocol.EMAIL,
                volume_bytes=2048,
            )
        )
    )

    assert not outside.allowed
    assert outside.reason is dlp_validation.DlpDecisionReason.MISSING_TARGET_SCOPE
    assert "destination_system_outside_roe" in outside.details
    assert "protocol_outside_roe" in outside.details
    assert "volume_cap" in outside.details


def test_evidence_records_detection_outcome_latency_owner_and_remediation_without_sensitive_data() -> None:
    evidence = dlp_validation.DlpDetectionEvidence(
        evidence_id="dlp-evidence-1",
        validation_id="dlp-validation-1",
        detection_outcome=telemetry_feedback.TelemetryObservationStatus.OBSERVED,
        telemetry_source=attack_campaigns.TelemetrySource.SIEM,
        alert_latency_seconds=42,
        control_owner_user_id="dlp-owner",
        remediation_follow_up="Tune DLP alert route documentation.",
    )

    exported = dlp_validation.export_dlp_detection_evidence(evidence)

    assert exported == {
        "evidence_id": "dlp-evidence-1",
        "validation_id": "dlp-validation-1",
        "detection_outcome": "observed",
        "telemetry_source": "siem",
        "alert_latency_seconds": 42,
        "control_owner_user_id": "dlp-owner",
        "remediation_follow_up": "Tune DLP alert route documentation.",
        "contains_sensitive_data": False,
        "raw_canary_value_present": False,
    }
    with pytest.raises(ValueError, match="sensitive_dlp_evidence_forbidden"):
        dlp_validation.export_dlp_detection_evidence(
            dlp_validation.DlpDetectionEvidence(
                evidence_id="dlp-evidence-2",
                validation_id="dlp-validation-1",
                detection_outcome=telemetry_feedback.TelemetryObservationStatus.MISSING,
                telemetry_source=attack_campaigns.TelemetrySource.SIEM,
                alert_latency_seconds=None,
                control_owner_user_id="dlp-owner",
                remediation_follow_up="Investigate missing alert.",
                contains_sensitive_data=True,
            )
        )
    with pytest.raises(ValueError, match="raw_canary_value_forbidden"):
        dlp_validation.export_dlp_detection_evidence(
            dlp_validation.DlpDetectionEvidence(
                evidence_id="dlp-evidence-3",
                validation_id="dlp-validation-1",
                detection_outcome=telemetry_feedback.TelemetryObservationStatus.OBSERVED,
                telemetry_source=attack_campaigns.TelemetrySource.SIEM,
                alert_latency_seconds=10,
                control_owner_user_id="dlp-owner",
                remediation_follow_up="Remove raw canary value from export.",
                raw_canary_value_present=True,
            )
        )
