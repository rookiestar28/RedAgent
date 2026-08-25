from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import attack_campaigns, dlp_runtime, dlp_validation, domain, evidence_chain, job_queue
from redagent_platform.scope_authorization import ScopeTarget
from redagent_platform.telemetry_feedback import TelemetryObservationStatus


NOW = datetime(2026, 7, 9, 13, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.LAB_TARGET, value="source-lab-1->sink-lab-1")


def dataset(**overrides: object) -> dlp_validation.CanaryDataset:
    values = {
        "dataset_id": "canary-dataset-1",
        "data_classes": (dlp_validation.CanaryDataClass.SYNTHETIC, dlp_validation.CanaryDataClass.CANARY),
        "canary_markers": ("canary-marker-1",),
        "synthetic_generation_note": "Generated synthetic records with non-sensitive canary markers.",
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
        "window_start": NOW - timedelta(minutes=5),
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
        "approved_at": NOW - timedelta(minutes=10),
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


def validation_request(**overrides: object) -> dlp_validation.DlpValidationRequest:
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


def profile(**overrides: object) -> dlp_runtime.DlpWorkflowProfile:
    values = {
        "profile_id": "dlp-workflow-profile",
        "module_id": "dlp-canary-runtime",
        "allowed_source_systems": ("source-lab-1",),
        "allowed_destination_systems": ("sink-lab-1",),
        "allowed_protocols": (dlp_validation.DlpProtocol.HTTPS,),
        "max_volume_bytes": 1024,
        "max_record_count": 10,
        "timeout_seconds": 120,
        "kill_switch_enabled": True,
        "actions": (
            dlp_runtime.DlpWorkflowAction.IMPORT_DETECTION_EVIDENCE,
            dlp_runtime.DlpWorkflowAction.PREPARE_REVIEW_QUEUE,
        ),
    }
    values.update(overrides)
    return dlp_runtime.DlpWorkflowProfile(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.DLP_CANARY_VALIDATION,),
        "policy_token_reference": "policy-ref-dlp",
        "target_scope": TARGET,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "dlp_report_rows"),
        "cleanup_callback": "cleanup://runner-1/dlp-runtime",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def workflow_request(**overrides: object) -> dlp_runtime.DlpWorkflowRequest:
    values = {
        "runtime_id": "dlp-runtime-1",
        "validation_request": validation_request(),
        "profile": profile(),
        "runner": runner(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return dlp_runtime.DlpWorkflowRequest(**values)  # type: ignore[arg-type]


def detection_evidence(**overrides: object) -> dlp_validation.DlpDetectionEvidence:
    values = {
        "evidence_id": "dlp-evidence-1",
        "validation_id": "dlp-validation-1",
        "detection_outcome": TelemetryObservationStatus.OBSERVED,
        "telemetry_source": attack_campaigns.TelemetrySource.SIEM,
        "alert_latency_seconds": 42,
        "control_owner_user_id": "dlp-owner",
        "remediation_follow_up": "Tune DLP alert route for canary-marker-1 handling.",
        "contains_sensitive_data": False,
        "raw_canary_value_present": False,
    }
    values.update(overrides)
    return dlp_validation.DlpDetectionEvidence(**values)  # type: ignore[arg-type]


def test_plan_requires_synthetic_data_roe_approval_monitoring_caps_and_kill_switch() -> None:
    plan = dlp_runtime.build_dlp_workflow_plan(workflow_request())

    assert plan.validation_id == "dlp-validation-1"
    assert plan.job.mode is domain.TestMode.DLP_CANARY_VALIDATION
    assert not plan.execution_enabled
    assert plan.protocol is dlp_validation.DlpProtocol.HTTPS
    assert plan.volume_bytes == 512
    assert plan.record_count == 5
    assert plan.canary_markers == ("canary-marker-1",)

    with pytest.raises(ValueError, match="dlp_workflow_denied:sensitive_data_forbidden"):
        dlp_runtime.build_dlp_workflow_plan(
            workflow_request(
                validation_request=validation_request(
                    dataset=dataset(data_classes=(dlp_validation.CanaryDataClass.PERSONAL_DATA,))
                )
            )
        )

    with pytest.raises(ValueError, match="dlp_workflow_denied:monitoring_not_ready"):
        dlp_runtime.build_dlp_workflow_plan(
            workflow_request(validation_request=validation_request(monitoring=monitoring(ready=False)))
        )

    with pytest.raises(ValueError, match="workflow_volume_cap_exceeded"):
        dlp_runtime.build_dlp_workflow_plan(workflow_request(profile=profile(max_volume_bytes=256)))

    with pytest.raises(ValueError, match="kill_switch_required"):
        dlp_runtime.build_dlp_workflow_plan(workflow_request(profile=profile(kill_switch_enabled=False)))


def test_transfer_protocol_connector_and_file_actions_are_denied() -> None:
    with pytest.raises(ValueError, match="dlp_transfer_or_connector_action_not_allowed"):
        dlp_runtime.build_dlp_workflow_plan(
            workflow_request(
                profile=profile(
                    actions=(
                        dlp_runtime.DlpWorkflowAction.IMPORT_DETECTION_EVIDENCE,
                        dlp_runtime.DlpWorkflowAction.PREPARE_REVIEW_QUEUE,
                        dlp_runtime.DlpWorkflowAction.TRANSFER_DATA,
                    )
                )
            )
        )


def test_detection_evidence_import_redacts_canary_markers_and_maps_report_rows() -> None:
    request_obj = workflow_request()
    plan = dlp_runtime.build_dlp_workflow_plan(request_obj)
    result = dlp_runtime.execute_dlp_workflow_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        detection_evidence=(detection_evidence(),),
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert result.imported_evidence_ids == ("dlp-runtime-1:dlp-detection:dlp-evidence-1",)
    assert len(result.report_rows) == 1
    assert result.report_rows[0].detection_outcome == "observed"
    assert result.report_rows[0].redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert "[redacted-canary]" in result.report_rows[0].remediation_follow_up
    assert "canary-marker-1" not in str(result.report_rows)


def test_sensitive_or_raw_canary_detection_evidence_is_rejected() -> None:
    request_obj = workflow_request()
    plan = dlp_runtime.build_dlp_workflow_plan(request_obj)

    with pytest.raises(ValueError, match="sensitive_dlp_evidence_forbidden"):
        dlp_runtime.execute_dlp_workflow_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            detection_evidence=(detection_evidence(contains_sensitive_data=True),),
        )

    with pytest.raises(ValueError, match="raw_canary_value_forbidden"):
        dlp_runtime.execute_dlp_workflow_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            detection_evidence=(detection_evidence(raw_canary_value_present=True),),
        )


def test_kill_switch_blocks_dispatch_and_cancellation_finishes_without_credentials() -> None:
    request_obj = workflow_request()
    plan = dlp_runtime.build_dlp_workflow_plan(request_obj)
    blocked = dlp_runtime.execute_dlp_workflow_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        detection_evidence=(detection_evidence(),),
        kill_switch_scope=dlp_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.DLP_CANARY_VALIDATION,),
        ),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert blocked.state.jobs[0].status is domain.JobStatus.QUEUED

    cancelled = dlp_runtime.execute_dlp_workflow_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        cancel_requested=True,
    )

    assert cancelled.allowed
    assert cancelled.reason == "cancelled"
    assert not cancelled.cancellation_evidence[0].credential_revoked
