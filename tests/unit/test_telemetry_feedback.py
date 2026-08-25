from datetime import datetime, timezone

import pytest

from redagent_platform import attack_campaigns, telemetry_feedback


NOW = datetime(2026, 7, 8, 23, 0, tzinfo=timezone.utc)


def expectation(
    expectation_id: str,
    source: attack_campaigns.TelemetrySource,
    event_name: str,
    *,
    required: bool = True,
) -> telemetry_feedback.TelemetryExpectation:
    return telemetry_feedback.TelemetryExpectation(
        expectation_id=expectation_id,
        source=source,
        event_name=event_name,
        detection_owner="blue-team",
        success_criteria=f"{event_name} is observed by blue-team.",
        required=required,
    )


def definition(**overrides: object) -> telemetry_feedback.TelemetryEnabledTestDefinition:
    values = {
        "test_definition_id": "test-1",
        "expected_logs": (expectation("log-1", attack_campaigns.TelemetrySource.APPLICATION_LOG, "app.auth.failure"),),
        "siem_events": (expectation("siem-1", attack_campaigns.TelemetrySource.SIEM, "siem.correlation.rule"),),
        "edr_detections": (expectation("edr-1", attack_campaigns.TelemetrySource.EDR, "edr.suspicious.process"),),
        "cloud_audit_events": (
            expectation("cloud-1", attack_campaigns.TelemetrySource.CLOUD_AUDIT, "cloudtrail.AssumeRole", required=False),
        ),
        "detection_owner": "blue-team",
    }
    values.update(overrides)
    return telemetry_feedback.TelemetryEnabledTestDefinition(**values)  # type: ignore[arg-type]


def observed(
    expectation_id: str,
    source: attack_campaigns.TelemetrySource,
    event_name: str,
    status: telemetry_feedback.TelemetryObservationStatus = telemetry_feedback.TelemetryObservationStatus.OBSERVED,
) -> telemetry_feedback.ObservedTelemetryEvent:
    return telemetry_feedback.ObservedTelemetryEvent(
        expectation_id=expectation_id,
        source=source,
        event_name=event_name,
        observed_at=NOW if status is telemetry_feedback.TelemetryObservationStatus.OBSERVED else None,
        evidence_id=f"evidence-{expectation_id}" if status is telemetry_feedback.TelemetryObservationStatus.OBSERVED else None,
        status=status,
    )


def test_test_definition_declares_logs_siem_edr_cloud_audit_and_detection_owner() -> None:
    telemetry_feedback.validate_telemetry_test_definition(definition())

    expected = telemetry_feedback.all_expectations(definition())
    assert {item.source for item in expected} == {
        attack_campaigns.TelemetrySource.APPLICATION_LOG,
        attack_campaigns.TelemetrySource.SIEM,
        attack_campaigns.TelemetrySource.EDR,
        attack_campaigns.TelemetrySource.CLOUD_AUDIT,
    }
    with pytest.raises(ValueError, match="missing_detection_owner"):
        telemetry_feedback.validate_telemetry_test_definition(definition(detection_owner=""))


def test_evidence_records_observed_vs_expected_telemetry() -> None:
    evidence = telemetry_feedback.compare_telemetry(
        definition(),
        (
            observed("log-1", attack_campaigns.TelemetrySource.APPLICATION_LOG, "app.auth.failure"),
            observed("siem-1", attack_campaigns.TelemetrySource.SIEM, "siem.correlation.rule"),
        ),
        evidence_id="telemetry-evidence-1",
    )

    by_id = {comparison.expectation_id: comparison for comparison in evidence.comparisons}
    assert by_id["log-1"].status is telemetry_feedback.TelemetryObservationStatus.OBSERVED
    assert by_id["siem-1"].status is telemetry_feedback.TelemetryObservationStatus.OBSERVED
    assert by_id["edr-1"].status is telemetry_feedback.TelemetryObservationStatus.MISSING
    assert by_id["cloud-1"].status is telemetry_feedback.TelemetryObservationStatus.NOT_EVALUATED
    assert by_id["edr-1"].gap_reason == "expected_telemetry_not_observed"


def test_campaign_report_includes_gaps_without_overstating_unobserved_controls() -> None:
    evidence = telemetry_feedback.compare_telemetry(
        definition(),
        (observed("log-1", attack_campaigns.TelemetrySource.APPLICATION_LOG, "app.auth.failure"),),
        evidence_id="telemetry-evidence-1",
    )

    report = telemetry_feedback.build_campaign_detection_report("campaign-1", evidence)

    assert len(report.observed) == 1
    assert {gap["expectation_id"] for gap in report.gaps} == {"siem-1", "edr-1"}
    assert {item["expectation_id"] for item in report.not_evaluated} == {"cloud-1"}
    assert not report.overstates_unobserved_controls
    assert all(gap["status"] == "missing" for gap in report.gaps)


def test_observed_telemetry_requires_timestamp_and_evidence_id() -> None:
    with pytest.raises(ValueError, match="observed_telemetry_timestamp_required"):
        telemetry_feedback.compare_telemetry(
            definition(expected_logs=(expectation("log-1", attack_campaigns.TelemetrySource.APPLICATION_LOG, "app.auth.failure"),), siem_events=(), edr_detections=(), cloud_audit_events=()),
            (
                telemetry_feedback.ObservedTelemetryEvent(
                    expectation_id="log-1",
                    source=attack_campaigns.TelemetrySource.APPLICATION_LOG,
                    event_name="app.auth.failure",
                    observed_at=None,
                    evidence_id="evidence-log-1",
                    status=telemetry_feedback.TelemetryObservationStatus.OBSERVED,
                ),
            ),
            evidence_id="telemetry-evidence-1",
        )


def test_integrations_use_credential_references_and_reject_plaintext_siem_credentials() -> None:
    telemetry_feedback.validate_integration_config(
        telemetry_feedback.TelemetryIntegrationConfig(
            integration_id="siem-1",
            provider_label="enterprise-siem",
            credential_reference_id="cred-ref-siem-1",
        )
    )

    with pytest.raises(ValueError, match="plaintext_telemetry_credential_forbidden"):
        telemetry_feedback.validate_integration_config(
            telemetry_feedback.TelemetryIntegrationConfig(
                integration_id="siem-2",
                provider_label="enterprise-siem",
                credential_reference_id="cred-ref-siem-2",
                plaintext_credential="do-not-store-this",
            )
        )
