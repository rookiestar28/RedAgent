"""Purple-team telemetry expectation, evidence comparison, and report-gap contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.attack_campaigns import TelemetrySource


class TelemetryObservationStatus(str, Enum):
    OBSERVED = "observed"
    MISSING = "missing"
    NOT_EVALUATED = "not_evaluated"


@dataclass(frozen=True, kw_only=True)
class TelemetryExpectation:
    expectation_id: str
    source: TelemetrySource
    event_name: str
    detection_owner: str
    success_criteria: str
    required: bool = True


@dataclass(frozen=True, kw_only=True)
class TelemetryEnabledTestDefinition:
    test_definition_id: str
    expected_logs: tuple[TelemetryExpectation, ...]
    siem_events: tuple[TelemetryExpectation, ...]
    edr_detections: tuple[TelemetryExpectation, ...]
    cloud_audit_events: tuple[TelemetryExpectation, ...]
    detection_owner: str


@dataclass(frozen=True, kw_only=True)
class ObservedTelemetryEvent:
    expectation_id: str
    source: TelemetrySource
    event_name: str
    observed_at: datetime | None
    evidence_id: str | None
    status: TelemetryObservationStatus


@dataclass(frozen=True, kw_only=True)
class TelemetryComparison:
    expectation_id: str
    source: TelemetrySource
    event_name: str
    detection_owner: str
    status: TelemetryObservationStatus
    evidence_id: str | None
    gap_reason: str | None


@dataclass(frozen=True, kw_only=True)
class TelemetryEvidence:
    evidence_id: str
    test_definition_id: str
    comparisons: tuple[TelemetryComparison, ...]


@dataclass(frozen=True, kw_only=True)
class TelemetryIntegrationConfig:
    integration_id: str
    provider_label: str
    credential_reference_id: str
    plaintext_credential: str | None = None


@dataclass(frozen=True, kw_only=True)
class CampaignDetectionReport:
    campaign_id: str
    observed: tuple[dict[str, str], ...]
    gaps: tuple[dict[str, str], ...]
    not_evaluated: tuple[dict[str, str], ...]
    overstates_unobserved_controls: bool = False


def validate_telemetry_test_definition(definition: TelemetryEnabledTestDefinition) -> None:
    _require_non_empty("test_definition_id", definition.test_definition_id)
    _require_non_empty("detection_owner", definition.detection_owner)
    expectations = all_expectations(definition)
    if not expectations:
        raise ValueError("telemetry_expectations_required")
    for expectation in expectations:
        _validate_expectation(expectation)


def all_expectations(definition: TelemetryEnabledTestDefinition) -> tuple[TelemetryExpectation, ...]:
    return definition.expected_logs + definition.siem_events + definition.edr_detections + definition.cloud_audit_events


def compare_telemetry(
    definition: TelemetryEnabledTestDefinition,
    observed_events: tuple[ObservedTelemetryEvent, ...],
    *,
    evidence_id: str,
) -> TelemetryEvidence:
    validate_telemetry_test_definition(definition)
    _require_non_empty("evidence_id", evidence_id)
    observed_by_id = {event.expectation_id: event for event in observed_events}
    comparisons = []
    for expectation in all_expectations(definition):
        observed = observed_by_id.get(expectation.expectation_id)
        if observed is None:
            status = TelemetryObservationStatus.MISSING if expectation.required else TelemetryObservationStatus.NOT_EVALUATED
            comparisons.append(_comparison(expectation, status, None, "expected_telemetry_not_observed"))
            continue
        _validate_observed_event(observed)
        if observed.source is not expectation.source or observed.event_name != expectation.event_name:
            comparisons.append(_comparison(expectation, TelemetryObservationStatus.MISSING, observed.evidence_id, "observed_event_mismatch"))
            continue
        comparisons.append(_comparison(expectation, observed.status, observed.evidence_id, None if observed.status is TelemetryObservationStatus.OBSERVED else "telemetry_not_observed"))
    return TelemetryEvidence(evidence_id=evidence_id, test_definition_id=definition.test_definition_id, comparisons=tuple(comparisons))


def build_campaign_detection_report(campaign_id: str, evidence: TelemetryEvidence) -> CampaignDetectionReport:
    _require_non_empty("campaign_id", campaign_id)
    _require_non_empty("evidence_id", evidence.evidence_id)
    observed = []
    gaps = []
    not_evaluated = []
    for comparison in evidence.comparisons:
        row = {
            "expectation_id": comparison.expectation_id,
            "source": comparison.source.value,
            "event_name": comparison.event_name,
            "detection_owner": comparison.detection_owner,
        }
        if comparison.status is TelemetryObservationStatus.OBSERVED:
            observed.append(row | {"status": comparison.status.value, "evidence_id": comparison.evidence_id or ""})
        elif comparison.status is TelemetryObservationStatus.MISSING:
            gaps.append(row | {"status": comparison.status.value, "gap_reason": comparison.gap_reason or "missing"})
        else:
            not_evaluated.append(row | {"status": comparison.status.value})
    return CampaignDetectionReport(
        campaign_id=campaign_id,
        observed=tuple(observed),
        gaps=tuple(gaps),
        not_evaluated=tuple(not_evaluated),
        overstates_unobserved_controls=False,
    )


def validate_integration_config(config: TelemetryIntegrationConfig) -> None:
    for field_name, value in (
        ("integration_id", config.integration_id),
        ("provider_label", config.provider_label),
        ("credential_reference_id", config.credential_reference_id),
    ):
        _require_non_empty(field_name, value)
    if config.plaintext_credential:
        raise ValueError("plaintext_telemetry_credential_forbidden")


def _validate_expectation(expectation: TelemetryExpectation) -> None:
    for field_name, value in (
        ("expectation_id", expectation.expectation_id),
        ("event_name", expectation.event_name),
        ("detection_owner", expectation.detection_owner),
        ("success_criteria", expectation.success_criteria),
    ):
        _require_non_empty(field_name, value)


def _validate_observed_event(event: ObservedTelemetryEvent) -> None:
    _require_non_empty("expectation_id", event.expectation_id)
    _require_non_empty("event_name", event.event_name)
    if event.status is TelemetryObservationStatus.OBSERVED:
        if event.observed_at is None or event.observed_at.tzinfo is None or event.observed_at.utcoffset() is None:
            raise ValueError("observed_telemetry_timestamp_required")
        if not event.evidence_id or not event.evidence_id.strip():
            raise ValueError("observed_telemetry_evidence_required")


def _comparison(
    expectation: TelemetryExpectation,
    status: TelemetryObservationStatus,
    evidence_id: str | None,
    gap_reason: str | None,
) -> TelemetryComparison:
    return TelemetryComparison(
        expectation_id=expectation.expectation_id,
        source=expectation.source,
        event_name=expectation.event_name,
        detection_owner=expectation.detection_owner,
        status=status,
        evidence_id=evidence_id,
        gap_reason=gap_reason,
    )


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
