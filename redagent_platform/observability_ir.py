"""Operational observability and incident-response readiness contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping


class MetricKind(str, Enum):
    JOB_STATE = "job_state"
    RUNNER_HEARTBEAT = "runner_heartbeat"
    QUEUE_DEPTH = "queue_depth"
    SCAN_VOLUME = "scan_volume"
    POLICY_DENIAL = "policy_denial"
    AUTH_EVENT = "auth_event"
    AUDIT_WRITE = "audit_write"
    EVIDENCE_WRITE = "evidence_write"
    CONNECTOR_FAILURE = "connector_failure"


class AlertKind(str, Enum):
    OUT_OF_SCOPE_ATTEMPT = "out_of_scope_attempt"
    FAILED_CLEANUP = "failed_cleanup"
    RUNNER_ANOMALY = "runner_anomaly"
    AUTH_ANOMALY = "auth_anomaly"
    EVIDENCE_INTEGRITY_FAILURE = "evidence_integrity_failure"


class IncidentScenario(str, Enum):
    COMPROMISED_ACCOUNT = "compromised_account"
    ROGUE_RUNNER = "rogue_runner"
    LEAKED_EVIDENCE = "leaked_evidence"
    FAILED_CLEANUP = "failed_cleanup"
    ACCIDENTAL_PRODUCTION_TEST = "accidental_production_test"


@dataclass(frozen=True, kw_only=True)
class MetricDefinition:
    kind: MetricKind
    name: str
    source: str
    owner: str
    aggregation: str


@dataclass(frozen=True, kw_only=True)
class AlertRule:
    kind: AlertKind
    name: str
    signal: str
    severity: str
    route: str
    runbook_scenario: IncidentScenario
    enabled: bool


@dataclass(frozen=True, kw_only=True)
class IncidentRunbook:
    scenario: IncidentScenario
    owner: str
    containment_steps: tuple[str, ...]
    evidence_handling_steps: tuple[str, ...]
    escalation_steps: tuple[str, ...]
    recovery_steps: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class LogStreamPolicy:
    stream_name: str
    owner: str
    redaction_enabled: bool
    sensitive_value_validation_enabled: bool
    retention_days: int


@dataclass(frozen=True, kw_only=True)
class ObservabilityIncidentResponsePlan:
    plan_id: str
    metrics: tuple[MetricDefinition, ...]
    alerts: tuple[AlertRule, ...]
    runbooks: tuple[IncidentRunbook, ...]
    log_streams: tuple[LogStreamPolicy, ...]


@dataclass(frozen=True, kw_only=True)
class ObservabilityValidation:
    accepted: bool
    reason: str
    gaps: tuple[str, ...] = ()


REQUIRED_METRICS: frozenset[MetricKind] = frozenset(MetricKind)
REQUIRED_ALERTS: frozenset[AlertKind] = frozenset(AlertKind)
REQUIRED_SCENARIOS: frozenset[IncidentScenario] = frozenset(IncidentScenario)
_SENSITIVE_VALUE_MARKERS = (
    "authorization:" + " bearer",
    "api" + "_" + "key",
    "api" + "-" + "key",
    "password" + "=",
    "token" + "=",
    "secret" + "=",
)


def build_observability_plan() -> ObservabilityIncidentResponsePlan:
    return ObservabilityIncidentResponsePlan(
        plan_id="R033-observability-incident-response",
        metrics=tuple(
            MetricDefinition(
                kind=kind,
                name=f"redteam.{kind.value}",
                source=_metric_source(kind),
                owner="security-operations",
                aggregation="count_by_status_and_scope",
            )
            for kind in MetricKind
        ),
        alerts=(
            AlertRule(
                kind=AlertKind.OUT_OF_SCOPE_ATTEMPT,
                name="Out-of-scope attempt",
                signal="policy_denial.reason starts with scope_ or target_",
                severity="high",
                route="security-on-call",
                runbook_scenario=IncidentScenario.ACCIDENTAL_PRODUCTION_TEST,
                enabled=True,
            ),
            AlertRule(
                kind=AlertKind.FAILED_CLEANUP,
                name="Failed cleanup",
                signal="job.status in failed cleanup states or cleanup retry exhausted",
                severity="high",
                route="security-on-call",
                runbook_scenario=IncidentScenario.FAILED_CLEANUP,
                enabled=True,
            ),
            AlertRule(
                kind=AlertKind.RUNNER_ANOMALY,
                name="Runner anomaly",
                signal="missed heartbeat, duplicate callback, runner mismatch, or unexpected egress",
                severity="high",
                route="security-on-call",
                runbook_scenario=IncidentScenario.ROGUE_RUNNER,
                enabled=True,
            ),
            AlertRule(
                kind=AlertKind.AUTH_ANOMALY,
                name="Auth anomaly",
                signal="login failure spike, role change anomaly, or cross-tenant denial spike",
                severity="high",
                route="identity-security-on-call",
                runbook_scenario=IncidentScenario.COMPROMISED_ACCOUNT,
                enabled=True,
            ),
            AlertRule(
                kind=AlertKind.EVIDENCE_INTEGRITY_FAILURE,
                name="Evidence integrity failure",
                signal="hash mismatch, overwrite attempt, or unredacted sensitive evidence rejection",
                severity="critical",
                route="security-lead",
                runbook_scenario=IncidentScenario.LEAKED_EVIDENCE,
                enabled=True,
            ),
        ),
        runbooks=(
            _runbook(IncidentScenario.COMPROMISED_ACCOUNT, "disable session, revoke roles, preserve audit chain"),
            _runbook(IncidentScenario.ROGUE_RUNNER, "revoke runner token, cut runner egress, quarantine evidence"),
            _runbook(IncidentScenario.LEAKED_EVIDENCE, "block export, restrict evidence access, rotate affected references"),
            _runbook(IncidentScenario.FAILED_CLEANUP, "pause scheduler, run cleanup retry plan, verify evidence lock"),
            _runbook(IncidentScenario.ACCIDENTAL_PRODUCTION_TEST, "activate kill switch, notify owner, preserve scope evidence"),
        ),
        log_streams=(
            LogStreamPolicy(
                stream_name="control-plane-audit",
                owner="security-operations",
                redaction_enabled=True,
                sensitive_value_validation_enabled=True,
                retention_days=365,
            ),
            LogStreamPolicy(
                stream_name="runner-callbacks",
                owner="security-operations",
                redaction_enabled=True,
                sensitive_value_validation_enabled=True,
                retention_days=180,
            ),
            LogStreamPolicy(
                stream_name="evidence-writes",
                owner="security-operations",
                redaction_enabled=True,
                sensitive_value_validation_enabled=True,
                retention_days=365,
            ),
        ),
    )


def validate_observability_ir_plan(plan: ObservabilityIncidentResponsePlan) -> ObservabilityValidation:
    gaps: list[str] = []
    _append_missing(gaps, "plan_id", plan.plan_id)
    gaps.extend(_metric_gaps(plan.metrics))
    gaps.extend(_alert_gaps(plan.alerts))
    gaps.extend(_runbook_gaps(plan.runbooks))
    gaps.extend(_log_stream_gaps(plan.log_streams))
    if gaps:
        return ObservabilityValidation(accepted=False, reason="observability_ir_incomplete", gaps=tuple(gaps))
    return ObservabilityValidation(accepted=True, reason="observability_ir_accepted")


def validate_log_records_sensitive_value_free(records: Mapping[str, str]) -> ObservabilityValidation:
    gaps: list[str] = []
    for record_id, content in records.items():
        _append_missing(gaps, "log_record_id", record_id)
        lowered = content.lower()
        for marker in _SENSITIVE_VALUE_MARKERS:
            if marker in lowered:
                gaps.append(f"sensitive_value_in_log:{record_id}")
                break
    if gaps:
        return ObservabilityValidation(accepted=False, reason="log_sensitive_value_validation_failed", gaps=tuple(gaps))
    return ObservabilityValidation(accepted=True, reason="logs_sensitive_value_free")


def _metric_gaps(metrics: tuple[MetricDefinition, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    present = {metric.kind for metric in metrics}
    missing = REQUIRED_METRICS - present
    gaps.extend(f"missing_metric:{kind.value}" for kind in sorted(missing, key=lambda item: item.value))
    for metric in metrics:
        _append_missing(gaps, "metric_name", metric.name)
        _append_missing(gaps, "metric_source", metric.source)
        _append_missing(gaps, "metric_owner", metric.owner)
        _append_missing(gaps, "metric_aggregation", metric.aggregation)
    return tuple(gaps)


def _alert_gaps(alerts: tuple[AlertRule, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    present = {alert.kind for alert in alerts}
    missing = REQUIRED_ALERTS - present
    gaps.extend(f"missing_alert:{kind.value}" for kind in sorted(missing, key=lambda item: item.value))
    for alert in alerts:
        _append_missing(gaps, "alert_name", alert.name)
        _append_missing(gaps, "alert_signal", alert.signal)
        _append_missing(gaps, "alert_severity", alert.severity)
        _append_missing(gaps, "alert_route", alert.route)
        if not alert.enabled:
            gaps.append(f"alert_disabled:{alert.kind.value}")
        if alert.runbook_scenario not in REQUIRED_SCENARIOS:
            gaps.append(f"unknown_alert_runbook:{alert.kind.value}")
    return tuple(gaps)


def _runbook_gaps(runbooks: tuple[IncidentRunbook, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    present = {runbook.scenario for runbook in runbooks}
    missing = REQUIRED_SCENARIOS - present
    gaps.extend(f"missing_runbook:{scenario.value}" for scenario in sorted(missing, key=lambda item: item.value))
    for runbook in runbooks:
        _append_missing(gaps, "runbook_owner", runbook.owner)
        if not runbook.containment_steps:
            gaps.append(f"missing_containment_steps:{runbook.scenario.value}")
        if not runbook.evidence_handling_steps:
            gaps.append(f"missing_evidence_steps:{runbook.scenario.value}")
        if not runbook.escalation_steps:
            gaps.append(f"missing_escalation_steps:{runbook.scenario.value}")
        if not runbook.recovery_steps:
            gaps.append(f"missing_recovery_steps:{runbook.scenario.value}")
    return tuple(gaps)


def _log_stream_gaps(streams: tuple[LogStreamPolicy, ...]) -> tuple[str, ...]:
    gaps: list[str] = []
    if not streams:
        return ("log_stream_policy_required",)
    for stream in streams:
        _append_missing(gaps, "log_stream_name", stream.stream_name)
        _append_missing(gaps, "log_stream_owner", stream.owner)
        if not stream.redaction_enabled:
            gaps.append(f"log_redaction_required:{stream.stream_name}")
        if not stream.sensitive_value_validation_enabled:
            gaps.append(f"log_sensitive_value_validation_required:{stream.stream_name}")
        if stream.retention_days <= 0:
            gaps.append(f"log_retention_required:{stream.stream_name}")
    return tuple(gaps)


def _runbook(scenario: IncidentScenario, containment: str) -> IncidentRunbook:
    return IncidentRunbook(
        scenario=scenario,
        owner="security-operations",
        containment_steps=(containment,),
        evidence_handling_steps=("preserve immutable audit/evidence chain and restrict exports",),
        escalation_steps=("notify security lead and engagement owner",),
        recovery_steps=("verify control restoration and document follow-up actions",),
    )


def _metric_source(kind: MetricKind) -> str:
    source_by_kind = {
        MetricKind.JOB_STATE: "job_queue",
        MetricKind.RUNNER_HEARTBEAT: "runner_callbacks",
        MetricKind.QUEUE_DEPTH: "scheduler",
        MetricKind.SCAN_VOLUME: "scheduler_and_job_queue",
        MetricKind.POLICY_DENIAL: "policy_decisions",
        MetricKind.AUTH_EVENT: "identity_audit",
        MetricKind.AUDIT_WRITE: "evidence_chain",
        MetricKind.EVIDENCE_WRITE: "evidence_chain",
        MetricKind.CONNECTOR_FAILURE: "issue_and_telemetry_connectors",
    }
    return source_by_kind[kind]


def _append_missing(gaps: list[str], field_name: str, value: str) -> None:
    if not value or not value.strip():
        gaps.append(f"missing_{field_name}")
