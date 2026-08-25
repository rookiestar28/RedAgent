"""Reviewed compat_102 SLO, alert, and incident-runbook catalog."""

from __future__ import annotations

from dataclasses import dataclass

from redagent_platform.telemetry_service.contracts import MEASUREMENT_NAMES
from redagent_platform.telemetry_service.slo import Comparison, SloObjective


@dataclass(frozen=True, kw_only=True)
class FoundationObjective:
    measurement_name: str
    objective: SloObjective
    owner: str


@dataclass(frozen=True, kw_only=True)
class FoundationAlertRule:
    rule_id: str
    measurement_name: str
    severity: str
    runbook_id: str


@dataclass(frozen=True, kw_only=True)
class FoundationRunbook:
    runbook_id: str
    owner: str
    triage: tuple[str, ...]
    containment: tuple[str, ...]
    evidence: tuple[str, ...]
    recovery: tuple[str, ...]
    review: tuple[str, ...]


def foundation_objectives() -> tuple[FoundationObjective, ...]:
    return tuple(
        FoundationObjective(
            measurement_name=name,
            objective=_objective(name),
            owner="security-operations",
        )
        for name in sorted(MEASUREMENT_NAMES)
    )


def foundation_alert_rules() -> tuple[FoundationAlertRule, ...]:
    rows = (
        ("api_availability_breach", "api_availability", "critical", "service_outage"),
        ("api_latency_breach", "api_request_duration_ms", "high", "service_outage"),
        ("stop_slo_breach", "emergency_stop_ack_ms", "critical", "failed_containment"),
        ("evidence_failure", "evidence_failure", "critical", "evidence_integrity"),
        ("lease_failure", "lease_failure", "high", "credential_failure"),
        ("policy_failure", "policy_failure", "high", "policy_failure"),
        ("queue_pressure", "queue_depth", "high", "service_outage"),
        ("runner_heartbeat_stale", "runner_heartbeat_age_ms", "critical", "rogue_runner"),
        ("security_denial_spike", "security_denial", "high", "authorization_anomaly"),
        ("telemetry_export_failure", "telemetry_export_failure", "high", "telemetry_outage"),
        ("telemetry_backlog", "telemetry_export_backlog", "high", "telemetry_outage"),
        ("idle_cpu_budget", "idle_cpu_millipercent", "medium", "resource_budget"),
        ("idle_ram_budget", "idle_ram_mib", "medium", "resource_budget"),
        ("workflow_latency", "workflow_activity_duration_ms", "high", "service_outage"),
        ("zap_scope_denial", "security_denial", "critical", "failed_containment"),
        ("zap_stop_slo_breach", "emergency_stop_ack_ms", "critical", "failed_containment"),
        ("zap_passive_queue_pressure", "queue_depth", "high", "service_outage"),
    )
    return tuple(FoundationAlertRule(
        rule_id=rule, measurement_name=measurement, severity=severity, runbook_id=runbook,
    ) for rule, measurement, severity, runbook in rows)


def foundation_runbooks() -> tuple[FoundationRunbook, ...]:
    identifiers = {
        rule.runbook_id for rule in foundation_alert_rules()
    }
    return tuple(_runbook(runbook_id) for runbook_id in sorted(identifiers))


def validate_foundation_catalog() -> tuple[str, ...]:
    errors: list[str] = []
    objectives = foundation_objectives()
    alerts = foundation_alert_rules()
    runbooks = {item.runbook_id: item for item in foundation_runbooks()}
    if {item.measurement_name for item in objectives} != MEASUREMENT_NAMES:
        errors.append("foundation_objective_coverage_incomplete")
    if len({item.objective.objective_id for item in objectives}) != len(objectives):
        errors.append("foundation_objective_duplicate")
    for rule in alerts:
        if rule.measurement_name not in MEASUREMENT_NAMES:
            errors.append(f"foundation_alert_measurement_unknown:{rule.rule_id}")
        if rule.runbook_id not in runbooks:
            errors.append(f"foundation_alert_runbook_missing:{rule.rule_id}")
        if rule.severity not in {"medium", "high", "critical"}:
            errors.append(f"foundation_alert_severity_invalid:{rule.rule_id}")
    for runbook in runbooks.values():
        if not all((runbook.triage, runbook.containment, runbook.evidence, runbook.recovery, runbook.review)):
            errors.append(f"foundation_runbook_incomplete:{runbook.runbook_id}")
    return tuple(errors)


def _objective(name: str) -> SloObjective:
    latency = name.endswith("_ms")
    availability = name == "api_availability"
    return SloObjective(
        objective_id=name,
        metric_name=name,
        comparison=Comparison.MIN if availability else Comparison.MAX,
        threshold_millionths=(
            999_000 if availability else (10_000 if latency else 1_000) * 1_000_000
        ),
        window_seconds=300,
        minimum_samples=1,
        error_budget_millionths=1_000,
    )


def _runbook(runbook_id: str) -> FoundationRunbook:
    return FoundationRunbook(
        runbook_id=runbook_id, owner="security-operations",
        triage=("Confirm authoritative audit and current tenant scope.",),
        containment=("Apply the reviewed R101 stop or isolation control when required.",),
        evidence=("Preserve metadata-only evidence references and immutable custody records.",),
        recovery=("Verify policy, credential, runner, evidence, and containment prerequisites.",),
        review=("Record an independent post-incident review before closure.",),
    )
