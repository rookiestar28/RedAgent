from redagent_platform.observability_ir import (
    AlertKind,
    AlertRule,
    IncidentRunbook,
    IncidentScenario,
    LogStreamPolicy,
    MetricKind,
    ObservabilityIncidentResponsePlan,
    build_r033_observability_plan,
    validate_log_records_sensitive_value_free,
    validate_observability_ir_plan,
)


def test_r033_observability_plan_is_accepted():
    plan = build_r033_observability_plan()

    validation = validate_observability_ir_plan(plan)

    assert validation.accepted is True
    assert validation.reason == "observability_ir_accepted"


def test_required_metric_coverage_is_complete():
    plan = build_r033_observability_plan()

    metric_kinds = {metric.kind for metric in plan.metrics}

    assert metric_kinds == set(MetricKind)


def test_missing_metric_fails_closed():
    plan = build_r033_observability_plan()
    changed = _replace_plan(plan, metrics=tuple(metric for metric in plan.metrics if metric.kind is not MetricKind.RUNNER_HEARTBEAT))

    validation = validate_observability_ir_plan(changed)

    assert validation.accepted is False
    assert "missing_metric:runner_heartbeat" in validation.gaps


def test_required_alert_coverage_is_complete():
    plan = build_r033_observability_plan()

    alert_kinds = {alert.kind for alert in plan.alerts}

    assert alert_kinds == set(AlertKind)


def test_disabled_or_missing_alert_fails_closed():
    plan = build_r033_observability_plan()
    disabled = AlertRule(
        kind=AlertKind.RUNNER_ANOMALY,
        name="Runner anomaly",
        signal="missed heartbeat",
        severity="high",
        route="security-on-call",
        runbook_scenario=IncidentScenario.ROGUE_RUNNER,
        enabled=False,
    )
    changed = _replace_plan(plan, alerts=(disabled,) + tuple(alert for alert in plan.alerts if alert.kind is not AlertKind.RUNNER_ANOMALY))

    validation = validate_observability_ir_plan(changed)

    assert validation.accepted is False
    assert "alert_disabled:runner_anomaly" in validation.gaps


def test_required_incident_runbooks_are_complete():
    plan = build_r033_observability_plan()

    scenarios = {runbook.scenario for runbook in plan.runbooks}

    assert scenarios == set(IncidentScenario)


def test_incomplete_incident_runbook_fails_closed():
    plan = build_r033_observability_plan()
    incomplete = IncidentRunbook(
        scenario=IncidentScenario.LEAKED_EVIDENCE,
        owner="security-operations",
        containment_steps=(),
        evidence_handling_steps=(),
        escalation_steps=(),
        recovery_steps=(),
    )
    changed = _replace_plan(plan, runbooks=(incomplete,) + tuple(runbook for runbook in plan.runbooks if runbook.scenario is not IncidentScenario.LEAKED_EVIDENCE))

    validation = validate_observability_ir_plan(changed)

    assert validation.accepted is False
    assert "missing_containment_steps:leaked_evidence" in validation.gaps
    assert "missing_evidence_steps:leaked_evidence" in validation.gaps
    assert "missing_escalation_steps:leaked_evidence" in validation.gaps
    assert "missing_recovery_steps:leaked_evidence" in validation.gaps


def test_log_stream_requires_redaction_sensitive_validation_and_retention():
    plan = build_r033_observability_plan()
    weak_stream = LogStreamPolicy(
        stream_name="runner-callbacks",
        owner="security-operations",
        redaction_enabled=False,
        sensitive_value_validation_enabled=False,
        retention_days=0,
    )
    changed = _replace_plan(plan, log_streams=(weak_stream,))

    validation = validate_observability_ir_plan(changed)

    assert validation.accepted is False
    assert "log_redaction_required:runner-callbacks" in validation.gaps
    assert "log_sensitive_value_validation_required:runner-callbacks" in validation.gaps
    assert "log_retention_required:runner-callbacks" in validation.gaps


def test_log_records_reject_sensitive_value_indicators():
    sensitive_log = "runner callback " + "token=" + "redacted-placeholder"

    validation = validate_log_records_sensitive_value_free({"runner-log": sensitive_log})

    assert validation.accepted is False
    assert "sensitive_value_in_log:runner-log" in validation.gaps


def test_log_records_accept_sanitized_output():
    validation = validate_log_records_sensitive_value_free(
        {
            "audit-log": "policy denial reason=scope_target_not_in_allowlist",
            "runner-log": "heartbeat status=observed evidence_id=evidence-1",
        }
    )

    assert validation.accepted is True
    assert validation.reason == "logs_sensitive_value_free"


def _replace_plan(plan: ObservabilityIncidentResponsePlan, **changes):
    values = {
        "plan_id": plan.plan_id,
        "metrics": plan.metrics,
        "alerts": plan.alerts,
        "runbooks": plan.runbooks,
        "log_streams": plan.log_streams,
    }
    values.update(changes)
    return ObservabilityIncidentResponsePlan(**values)
