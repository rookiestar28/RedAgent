from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TABLES = (
    "telemetry_export_operations",
    "telemetry_delivery_attempts",
    "telemetry_dead_letters",
    "security_incidents",
    "incident_timeline_events",
    "incident_actions",
    "slo_definitions",
    "slo_windows",
    "slo_evaluations",
    "alert_instances",
    "alert_notifications",
)


def _source() -> str:
    return (ROOT / "migrations" / "versions" / "0009_r102_observability_incidents.py").read_text(encoding="utf-8")


def test_revision_0009_owns_delivery_incident_alert_and_slo_truth_with_force_rls() -> None:
    source = _source()
    assert 'revision = "0009_r102_observability_ir"' in source
    assert 'down_revision = "0008_r101_containment_quotas"' in source
    for table in TABLES:
        assert f'"{table}"' in source
    assert "for table in TABLES:" in source and "_tenant_rls(table)" in source
    assert 'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY' in source
    assert 'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' in source


def test_revision_0009_has_replay_and_concurrency_uniqueness() -> None:
    source = _source()
    for name in (
        "uq_telemetry_exports_tenant_operation",
        "uq_telemetry_attempts_tenant_export_number",
        "uq_telemetry_dead_letters_tenant_export",
        "uq_security_incidents_tenant_incident",
        "uq_incident_timeline_tenant_event",
        "uq_incident_actions_tenant_action",
        "uq_slo_definitions_tenant_objective_revision",
        "uq_slo_windows_tenant_objective_window",
        "uq_slo_evaluations_tenant_window",
        "uq_alert_instances_tenant_rule_fingerprint",
        "uq_alert_notifications_tenant_attempt",
    ):
        assert name in source
    assert 'sa.CheckConstraint("opened_by_user_id <> recovered_by_user_id"' in source


def test_revision_0009_downgrade_is_dependency_safe() -> None:
    source = _source()
    downgrade = source.split("def downgrade() -> None:", maxsplit=1)[1]
    positions = [downgrade.index(f'op.drop_table("{table}"') for table in reversed(TABLES)]
    assert positions == sorted(positions)
    assert downgrade.count("op.drop_table(") == len(TABLES)
