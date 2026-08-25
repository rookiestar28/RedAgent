from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TABLES = (
    "containment_controls", "containment_approvals", "containment_job_actions",
    "containment_phase_receipts", "containment_residual_risks", "containment_incidents",
    "quota_policies", "quota_usage", "quota_reservations", "quota_operations",
)


def _source() -> str:
    return (ROOT / "migrations" / "versions" / "0008_r101_containment_quotas.py").read_text(encoding="utf-8")


def test_revision_0008_owns_containment_and_quota_truth_with_force_rls() -> None:
    source = _source()
    assert 'revision = "0008_r101_containment_quotas"' in source
    assert 'down_revision = "0007_r100_ephemeral_runners"' in source
    for table in TABLES:
        assert f'"{table}"' in source
    assert "for table in TABLES:" in source and "_tenant_rls(table)" in source
    assert 'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY' in source
    assert 'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' in source


def test_revision_has_replay_sod_phase_and_atomic_quota_uniqueness() -> None:
    source = _source()
    for name in (
        "uq_containment_controls_tenant_request",
        "uq_containment_approvals_tenant_approval",
        "uq_containment_actions_tenant_job",
        "uq_containment_phases_tenant_action_phase",
        "uq_containment_residual_tenant_risk",
        "uq_containment_incidents_tenant_incident",
        "uq_quota_policies_tenant_revision_dimension_scope",
        "uq_quota_operations_tenant_operation",
        "uq_quota_usage_tenant_policy_window_scope",
        "uq_quota_reservations_tenant_reservation",
    ):
        assert name in source
    assert 'sa.CheckConstraint("initiated_by_user_id <> approved_by_user_id"' in source
    assert 'sa.CheckConstraint("hard_limit > 0"' in source


def test_revision_downgrade_is_dependency_safe() -> None:
    source = _source()
    downgrade = source.split("def downgrade() -> None:", maxsplit=1)[1]
    positions = [downgrade.index(f'op.drop_table("{table}"') for table in reversed(TABLES)]
    assert positions == sorted(positions)
    assert downgrade.count("op.drop_table(") == len(TABLES)
