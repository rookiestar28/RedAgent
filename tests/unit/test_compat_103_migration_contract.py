from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations" / "versions" / "0010_r103_safe_lab_qualification.py"


def test_revision_0010_owns_lab_scenario_measurement_and_restore_truth() -> None:
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0010_r103_safe_lab"' in source
    assert 'down_revision = "0009_r102_observability_ir"' in source
    tables = (
        "lab_bundles", "lab_target_attestations", "lab_target_leases",
        "golden_scenario_runs", "golden_scenario_steps", "golden_finding_expectations",
        "qualification_measurements", "lab_backup_restore_receipts", "lab_teardown_receipts",
    )
    for table in tables:
        assert f'"{table}"' in source
        assert f'op.drop_table("{table}")' in source
    assert "for table in TABLES:" in source and "_tenant_rls(table)" in source
    assert 'ALTER TABLE \"{table}\" ENABLE ROW LEVEL SECURITY' in source
    assert 'ALTER TABLE \"{table}\" FORCE ROW LEVEL SECURITY' in source
    assert 'CREATE POLICY \"{table}_tenant_isolation\"' in source
    assert "expected_finding_manifest_sha256" in source
    assert "attestation_sha256" in source and "lease_state" in source
    assert "request_count" in source and "contact_count" in source
    assert "source_inventory_sha256" in source and "restored_inventory_sha256" in source
    assert "teardown_complete" in source and "residual_resource_count" in source
