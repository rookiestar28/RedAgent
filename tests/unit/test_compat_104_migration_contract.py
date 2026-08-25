from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations" / "versions" / "0011_r104_zap_controlled_runtime.py"


def test_revision_0011_owns_zap_profiles_runs_gateway_alerts_and_cleanup_truth() -> None:
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0011_r104_zap_runtime"' in source
    assert 'down_revision = "0010_r103_safe_lab"' in source
    tables = (
        "zap_profile_revisions", "zap_target_attestations", "zap_compiled_plans", "zap_runs", "zap_run_steps",
        "zap_gateway_decisions", "zap_normalized_alerts", "zap_cancellation_receipts",
        "zap_cleanup_receipts",
    )
    for table in tables:
        assert f'"{table}"' in source
        if table == "zap_target_attestations":
            assert 'op.drop_table("zap_target_attestations", if_exists=True)' in source
        else:
            assert f'op.drop_table("{table}")' in source
    assert "for table in TABLES:" in source and "_tenant_rls(table)" in source
    assert 'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY' in source
    assert 'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' in source
    assert "image_digest" in source and "addon_inventory_sha256" in source
    assert "plan_sha256" in source and "scope_sha256" in source
    assert "request_count" in source and "response_bytes" in source
    assert "native_stop_attempted" in source and "forced_termination" in source
    assert "residual_resource_count" in source and "cleanup_complete" in source
