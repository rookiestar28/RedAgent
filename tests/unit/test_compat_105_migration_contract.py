from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0012_r105_nuclei_template_trust.py"


def test_revision_0012_owns_engine_bundle_plan_run_result_stop_and_cleanup_truth() -> None:
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0012_r105_nuclei"' in source
    assert 'down_revision = "0011_r104_zap_runtime"' in source
    tables = (
        "nuclei_engine_artifacts", "nuclei_target_attestations", "nuclei_bundle_revisions", "nuclei_bundle_files",
        "nuclei_template_revisions", "nuclei_bundle_reviews", "nuclei_bundle_promotions",
        "nuclei_profile_revisions", "nuclei_compiled_plans", "nuclei_runs",
        "nuclei_gateway_decisions", "nuclei_normalized_results", "nuclei_result_rejections",
        "nuclei_cancellation_receipts", "nuclei_cleanup_receipts",
    )
    for table in tables:
        assert f'"{table}"' in source
    assert "for table in reversed(TABLES):" in source and 'DROP TABLE IF EXISTS' in source
    assert "for table in TABLES:" in source and "_tenant_rls(table)" in source
    assert 'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' in source
    for field in (
        "image_digest", "sbom_sha256", "vulnerability_review", "bundle_sha256",
        "signature_sha256", "template_sha256", "payload_file_count", "plan_sha256",
        "request_count", "response_bytes", "native_stop_attempted",
        "residual_resource_count", "cleanup_complete",
    ):
        assert field in source
