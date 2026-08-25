from __future__ import annotations

from pathlib import Path

from redagent_platform.persistence.models import metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0013_r106_openapi_authorization_differential.py"
TABLES = (
    "api_diff_engine_artifacts", "api_diff_spec_revisions", "api_diff_operation_manifests",
    "api_diff_identity_matrices", "api_diff_sequence_grammars", "api_diff_reviews",
    "api_diff_promotions", "api_diff_profiles", "api_diff_target_attestations",
    "api_diff_plans", "api_diff_cases", "api_diff_runs", "api_diff_resource_ledger",
    "api_diff_gateway_decisions", "api_diff_observations", "api_diff_replay_artifacts",
    "api_diff_cancellation_receipts", "api_diff_cleanup_receipts",
)


def test_revision_0013_owns_promoted_runtime_case_replay_and_cleanup_truth() -> None:
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0013_r106_api_diff"' in source
    assert 'down_revision = "0012_r105_nuclei"' in source
    for table in TABLES:
        assert f'"{table}"' in source
        assert table in metadata.tables
    assert "for table in reversed(TABLES):" in source and "DROP TABLE IF EXISTS" in source
    assert "for table in TABLES:" in source and "_tenant_rls(table)" in source
    assert 'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' in source
    for field in (
        "spec_sha256", "operation_manifest_sha256", "identity_matrix_sha256",
        "sequence_grammar_sha256", "policy_decision_id", "attestation_sha256", "identity_handle",
        "resource_lineage_sha256", "minimized_replay_sha256", "lease_revoked",
        "compensation_complete", "residual_resource_count",
    ):
        assert field in source


def test_r106_tables_are_tenant_owned_with_immutable_keys() -> None:
    for name in TABLES:
        table = metadata.tables[name]
        assert {"id", "tenant_id", "version", "created_at", "updated_at"} <= set(table.c.keys())
        assert any(
            constraint.__class__.__name__ == "UniqueConstraint" and "tenant_id" in {column.name for column in constraint.columns}
            for constraint in table.constraints
        )
