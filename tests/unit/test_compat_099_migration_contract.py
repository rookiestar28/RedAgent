from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TABLES = (
    "policy_bundle_revisions", "policy_bundle_promotions", "policy_agent_status",
    "policy_decisions", "policy_boundary_receipts", "policy_log_receipts",
)


def test_revision_0006_owns_policy_distribution_truth_and_descends_from_r098() -> None:
    source = (ROOT / "migrations" / "versions" / "0006_r099_policy_distribution.py").read_text(encoding="utf-8")
    assert 'revision = "0006_r099_policy_distribution"' in source
    assert 'down_revision = "0005_r098_external_secret_leases"' in source
    for table in TABLES:
        assert f'"{table}"' in source
        assert f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY' in source
        assert f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' in source
        assert f'CREATE POLICY "{table}_tenant_isolation"' in source


def test_revision_stores_no_bundle_bytes_full_inputs_results_or_key_material() -> None:
    source = (ROOT / "migrations" / "versions" / "0006_r099_policy_distribution.py").read_text(encoding="utf-8").lower()
    for forbidden in (
        '"bundle_bytes"', '"input_document"', '"decision_result"', '"private_key"',
        '"token"', '"rego_source"', '"policy_text"',
    ):
        assert forbidden not in source


def test_revision_has_explicit_promotion_decision_agent_and_receipt_uniqueness() -> None:
    source = (ROOT / "migrations" / "versions" / "0006_r099_policy_distribution.py").read_text(encoding="utf-8")
    for name in (
        "uq_policy_bundle_revisions_tenant_revision",
        "uq_policy_bundle_promotions_tenant_idempotency",
        "uq_policy_agent_status_tenant_agent",
        "uq_policy_decisions_tenant_opa_decision",
        "uq_policy_boundary_receipts_tenant_boundary_operation",
        "uq_policy_log_receipts_tenant_opa_decision",
    ):
        assert name in source
