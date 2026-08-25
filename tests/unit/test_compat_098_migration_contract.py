from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_r098_revision_0005_has_secret_metadata_tables_force_rls_and_rollback() -> None:
    source = (ROOT / "migrations" / "versions" / "0005_r098_external_secret_leases.py").read_text(encoding="utf-8")
    assert 'revision = "0005_r098_external_secret_leases"' in source
    assert 'down_revision = "0004_r097_persistent_evidence"' in source
    tables = (
        "secret_references", "secret_workload_clients", "secret_lease_operations",
        "secret_leases", "secret_lease_events",
    )
    for table in tables:
        assert f'create_table(\n        "{table}"' in source
        assert f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY' in source
        assert f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' in source
        assert f'drop_table("{table}")' in source


def test_r098_schema_has_only_opaque_metadata_state_and_idempotency_fields() -> None:
    source = (ROOT / "migrations" / "versions" / "0005_r098_external_secret_leases.py").read_text(encoding="utf-8")
    for column in (
        "provider_alias", "role_reference", "allowed_capabilities", "allowed_permissions",
        "attestation_fingerprint", "idempotency_key", "request_hash", "operation_state",
        "provider_lease_reference", "permission_digest", "permission_count", "renewable",
        "renewal_count", "lease_state", "policy_reference", "roe_version_id", "failure_code",
    ):
        assert f'"{column}"' in source
    for forbidden in (
        '"secret_value"', '"password"', '"client_token"', '"secret_id"',
        '"unwrap_token"', '"provider_response"', '"credential_material"',
    ):
        assert forbidden not in source
