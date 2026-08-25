from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_r097_migration_is_revision_0004_with_evidence_tables_rls_and_rollback() -> None:
    source = (ROOT / "migrations" / "versions" / "0004_r097_persistent_evidence.py").read_text(encoding="utf-8")
    assert 'revision = "0004_r097_persistent_evidence"' in source
    assert 'down_revision = "0003_r096_durable_workflows"' in source
    for table in (
        "evidence_artifacts", "evidence_derivatives", "evidence_operations",
        "evidence_custody_events", "evidence_verifications",
    ):
        assert f'create_table(\n        "{table}"' in source
        assert f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY' in source
        assert f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY' in source
        assert f'drop_table("{table}")' in source


def test_r097_schema_persists_exact_version_integrity_retention_lineage_and_quarantine() -> None:
    source = (ROOT / "migrations" / "versions" / "0004_r097_persistent_evidence.py").read_text(encoding="utf-8")
    for column in (
        "object_key", "object_version_id", "content_sha256", "provider_checksum", "size_bytes",
        "content_type", "producer_id", "artifact_class", "classification", "redaction_state",
        "retention_mode", "retain_until", "legal_hold", "kms_reference", "attestation_hash",
        "source_artifact_id", "source_object_version_id", "transform_name", "transform_version",
        "transform_config_hash", "operation_state", "request_hash", "quarantine_reason",
    ):
        assert f'"{column}"' in source
    assert (
        'sa.UniqueConstraint("tenant_id", "object_key", "object_version_id", '
        'name="uq_evidence_artifacts_tenant_object_version")'
    ) in source
    assert (
        'sa.UniqueConstraint("tenant_id", "idempotency_key", '
        'name="uq_evidence_operations_tenant_idempotency")'
    ) in source
