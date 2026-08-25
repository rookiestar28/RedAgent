from __future__ import annotations

from redagent_platform.persistence.models import metadata


TABLES = {
    "evidence_artifacts", "evidence_derivatives", "evidence_operations",
    "evidence_custody_events", "evidence_verifications",
}


def test_r097_relational_metadata_matches_migration_truth_fields() -> None:
    assert TABLES <= set(metadata.tables)
    artifact = metadata.tables["evidence_artifacts"]
    assert {
        "tenant_id", "engagement_id", "job_id", "producer_id", "object_key", "object_version_id",
        "content_sha256", "provider_checksum", "size_bytes", "content_type", "artifact_class",
        "classification", "redaction_state", "retention_mode", "retain_until", "legal_hold",
        "kms_reference", "attestation_hash", "policy_reference", "quarantine_reason", "version",
    } <= set(artifact.c.keys())
    derivative = metadata.tables["evidence_derivatives"]
    assert {"source_artifact_id", "source_object_version_id", "transform_name", "transform_version", "transform_config_hash"} <= set(derivative.c.keys())


def test_r097_uniqueness_covers_artifact_idempotency_and_exact_object_version() -> None:
    operations = metadata.tables["evidence_operations"]
    operation_unique = {tuple(column.name for column in item.columns) for item in operations.constraints if hasattr(item, "columns")}
    assert ("tenant_id", "idempotency_key") in operation_unique
    artifact = metadata.tables["evidence_artifacts"]
    artifact_unique = {tuple(column.name for column in item.columns) for item in artifact.constraints if hasattr(item, "columns")}
    assert ("tenant_id", "object_key", "object_version_id") in artifact_unique
