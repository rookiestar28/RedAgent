"""SQLAlchemy table registrations for the evidence domain."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    JSON,
    String,
    Table,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "evidence_operations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("artifact_id", String(64), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("operation_state", String(32), nullable=False),
    Column("object_key", String(1000), nullable=False),
    Column("object_version_id", String(256)),
    Column("quarantine_reason", String(200)),
    Column("provider_error_code", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "idempotency_key", name="uq_evidence_operations_tenant_idempotency"),
    UniqueConstraint("tenant_id", "artifact_id", name="uq_evidence_operations_tenant_artifact"),
)

Table(
    "evidence_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("engagement_id", String(64), ForeignKey("engagements.id"), nullable=False),
    Column("job_id", String(64), ForeignKey("jobs.id"), nullable=False),
    Column("producer_id", String(64), nullable=False),
    Column("object_key", String(1000), nullable=False),
    Column("object_version_id", String(256), nullable=False),
    Column("content_sha256", String(64), nullable=False),
    Column("provider_checksum", String(256), nullable=False),
    Column("size_bytes", BigInteger, nullable=False),
    Column("content_type", String(100), nullable=False),
    Column("artifact_class", String(32), nullable=False),
    Column("classification", String(32), nullable=False),
    Column("redaction_state", String(32), nullable=False),
    Column("retention_mode", String(16), nullable=False),
    Column("retain_until", DateTime(timezone=True), nullable=False),
    Column("legal_hold", Boolean, nullable=False),
    Column("kms_reference", String(200), nullable=False),
    Column("attestation_hash", String(64), nullable=False),
    Column("policy_reference", String(200), nullable=False),
    Column("quarantine_reason", String(200)),
    Column("finalized_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "object_key", "object_version_id", name="uq_evidence_artifacts_tenant_object_version"
    ),
)

Table(
    "evidence_derivatives",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("artifact_id", String(64), ForeignKey("evidence_artifacts.id"), nullable=False),
    Column("source_artifact_id", String(64), ForeignKey("evidence_artifacts.id"), nullable=False),
    Column("source_object_version_id", String(256), nullable=False),
    Column("transform_name", String(100), nullable=False),
    Column("transform_version", String(100), nullable=False),
    Column("transform_config_hash", String(64), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "artifact_id", name="uq_evidence_derivatives_tenant_artifact"),
)

Table(
    "evidence_custody_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("artifact_id", String(64), ForeignKey("evidence_artifacts.id"), nullable=False),
    Column("event_type", String(32), nullable=False),
    Column("actor_id", String(64), nullable=False),
    Column("attestation_hash", String(64), nullable=False),
    Column("details", JSON, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
)

Table(
    "evidence_verifications",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("artifact_id", String(64), ForeignKey("evidence_artifacts.id"), nullable=False),
    Column("object_key", String(1000), nullable=False),
    Column("object_version_id", String(256), nullable=False),
    Column("content_sha256", String(64), nullable=False),
    Column("provider_checksum", String(256), nullable=False),
    Column("size_bytes", BigInteger, nullable=False),
    Column("verified", Boolean, nullable=False),
    Column("quarantine_reason", String(200)),
    Column("verified_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
)
