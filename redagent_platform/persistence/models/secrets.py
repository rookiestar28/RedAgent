"""SQLAlchemy table registrations for the secrets domain."""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Table,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "secret_references",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("engagement_id", String(64), ForeignKey("engagements.id"), nullable=False),
    Column("owner_user_id", String(64), nullable=False),
    Column("reference_kind", String(32), nullable=False),
    Column("provider_alias", String(64), nullable=False),
    Column("role_reference", String(200), nullable=False),
    Column("allowed_capabilities", JSON, nullable=False),
    Column("allowed_permissions", JSON, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("rotation_due_at", DateTime(timezone=True), nullable=False),
    Column("reference_status", String(32), nullable=False),
    Column("redaction_label", String(200), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "id", name="uq_secret_references_tenant_reference"),
)

Table(
    "secret_workload_clients",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("job_id", String(64), ForeignKey("jobs.id"), nullable=False),
    Column("capability", String(64), nullable=False),
    Column("attestation_fingerprint", String(64), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("last_seen_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "id", name="uq_secret_workload_clients_tenant_client"),
)

Table(
    "secret_lease_operations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("lease_id", String(64), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("operation_state", String(32), nullable=False),
    Column("provider_lease_reference", String(256)),
    Column("failure_code", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "idempotency_key", name="uq_secret_lease_operations_tenant_idempotency"),
    UniqueConstraint("tenant_id", "lease_id", name="uq_secret_lease_operations_tenant_lease"),
)

Table(
    "secret_leases",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("reference_id", String(64), ForeignKey("secret_references.id"), nullable=False),
    Column("engagement_id", String(64), ForeignKey("engagements.id"), nullable=False),
    Column("job_id", String(64), ForeignKey("jobs.id"), nullable=False),
    Column("workload_client_id", String(64), ForeignKey("secret_workload_clients.id"), nullable=False),
    Column("capability", String(64), nullable=False),
    Column("permission_digest", String(64), nullable=False),
    Column("permission_count", Integer, nullable=False),
    Column("provider_lease_reference", String(256), nullable=False),
    Column("issued_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("renewed_at", DateTime(timezone=True)),
    Column("revoked_at", DateTime(timezone=True)),
    Column("renewable", Boolean, nullable=False),
    Column("renewal_count", Integer, nullable=False),
    Column("lease_state", String(32), nullable=False),
    Column("policy_reference", String(200), nullable=False),
    Column("roe_version_id", String(64), nullable=False),
    Column("failure_code", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "provider_lease_reference", name="uq_secret_leases_tenant_provider_lease"),
)

Table(
    "secret_lease_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("lease_id", String(64), ForeignKey("secret_leases.id"), nullable=False),
    Column("event_type", String(32), nullable=False),
    Column("actor_id", String(64), nullable=False),
    Column("details", JSON, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
)
