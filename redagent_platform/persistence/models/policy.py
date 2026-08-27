"""SQLAlchemy table registrations for the policy domain."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
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
    "policy_bundle_revisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("revision_name", String(100), nullable=False),
    Column("source_sha256", String(64), nullable=False),
    Column("artifact_sha256", String(64), nullable=False),
    Column("artifact_size", BigInteger, nullable=False),
    Column("manifest_roots", JSON, nullable=False),
    Column("rego_version", Integer, nullable=False),
    Column("signing_key_id", String(100), nullable=False),
    Column("signing_scope", String(100), nullable=False),
    Column("signing_algorithm", String(32), nullable=False),
    Column("author_user_id", String(64), nullable=False),
    Column("reviewer_user_id", String(64)),
    Column("test_evidence_sha256", String(64), nullable=False),
    Column("coverage_basis_points", Integer, nullable=False),
    Column("conformance_sha256", String(64), nullable=False),
    Column("bundle_status", String(32), nullable=False),
    Column("supersedes_revision", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "revision_name", name="uq_policy_bundle_revisions_tenant_revision"),
)

Table(
    "policy_bundle_promotions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("bundle_revision", String(100), nullable=False),
    Column("previous_revision", String(100)),
    Column("idempotency_key", String(200), nullable=False),
    Column("required_agents", JSON, nullable=False),
    Column("acknowledged_agents", JSON, nullable=False),
    Column("promotion_state", String(32), nullable=False),
    Column("promoted_by_user_id", String(64), nullable=False),
    Column("reason", String(500), nullable=False),
    Column("promoted_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "idempotency_key", name="uq_policy_bundle_promotions_tenant_idempotency"),
)

Table(
    "policy_agent_status",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("agent_id", String(64), nullable=False),
    Column("boundary", String(32), nullable=False),
    Column("active_revision", String(100)),
    Column("artifact_sha256", String(64)),
    Column("bundle_state", String(32), nullable=False),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("error_code", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "agent_id", name="uq_policy_agent_status_tenant_agent"),
)

Table(
    "policy_decisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("opa_decision_id", String(100), nullable=False),
    Column("bundle_revision", String(100), nullable=False),
    Column("input_hash", String(64), nullable=False),
    Column("boundary", String(32), nullable=False),
    Column("action", String(100), nullable=False),
    Column("subject_id", String(64), nullable=False),
    Column("resource_type", String(64), nullable=False),
    Column("resource_id", String(100), nullable=False),
    Column("resource_version", Integer),
    Column("allowed", Boolean, nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("obligations", JSON, nullable=False),
    Column("issued_at", DateTime(timezone=True), nullable=False),
    Column("valid_until", DateTime(timezone=True), nullable=False),
    Column("correlation_id", String(100), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "opa_decision_id", name="uq_policy_decisions_tenant_opa_decision"),
)

Table(
    "policy_boundary_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("decision_id", String(64), ForeignKey("policy_decisions.id"), nullable=False),
    Column("boundary", String(32), nullable=False),
    Column("aggregate_type", String(64), nullable=False),
    Column("aggregate_id", String(100), nullable=False),
    Column("operation", String(100), nullable=False),
    Column("input_hash", String(64), nullable=False),
    Column("enforcement_outcome", String(32), nullable=False),
    Column("enforced_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id",
        "boundary",
        "aggregate_id",
        "operation",
        name="uq_policy_boundary_receipts_tenant_boundary_operation",
    ),
)

Table(
    "policy_log_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("opa_decision_id", String(100), nullable=False),
    Column("event_sha256", String(64), nullable=False),
    Column("masked", Boolean, nullable=False),
    Column("received_at", DateTime(timezone=True), nullable=False),
    Column("reconciled_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "opa_decision_id", name="uq_policy_log_receipts_tenant_opa_decision"),
)
