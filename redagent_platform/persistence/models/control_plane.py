"""SQLAlchemy table registrations for the control plane domain."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
    Column,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    JSON,
    String,
    Table,
    UniqueConstraint,
    text,
)
from sqlalchemy.schema import conv

from ._base import _owned_columns, metadata


Table(
    "tenants",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("version", Integer, nullable=False, default=1),
    Column("created_at", DateTime(timezone=True), nullable=False),
    Column("updated_at", DateTime(timezone=True), nullable=False),
)

Table(
    "users",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("subject", String(200), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "subject"),
)

Table(
    "engagements",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("name", String(200), nullable=False),
    Column("owner_user_id", String(64), nullable=False),
    *_owned_columns(),
)

Table(
    "targets",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("engagement_id", String(64), ForeignKey("engagements.id"), nullable=False),
    Column("target_type", String(32), nullable=False),
    Column("normalized_value", String(500), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "engagement_id", "normalized_value"),
)

Table(
    "roe_versions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("engagement_id", String(64), ForeignKey("engagements.id"), nullable=False),
    Column("revision", Integer, nullable=False),
    Column("status", String(32), nullable=False),
    Column("document", JSON, nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "engagement_id", "revision"),
)

Table(
    "approvals",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("roe_version_id", String(64), ForeignKey("roe_versions.id"), nullable=False),
    Column("approved_by_user_id", String(64), nullable=False),
    *_owned_columns(),
)

Table(
    "policy_references",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("roe_version_id", String(64), ForeignKey("roe_versions.id"), nullable=False),
    Column("policy_name", String(200), nullable=False),
    Column("policy_version", String(100), nullable=False),
    *_owned_columns(),
)

Table(
    "campaigns",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("engagement_id", String(64), ForeignKey("engagements.id"), nullable=False),
    Column("roe_version_id", String(64), ForeignKey("roe_versions.id"), nullable=False),
    Column("name", String(200), nullable=False),
    Column("status", String(32), nullable=False),
    Column("workflow_id", String(64), nullable=False),
    Column("workflow_run_id", String(64)),
    Column("orchestration_revision", Integer, nullable=False, default=1),
    Column("intent_sha256", String(64)),
    Column("current_strategy_revision_id", String(64), ForeignKey("campaign_strategy_revisions.id")),
    Column("aggregate_sequence", BigInteger, nullable=False, default=0),
    Column("replan_count", Integer, nullable=False, default=0),
    Column("attention_reason", String(100)),
    Column("terminal_receipt_sha256", String(64)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "id", name="uq_campaign_tenant_identity"),
    UniqueConstraint("tenant_id", "workflow_id"),
)

Table(
    "jobs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("engagement_id", String(64), ForeignKey("engagements.id"), nullable=False),
    Column("roe_version_id", String(64), ForeignKey("roe_versions.id"), nullable=False),
    Column("created_by_user_id", String(64), nullable=False),
    Column("campaign_id", String(64), ForeignKey("campaigns.id")),
    Column("status", String(32), nullable=False),
    Column("request", JSON, nullable=False),
    Column("policy_reference", String(100), nullable=False),
    Column("workflow_id", String(64)),
    Column("workflow_run_id", String(64)),
    Column("orchestration_state", String(32), nullable=False, default="dispatch_pending"),
    Column("orchestration_revision", Integer, nullable=False, default=1),
    Column("current_gate", String(100), nullable=False, default="temporal_dispatch_pending"),
    Column("failure_code", String(100)),
    Column("retry_count", Integer, nullable=False, default=0),
    Column("dispatch_blocked", Boolean, nullable=False, default=True),
    Column("stop_requested", Boolean, nullable=False, default=False),
    Column("strategy_revision_id", String(64), ForeignKey("campaign_strategy_revisions.id")),
    Column("execution_run_id", String(64)),
    Column("node_id", String(100)),
    Column("effect_id", String(100)),
    Column("envelope_sha256", String(64)),
    Column("manifest_v2_sha256", String(64)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "workflow_id"),
    UniqueConstraint(
        "tenant_id", "execution_run_id", "node_id", name="uq_jobs_campaign_execution_node"
    ),
    ForeignKeyConstraint(
        ("tenant_id", "execution_run_id", "campaign_id"),
        (
            "campaign_execution_runs.tenant_id",
            "campaign_execution_runs.id",
            "campaign_execution_runs.campaign_id",
        ),
        name="fk_jobs_tenant_execution_run_campaign",
    ),
    CheckConstraint(
        "NOT (strategy_revision_id IS NOT NULL AND execution_run_id IS NOT NULL)",
        name=conv("jobs_campaign_lineage_not_ambiguous"),
    ),
)

Table(
    "workflow_commands",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("job_id", String(64), ForeignKey("jobs.id"), nullable=False),
    Column("command_id", String(64), nullable=False),
    Column("action", String(32), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("state", String(32), nullable=False),
    Column("result_revision", Integer, nullable=False),
    Column("actor_user_id", String(64), nullable=False),
    Column("expected_revision", Integer, nullable=False),
    Column("policy_reference", String(100), nullable=False),
    Column("audit_id", String(64)),
    Column("outbox_id", String(64)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "job_id", "command_id"),
)

Table(
    "audit_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("actor_user_id", String(64), nullable=False),
    Column("action", String(100), nullable=False),
    Column("subject_type", String(100), nullable=False),
    Column("subject_id", String(64), nullable=False),
    Column("correlation_id", String(100), nullable=False),
    Column("details", JSON, nullable=False),
    *_owned_columns(),
)

Table(
    "outbox_events",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("event_type", String(100), nullable=False),
    Column("aggregate_id", String(64), nullable=False),
    Column("payload", JSON, nullable=False),
    Column("published", Boolean, nullable=False, default=False),
    Column("schema_revision", Integer, nullable=False, default=1, server_default="1"),
    Column("aggregate_type", String(64), nullable=False, default="legacy", server_default="legacy"),
    Column("aggregate_sequence", BigInteger, nullable=False, default=0, server_default="0"),
    Column("available_at", DateTime(timezone=True), nullable=False, server_default=text("CURRENT_TIMESTAMP")),
    Column("claim_owner", String(100)),
    Column("claim_expires_at", DateTime(timezone=True)),
    Column("attempt_count", Integer, nullable=False, default=0, server_default="0"),
    Column("last_error", String(500)),
    Column("delivered_at", DateTime(timezone=True)),
    Column("delivery_state", String(32), nullable=False, default="pending", server_default="pending"),
    Column("reconciliation_state", String(32), nullable=False, default="none", server_default="none"),
    Column("dead_lettered_at", DateTime(timezone=True)),
    *_owned_columns(),
)

Table(
    "idempotency_records",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("operation", String(100), nullable=False),
    Column("idempotency_key", String(200), nullable=False),
    Column("request_hash", String(64), nullable=False),
    Column("response_status", Integer),
    Column("response_body", JSON),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "operation", "idempotency_key"),
)

Table(
    "issue_definitions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("fingerprint", String(64), nullable=False),
    Column("title", String(500), nullable=False),
    Column("tool", String(100), nullable=False),
    Column("rule_id", String(200), nullable=False),
    Column("tool_version", String(100), nullable=False),
    Column("database_version", String(100), nullable=False),
    Column("severity", String(32), nullable=False),
    Column("confidence", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "fingerprint"),
)

Table(
    "finding_instances",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("issue_definition_id", String(64), ForeignKey("issue_definitions.id"), nullable=False),
    Column("affected_resource", String(500), nullable=False),
    Column("location", String(1000), nullable=False),
    Column("evidence_reference", String(500)),
    Column("redaction_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "issue_definition_id", "affected_resource", "location"),
)

Index(
    "uq_outbox_r123_ordered_event",
    metadata.tables["outbox_events"].c.tenant_id,
    metadata.tables["outbox_events"].c.aggregate_type,
    metadata.tables["outbox_events"].c.aggregate_id,
    metadata.tables["outbox_events"].c.aggregate_sequence,
    unique=True,
    postgresql_where=text("schema_revision = 2"),
)

Index(
    "ix_outbox_r123_claimable",
    metadata.tables["outbox_events"].c.tenant_id,
    metadata.tables["outbox_events"].c.delivery_state,
    metadata.tables["outbox_events"].c.available_at,
)
