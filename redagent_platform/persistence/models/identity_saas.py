"""SQLAlchemy table registrations for the identity saas domain."""

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
    Text,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "identity_adapter_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("adapter_id", String(100), nullable=False),
    Column("artifact_sha256", String(64), nullable=False),
    Column("execution_enabled", Boolean, nullable=False),
    Column("production_qualified", Boolean, nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "adapter_id", "artifact_sha256"),
)

Table(
    "identity_provider_profiles",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("profile_id", String(100), nullable=False),
    Column("provider", String(32), nullable=False),
    Column("profile_sha256", String(64), nullable=False),
    Column("emulator_only", Boolean, nullable=False),
    Column("limits", JSON, nullable=False),
    Column("retention_days", Integer, nullable=False),
    Column("profile_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "profile_id", "profile_sha256"),
)

Table(
    "identity_operation_manifests",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("profile_record_id", String(64), ForeignKey("identity_provider_profiles.id"), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("method", String(16), nullable=False),
    Column("api_version", String(32), nullable=False),
    Column("permission_scope", String(300), nullable=False),
    Column("role_permission", String(300), nullable=False),
    Column("selected_fields", JSON, nullable=False),
    Column("data_class", String(64), nullable=False),
    Column("graph_eligible", Boolean, nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "profile_record_id", "operation_id"),
)

Table(
    "identity_tenant_bindings",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("binding_id", String(100), nullable=False),
    Column("profile_record_id", String(64), ForeignKey("identity_provider_profiles.id"), nullable=False),
    Column("provider_tenant_id", String(200), nullable=False),
    Column("audience", String(200), nullable=False),
    Column("consent_mode", String(32), nullable=False),
    Column("scopes", JSON, nullable=False),
    Column("role_permissions", JSON, nullable=False),
    Column("permission_digest", String(64), nullable=False),
    Column("binding_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "binding_id"),
)

Table(
    "identity_baseline_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("baseline_id", String(100), nullable=False),
    Column("baseline_version", String(64), nullable=False),
    Column("baseline_sha256", String(64), nullable=False),
    Column("schema_sha256", String(64), nullable=False),
    Column("baseline_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "baseline_id", "baseline_sha256"),
)

Table(
    "identity_collection_plans",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("plan_id", String(100), nullable=False),
    Column("profile_record_id", String(64), ForeignKey("identity_provider_profiles.id"), nullable=False),
    Column("binding_record_id", String(64), ForeignKey("identity_tenant_bindings.id"), nullable=False),
    Column("baseline_record_id", String(64), ForeignKey("identity_baseline_artifacts.id"), nullable=False),
    Column("policy_decision_id", String(100), nullable=False),
    Column("reservation_id", String(100), nullable=False),
    Column("credential_lease_id", String(100), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("plan_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "plan_id"),
)

Table(
    "identity_collection_runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(100), nullable=False),
    Column("plan_record_id", String(64), ForeignKey("identity_collection_plans.id"), nullable=False),
    Column("job_id", String(100), nullable=False),
    Column("runner_id", String(100), nullable=False),
    Column("run_state", String(32), nullable=False),
    Column("complete", Boolean, nullable=False),
    Column("partial_reasons", JSON, nullable=False),
    Column("snapshot_sha256", String(64)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_id"),
)

Table(
    "identity_snapshot_pages",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("identity_collection_runs.id"), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("page_index", Integer, nullable=False),
    Column("page_sha256", String(64), nullable=False),
    Column("partial_reason", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "operation_id", "page_index"),
)

Table(
    "identity_snapshot_resources",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("identity_collection_runs.id"), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("resource_id", String(300), nullable=False),
    Column("resource_sha256", String(64), nullable=False),
    Column("data_class", String(64), nullable=False),
    Column("redaction_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "operation_id", "resource_id"),
)

Table(
    "identity_baseline_evaluations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("identity_collection_runs.id"), nullable=False),
    Column("evaluation_id", String(100), nullable=False),
    Column("control_id", String(100), nullable=False),
    Column("resource_id", String(300), nullable=False),
    Column("passed", Boolean, nullable=False),
    Column("evaluation_sha256", String(64), nullable=False),
    Column("evidence_instance_id", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "evaluation_id"),
)

Table(
    "identity_exception_annotations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("exception_id", String(100), nullable=False),
    Column("evaluation_record_id", String(64), ForeignKey("identity_baseline_evaluations.id"), nullable=False),
    Column("control_id", String(100), nullable=False),
    Column("resource_id", String(300), nullable=False),
    Column("justification", Text, nullable=False),
    Column("requested_by", String(64), nullable=False),
    Column("effective_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("supersedes_exception_id", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "exception_id"),
)

Table(
    "identity_exception_approvals",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("exception_record_id", String(64), ForeignKey("identity_exception_annotations.id"), nullable=False),
    Column("approval_id", String(100), nullable=False),
    Column("approved_by", String(64), nullable=False),
    Column("approved_at", DateTime(timezone=True), nullable=False),
    Column("approval_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "approval_id"),
)

Table(
    "identity_graph_approvals",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("approval_id", String(100), nullable=False),
    Column("approved_by", String(64), nullable=False),
    Column("restricted_role", String(64), nullable=False),
    Column("export_allowed", Boolean, nullable=False),
    Column("model_access_allowed", Boolean, nullable=False),
    Column("retention_hours", Integer, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "approval_id"),
)

Table(
    "identity_graph_nodes",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("approval_record_id", String(64), ForeignKey("identity_graph_approvals.id"), nullable=False),
    Column("node_id", String(100), nullable=False),
    Column("node_type", String(32), nullable=False),
    Column("node_sha256", String(64), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "approval_record_id", "node_id"),
)

Table(
    "identity_graph_edges",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("approval_record_id", String(64), ForeignKey("identity_graph_approvals.id"), nullable=False),
    Column("edge_id", String(100), nullable=False),
    Column("source_id", String(100), nullable=False),
    Column("target_id", String(100), nullable=False),
    Column("edge_type", String(64), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "approval_record_id", "edge_id"),
)

Table(
    "identity_cleanup_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("identity_collection_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("lease_revoked", Boolean, nullable=False),
    Column("new_requests_blocked", Boolean, nullable=False),
    Column("graph_expired", Boolean, nullable=False),
    Column("residual_resource_count", Integer, nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id"),
)
