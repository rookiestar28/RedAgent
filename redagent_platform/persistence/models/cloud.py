"""SQLAlchemy table registrations for the cloud domain."""

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
    "cloud_adapter_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("adapter_id", String(100), nullable=False),
    Column("adapter_version", String(64), nullable=False),
    Column("artifact_sha256", String(64), nullable=False),
    Column("license_id", String(100), nullable=False),
    Column("sbom_sha256", String(64), nullable=False),
    Column("execution_enabled", Boolean, nullable=False),
    Column("production_qualified", Boolean, nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "adapter_id", "artifact_sha256", name="uq_cloud_adapter_tenant_artifact"),
)

Table(
    "cloud_provider_profiles",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("profile_id", String(100), nullable=False),
    Column("provider", String(32), nullable=False),
    Column("profile_sha256", String(64), nullable=False),
    Column("emulator_only", Boolean, nullable=False),
    Column("limits", JSON, nullable=False),
    Column("profile_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "profile_id", "profile_sha256", name="uq_cloud_profile_tenant_digest"),
)

Table(
    "cloud_operation_manifests",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("profile_record_id", String(64), ForeignKey("cloud_provider_profiles.id"), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("action", String(200), nullable=False),
    Column("resource_scope", String(500), nullable=False),
    Column("data_class", String(64), nullable=False),
    Column("mutation", Boolean, nullable=False),
    Column("page_cost", Integer, nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "profile_record_id", "operation_id", name="uq_cloud_operation_tenant_profile"),
)

Table(
    "cloud_identity_bindings",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("binding_id", String(100), nullable=False),
    Column("profile_record_id", String(64), ForeignKey("cloud_provider_profiles.id"), nullable=False),
    Column("provider", String(32), nullable=False),
    Column("expected_tenant", String(200), nullable=False),
    Column("expected_parent", String(200)),
    Column("permissions", JSON, nullable=False),
    Column("data_classes", JSON, nullable=False),
    Column("permission_digest", String(64), nullable=False),
    Column("binding_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "binding_id", name="uq_cloud_identity_tenant_binding"),
)

Table(
    "cloud_control_packs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("pack_id", String(100), nullable=False),
    Column("pack_version", String(64), nullable=False),
    Column("pack_sha256", String(64), nullable=False),
    Column("database_sha256", String(64), nullable=False),
    Column("data_classes", JSON, nullable=False),
    Column("pack_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "pack_id", "pack_sha256", name="uq_cloud_pack_tenant_digest"),
)

Table(
    "cloud_offline_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("input_id", String(100), nullable=False),
    Column("input_kind", String(32), nullable=False),
    Column("input_sha256", String(64), nullable=False),
    Column("file_count", Integer, nullable=False),
    Column("size_bytes", BigInteger, nullable=False),
    Column("network_allowed", Boolean, nullable=False),
    Column("artifact_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "input_id", "input_sha256", name="uq_cloud_offline_tenant_digest"),
)

Table(
    "cloud_collection_plans",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("plan_id", String(100), nullable=False),
    Column("profile_record_id", String(64), ForeignKey("cloud_provider_profiles.id"), nullable=False),
    Column("identity_binding_id", String(64), ForeignKey("cloud_identity_bindings.id"), nullable=False),
    Column("policy_decision_id", String(100), nullable=False),
    Column("policy_revision", String(100), nullable=False),
    Column("reservation_id", String(100), nullable=False),
    Column("credential_lease_id", String(100), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("plan_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "plan_id", name="uq_cloud_plan_tenant_id"),
)

Table(
    "cloud_collection_runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(100), nullable=False),
    Column("plan_record_id", String(64), ForeignKey("cloud_collection_plans.id"), nullable=False),
    Column("job_id", String(100), nullable=False),
    Column("runner_id", String(100), nullable=False),
    Column("run_state", String(32), nullable=False),
    Column("complete", Boolean, nullable=False),
    Column("partial_reasons", JSON, nullable=False),
    Column("snapshot_sha256", String(64)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_id", name="uq_cloud_run_tenant_id"),
)

Table(
    "cloud_snapshot_pages",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("cloud_collection_runs.id"), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("page_index", Integer, nullable=False),
    Column("response_sha256", String(64), nullable=False),
    Column("response_bytes", BigInteger, nullable=False),
    Column("partial_reason", String(100)),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "run_record_id", "operation_id", "page_index", name="uq_cloud_page_tenant_run_operation"
    ),
)

Table(
    "cloud_snapshot_resources",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("cloud_collection_runs.id"), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("resource_id", String(500), nullable=False),
    Column("resource_sha256", String(64), nullable=False),
    Column("data_class", String(64), nullable=False),
    Column("redaction_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint(
        "tenant_id", "run_record_id", "operation_id", "resource_id", name="uq_cloud_resource_tenant_run_resource"
    ),
)

Table(
    "cloud_check_results",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("cloud_collection_runs.id"), nullable=False),
    Column("result_id", String(100), nullable=False),
    Column("control_pack_id", String(100), nullable=False),
    Column("check_id", String(100), nullable=False),
    Column("resource_id", String(500), nullable=False),
    Column("passed", Boolean, nullable=False),
    Column("severity", String(32), nullable=False),
    Column("evidence_instance_id", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "result_id", name="uq_cloud_result_tenant_id"),
)

Table(
    "cloud_cleanup_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("cloud_collection_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("lease_revoked", Boolean, nullable=False),
    Column("new_requests_blocked", Boolean, nullable=False),
    Column("residual_resource_count", Integer, nullable=False),
    Column("inventory_sha256", String(64), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id", name="uq_cloud_cleanup_tenant_id"),
)
