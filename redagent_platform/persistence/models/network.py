"""SQLAlchemy table registrations for the network domain."""

from __future__ import annotations

from sqlalchemy import (
    BigInteger,
    Boolean,
    CheckConstraint,
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
    "network_engine_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("engine_id", String(100), nullable=False),
    Column("engine_version", String(32), nullable=False),
    Column("artifact_sha256", String(64), nullable=False),
    Column("sbom_sha256", String(64), nullable=False),
    Column("license_review_sha256", String(64), nullable=False),
    Column("vulnerability_review", String(64), nullable=False),
    Column("production_qualified", Boolean, nullable=False),
    Column("artifact_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "engine_id", "artifact_sha256", name="uq_network_engine_tenant_artifact"),
)

Table(
    "network_adapter_declarations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("adapter_id", String(100), nullable=False),
    Column("adapter_version", String(32), nullable=False),
    Column("source_url", String(500), nullable=False),
    Column("license_id", String(100), nullable=False),
    Column("execution_enabled", Boolean, nullable=False),
    Column("capabilities", JSON, nullable=False),
    Column("declaration_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "adapter_id", "adapter_version", name="uq_network_adapter_tenant_version"),
)

Table(
    "network_profiles",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("profile_id", String(100), nullable=False),
    Column("profile_revision", Integer, nullable=False),
    Column("engine_record_id", String(64), ForeignKey("network_engine_artifacts.id"), nullable=False),
    Column("profile_sha256", String(64), nullable=False),
    Column("category", String(32), nullable=False),
    Column("limits", JSON, nullable=False),
    Column("enabled", Boolean, nullable=False),
    Column("profile_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "profile_id", "profile_revision", name="uq_network_profile_tenant_revision"),
)

Table(
    "network_topology_attestations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("topology_id", String(100), nullable=False),
    Column("topology_sha256", String(64), nullable=False),
    Column("route_sha256", String(64), nullable=False),
    Column("network_id", String(100), nullable=False),
    Column("non_production", Boolean, nullable=False),
    Column("no_public_route", Boolean, nullable=False),
    Column("no_direct_target_route", Boolean, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "topology_id", "topology_sha256", name="uq_network_topology_tenant_digest"),
)

Table(
    "network_target_sets",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("target_set_id", String(100), nullable=False),
    Column("topology_record_id", String(64), ForeignKey("network_topology_attestations.id"), nullable=False),
    Column("target_set_sha256", String(64), nullable=False),
    Column("literal_targets", JSON, nullable=False),
    Column("allowed_ports", JSON, nullable=False),
    Column("protocol", String(16), nullable=False),
    Column("target_set_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "target_set_id", "target_set_sha256", name="uq_network_target_set_tenant_digest"),
)

Table(
    "network_plans",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("plan_id", String(100), nullable=False),
    Column("profile_record_id", String(64), ForeignKey("network_profiles.id"), nullable=False),
    Column("target_set_record_id", String(64), ForeignKey("network_target_sets.id"), nullable=False),
    Column("policy_decision_id", String(100), nullable=False),
    Column("policy_revision", String(100), nullable=False),
    Column("roe_version_id", String(100), nullable=False),
    Column("reservation_id", String(100), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("budgets", JSON, nullable=False),
    Column("plan_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "plan_id", name="uq_network_plan_tenant_id"),
)

Table(
    "network_plan_tuples",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("plan_record_id", String(64), ForeignKey("network_plans.id"), nullable=False),
    Column("tuple_id", String(100), nullable=False),
    Column("literal_ip", String(64), nullable=False),
    Column("port", Integer, nullable=False),
    Column("protocol", String(16), nullable=False),
    Column("tuple_sha256", String(64), nullable=False),
    Column("tuple_state", String(32), nullable=False),
    *_owned_columns(),
    CheckConstraint("port >= 1 AND port <= 65535", name="network_tuple_port"),
    UniqueConstraint("tenant_id", "plan_record_id", "tuple_id", name="uq_network_tuple_tenant_plan_tuple"),
)

Table(
    "network_runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(100), nullable=False),
    Column("plan_record_id", String(64), ForeignKey("network_plans.id"), nullable=False),
    Column("job_id", String(100), nullable=False),
    Column("runner_id", String(100), nullable=False),
    Column("run_state", String(32), nullable=False),
    Column("completed_tuples", Integer, nullable=False),
    Column("total_tuples", Integer, nullable=False),
    Column("partial", Boolean, nullable=False),
    Column("reason_code", String(100), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_id", name="uq_network_run_tenant_id"),
)

Table(
    "network_gateway_decisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("network_runs.id"), nullable=False),
    Column("decision_id", String(100), nullable=False),
    Column("tuple_id", String(100), nullable=False),
    Column("allowed", Boolean, nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("attempt_count", Integer, nullable=False),
    Column("data_bytes", BigInteger, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "decision_id", name="uq_network_decision_tenant_id"),
)

Table(
    "network_observations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("network_runs.id"), nullable=False),
    Column("observation_id", String(100), nullable=False),
    Column("tuple_id", String(100), nullable=False),
    Column("connection_state", String(32), nullable=False),
    Column("latency_bucket", String(32), nullable=False),
    Column("service_class", String(64), nullable=False),
    Column("sample_sha256", String(64), nullable=False),
    Column("uncertainty", String(32), nullable=False),
    Column("redaction_state", String(32), nullable=False),
    Column("evidence_instance_id", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "observation_id", name="uq_network_observation_tenant_id"),
)

Table(
    "network_cancellation_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("network_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("gateway_blocked", Boolean, nullable=False),
    Column("worker_stop_attempted", Boolean, nullable=False),
    Column("worker_stop_acknowledged", Boolean, nullable=False),
    Column("forced_termination", Boolean, nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id", name="uq_network_cancel_tenant_id"),
)

Table(
    "network_cleanup_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("network_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("container_count", Integer, nullable=False),
    Column("network_count", Integer, nullable=False),
    Column("transient_file_count", Integer, nullable=False),
    Column("residual_resource_count", Integer, nullable=False),
    Column("inventory_sha256", String(64), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id", name="uq_network_cleanup_tenant_id"),
)
