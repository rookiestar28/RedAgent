"""SQLAlchemy table registrations for the artifact domain."""

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
    Text,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "artifact_adapter_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("adapter_id", String(100), nullable=False),
    Column("artifact_sha256", String(64), nullable=False),
    Column("execution_enabled", Boolean, nullable=False),
    Column("production_qualified", Boolean, nullable=False),
    Column("legal_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "adapter_id", "artifact_sha256"),
)

Table(
    "artifact_pipeline_profiles",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("profile_id", String(100), nullable=False),
    Column("artifact_kind", String(32), nullable=False),
    Column("profile_sha256", String(64), nullable=False),
    Column("stages", JSON, nullable=False),
    Column("limits", JSON, nullable=False),
    Column("zero_execution", Boolean, nullable=False),
    Column("profile_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "profile_id", "profile_sha256"),
)

Table(
    "artifact_rule_bundles",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("bundle_id", String(100), nullable=False),
    Column("bundle_kind", String(32), nullable=False),
    Column("bundle_version", String(64), nullable=False),
    Column("bundle_sha256", String(64), nullable=False),
    Column("schema_sha256", String(64), nullable=False),
    Column("bundle_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "bundle_id", "bundle_sha256"),
)

Table(
    "artifact_database_snapshots",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("database_id", String(100), nullable=False),
    Column("database_kind", String(32), nullable=False),
    Column("database_version", String(64), nullable=False),
    Column("database_sha256", String(64), nullable=False),
    Column("schema_sha256", String(64), nullable=False),
    Column("database_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "database_id", "database_sha256"),
)

Table(
    "artifact_bindings",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("binding_id", String(100), nullable=False),
    Column("artifact_kind", String(32), nullable=False),
    Column("artifact_sha256", String(64), nullable=False),
    Column("manifest_sha256", String(64), nullable=False),
    Column("declared_files", Integer, nullable=False),
    Column("declared_bytes", BigInteger, nullable=False),
    Column("classification", String(32), nullable=False),
    Column("binding_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "binding_id"),
)

Table(
    "artifact_analysis_plans",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("plan_id", String(100), nullable=False),
    Column("profile_record_id", String(64), ForeignKey("artifact_pipeline_profiles.id"), nullable=False),
    Column("binding_record_id", String(64), ForeignKey("artifact_bindings.id"), nullable=False),
    Column("rule_bundle_id", String(64), ForeignKey("artifact_rule_bundles.id"), nullable=False),
    Column("database_snapshot_id", String(64), ForeignKey("artifact_database_snapshots.id"), nullable=False),
    Column("policy_decision_id", String(100), nullable=False),
    Column("reservation_id", String(100), nullable=False),
    Column("artifact_lease_id", String(100), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("plan_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "plan_id"),
)

Table(
    "artifact_analysis_runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(100), nullable=False),
    Column("plan_record_id", String(64), ForeignKey("artifact_analysis_plans.id"), nullable=False),
    Column("job_id", String(100), nullable=False),
    Column("runner_id", String(100), nullable=False),
    Column("run_state", String(32), nullable=False),
    Column("complete", Boolean, nullable=False),
    Column("partial_reasons", JSON, nullable=False),
    Column("result_sha256", String(64)),
    Column("untrusted_execution_count", Integer, nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_id"),
)

Table(
    "artifact_manifest_entries",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("artifact_analysis_runs.id"), nullable=False),
    Column("path", String(500), nullable=False),
    Column("entry_kind", String(32), nullable=False),
    Column("size_bytes", BigInteger, nullable=False),
    Column("entry_sha256", String(64), nullable=False),
    Column("compressed_bytes", BigInteger, nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "path"),
)

Table(
    "artifact_components",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("artifact_analysis_runs.id"), nullable=False),
    Column("component_id", String(100), nullable=False),
    Column("purl", String(500)),
    Column("component_type", String(64), nullable=False),
    Column("name", String(300), nullable=False),
    Column("component_version", String(200)),
    Column("component_sha256", String(64), nullable=False),
    Column("identity_complete", Boolean, nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "component_id"),
)

Table(
    "artifact_license_observations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("observation_id", String(100), nullable=False),
    Column("component_record_id", String(64), ForeignKey("artifact_components.id"), nullable=False),
    Column("license_expression", String(500), nullable=False),
    Column("license_state", String(32), nullable=False),
    Column("rule_sha256", String(64), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "observation_id"),
)

Table(
    "artifact_vulnerability_observations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("observation_id", String(100), nullable=False),
    Column("component_record_id", String(64), ForeignKey("artifact_components.id"), nullable=False),
    Column("advisory_id", String(100), nullable=False),
    Column("severity", String(32), nullable=False),
    Column("database_sha256", String(64), nullable=False),
    Column("observation_sha256", String(64), nullable=False),
    Column("evidence_instance_id", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "observation_id"),
)

Table(
    "artifact_vex_annotations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("annotation_id", String(100), nullable=False),
    Column("observation_record_id", String(64), ForeignKey("artifact_vulnerability_observations.id"), nullable=False),
    Column("status", String(32), nullable=False),
    Column("justification", Text, nullable=False),
    Column("requested_by", String(64), nullable=False),
    Column("approved_by", String(64), nullable=False),
    Column("effective_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("supersedes_annotation_id", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "annotation_id"),
)

Table(
    "artifact_credential_findings",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("finding_id", String(100), nullable=False),
    Column("run_record_id", String(64), ForeignKey("artifact_analysis_runs.id"), nullable=False),
    Column("fingerprint", String(64), nullable=False),
    Column("path", String(500), nullable=False),
    Column("line", Integer, nullable=False),
    Column("rule_id", String(100), nullable=False),
    Column("classification", String(64), nullable=False),
    Column("redacted_fragment", String(32), nullable=False),
    Column("evidence_instance_id", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "fingerprint"),
)

Table(
    "artifact_static_findings",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("finding_id", String(100), nullable=False),
    Column("run_record_id", String(64), ForeignKey("artifact_analysis_runs.id"), nullable=False),
    Column("stage_kind", String(32), nullable=False),
    Column("rule_id", String(100), nullable=False),
    Column("resource_id", String(500), nullable=False),
    Column("severity", String(32), nullable=False),
    Column("finding_sha256", String(64), nullable=False),
    Column("evidence_instance_id", String(100)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "finding_id"),
)

Table(
    "artifact_mobile_observations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("observation_id", String(100), nullable=False),
    Column("run_record_id", String(64), ForeignKey("artifact_analysis_runs.id"), nullable=False),
    Column("platform", String(32), nullable=False),
    Column("control_id", String(100), nullable=False),
    Column("resource_id", String(500), nullable=False),
    Column("passed", Boolean, nullable=False),
    Column("observation_sha256", String(64), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "observation_id"),
)

Table(
    "artifact_cleanup_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("artifact_analysis_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("lease_revoked", Boolean, nullable=False),
    Column("new_reads_blocked", Boolean, nullable=False),
    Column("untrusted_execution_count", Integer, nullable=False),
    Column("residual_resource_count", Integer, nullable=False),
    Column("inventory_sha256", String(64), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id"),
)
