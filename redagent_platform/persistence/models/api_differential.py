"""SQLAlchemy table registrations for the api differential domain."""

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
    "api_diff_engine_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("engine_id", String(100), nullable=False),
    Column("engine_version", String(32), nullable=False),
    Column("artifact_sha256", String(64), nullable=False),
    Column("lock_sha256", String(64), nullable=False),
    Column("sbom_sha256", String(64), nullable=False),
    Column("vulnerability_review", String(64), nullable=False),
    Column("license_review_sha256", String(64), nullable=False),
    Column("artifact_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "engine_id", "artifact_sha256", name="uq_api_diff_engine_tenant_artifact"),
)

Table(
    "api_diff_spec_revisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("spec_id", String(100), nullable=False),
    Column("spec_revision", Integer, nullable=False),
    Column("spec_sha256", String(64), nullable=False),
    Column("dialect", String(16), nullable=False),
    Column("server_origin", String(300), nullable=False),
    Column("operation_count", Integer, nullable=False),
    Column("spec_state", String(32), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "spec_id", "spec_revision", name="uq_api_diff_spec_tenant_revision"),
)

Table(
    "api_diff_operation_manifests",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("spec_record_id", String(64), ForeignKey("api_diff_spec_revisions.id"), nullable=False),
    Column("operation_manifest_sha256", String(64), nullable=False),
    Column("operations", JSON, nullable=False),
    Column("risk_classes", JSON, nullable=False),
    Column("media_types", JSON, nullable=False),
    Column("manifest_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "spec_record_id", name="uq_api_diff_operation_manifest_tenant_spec"),
)

Table(
    "api_diff_identity_matrices",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("matrix_id", String(100), nullable=False),
    Column("identity_matrix_sha256", String(64), nullable=False),
    Column("identity_states", JSON, nullable=False),
    Column("relations", JSON, nullable=False),
    Column("expectations", JSON, nullable=False),
    Column("matrix_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "matrix_id", "identity_matrix_sha256", name="uq_api_diff_matrix_tenant_digest"),
)

Table(
    "api_diff_sequence_grammars",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("grammar_id", String(100), nullable=False),
    Column("sequence_grammar_sha256", String(64), nullable=False),
    Column("producer_consumer", JSON, nullable=False),
    Column("cleanup_grammar", JSON, nullable=False),
    Column("max_steps", Integer, nullable=False),
    Column("grammar_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "grammar_id", "sequence_grammar_sha256", name="uq_api_diff_grammar_tenant_digest"),
)

Table(
    "api_diff_reviews",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("review_id", String(100), nullable=False),
    Column("spec_record_id", String(64), ForeignKey("api_diff_spec_revisions.id"), nullable=False),
    Column("author_user_id", String(64), nullable=False),
    Column("reviewer_user_id", String(64), nullable=False),
    Column("review_sha256", String(64), nullable=False),
    Column("review_state", String(32), nullable=False),
    *_owned_columns(),
    CheckConstraint("author_user_id <> reviewer_user_id", name="api_diff_review_sod"),
    UniqueConstraint("tenant_id", "review_id", name="uq_api_diff_review_tenant_id"),
)

Table(
    "api_diff_promotions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("promotion_id", String(100), nullable=False),
    Column("spec_record_id", String(64), ForeignKey("api_diff_spec_revisions.id"), nullable=False),
    Column("engine_record_id", String(64), ForeignKey("api_diff_engine_artifacts.id"), nullable=False),
    Column("identity_matrix_sha256", String(64), nullable=False),
    Column("sequence_grammar_sha256", String(64), nullable=False),
    Column("promotion_sha256", String(64), nullable=False),
    Column("signature_sha256", String(64), nullable=False),
    Column("promotion_state", String(32), nullable=False),
    Column("promoted_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "promotion_id", name="uq_api_diff_promotion_tenant_id"),
)

Table(
    "api_diff_profiles",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("profile_id", String(100), nullable=False),
    Column("profile_revision", Integer, nullable=False),
    Column("promotion_record_id", String(64), ForeignKey("api_diff_promotions.id"), nullable=False),
    Column("profile_sha256", String(64), nullable=False),
    Column("limits", JSON, nullable=False),
    Column("profile_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "profile_id", "profile_revision", name="uq_api_diff_profile_tenant_revision"),
)

Table(
    "api_diff_target_attestations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("attestation_id", String(100), nullable=False),
    Column("target_id", String(100), nullable=False),
    Column("attestation_sha256", String(64), nullable=False),
    Column("fixture_sha256", String(64), nullable=False),
    Column("endpoint", String(300), nullable=False),
    Column("network_id", String(100), nullable=False),
    Column("non_production", Boolean, nullable=False),
    Column("attestation_state", String(32), nullable=False),
    Column("issued_at", DateTime(timezone=True), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "attestation_id", name="uq_api_diff_target_tenant_attestation"),
)

Table(
    "api_diff_plans",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("plan_id", String(100), nullable=False),
    Column("profile_record_id", String(64), ForeignKey("api_diff_profiles.id"), nullable=False),
    Column("target_attestation_id", String(64), ForeignKey("api_diff_target_attestations.id"), nullable=False),
    Column("policy_decision_id", String(100), nullable=False),
    Column("roe_version_id", String(64), nullable=False),
    Column("spec_sha256", String(64), nullable=False),
    Column("plan_sha256", String(64), nullable=False),
    Column("seed", BigInteger, nullable=False),
    Column("compiled_plan", JSON, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "plan_id", name="uq_api_diff_plan_tenant_id"),
)

Table(
    "api_diff_cases",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("plan_record_id", String(64), ForeignKey("api_diff_plans.id"), nullable=False),
    Column("case_id", String(150), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("identity_handle", String(100), nullable=False),
    Column("relation", String(32), nullable=False),
    Column("risk_class", String(32), nullable=False),
    Column("case_sha256", String(64), nullable=False),
    Column("case_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "plan_record_id", "case_id", name="uq_api_diff_case_tenant_plan_case"),
)

Table(
    "api_diff_runs",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_id", String(100), nullable=False),
    Column("plan_record_id", String(64), ForeignKey("api_diff_plans.id"), nullable=False),
    Column("job_id", String(100), nullable=False),
    Column("runner_id", String(100), nullable=False),
    Column("run_state", String(32), nullable=False),
    Column("progress_percent", Integer, nullable=False),
    Column("request_count", Integer, nullable=False),
    Column("response_bytes", BigInteger, nullable=False),
    Column("finding_count", Integer, nullable=False),
    Column("reason_code", String(100), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_id", name="uq_api_diff_run_tenant_id"),
)

Table(
    "api_diff_resource_ledger",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("api_diff_runs.id"), nullable=False),
    Column("resource_id", String(100), nullable=False),
    Column("resource_lineage_sha256", String(64), nullable=False),
    Column("owner_identity_handle", String(100), nullable=False),
    Column("tenant_handle", String(100), nullable=False),
    Column("idempotency_key", String(150), nullable=False),
    Column("resource_state", String(32), nullable=False),
    Column("compensation_operation", String(100), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "run_record_id", "resource_id", name="uq_api_diff_resource_tenant_run_id"),
)

Table(
    "api_diff_gateway_decisions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("api_diff_runs.id"), nullable=False),
    Column("decision_id", String(100), nullable=False),
    Column("operation_id", String(100), nullable=False),
    Column("identity_handle", String(100), nullable=False),
    Column("allowed", Boolean, nullable=False),
    Column("reason_code", String(100), nullable=False),
    Column("request_count", Integer, nullable=False),
    Column("response_bytes", BigInteger, nullable=False),
    Column("occurred_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "decision_id", name="uq_api_diff_gateway_tenant_id"),
)

Table(
    "api_diff_observations",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("api_diff_runs.id"), nullable=False),
    Column("observation_id", String(100), nullable=False),
    Column("case_id", String(150), nullable=False),
    Column("resource_lineage_sha256", String(64), nullable=False),
    Column("outcome_sha256", String(64), nullable=False),
    Column("finding_type", String(32)),
    Column("violated", Boolean, nullable=False),
    Column("evidence_instance_id", String(100)),
    Column("reason_code", String(100), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "observation_id", name="uq_api_diff_observation_tenant_id"),
)

Table(
    "api_diff_replay_artifacts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("api_diff_runs.id"), nullable=False),
    Column("replay_id", String(100), nullable=False),
    Column("case_id", String(150), nullable=False),
    Column("minimized_replay_sha256", String(64), nullable=False),
    Column("public_replay", JSON, nullable=False),
    Column("semantic_predicate", String(100), nullable=False),
    Column("replay_state", String(32), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "replay_id", name="uq_api_diff_replay_tenant_id"),
)

Table(
    "api_diff_cancellation_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("api_diff_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("gateway_blocked", Boolean, nullable=False),
    Column("native_stop_attempted", Boolean, nullable=False),
    Column("native_stop_acknowledged", Boolean, nullable=False),
    Column("lease_revoked", Boolean, nullable=False),
    Column("forced_termination", Boolean, nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id", name="uq_api_diff_cancel_tenant_id"),
)

Table(
    "api_diff_cleanup_receipts",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("run_record_id", String(64), ForeignKey("api_diff_runs.id"), nullable=False),
    Column("receipt_id", String(100), nullable=False),
    Column("compensation_complete", Boolean, nullable=False),
    Column("lease_revoked", Boolean, nullable=False),
    Column("container_count", Integer, nullable=False),
    Column("network_count", Integer, nullable=False),
    Column("transient_file_count", Integer, nullable=False),
    Column("residual_resource_count", Integer, nullable=False),
    Column("inventory_sha256", String(64), nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "receipt_id", name="uq_api_diff_cleanup_tenant_id"),
)
