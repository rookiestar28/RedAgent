"""compat_106 controlled OpenAPI authorization-differential runtime."""

from alembic import op
import sqlalchemy as sa


revision = "0013_r106_api_diff"
down_revision = "0012_r105_nuclei"
branch_labels = None
depends_on = None


TABLES = (
    "api_diff_engine_artifacts", "api_diff_spec_revisions", "api_diff_operation_manifests",
    "api_diff_identity_matrices", "api_diff_sequence_grammars", "api_diff_reviews",
    "api_diff_promotions", "api_diff_profiles", "api_diff_target_attestations",
    "api_diff_plans", "api_diff_cases", "api_diff_runs", "api_diff_resource_ledger",
    "api_diff_gateway_decisions", "api_diff_observations", "api_diff_replay_artifacts",
    "api_diff_cancellation_receipts", "api_diff_cleanup_receipts",
)


def upgrade() -> None:
    _create("api_diff_engine_artifacts",
        sa.Column("engine_id", sa.String(100), nullable=False), sa.Column("engine_version", sa.String(32), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False), sa.Column("lock_sha256", sa.String(64), nullable=False),
        sa.Column("sbom_sha256", sa.String(64), nullable=False), sa.Column("vulnerability_review", sa.String(64), nullable=False),
        sa.Column("license_review_sha256", sa.String(64), nullable=False), sa.Column("artifact_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "engine_id", "artifact_sha256", name="uq_api_diff_engine_tenant_artifact"))
    _create("api_diff_spec_revisions",
        sa.Column("spec_id", sa.String(100), nullable=False), sa.Column("spec_revision", sa.Integer(), nullable=False),
        sa.Column("spec_sha256", sa.String(64), nullable=False), sa.Column("dialect", sa.String(16), nullable=False),
        sa.Column("server_origin", sa.String(300), nullable=False), sa.Column("operation_count", sa.Integer(), nullable=False),
        sa.Column("spec_state", sa.String(32), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "spec_id", "spec_revision", name="uq_api_diff_spec_tenant_revision"))
    _create("api_diff_operation_manifests",
        sa.Column("spec_record_id", sa.String(64), sa.ForeignKey("api_diff_spec_revisions.id"), nullable=False),
        sa.Column("operation_manifest_sha256", sa.String(64), nullable=False), sa.Column("operations", sa.JSON(), nullable=False),
        sa.Column("risk_classes", sa.JSON(), nullable=False), sa.Column("media_types", sa.JSON(), nullable=False),
        sa.Column("manifest_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "spec_record_id", name="uq_api_diff_operation_manifest_tenant_spec"))
    _create("api_diff_identity_matrices",
        sa.Column("matrix_id", sa.String(100), nullable=False), sa.Column("identity_matrix_sha256", sa.String(64), nullable=False),
        sa.Column("identity_states", sa.JSON(), nullable=False), sa.Column("relations", sa.JSON(), nullable=False),
        sa.Column("expectations", sa.JSON(), nullable=False), sa.Column("matrix_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "matrix_id", "identity_matrix_sha256", name="uq_api_diff_matrix_tenant_digest"))
    _create("api_diff_sequence_grammars",
        sa.Column("grammar_id", sa.String(100), nullable=False), sa.Column("sequence_grammar_sha256", sa.String(64), nullable=False),
        sa.Column("producer_consumer", sa.JSON(), nullable=False), sa.Column("cleanup_grammar", sa.JSON(), nullable=False),
        sa.Column("max_steps", sa.Integer(), nullable=False), sa.Column("grammar_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "grammar_id", "sequence_grammar_sha256", name="uq_api_diff_grammar_tenant_digest"))
    _create("api_diff_reviews",
        sa.Column("review_id", sa.String(100), nullable=False), sa.Column("spec_record_id", sa.String(64), sa.ForeignKey("api_diff_spec_revisions.id"), nullable=False),
        sa.Column("author_user_id", sa.String(64), nullable=False), sa.Column("reviewer_user_id", sa.String(64), nullable=False),
        sa.Column("review_sha256", sa.String(64), nullable=False), sa.Column("review_state", sa.String(32), nullable=False),
        sa.CheckConstraint("author_user_id <> reviewer_user_id", name="ck_api_diff_review_sod"),
        sa.UniqueConstraint("tenant_id", "review_id", name="uq_api_diff_review_tenant_id"))
    _create("api_diff_promotions",
        sa.Column("promotion_id", sa.String(100), nullable=False), sa.Column("spec_record_id", sa.String(64), sa.ForeignKey("api_diff_spec_revisions.id"), nullable=False),
        sa.Column("engine_record_id", sa.String(64), sa.ForeignKey("api_diff_engine_artifacts.id"), nullable=False),
        sa.Column("identity_matrix_sha256", sa.String(64), nullable=False), sa.Column("sequence_grammar_sha256", sa.String(64), nullable=False),
        sa.Column("promotion_sha256", sa.String(64), nullable=False), sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("promotion_state", sa.String(32), nullable=False), sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "promotion_id", name="uq_api_diff_promotion_tenant_id"))
    _create("api_diff_profiles",
        sa.Column("profile_id", sa.String(100), nullable=False), sa.Column("profile_revision", sa.Integer(), nullable=False),
        sa.Column("promotion_record_id", sa.String(64), sa.ForeignKey("api_diff_promotions.id"), nullable=False),
        sa.Column("profile_sha256", sa.String(64), nullable=False), sa.Column("limits", sa.JSON(), nullable=False),
        sa.Column("profile_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "profile_id", "profile_revision", name="uq_api_diff_profile_tenant_revision"))
    _create("api_diff_target_attestations",
        sa.Column("attestation_id", sa.String(100), nullable=False), sa.Column("target_id", sa.String(100), nullable=False),
        sa.Column("attestation_sha256", sa.String(64), nullable=False),
        sa.Column("fixture_sha256", sa.String(64), nullable=False), sa.Column("endpoint", sa.String(300), nullable=False),
        sa.Column("network_id", sa.String(100), nullable=False), sa.Column("non_production", sa.Boolean(), nullable=False),
        sa.Column("attestation_state", sa.String(32), nullable=False), sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "attestation_id", name="uq_api_diff_target_tenant_attestation"))
    _create("api_diff_plans",
        sa.Column("plan_id", sa.String(100), nullable=False), sa.Column("profile_record_id", sa.String(64), sa.ForeignKey("api_diff_profiles.id"), nullable=False),
        sa.Column("target_attestation_id", sa.String(64), sa.ForeignKey("api_diff_target_attestations.id"), nullable=False),
        sa.Column("policy_decision_id", sa.String(100), nullable=False), sa.Column("roe_version_id", sa.String(64), nullable=False),
        sa.Column("spec_sha256", sa.String(64), nullable=False), sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("seed", sa.BigInteger(), nullable=False), sa.Column("compiled_plan", sa.JSON(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "plan_id", name="uq_api_diff_plan_tenant_id"))
    _create("api_diff_cases",
        sa.Column("plan_record_id", sa.String(64), sa.ForeignKey("api_diff_plans.id"), nullable=False),
        sa.Column("case_id", sa.String(150), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False),
        sa.Column("identity_handle", sa.String(100), nullable=False), sa.Column("relation", sa.String(32), nullable=False),
        sa.Column("risk_class", sa.String(32), nullable=False), sa.Column("case_sha256", sa.String(64), nullable=False),
        sa.Column("case_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "plan_record_id", "case_id", name="uq_api_diff_case_tenant_plan_case"))
    _create("api_diff_runs",
        sa.Column("run_id", sa.String(100), nullable=False), sa.Column("plan_record_id", sa.String(64), sa.ForeignKey("api_diff_plans.id"), nullable=False),
        sa.Column("job_id", sa.String(100), nullable=False), sa.Column("runner_id", sa.String(100), nullable=False),
        sa.Column("run_state", sa.String(32), nullable=False), sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False), sa.Column("response_bytes", sa.BigInteger(), nullable=False),
        sa.Column("finding_count", sa.Integer(), nullable=False), sa.Column("reason_code", sa.String(100), nullable=False),
        sa.UniqueConstraint("tenant_id", "run_id", name="uq_api_diff_run_tenant_id"))
    _create("api_diff_resource_ledger",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("api_diff_runs.id"), nullable=False),
        sa.Column("resource_id", sa.String(100), nullable=False), sa.Column("resource_lineage_sha256", sa.String(64), nullable=False),
        sa.Column("owner_identity_handle", sa.String(100), nullable=False), sa.Column("tenant_handle", sa.String(100), nullable=False),
        sa.Column("idempotency_key", sa.String(150), nullable=False), sa.Column("resource_state", sa.String(32), nullable=False),
        sa.Column("compensation_operation", sa.String(100), nullable=False),
        sa.UniqueConstraint("tenant_id", "run_record_id", "resource_id", name="uq_api_diff_resource_tenant_run_id"))
    _create("api_diff_gateway_decisions",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("api_diff_runs.id"), nullable=False),
        sa.Column("decision_id", sa.String(100), nullable=False), sa.Column("operation_id", sa.String(100), nullable=False),
        sa.Column("identity_handle", sa.String(100), nullable=False), sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False), sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("response_bytes", sa.BigInteger(), nullable=False), sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "decision_id", name="uq_api_diff_gateway_tenant_id"))
    _create("api_diff_observations",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("api_diff_runs.id"), nullable=False),
        sa.Column("observation_id", sa.String(100), nullable=False), sa.Column("case_id", sa.String(150), nullable=False),
        sa.Column("resource_lineage_sha256", sa.String(64), nullable=False), sa.Column("outcome_sha256", sa.String(64), nullable=False),
        sa.Column("finding_type", sa.String(32)), sa.Column("violated", sa.Boolean(), nullable=False),
        sa.Column("evidence_instance_id", sa.String(100)), sa.Column("reason_code", sa.String(100), nullable=False),
        sa.UniqueConstraint("tenant_id", "observation_id", name="uq_api_diff_observation_tenant_id"))
    _create("api_diff_replay_artifacts",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("api_diff_runs.id"), nullable=False),
        sa.Column("replay_id", sa.String(100), nullable=False), sa.Column("case_id", sa.String(150), nullable=False),
        sa.Column("minimized_replay_sha256", sa.String(64), nullable=False), sa.Column("public_replay", sa.JSON(), nullable=False),
        sa.Column("semantic_predicate", sa.String(100), nullable=False), sa.Column("replay_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "replay_id", name="uq_api_diff_replay_tenant_id"))
    _create("api_diff_cancellation_receipts",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("api_diff_runs.id"), nullable=False),
        sa.Column("receipt_id", sa.String(100), nullable=False), sa.Column("gateway_blocked", sa.Boolean(), nullable=False),
        sa.Column("native_stop_attempted", sa.Boolean(), nullable=False), sa.Column("native_stop_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("lease_revoked", sa.Boolean(), nullable=False), sa.Column("forced_termination", sa.Boolean(), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_api_diff_cancel_tenant_id"))
    _create("api_diff_cleanup_receipts",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("api_diff_runs.id"), nullable=False),
        sa.Column("receipt_id", sa.String(100), nullable=False), sa.Column("compensation_complete", sa.Boolean(), nullable=False),
        sa.Column("lease_revoked", sa.Boolean(), nullable=False), sa.Column("container_count", sa.Integer(), nullable=False),
        sa.Column("network_count", sa.Integer(), nullable=False), sa.Column("transient_file_count", sa.Integer(), nullable=False),
        sa.Column("residual_resource_count", sa.Integer(), nullable=False), sa.Column("inventory_sha256", sa.String(64), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_api_diff_cleanup_tenant_id"))
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f'DROP TABLE IF EXISTS "{table}"')


def _create(name: str, *columns: object) -> None:
    op.create_table(name, sa.Column("id", sa.String(64), primary_key=True), *columns, *_owned())


def _owned() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False), sa.Column("version", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def _tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(
        f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" '
        "USING (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), '')) "
        "WITH CHECK (tenant_id = NULLIF(current_setting('redagent.tenant_id', true), ''))"
    )
