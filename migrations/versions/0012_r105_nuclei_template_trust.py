"""compat_105 trusted Nuclei engine, bundles, plans, runs, results, stop, and cleanup."""

from alembic import op
import sqlalchemy as sa


revision = "0012_r105_nuclei"
down_revision = "0011_r104_zap_runtime"
branch_labels = None
depends_on = None


TABLES = (
    "nuclei_engine_artifacts", "nuclei_target_attestations", "nuclei_bundle_revisions", "nuclei_bundle_files",
    "nuclei_template_revisions", "nuclei_bundle_reviews", "nuclei_bundle_promotions",
    "nuclei_profile_revisions", "nuclei_compiled_plans", "nuclei_runs",
    "nuclei_gateway_decisions", "nuclei_normalized_results", "nuclei_result_rejections",
    "nuclei_cancellation_receipts", "nuclei_cleanup_receipts",
)


def upgrade() -> None:
    _create("nuclei_engine_artifacts",
        sa.Column("engine_id", sa.String(100), nullable=False),
        sa.Column("engine_version", sa.String(32), nullable=False),
        sa.Column("image_digest", sa.String(71), nullable=False),
        sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("provenance_sha256", sa.String(64), nullable=False),
        sa.Column("sbom_sha256", sa.String(64), nullable=False),
        sa.Column("vulnerability_review", sa.String(64), nullable=False),
        sa.Column("artifact_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "engine_id", "image_digest", name="uq_nuclei_engine_tenant_digest"))
    _create("nuclei_target_attestations",
        sa.Column("attestation_id", sa.String(100), nullable=False), sa.Column("target_id", sa.String(100), nullable=False),
        sa.Column("target_source_sha256", sa.String(64), nullable=False), sa.Column("target_image_id", sa.String(71), nullable=False),
        sa.Column("network_id", sa.String(100), nullable=False), sa.Column("container_name", sa.String(100), nullable=False),
        sa.Column("address_sha256", sa.String(64), nullable=False), sa.Column("endpoint", sa.String(300), nullable=False),
        sa.Column("allowed_paths", sa.JSON(), nullable=False), sa.Column("attestation_sha256", sa.String(64), nullable=False),
        sa.Column("non_production", sa.Boolean(), nullable=False), sa.Column("attestation_state", sa.String(32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "attestation_id", name="uq_nuclei_target_tenant_attestation"),
        sa.UniqueConstraint("tenant_id", "target_id", "attestation_sha256", name="uq_nuclei_target_tenant_digest"))
    _create("nuclei_bundle_revisions",
        sa.Column("bundle_id", sa.String(100), nullable=False), sa.Column("bundle_revision", sa.Integer(), nullable=False),
        sa.Column("bundle_sha256", sa.String(64), nullable=False), sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("engine_version", sa.String(32), nullable=False), sa.Column("payload_file_count", sa.Integer(), nullable=False),
        sa.Column("bundle_state", sa.String(32), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "bundle_id", "bundle_revision", name="uq_nuclei_bundle_tenant_revision"))
    _create("nuclei_bundle_files",
        sa.Column("bundle_record_id", sa.String(64), sa.ForeignKey("nuclei_bundle_revisions.id"), nullable=False), sa.Column("relative_path", sa.String(300), nullable=False),
        sa.Column("file_sha256", sa.String(64), nullable=False), sa.Column("size_bytes", sa.BigInteger(), nullable=False),
        sa.Column("file_kind", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "bundle_record_id", "relative_path", name="uq_nuclei_bundle_file_tenant_path"))
    _create("nuclei_template_revisions",
        sa.Column("bundle_record_id", sa.String(64), sa.ForeignKey("nuclei_bundle_revisions.id"), nullable=False), sa.Column("template_id", sa.String(100), nullable=False),
        sa.Column("template_sha256", sa.String(64), nullable=False), sa.Column("protocol", sa.String(32), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False), sa.Column("methods", sa.JSON(), nullable=False),
        sa.Column("paths", sa.JSON(), nullable=False), sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("matcher_names", sa.JSON(), nullable=False), sa.Column("template_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "bundle_record_id", "template_id", name="uq_nuclei_template_tenant_id"))
    _create("nuclei_bundle_reviews",
        sa.Column("bundle_record_id", sa.String(64), sa.ForeignKey("nuclei_bundle_revisions.id"), nullable=False), sa.Column("review_id", sa.String(100), nullable=False),
        sa.Column("author_user_id", sa.String(64), nullable=False), sa.Column("reviewer_user_id", sa.String(64), nullable=False),
        sa.Column("review_state", sa.String(32), nullable=False), sa.Column("review_sha256", sa.String(64), nullable=False),
        sa.CheckConstraint("author_user_id <> reviewer_user_id", name="ck_nuclei_bundle_review_sod"),
        sa.UniqueConstraint("tenant_id", "review_id", name="uq_nuclei_review_tenant_id"))
    _create("nuclei_bundle_promotions",
        sa.Column("bundle_record_id", sa.String(64), sa.ForeignKey("nuclei_bundle_revisions.id"), nullable=False), sa.Column("promotion_id", sa.String(100), nullable=False),
        sa.Column("promotion_sha256", sa.String(64), nullable=False), sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("promotion_state", sa.String(32), nullable=False), sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "promotion_id", name="uq_nuclei_promotion_tenant_id"))
    _create("nuclei_profile_revisions",
        sa.Column("profile_id", sa.String(100), nullable=False), sa.Column("profile_revision", sa.Integer(), nullable=False),
        sa.Column("engine_record_id", sa.String(64), sa.ForeignKey("nuclei_engine_artifacts.id"), nullable=False),
        sa.Column("bundle_record_id", sa.String(64), sa.ForeignKey("nuclei_bundle_revisions.id"), nullable=False),
        sa.Column("profile_sha256", sa.String(64), nullable=False), sa.Column("request_limit", sa.Integer(), nullable=False),
        sa.Column("request_rate_per_second", sa.Integer(), nullable=False), sa.Column("concurrency_limit", sa.Integer(), nullable=False),
        sa.Column("timeout_seconds", sa.Integer(), nullable=False), sa.Column("response_bytes_limit", sa.BigInteger(), nullable=False),
        sa.Column("result_limit", sa.Integer(), nullable=False), sa.Column("profile_state", sa.String(32), nullable=False),
        sa.UniqueConstraint("tenant_id", "profile_id", "profile_revision", name="uq_nuclei_profile_tenant_revision"))
    _create("nuclei_compiled_plans",
        sa.Column("profile_record_id", sa.String(64), sa.ForeignKey("nuclei_profile_revisions.id"), nullable=False), sa.Column("plan_id", sa.String(100), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=False), sa.Column("target_attestation_sha256", sa.String(64), nullable=False),
        sa.Column("policy_decision_id", sa.String(100), nullable=False), sa.Column("roe_version_id", sa.String(64), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False), sa.Column("scope_sha256", sa.String(64), nullable=False),
        sa.Column("compiled_plan", sa.JSON(), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "plan_id", name="uq_nuclei_plan_tenant_id"))
    _create("nuclei_runs",
        sa.Column("plan_record_id", sa.String(64), sa.ForeignKey("nuclei_compiled_plans.id"), nullable=False), sa.Column("run_id", sa.String(100), nullable=False),
        sa.Column("job_id", sa.String(100), nullable=False), sa.Column("runner_id", sa.String(100), nullable=False),
        sa.Column("run_state", sa.String(32), nullable=False), sa.Column("progress_percent", sa.Integer(), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False), sa.Column("response_bytes", sa.BigInteger(), nullable=False),
        sa.Column("result_count", sa.Integer(), nullable=False), sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)), sa.Column("completed_at", sa.DateTime(timezone=True)),
        sa.UniqueConstraint("tenant_id", "run_id", name="uq_nuclei_run_tenant_id"))
    _create("nuclei_gateway_decisions",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("nuclei_runs.id"), nullable=False), sa.Column("decision_id", sa.String(100), nullable=False),
        sa.Column("method", sa.String(16), nullable=False), sa.Column("path_sha256", sa.String(64), nullable=False),
        sa.Column("destination_sha256", sa.String(64), nullable=False), sa.Column("allowed", sa.Boolean(), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False), sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("response_bytes", sa.BigInteger(), nullable=False), sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "decision_id", name="uq_nuclei_gateway_tenant_id"))
    _create("nuclei_normalized_results",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("nuclei_runs.id"), nullable=False), sa.Column("result_id", sa.String(100), nullable=False),
        sa.Column("template_id", sa.String(100), nullable=False), sa.Column("matcher_name", sa.String(100), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False), sa.Column("affected_resource", sa.String(300), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False), sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_instance_id", sa.String(100), nullable=False),
        sa.UniqueConstraint("tenant_id", "run_record_id", "fingerprint", name="uq_nuclei_result_tenant_fingerprint"))
    _create("nuclei_result_rejections",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("nuclei_runs.id"), nullable=False), sa.Column("rejection_id", sa.String(100), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False), sa.Column("source_sha256", sa.String(64), nullable=False),
        sa.Column("size_bytes", sa.BigInteger(), nullable=False), sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "rejection_id", name="uq_nuclei_rejection_tenant_id"))
    _create("nuclei_cancellation_receipts",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("nuclei_runs.id"), nullable=False), sa.Column("receipt_id", sa.String(100), nullable=False),
        sa.Column("native_stop_attempted", sa.Boolean(), nullable=False), sa.Column("native_stop_acknowledged", sa.Boolean(), nullable=False),
        sa.Column("lease_revoked", sa.Boolean(), nullable=False), sa.Column("evidence_finalized", sa.Boolean(), nullable=False),
        sa.Column("forced_termination", sa.Boolean(), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_nuclei_cancel_tenant_id"))
    _create("nuclei_cleanup_receipts",
        sa.Column("run_record_id", sa.String(64), sa.ForeignKey("nuclei_runs.id"), nullable=False), sa.Column("receipt_id", sa.String(100), nullable=False),
        sa.Column("container_count", sa.Integer(), nullable=False), sa.Column("network_count", sa.Integer(), nullable=False),
        sa.Column("home_count", sa.Integer(), nullable=False), sa.Column("key_count", sa.Integer(), nullable=False),
        sa.Column("residual_resource_count", sa.Integer(), nullable=False), sa.Column("cleanup_complete", sa.Boolean(), nullable=False),
        sa.Column("inventory_sha256", sa.String(64), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_nuclei_cleanup_tenant_id"))
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    for table in reversed(TABLES):
        # IMPORTANT: compat_105 was exercised pre-acceptance with an earlier 0012 shape lacking later tables.
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
