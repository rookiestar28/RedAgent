"""compat_103 disposable lab, golden scenario, qualification, and teardown truth."""

from alembic import op
import sqlalchemy as sa


revision = "0010_r103_safe_lab"
down_revision = "0009_r102_observability_ir"
branch_labels = None
depends_on = None


TABLES = (
    "lab_bundles", "lab_target_attestations", "lab_target_leases",
    "golden_scenario_runs", "golden_scenario_steps", "golden_finding_expectations",
    "qualification_measurements", "lab_backup_restore_receipts", "lab_teardown_receipts",
)


def upgrade() -> None:
    op.create_table(
        "lab_bundles", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("bundle_id", sa.String(100), nullable=False),
        sa.Column("bundle_revision", sa.Integer(), nullable=False),
        sa.Column("fixture_digest", sa.String(71), nullable=False),
        sa.Column("seed_manifest_sha256", sa.String(64), nullable=False),
        sa.Column("network_id", sa.String(100), nullable=False),
        sa.Column("manifest", sa.JSON(), nullable=False),
        sa.Column("bundle_state", sa.String(32), nullable=False),
        sa.Column("activated_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.UniqueConstraint("tenant_id", "bundle_id", "bundle_revision", name="uq_lab_bundles_tenant_revision"),
    )
    op.create_table(
        "lab_target_attestations", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("bundle_record_id", sa.String(64), nullable=False),
        sa.Column("attestation_id", sa.String(100), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=False),
        sa.Column("fixture_kind", sa.String(32), nullable=False),
        sa.Column("endpoint", sa.String(200), nullable=False),
        sa.Column("network_id", sa.String(100), nullable=False),
        sa.Column("allowed_test_classes", sa.JSON(), nullable=False),
        sa.Column("expected_finding_manifest_sha256", sa.String(64), nullable=False),
        sa.Column("attestation_sha256", sa.String(64), nullable=False),
        sa.Column("non_production", sa.Boolean(), nullable=False),
        sa.Column("attestation_state", sa.String(32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["bundle_record_id"], ["lab_bundles.id"]),
        sa.UniqueConstraint("tenant_id", "attestation_id", name="uq_lab_attestations_tenant_attestation"),
        sa.UniqueConstraint("tenant_id", "target_id", "attestation_sha256", name="uq_lab_attestations_tenant_target_hash"),
    )
    op.create_table(
        "lab_target_leases", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("attestation_record_id", sa.String(64), nullable=False),
        sa.Column("lease_id", sa.String(100), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=False),
        sa.Column("runner_id", sa.String(100), nullable=False),
        sa.Column("test_class", sa.String(32), nullable=False),
        sa.Column("endpoint", sa.String(200), nullable=False),
        sa.Column("attestation_sha256", sa.String(64), nullable=False),
        sa.Column("policy_reference", sa.String(200), nullable=False),
        sa.Column("roe_version_id", sa.String(64), nullable=False),
        sa.Column("lease_state", sa.String(32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)), *_owned(),
        sa.ForeignKeyConstraint(["attestation_record_id"], ["lab_target_attestations.id"]),
        sa.UniqueConstraint("tenant_id", "lease_id", name="uq_lab_target_leases_tenant_lease"),
    )
    op.create_table(
        "golden_scenario_runs", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("bundle_record_id", sa.String(64), nullable=False),
        sa.Column("run_id", sa.String(100), nullable=False),
        sa.Column("scenario_id", sa.String(100), nullable=False),
        sa.Column("scenario_state", sa.String(32), nullable=False),
        sa.Column("current_step", sa.Integer(), nullable=False),
        sa.Column("last_action_id", sa.String(100)),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)), *_owned(),
        sa.ForeignKeyConstraint(["bundle_record_id"], ["lab_bundles.id"]),
        sa.CheckConstraint("current_step >= 0", name="ck_golden_scenario_step_nonnegative"),
        sa.UniqueConstraint("tenant_id", "run_id", "scenario_id", name="uq_golden_scenario_runs_tenant_run_scenario"),
    )
    op.create_table(
        "golden_scenario_steps", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("scenario_run_record_id", sa.String(64), nullable=False),
        sa.Column("step_id", sa.String(100), nullable=False),
        sa.Column("action_id", sa.String(100), nullable=False),
        sa.Column("step_name", sa.String(100), nullable=False),
        sa.Column("step_state", sa.String(32), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("receipt_sha256", sa.String(64), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("contact_count", sa.Integer(), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["scenario_run_record_id"], ["golden_scenario_runs.id"]),
        sa.CheckConstraint("request_count >= 0 AND contact_count >= 0", name="ck_golden_step_counts_nonnegative"),
        sa.UniqueConstraint("tenant_id", "action_id", name="uq_golden_scenario_steps_tenant_action"),
    )
    op.create_table(
        "golden_finding_expectations", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("bundle_record_id", sa.String(64), nullable=False),
        sa.Column("expectation_id", sa.String(100), nullable=False),
        sa.Column("fixture_kind", sa.String(32), nullable=False),
        sa.Column("tool", sa.String(100), nullable=False),
        sa.Column("rule_id", sa.String(200), nullable=False),
        sa.Column("tool_version", sa.String(100), nullable=False),
        sa.Column("database_version", sa.String(100), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("severity", sa.String(32), nullable=False),
        sa.Column("confidence", sa.String(32), nullable=False),
        sa.Column("resource_id", sa.String(100), nullable=False),
        sa.Column("evidence_class", sa.String(32), nullable=False),
        sa.Column("fingerprint", sa.String(64), nullable=False),
        sa.Column("expectation_sha256", sa.String(64), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["bundle_record_id"], ["lab_bundles.id"]),
        sa.UniqueConstraint("tenant_id", "expectation_id", name="uq_golden_findings_tenant_expectation"),
        sa.UniqueConstraint("tenant_id", "bundle_record_id", "fingerprint", name="uq_golden_findings_tenant_bundle_fingerprint"),
    )
    op.create_table(
        "qualification_measurements", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("scenario_run_record_id", sa.String(64)),
        sa.Column("measurement_id", sa.String(100), nullable=False),
        sa.Column("metric_id", sa.String(100), nullable=False),
        sa.Column("comparison", sa.String(8), nullable=False),
        sa.Column("observed_millionths", sa.BigInteger(), nullable=False),
        sa.Column("threshold_millionths", sa.BigInteger(), nullable=False),
        sa.Column("unit", sa.String(64), nullable=False),
        sa.Column("sample_count", sa.Integer(), nullable=False),
        sa.Column("p95_millionths", sa.BigInteger()),
        sa.Column("result_state", sa.String(32), nullable=False),
        sa.Column("artifact_sha256", sa.String(64), nullable=False),
        sa.Column("measured_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["scenario_run_record_id"], ["golden_scenario_runs.id"]),
        sa.CheckConstraint("sample_count > 0", name="ck_qualification_measurement_samples_positive"),
        sa.UniqueConstraint("tenant_id", "measurement_id", name="uq_qualification_measurements_tenant_measurement"),
    )
    op.create_table(
        "lab_backup_restore_receipts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("scenario_run_record_id", sa.String(64), nullable=False),
        sa.Column("receipt_id", sa.String(100), nullable=False),
        sa.Column("source_inventory_sha256", sa.String(64), nullable=False),
        sa.Column("restored_inventory_sha256", sa.String(64), nullable=False),
        sa.Column("source_schema_revision", sa.String(32), nullable=False),
        sa.Column("restored_schema_revision", sa.String(32), nullable=False),
        sa.Column("source_row_count", sa.BigInteger(), nullable=False),
        sa.Column("restored_row_count", sa.BigInteger(), nullable=False),
        sa.Column("source_object_count", sa.BigInteger(), nullable=False),
        sa.Column("restored_object_count", sa.BigInteger(), nullable=False),
        sa.Column("restore_state", sa.String(32), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["scenario_run_record_id"], ["golden_scenario_runs.id"]),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_lab_restore_receipts_tenant_receipt"),
    )
    op.create_table(
        "lab_teardown_receipts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("scenario_run_record_id", sa.String(64), nullable=False),
        sa.Column("receipt_id", sa.String(100), nullable=False),
        sa.Column("container_count", sa.Integer(), nullable=False),
        sa.Column("network_count", sa.Integer(), nullable=False),
        sa.Column("volume_count", sa.Integer(), nullable=False),
        sa.Column("residual_resource_count", sa.Integer(), nullable=False),
        sa.Column("teardown_complete", sa.Boolean(), nullable=False),
        sa.Column("inventory_sha256", sa.String(64), nullable=False),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["scenario_run_record_id"], ["golden_scenario_runs.id"]),
        sa.CheckConstraint(
            "container_count >= 0 AND network_count >= 0 AND volume_count >= 0 AND residual_resource_count >= 0",
            name="ck_lab_teardown_counts_nonnegative",
        ),
        sa.UniqueConstraint("tenant_id", "receipt_id", name="uq_lab_teardown_receipts_tenant_receipt"),
    )
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    op.drop_table("lab_teardown_receipts")
    op.drop_table("lab_backup_restore_receipts")
    op.drop_table("qualification_measurements")
    op.drop_table("golden_finding_expectations")
    op.drop_table("golden_scenario_steps")
    op.drop_table("golden_scenario_runs")
    op.drop_table("lab_target_leases")
    op.drop_table("lab_target_attestations")
    op.drop_table("lab_bundles")


def _owned() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False),
        sa.Column("version", sa.Integer(), nullable=False),
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
