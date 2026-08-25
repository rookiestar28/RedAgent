"""compat_100 ephemeral runner identity, capability, manifest, lease, and receipt truth."""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "0007_r100_ephemeral_runners"
down_revision = "0006_r099_policy_distribution"
branch_labels = None
depends_on = None


TABLES = (
    "runner_classes", "runner_registrations", "runner_identities",
    "execution_capability_manifests", "artifact_verification_receipts",
    "runner_job_manifests", "runner_pull_leases", "runner_lifecycle_events",
    "runner_execution_receipts",
)


def upgrade() -> None:
    op.create_table(
        "runner_classes", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("class_id", sa.String(100), nullable=False), sa.Column("class_revision", sa.Integer(), nullable=False),
        sa.Column("environment", sa.String(64), nullable=False), sa.Column("network_plane", sa.String(64), nullable=False),
        sa.Column("isolation_tier", sa.String(32), nullable=False), sa.Column("runtime_name", sa.String(32), nullable=False),
        sa.Column("sandbox_profile_id", sa.String(100), nullable=False), sa.Column("policy_revision", sa.String(100), nullable=False),
        sa.Column("resource_limits", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("credential_classes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("evidence_schemas", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("class_status", sa.String(32), nullable=False), sa.Column("author_user_id", sa.String(64), nullable=False),
        sa.Column("reviewer_user_id", sa.String(64), nullable=False), *_owned(),
        sa.UniqueConstraint("tenant_id", "class_id", "class_revision", name="uq_runner_classes_tenant_class_revision"),
    )
    op.create_table(
        "runner_registrations", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("runner_id", sa.String(100), nullable=False), sa.Column("runner_class_record_id", sa.String(64), nullable=False),
        sa.Column("environment", sa.String(64), nullable=False), sa.Column("network_plane", sa.String(64), nullable=False),
        sa.Column("spiffe_id", sa.String(300), nullable=False), sa.Column("certificate_fingerprint", sa.String(64), nullable=False),
        sa.Column("certificate_serial", sa.String(100), nullable=False),
        sa.Column("adapter_allowlist", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("image_allowlist", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("required_policy_revision", sa.String(100), nullable=False), sa.Column("generation", sa.Integer(), nullable=False),
        sa.Column("attestation_sha256", sa.String(64), nullable=False), sa.Column("registration_state", sa.String(32), nullable=False),
        sa.Column("registered_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("last_seen_at", sa.DateTime(timezone=True)), *_owned(),
        sa.ForeignKeyConstraint(["runner_class_record_id"], ["runner_classes.id"]),
        sa.UniqueConstraint("tenant_id", "runner_id", "generation", name="uq_runner_registrations_tenant_runner_generation"),
    )
    op.create_table(
        "runner_identities", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("registration_id", sa.String(64), nullable=False), sa.Column("spiffe_id", sa.String(300), nullable=False),
        sa.Column("certificate_fingerprint", sa.String(64), nullable=False), sa.Column("certificate_serial", sa.String(100), nullable=False),
        sa.Column("not_before", sa.DateTime(timezone=True), nullable=False), sa.Column("not_after", sa.DateTime(timezone=True), nullable=False),
        sa.Column("identity_state", sa.String(32), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["registration_id"], ["runner_registrations.id"]),
        sa.UniqueConstraint("tenant_id", "certificate_fingerprint", name="uq_runner_identities_tenant_fingerprint"),
    )
    op.create_table(
        "execution_capability_manifests", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("capability_id", sa.String(100), nullable=False), sa.Column("capability_revision", sa.Integer(), nullable=False),
        sa.Column("adapter_id", sa.String(100), nullable=False), sa.Column("adapter_version", sa.String(100), nullable=False),
        sa.Column("image_digest", sa.String(71), nullable=False), sa.Column("input_schema_id", sa.String(100), nullable=False),
        sa.Column("supported_modes", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("phases", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("sandbox_profile_id", sa.String(100), nullable=False), sa.Column("network_mode", sa.String(32), nullable=False),
        sa.Column("credential_class", sa.String(32), nullable=False),
        sa.Column("evidence_schema", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("unsupported_features", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("resource_limits", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("artifact_receipt_id", sa.String(64), nullable=False), sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("reviewed_by_user_id", sa.String(64), nullable=False), sa.Column("capability_status", sa.String(32), nullable=False), *_owned(),
        sa.UniqueConstraint("tenant_id", "capability_id", "capability_revision", name="uq_execution_capabilities_tenant_capability_revision"),
    )
    op.create_table(
        "artifact_verification_receipts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("receipt_id", sa.String(100), nullable=False), sa.Column("image_digest", sa.String(71), nullable=False),
        sa.Column("signature_verified", sa.Boolean(), nullable=False), sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("signer_identity", sa.String(200), nullable=False),
        sa.Column("provenance_sha256", sa.String(64), nullable=False), sa.Column("sbom_sha256", sa.String(64), nullable=False),
        sa.Column("vulnerability_review", sa.String(64), nullable=False), sa.Column("verifier", sa.String(100), nullable=False),
        sa.Column("verified_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.UniqueConstraint("tenant_id", "image_digest", name="uq_artifact_verification_tenant_image_digest"),
    )
    op.create_table(
        "runner_job_manifests", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("manifest_id", sa.String(100), nullable=False), sa.Column("job_id", sa.String(64), nullable=False),
        sa.Column("runner_registration_id", sa.String(64), nullable=False), sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("request_hash", sa.String(64), nullable=False),
        sa.Column("manifest_document", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("manifest_sha256", sa.String(64), nullable=False), sa.Column("signature_sha256", sa.String(64), nullable=False),
        sa.Column("signing_key_id", sa.String(100), nullable=False), sa.Column("capability_id", sa.String(100), nullable=False),
        sa.Column("capability_revision", sa.Integer(), nullable=False), sa.Column("capability_sha256", sa.String(64), nullable=False),
        sa.Column("image_digest", sa.String(71), nullable=False), sa.Column("artifact_receipt_id", sa.String(64), nullable=False),
        sa.Column("policy_revision", sa.String(100), nullable=False), sa.Column("policy_decision_id", sa.String(100), nullable=False),
        sa.Column("nonce_hash", sa.String(64), nullable=False), sa.Column("manifest_state", sa.String(32), nullable=False),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["job_id"], ["jobs.id"]),
        sa.ForeignKeyConstraint(["runner_registration_id"], ["runner_registrations.id"]),
        sa.UniqueConstraint("tenant_id", "job_id", "idempotency_key", name="uq_runner_manifests_tenant_job_request"),
    )
    op.create_table(
        "runner_pull_leases", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("manifest_id", sa.String(64), nullable=False), sa.Column("runner_registration_id", sa.String(64), nullable=False),
        sa.Column("claim_id", sa.String(100), nullable=False), sa.Column("lease_token_hash", sa.String(64), nullable=False),
        sa.Column("runner_generation", sa.Integer(), nullable=False), sa.Column("manifest_sha256", sa.String(64), nullable=False),
        sa.Column("lease_state", sa.String(32), nullable=False), sa.Column("claimed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_heartbeat_at", sa.DateTime(timezone=True)), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("finalized_at", sa.DateTime(timezone=True)), sa.Column("failure_code", sa.String(100)), *_owned(),
        sa.ForeignKeyConstraint(["manifest_id"], ["runner_job_manifests.id"]),
        sa.ForeignKeyConstraint(["runner_registration_id"], ["runner_registrations.id"]),
        sa.UniqueConstraint("tenant_id", "manifest_id", name="uq_runner_pull_leases_tenant_manifest"),
    )
    op.create_table(
        "runner_lifecycle_events", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("lease_id", sa.String(64), nullable=False), sa.Column("event_id", sa.String(100), nullable=False),
        sa.Column("phase", sa.String(32), nullable=False), sa.Column("event_sha256", sa.String(64), nullable=False),
        sa.Column("phase_state", sa.String(32), nullable=False), sa.Column("reason_code", sa.String(100)),
        sa.Column("metadata", postgresql.JSONB(astext_type=sa.Text()), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["lease_id"], ["runner_pull_leases.id"]),
        sa.UniqueConstraint("tenant_id", "event_id", name="uq_runner_lifecycle_events_tenant_event"),
    )
    op.create_table(
        "runner_execution_receipts", sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("lease_id", sa.String(64), nullable=False), sa.Column("evidence_artifact_id", sa.String(64)),
        sa.Column("execution_id", sa.String(100), nullable=False), sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("final_phase", sa.String(32), nullable=False), sa.Column("policy_decision_id", sa.String(100), nullable=False),
        sa.Column("evidence_sha256", sa.String(64)), sa.Column("cleanup_completed", sa.Boolean(), nullable=False),
        sa.Column("residual_risk", sa.String(100)), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), *_owned(),
        sa.ForeignKeyConstraint(["lease_id"], ["runner_pull_leases.id"]),
        sa.ForeignKeyConstraint(["evidence_artifact_id"], ["evidence_artifacts.id"]),
        sa.UniqueConstraint("tenant_id", "execution_id", name="uq_runner_execution_receipts_tenant_execution"),
    )
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    op.drop_table("runner_execution_receipts")
    op.drop_table("runner_lifecycle_events")
    op.drop_table("runner_pull_leases")
    op.drop_table("runner_job_manifests")
    op.drop_table("artifact_verification_receipts")
    op.drop_table("execution_capability_manifests")
    op.drop_table("runner_identities")
    op.drop_table("runner_registrations")
    op.drop_table("runner_classes")


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
