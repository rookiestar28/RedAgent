"""compat_114 attested MCP broker and supervised-workbench persistence."""

from alembic import op
import sqlalchemy as sa


revision = "0021_r114_mcp"
down_revision = "0020_r113_agent"
branch_labels = None
depends_on = None

TABLES = (
    "mcp_server_registrations", "mcp_transport_attestations", "mcp_inventory_revisions",
    "mcp_inventory_items", "mcp_freeze_events", "workbench_campaign_drafts", "workbench_trust_items",
    "workbench_disclosures", "workbench_reviewer_decisions", "workbench_conclusions",
    "workbench_lifecycle_events", "mcp_qualification_receipts",
)


def upgrade() -> None:
    _create("mcp_server_registrations", sa.Column("registration_id", sa.String(100), nullable=False), sa.Column("server_id", sa.String(100), nullable=False), sa.Column("protocol_version", sa.String(32), nullable=False), sa.Column("transport_kind", sa.String(32), nullable=False), sa.Column("transport_identity_sha256", sa.String(64), nullable=False), sa.Column("inventory_sha256", sa.String(64), nullable=False), sa.Column("risk_class", sa.String(32), nullable=False), sa.Column("data_class", sa.String(32), nullable=False), sa.Column("allowed_inventory_sha256", sa.String(64), nullable=False), sa.Column("registered_by", sa.String(64), nullable=False), sa.Column("reviewed_by", sa.String(64), nullable=False), sa.Column("signature_sha256", sa.String(64), nullable=False), sa.Column("registration_state", sa.String(32), nullable=False), sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "registration_id", name="uq_mcp_registration_tenant_id"))
    _create("mcp_transport_attestations", sa.Column("registration_record_id", sa.String(64), sa.ForeignKey("mcp_server_registrations.id"), nullable=False), sa.Column("attestation_id", sa.String(100), nullable=False), sa.Column("transport_kind", sa.String(32), nullable=False), sa.Column("identity_sha256", sa.String(64), nullable=False), sa.Column("authorization_profile_sha256", sa.String(64), nullable=False), sa.Column("boundary_controls_sha256", sa.String(64), nullable=False), sa.Column("transport_enabled", sa.Boolean(), nullable=False), sa.Column("attestation_state", sa.String(32), nullable=False), sa.Column("attested_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "attestation_id", name="uq_mcp_transport_attestation_tenant_id"))
    _create("mcp_inventory_revisions", sa.Column("registration_record_id", sa.String(64), sa.ForeignKey("mcp_server_registrations.id"), nullable=False), sa.Column("inventory_id", sa.String(100), nullable=False), sa.Column("inventory_revision", sa.Integer(), nullable=False), sa.Column("inventory_sha256", sa.String(64), nullable=False), sa.Column("protocol_version", sa.String(32), nullable=False), sa.Column("inventory_state", sa.String(32), nullable=False), sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "inventory_id", "inventory_revision", name="uq_mcp_inventory_tenant_revision"))
    _create("mcp_inventory_items", sa.Column("inventory_record_id", sa.String(64), sa.ForeignKey("mcp_inventory_revisions.id"), nullable=False), sa.Column("item_id", sa.String(100), nullable=False), sa.Column("item_name", sa.String(128), nullable=False), sa.Column("item_kind", sa.String(32), nullable=False), sa.Column("description_sha256", sa.String(64), nullable=False), sa.Column("request_schema_sha256", sa.String(64), nullable=False), sa.Column("result_schema_sha256", sa.String(64), nullable=False), sa.Column("risk_class", sa.String(32), nullable=False), sa.Column("data_class", sa.String(32), nullable=False), sa.Column("tool_mode", sa.String(32), nullable=False), sa.Column("item_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "inventory_record_id", "item_name", name="uq_mcp_inventory_item_tenant_name"))
    _create("mcp_freeze_events", sa.Column("registration_record_id", sa.String(64), sa.ForeignKey("mcp_server_registrations.id"), nullable=False), sa.Column("freeze_id", sa.String(100), nullable=False), sa.Column("reason_code", sa.String(100), nullable=False), sa.Column("expected_inventory_sha256", sa.String(64)), sa.Column("observed_inventory_sha256", sa.String(64)), sa.Column("invalidated_approval_count", sa.Integer(), nullable=False), sa.Column("freeze_state", sa.String(32), nullable=False), sa.Column("frozen_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "freeze_id", name="uq_mcp_freeze_tenant_id"))
    _create("workbench_campaign_drafts", sa.Column("draft_id", sa.String(100), nullable=False), sa.Column("campaign_id", sa.String(100), nullable=False), sa.Column("draft_revision", sa.Integer(), nullable=False), sa.Column("predecessor_draft_id", sa.String(100)), sa.Column("proposal_sha256", sa.String(64), nullable=False), sa.Column("authority_sha256", sa.String(64), nullable=False), sa.Column("draft_state", sa.String(32), nullable=False), sa.Column("created_by", sa.String(64), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "draft_id", name="uq_workbench_draft_tenant_id"))
    _create("workbench_trust_items", sa.Column("draft_record_id", sa.String(64), sa.ForeignKey("workbench_campaign_drafts.id"), nullable=False), sa.Column("item_id", sa.String(100), nullable=False), sa.Column("trust_lane", sa.String(32), nullable=False), sa.Column("summary_sha256", sa.String(64), nullable=False), sa.Column("provenance_sha256", sa.String(64), nullable=False), sa.Column("item_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "draft_record_id", "item_id", name="uq_workbench_trust_item_tenant_id"))
    _create("workbench_disclosures", sa.Column("draft_record_id", sa.String(64), sa.ForeignKey("workbench_campaign_drafts.id"), nullable=False), sa.Column("disclosure_id", sa.String(100), nullable=False), sa.Column("sanitized_fields_sha256", sa.String(64), nullable=False), sa.Column("target_scope_sha256", sa.String(64), nullable=False), sa.Column("access_class", sa.String(32), nullable=False), sa.Column("egress_class", sa.String(32), nullable=False), sa.Column("side_effects_sha256", sa.String(64), nullable=False), sa.Column("budget_sha256", sa.String(64), nullable=False), sa.Column("disclosure_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "disclosure_id", name="uq_workbench_disclosure_tenant_id"))
    _create("workbench_reviewer_decisions", sa.Column("draft_record_id", sa.String(64), sa.ForeignKey("workbench_campaign_drafts.id"), nullable=False), sa.Column("decision_id", sa.String(100), nullable=False), sa.Column("decision_kind", sa.String(32), nullable=False), sa.Column("proposal_sha256", sa.String(64), nullable=False), sa.Column("actor_id", sa.String(64), nullable=False), sa.Column("rationale_sha256", sa.String(64), nullable=False), sa.Column("decision_state", sa.String(32), nullable=False), sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "decision_id", name="uq_workbench_decision_tenant_id"))
    _create("workbench_conclusions", sa.Column("draft_record_id", sa.String(64), sa.ForeignKey("workbench_campaign_drafts.id"), nullable=False), sa.Column("conclusion_id", sa.String(100), nullable=False), sa.Column("reviewer_id", sa.String(64), nullable=False), sa.Column("conclusion_sha256", sa.String(64), nullable=False), sa.Column("provenance_sha256", sa.String(64), nullable=False), sa.Column("conclusion_state", sa.String(32), nullable=False), sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "conclusion_id", name="uq_workbench_conclusion_tenant_id"))
    _create("workbench_lifecycle_events", sa.Column("draft_record_id", sa.String(64), sa.ForeignKey("workbench_campaign_drafts.id"), nullable=False), sa.Column("event_id", sa.String(100), nullable=False), sa.Column("event_kind", sa.String(32), nullable=False), sa.Column("from_state", sa.String(32), nullable=False), sa.Column("to_state", sa.String(32), nullable=False), sa.Column("event_sha256", sa.String(64), nullable=False), sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "event_id", name="uq_workbench_lifecycle_tenant_id"))
    _create("mcp_qualification_receipts", sa.Column("qualification_id", sa.String(100), nullable=False), sa.Column("registration_sha256", sa.String(64), nullable=False), sa.Column("inventory_sha256", sa.String(64), nullable=False), sa.Column("scenario_sha256", sa.String(64), nullable=False), sa.Column("adversarial_case_count", sa.Integer(), nullable=False), sa.Column("denied_case_count", sa.Integer(), nullable=False), sa.Column("network_contact_count", sa.Integer(), nullable=False), sa.Column("process_launch_count", sa.Integer(), nullable=False), sa.Column("sensitive_retention_count", sa.Integer(), nullable=False), sa.Column("direct_dispatch_count", sa.Integer(), nullable=False), sa.Column("qualification_state", sa.String(32), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "qualification_id", name="uq_mcp_qualification_tenant_id"))
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f'DROP TABLE IF EXISTS "{table}"')


def _create(name: str, *columns: object) -> None:
    op.create_table(name, sa.Column("id", sa.String(64), primary_key=True), *columns, *_owned())


def _owned() -> tuple[sa.Column, ...]:
    return (sa.Column("tenant_id", sa.String(64), nullable=False), sa.Column("version", sa.Integer(), nullable=False),
            sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
            sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False))


def _tenant_rls(table: str) -> None:
    op.execute(f'ALTER TABLE "{table}" ENABLE ROW LEVEL SECURITY')
    op.execute(f'ALTER TABLE "{table}" FORCE ROW LEVEL SECURITY')
    op.execute(f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" USING (tenant_id = NULLIF(current_setting(\'redagent.tenant_id\', true), \'\')) WITH CHECK (tenant_id = NULLIF(current_setting(\'redagent.tenant_id\', true), \'\'))')
