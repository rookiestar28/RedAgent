"""compat_113 model-independent agent-kernel persistence."""

from alembic import op
import sqlalchemy as sa


revision = "0020_r113_agent"
down_revision = "0019_r112_human"
branch_labels = None
depends_on = None

TABLES = (
    "agent_provider_profiles",
    "agent_projected_tools",
    "agent_runs",
    "agent_steps",
    "agent_proposals",
    "agent_approvals",
    "agent_budget_ledgers",
    "agent_working_memory",
    "agent_reviewed_facts",
    "agent_trace_envelopes",
    "agent_qualification_receipts",
)


def upgrade() -> None:
    _create("agent_provider_profiles", sa.Column("provider_id", sa.String(100), nullable=False), sa.Column("adapter_version", sa.String(100), nullable=False), sa.Column("model_snapshot", sa.String(100), nullable=False), sa.Column("settings_sha256", sa.String(64), nullable=False), sa.Column("response_storage_enabled", sa.Boolean(), nullable=False), sa.Column("background_enabled", sa.Boolean(), nullable=False), sa.Column("provider_tracing_enabled", sa.Boolean(), nullable=False), sa.Column("profile_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "provider_id", "adapter_version", "model_snapshot", name="uq_agent_provider_tenant_version"))
    _create("agent_projected_tools", sa.Column("tool_fqn", sa.String(200), nullable=False), sa.Column("projection_revision", sa.Integer(), nullable=False), sa.Column("source_capability_id", sa.String(100), nullable=False), sa.Column("source_capability_revision", sa.Integer(), nullable=False), sa.Column("source_capability_sha256", sa.String(64), nullable=False), sa.Column("adapter_id", sa.String(100), nullable=False), sa.Column("adapter_version", sa.String(100), nullable=False), sa.Column("input_schema_sha256", sa.String(64), nullable=False), sa.Column("result_schema_sha256", sa.String(64), nullable=False), sa.Column("description_sha256", sa.String(64), nullable=False), sa.Column("network_class", sa.String(32), nullable=False), sa.Column("access_class", sa.String(32), nullable=False), sa.Column("approval_tier", sa.String(32), nullable=False), sa.Column("budget_policy", sa.JSON(), nullable=False), sa.Column("unsupported_features", sa.JSON(), nullable=False), sa.Column("tool_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "tool_fqn", "projection_revision", name="uq_agent_tool_tenant_revision"))
    _create("agent_runs", sa.Column("run_id", sa.String(100), nullable=False), sa.Column("provider_record_id", sa.String(64), sa.ForeignKey("agent_provider_profiles.id"), nullable=False), sa.Column("campaign_id", sa.String(100), nullable=False), sa.Column("operator_id", sa.String(64), nullable=False), sa.Column("trusted_context_sha256", sa.String(64), nullable=False), sa.Column("registry_sha256", sa.String(64), nullable=False), sa.Column("run_state", sa.String(32), nullable=False), sa.Column("cancel_requested", sa.Boolean(), nullable=False), sa.Column("failure_code", sa.String(100)), sa.Column("started_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True)), sa.UniqueConstraint("tenant_id", "run_id", name="uq_agent_run_tenant_id"))
    _create("agent_steps", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("agent_runs.id"), nullable=False), sa.Column("step_id", sa.String(100), nullable=False), sa.Column("step_order", sa.Integer(), nullable=False), sa.Column("step_kind", sa.String(32), nullable=False), sa.Column("request_sha256", sa.String(64), nullable=False), sa.Column("response_sha256", sa.String(64)), sa.Column("trust_class", sa.String(32), nullable=False), sa.Column("step_state", sa.String(32), nullable=False), sa.Column("error_code", sa.String(100)), sa.UniqueConstraint("tenant_id", "run_record_id", "step_order", name="uq_agent_step_tenant_order"))
    _create("agent_proposals", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("agent_runs.id"), nullable=False), sa.Column("tool_record_id", sa.String(64), sa.ForeignKey("agent_projected_tools.id"), nullable=False), sa.Column("proposal_id", sa.String(100), nullable=False), sa.Column("call_id", sa.String(100), nullable=False), sa.Column("proposal_sha256", sa.String(64), nullable=False), sa.Column("argument_sha256", sa.String(64), nullable=False), sa.Column("target_sha256", sa.String(64), nullable=False), sa.Column("side_effect_classes", sa.JSON(), nullable=False), sa.Column("roe_version_id", sa.String(100), nullable=False), sa.Column("policy_revision", sa.String(100), nullable=False), sa.Column("policy_decision_id", sa.String(100), nullable=False), sa.Column("proposal_state", sa.String(32), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "proposal_id", name="uq_agent_proposal_tenant_id"))
    _create("agent_approvals", sa.Column("proposal_record_id", sa.String(64), sa.ForeignKey("agent_proposals.id"), nullable=False), sa.Column("approval_id", sa.String(100), nullable=False), sa.Column("proposal_sha256", sa.String(64), nullable=False), sa.Column("approved_by", sa.String(64), nullable=False), sa.Column("nonce_sha256", sa.String(64), nullable=False), sa.Column("approval_state", sa.String(32), nullable=False), sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("consumed_at", sa.DateTime(timezone=True)), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.UniqueConstraint("tenant_id", "approval_id", name="uq_agent_approval_tenant_id"), sa.UniqueConstraint("tenant_id", "nonce_sha256", name="uq_agent_approval_tenant_nonce"))
    _create("agent_budget_ledgers", sa.Column("run_record_id", sa.String(64), sa.ForeignKey("agent_runs.id"), nullable=False), sa.Column("ledger_id", sa.String(100), nullable=False), sa.Column("budget_sha256", sa.String(64), nullable=False), sa.Column("turn_count", sa.Integer(), nullable=False), sa.Column("tool_call_count", sa.Integer(), nullable=False), sa.Column("input_token_count", sa.Integer(), nullable=False), sa.Column("result_token_count", sa.Integer(), nullable=False), sa.Column("cost_microunits", sa.BigInteger(), nullable=False), sa.Column("result_bytes", sa.BigInteger(), nullable=False), sa.Column("elapsed_millis", sa.BigInteger(), nullable=False), sa.Column("ledger_state", sa.String(32), nullable=False), sa.UniqueConstraint("tenant_id", "ledger_id", name="uq_agent_budget_tenant_id"))
    _create("agent_working_memory", sa.Column("memory_id", sa.String(100), nullable=False), sa.Column("run_record_id", sa.String(64), sa.ForeignKey("agent_runs.id"), nullable=False), sa.Column("ciphertext_sha256", sa.String(64), nullable=False), sa.Column("key_reference_id", sa.String(100), nullable=False), sa.Column("trust_label", sa.String(32), nullable=False), sa.Column("plaintext_bytes", sa.Integer(), nullable=False), sa.Column("memory_state", sa.String(32), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("deleted_at", sa.DateTime(timezone=True)), sa.UniqueConstraint("tenant_id", "memory_id", name="uq_agent_memory_tenant_id"))
    _create("agent_reviewed_facts", sa.Column("fact_id", sa.String(100), nullable=False), sa.Column("candidate_sha256", sa.String(64), nullable=False), sa.Column("provenance_sha256", sa.String(64), nullable=False), sa.Column("proposed_by", sa.String(64), nullable=False), sa.Column("reviewed_by", sa.String(64), nullable=False), sa.Column("trust_label", sa.String(32), nullable=False), sa.Column("fact_state", sa.String(32), nullable=False), sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "fact_id", name="uq_agent_fact_tenant_id"))
    _create("agent_trace_envelopes", sa.Column("trace_id", sa.String(100), nullable=False), sa.Column("span_id", sa.String(100), nullable=False), sa.Column("parent_span_id", sa.String(100)), sa.Column("run_record_id", sa.String(64), sa.ForeignKey("agent_runs.id"), nullable=False), sa.Column("event_type", sa.String(100), nullable=False), sa.Column("trace_state", sa.String(32), nullable=False), sa.Column("input_sha256", sa.String(64), nullable=False), sa.Column("output_sha256", sa.String(64), nullable=False), sa.Column("policy_decision_id", sa.String(100)), sa.Column("approval_id", sa.String(100)), sa.Column("evidence_id", sa.String(100)), sa.Column("error_code", sa.String(100)), sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "trace_id", "span_id", name="uq_agent_trace_tenant_span"))
    _create("agent_qualification_receipts", sa.Column("qualification_id", sa.String(100), nullable=False), sa.Column("registry_sha256", sa.String(64), nullable=False), sa.Column("provider_id", sa.String(100), nullable=False), sa.Column("provider_settings_sha256", sa.String(64), nullable=False), sa.Column("scenario_sha256", sa.String(64), nullable=False), sa.Column("adversarial_case_count", sa.Integer(), nullable=False), sa.Column("denied_case_count", sa.Integer(), nullable=False), sa.Column("external_contact_count", sa.Integer(), nullable=False), sa.Column("direct_dispatch_count", sa.Integer(), nullable=False), sa.Column("sensitive_retention_count", sa.Integer(), nullable=False), sa.Column("qualification_state", sa.String(32), nullable=False), sa.Column("completed_at", sa.DateTime(timezone=True), nullable=False), sa.UniqueConstraint("tenant_id", "qualification_id", name="uq_agent_qualification_tenant_id"))
    for table in TABLES:
        _tenant_rls(table)


def downgrade() -> None:
    for table in reversed(TABLES):
        op.execute(f'DROP TABLE IF EXISTS "{table}"')


def _create(name: str, *columns: object) -> None:
    op.create_table(name, sa.Column("id", sa.String(64), primary_key=True), *columns, *_owned())


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
    op.execute(f'CREATE POLICY "{table}_tenant_isolation" ON "{table}" USING (tenant_id = NULLIF(current_setting(\'redagent.tenant_id\', true), \'\')) WITH CHECK (tenant_id = NULLIF(current_setting(\'redagent.tenant_id\', true), \'\'))')
