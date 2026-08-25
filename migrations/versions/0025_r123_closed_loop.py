"""Add compat_123 bounded strategy, effect, and durable outbox state."""

from alembic import op
import sqlalchemy as sa


revision = "0025_r123_closed_loop"
down_revision = "0024_r118_retirement"
branch_labels = None
depends_on = None


def _owned_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def upgrade() -> None:
    op.add_column("campaigns", sa.Column("intent_sha256", sa.String(64)))
    op.add_column("campaigns", sa.Column("current_strategy_revision_id", sa.String(64)))
    op.add_column(
        "campaigns",
        sa.Column("aggregate_sequence", sa.BigInteger(), nullable=False, server_default="0"),
    )
    op.add_column(
        "campaigns", sa.Column("replan_count", sa.Integer(), nullable=False, server_default="0")
    )
    op.add_column("campaigns", sa.Column("attention_reason", sa.String(100)))
    op.add_column("campaigns", sa.Column("terminal_receipt_sha256", sa.String(64)))
    op.create_check_constraint(
        "campaigns_r123_aggregate_sequence_bounded",
        "campaigns",
        "aggregate_sequence BETWEEN 0 AND 2147483647",
    )
    op.create_check_constraint(
        "campaigns_r123_replan_count_bounded",
        "campaigns",
        "replan_count BETWEEN 0 AND 1",
    )

    for column in (
        sa.Column("strategy_revision_id", sa.String(64)),
        sa.Column("node_id", sa.String(100)),
        sa.Column("effect_id", sa.String(100)),
        sa.Column("envelope_sha256", sa.String(64)),
        sa.Column("manifest_v2_sha256", sa.String(64)),
    ):
        op.add_column("jobs", column)

    op.create_table(
        "campaign_strategy_revisions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("strategy_revision_id", sa.String(100), nullable=False),
        sa.Column("campaign_id", sa.String(64), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("predecessor_revision_id", sa.String(100)),
        sa.Column("plan_revision", sa.Integer(), nullable=False),
        sa.Column("replan_count", sa.Integer(), nullable=False),
        sa.Column("context_schema", sa.String(100), nullable=False),
        sa.Column("context_sha256", sa.String(64), nullable=False),
        sa.Column("context_payload", sa.JSON(), nullable=False),
        sa.Column("decision_schema", sa.String(100), nullable=False),
        sa.Column("decision_sha256", sa.String(64), nullable=False),
        sa.Column("decision_payload", sa.JSON(), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("plan_payload", sa.JSON(), nullable=False),
        sa.Column("proposal_ceiling_sha256", sa.String(64), nullable=False),
        sa.Column("approval_receipt_id", sa.String(100), nullable=False),
        sa.Column("approval_receipt_revision", sa.Integer(), nullable=False),
        sa.Column("approval_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("envelope_core_sha256", sa.String(64), nullable=False),
        sa.Column("envelope_sha256", sa.String(64), nullable=False),
        sa.Column("created_by_user_id", sa.String(64), nullable=False),
        *_owned_columns(),
        sa.UniqueConstraint(
            "tenant_id", "strategy_revision_id", name="uq_campaign_strategy_tenant_revision"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "campaign_id",
            "plan_revision",
            name="uq_campaign_strategy_tenant_plan_revision",
        ),
        sa.CheckConstraint(
            "plan_revision BETWEEN 1 AND 2", name="campaign_strategy_plan_revision_bounded"
        ),
        sa.CheckConstraint(
            "replan_count BETWEEN 0 AND 1", name="campaign_strategy_replan_count_bounded"
        ),
    )

    op.create_table(
        "campaign_effects",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("effect_id", sa.String(100), nullable=False),
        sa.Column("campaign_id", sa.String(64), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column(
            "strategy_revision_id",
            sa.String(64),
            sa.ForeignKey("campaign_strategy_revisions.id"),
            nullable=False,
        ),
        sa.Column("node_id", sa.String(100), nullable=False),
        sa.Column("invocation_id", sa.String(100), nullable=False),
        sa.Column("effect_intent_sha256", sa.String(64), nullable=False),
        sa.Column("effect_intent_payload", sa.JSON(), nullable=False),
        sa.Column("envelope_sha256", sa.String(64), nullable=False),
        sa.Column("effect_state", sa.String(32), nullable=False),
        sa.Column("claim_owner", sa.String(100)),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True)),
        sa.Column("claim_version", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dispatch_attempt", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("dispatch_generation", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("runner_id", sa.String(100)),
        sa.Column("workload_identity", sa.String(300)),
        sa.Column("request_sha256", sa.String(64)),
        sa.Column("effect_receipt_sha256", sa.String(64)),
        sa.Column("effect_receipt_payload", sa.JSON()),
        sa.Column("external_status", sa.String(100)),
        sa.Column("external_receipt_id", sa.String(100)),
        sa.Column("evidence_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("cleanup_receipt_id", sa.String(100)),
        sa.Column("reconciliation_state", sa.String(32), nullable=False, server_default="none"),
        sa.Column("reconciliation_evidence_ids", sa.JSON(), nullable=False, server_default="[]"),
        sa.Column("redispatch_permitted", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("failure_code", sa.String(100)),
        sa.Column("next_retry_at", sa.DateTime(timezone=True)),
        sa.Column("outbox_sequence", sa.BigInteger(), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        *_owned_columns(),
        sa.UniqueConstraint("tenant_id", "effect_id", name="uq_campaign_effect_tenant_effect"),
        sa.UniqueConstraint(
            "tenant_id",
            "campaign_id",
            "strategy_revision_id",
            "node_id",
            name="uq_campaign_effect_stable_node",
        ),
        sa.CheckConstraint(
            "claim_version BETWEEN 0 AND 2147483647",
            name="campaign_effect_claim_version_bounded",
        ),
        sa.CheckConstraint(
            "dispatch_attempt BETWEEN 0 AND 2",
            name="campaign_effect_dispatch_attempt_bounded",
        ),
        sa.CheckConstraint(
            "dispatch_generation BETWEEN 0 AND 2147483647",
            name="campaign_effect_dispatch_generation_bounded",
        ),
        sa.CheckConstraint(
            "outbox_sequence BETWEEN 1 AND 2147483647",
            name="campaign_effect_outbox_sequence_bounded",
        ),
        sa.CheckConstraint(
            "effect_state IN ('reserved','claimed','dispatching','reconciliation_required',"
            "'not_applied','confirmed','compensated','manual_review_required','failed')",
            name="campaign_effect_state_closed",
        ),
        sa.CheckConstraint(
            "reconciliation_state IN ('none','reconciliation_required','confirmed','not_applied',"
            "'compensated','manual_review_required')",
            name="campaign_effect_reconciliation_state_closed",
        ),
    )

    op.create_foreign_key(
        "fk_campaigns_current_strategy_revision",
        "campaigns",
        "campaign_strategy_revisions",
        ["current_strategy_revision_id"],
        ["id"],
    )
    op.create_foreign_key(
        "fk_jobs_strategy_revision",
        "jobs",
        "campaign_strategy_revisions",
        ["strategy_revision_id"],
        ["id"],
    )

    outbox_columns = (
        sa.Column("schema_revision", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("aggregate_type", sa.String(64), nullable=False, server_default="legacy"),
        sa.Column("aggregate_sequence", sa.BigInteger(), nullable=False, server_default="0"),
        sa.Column(
            "available_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        ),
        sa.Column("claim_owner", sa.String(100)),
        sa.Column("claim_expires_at", sa.DateTime(timezone=True)),
        sa.Column("attempt_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("last_error", sa.String(500)),
        sa.Column("delivered_at", sa.DateTime(timezone=True)),
        sa.Column("delivery_state", sa.String(32), nullable=False, server_default="pending"),
        sa.Column("reconciliation_state", sa.String(32), nullable=False, server_default="none"),
        sa.Column("dead_lettered_at", sa.DateTime(timezone=True)),
    )
    for column in outbox_columns:
        op.add_column("outbox_events", column)
    op.create_check_constraint(
        "outbox_r123_attempt_count_bounded",
        "outbox_events",
        "attempt_count BETWEEN 0 AND 10",
    )
    op.create_check_constraint(
        "outbox_r123_delivery_state_closed",
        "outbox_events",
        "delivery_state IN ('pending','claimed','delivered','reconciliation_required','dead_letter')",
    )
    op.create_check_constraint(
        "outbox_r123_reconciliation_state_closed",
        "outbox_events",
        "reconciliation_state IN ('none','duplicate_confirmed','manual_review_required')",
    )
    op.create_check_constraint(
        "outbox_r123_workflow_start_shape",
        "outbox_events",
        "event_type <> 'workflow.start.requested.v1' OR "
        "(schema_revision = 2 AND aggregate_type = 'campaign' AND aggregate_sequence > 0)",
    )
    op.create_index(
        "uq_outbox_r123_ordered_event",
        "outbox_events",
        ["tenant_id", "aggregate_type", "aggregate_id", "aggregate_sequence"],
        unique=True,
        postgresql_where=sa.text("schema_revision = 2"),
    )
    op.create_index(
        "ix_outbox_r123_claimable",
        "outbox_events",
        ["tenant_id", "delivery_state", "available_at"],
    )

    # CRITICAL: execution and relay state remains tenant-owned even during retries/reconciliation.
    rls_statements = (
        "ALTER TABLE campaign_strategy_revisions ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE campaign_strategy_revisions FORCE ROW LEVEL SECURITY",
        "CREATE POLICY campaign_strategy_revisions_tenant_isolation ON "
        "campaign_strategy_revisions USING "
        "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE campaign_effects ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE campaign_effects FORCE ROW LEVEL SECURITY",
        "CREATE POLICY campaign_effects_tenant_isolation ON campaign_effects USING "
        "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
    )
    for statement in rls_statements:
        op.execute(statement)

    op.execute("REVOKE UPDATE, DELETE ON campaign_strategy_revisions FROM PUBLIC")
    op.execute(
        "CREATE FUNCTION redagent_reject_campaign_strategy_mutation() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'campaign_strategy_revision_immutable'; END $$"
    )
    op.execute(
        "CREATE TRIGGER campaign_strategy_revision_immutable "
        "BEFORE UPDATE OR DELETE ON campaign_strategy_revisions "
        "FOR EACH ROW EXECUTE FUNCTION redagent_reject_campaign_strategy_mutation()"
    )


def downgrade() -> None:
    op.execute(
        "DROP TRIGGER IF EXISTS campaign_strategy_revision_immutable ON campaign_strategy_revisions"
    )
    op.execute("DROP FUNCTION IF EXISTS redagent_reject_campaign_strategy_mutation()")

    op.drop_index("ix_outbox_r123_claimable", table_name="outbox_events")
    op.drop_index("uq_outbox_r123_ordered_event", table_name="outbox_events")
    for constraint in (
        "outbox_r123_workflow_start_shape",
        "outbox_r123_reconciliation_state_closed",
        "outbox_r123_delivery_state_closed",
        "outbox_r123_attempt_count_bounded",
    ):
        op.drop_constraint(constraint, "outbox_events", type_="check")
    for column in (
        "dead_lettered_at",
        "reconciliation_state",
        "delivery_state",
        "delivered_at",
        "last_error",
        "attempt_count",
        "claim_expires_at",
        "claim_owner",
        "available_at",
        "aggregate_sequence",
        "aggregate_type",
        "schema_revision",
    ):
        op.drop_column("outbox_events", column)

    op.drop_constraint("fk_jobs_strategy_revision", "jobs", type_="foreignkey")
    op.drop_constraint("fk_campaigns_current_strategy_revision", "campaigns", type_="foreignkey")
    op.drop_table("campaign_effects")
    op.drop_table("campaign_strategy_revisions")

    for column in (
        "manifest_v2_sha256",
        "envelope_sha256",
        "effect_id",
        "node_id",
        "strategy_revision_id",
    ):
        op.drop_column("jobs", column)
    for constraint in (
        "campaigns_r123_replan_count_bounded",
        "campaigns_r123_aggregate_sequence_bounded",
    ):
        op.drop_constraint(constraint, "campaigns", type_="check")
    for column in (
        "terminal_receipt_sha256",
        "attention_reason",
        "replan_count",
        "aggregate_sequence",
        "current_strategy_revision_id",
        "intent_sha256",
    ):
        op.drop_column("campaigns", column)
