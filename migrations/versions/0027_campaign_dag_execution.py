"""Add durable, authority-bound campaign DAG execution state."""

from alembic import op
import sqlalchemy as sa


revision = "0027_campaign_dag_execution"
down_revision = "0026_campaign_plan_admission"
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
    op.create_unique_constraint(
        "uq_campaign_budget_reservation_tenant_campaign_identity",
        "campaign_budget_reservations",
        ["tenant_id", "id", "campaign_id"],
    )
    op.create_unique_constraint(
        "uq_plan_admission_receipt_tenant_campaign_identity",
        "plan_admission_receipts",
        ["tenant_id", "id", "campaign_id"],
    )

    op.create_table(
        "campaign_execution_runs",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("execution_id", sa.String(100), nullable=False),
        sa.Column("principal_id", sa.String(100), nullable=False),
        sa.Column("campaign_id", sa.String(64), nullable=False),
        sa.Column("admission_receipt_id", sa.String(64), nullable=False),
        sa.Column("reservation_id", sa.String(64), nullable=False),
        sa.Column("workflow_id", sa.String(100), nullable=False),
        sa.Column("workflow_run_id", sa.String(100)),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("input_payload", sa.JSON(), nullable=False),
        sa.Column("signed_authority_sha256", sa.String(64), nullable=False),
        sa.Column("authority_sha256", sa.String(64), nullable=False),
        sa.Column("domain_sha256", sa.String(64), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("certificate_sha256", sa.String(64), nullable=False),
        sa.Column("admission_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("reserved_budget_sha256", sa.String(64), nullable=False),
        sa.Column("lifecycle_epoch", sa.Integer(), nullable=False),
        sa.Column("policy_revocation_epoch", sa.Integer(), nullable=False),
        sa.Column("roe_revocation_epoch", sa.Integer(), nullable=False),
        sa.Column("kill_switch_epoch", sa.Integer(), nullable=False),
        sa.Column("run_state", sa.String(32), nullable=False),
        sa.Column("transition_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("max_transitions", sa.Integer(), nullable=False),
        sa.Column("rate_window_started_at", sa.DateTime(timezone=True)),
        sa.Column("rate_claimed_requests", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("active_concurrency", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("stop_requested", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("terminal_reason", sa.String(100)),
        sa.Column("started_at", sa.DateTime(timezone=True)),
        sa.Column("completed_at", sa.DateTime(timezone=True)),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "campaign_id"),
            ("campaigns.tenant_id", "campaigns.id"),
            name="fk_campaign_execution_run_tenant_campaign",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "admission_receipt_id", "campaign_id"),
            (
                "plan_admission_receipts.tenant_id",
                "plan_admission_receipts.id",
                "plan_admission_receipts.campaign_id",
            ),
            name="fk_campaign_execution_run_tenant_admission_campaign",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "reservation_id", "campaign_id"),
            (
                "campaign_budget_reservations.tenant_id",
                "campaign_budget_reservations.id",
                "campaign_budget_reservations.campaign_id",
            ),
            name="fk_campaign_execution_run_tenant_reservation_campaign",
        ),
        sa.UniqueConstraint(
            "tenant_id", "id", "campaign_id", name="uq_campaign_execution_run_identity"
        ),
        sa.UniqueConstraint(
            "tenant_id", "execution_id", name="uq_campaign_execution_run_execution"
        ),
        sa.UniqueConstraint(
            "tenant_id", "workflow_id", name="uq_campaign_execution_run_workflow"
        ),
        sa.UniqueConstraint(
            "tenant_id", "campaign_id", "plan_sha256", name="uq_campaign_execution_run_plan"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "campaign_id",
            "idempotency_key",
            name="uq_campaign_execution_run_idempotency",
        ),
        sa.CheckConstraint(
            "run_state IN ('start_pending','running','stopping','reconciliation_required',"
            "'completed','contained','manual_review_required','failed_before_io','failed')",
            name="campaign_execution_run_state_closed",
        ),
        sa.CheckConstraint(
            "transition_count BETWEEN 0 AND 2147483647 AND "
            "max_transitions BETWEEN 1 AND 2147483647",
            name="campaign_execution_run_transition_budget_bounded",
        ),
        sa.CheckConstraint(
            "rate_claimed_requests BETWEEN 0 AND 2147483647 AND "
            "active_concurrency BETWEEN 0 AND 2147483647",
            name="campaign_execution_run_counters_bounded",
        ),
        sa.CheckConstraint(
            "lifecycle_epoch BETWEEN 0 AND 2147483647 AND "
            "policy_revocation_epoch BETWEEN 0 AND 2147483647 AND "
            "roe_revocation_epoch BETWEEN 0 AND 2147483647 AND "
            "kill_switch_epoch BETWEEN 0 AND 2147483647",
            name="campaign_execution_run_epochs_bounded",
        ),
    )

    op.create_table(
        "campaign_execution_nodes",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("execution_run_id", sa.String(64), nullable=False),
        sa.Column("campaign_id", sa.String(64), nullable=False),
        sa.Column("node_id", sa.String(100), nullable=False),
        sa.Column("node_order", sa.Integer(), nullable=False),
        sa.Column("operator_id", sa.String(100), nullable=False),
        sa.Column("capability_id", sa.String(100), nullable=False),
        sa.Column("capability_revision", sa.String(100), nullable=False),
        sa.Column("target_id", sa.String(100), nullable=False),
        sa.Column("environment", sa.String(100), nullable=False),
        sa.Column("arguments_sha256", sa.String(64), nullable=False),
        sa.Column("incoming_edges_sha256", sa.String(64), nullable=False),
        sa.Column("join_sha256", sa.String(64), nullable=False),
        sa.Column("node_sha256", sa.String(64), nullable=False),
        sa.Column("node_state", sa.String(32), nullable=False),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "execution_run_id", "campaign_id"),
            (
                "campaign_execution_runs.tenant_id",
                "campaign_execution_runs.id",
                "campaign_execution_runs.campaign_id",
            ),
            name="fk_campaign_execution_node_tenant_run_campaign",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "execution_run_id",
            "node_id",
            name="uq_campaign_execution_node_stable",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "execution_run_id",
            "node_order",
            name="uq_campaign_execution_node_order",
        ),
        sa.CheckConstraint(
            "node_order BETWEEN 0 AND 2147483647",
            name="campaign_execution_node_order_bounded",
        ),
        sa.CheckConstraint(
            "node_state IN ('pending','ready','reserved','claimed','dispatching',"
            "'reconciliation_required','not_applied','confirmed','skipped','contained',"
            "'manual_review_required','failed')",
            name="campaign_execution_node_state_closed",
        ),
    )

    op.create_table(
        "campaign_execution_authority_observations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("execution_run_id", sa.String(64), nullable=False),
        sa.Column("campaign_id", sa.String(64), nullable=False),
        sa.Column("observation_sequence", sa.Integer(), nullable=False),
        sa.Column("authority_sha256", sa.String(64), nullable=False),
        sa.Column("lifecycle_epoch", sa.Integer(), nullable=False),
        sa.Column("policy_revocation_epoch", sa.Integer(), nullable=False),
        sa.Column("roe_revocation_epoch", sa.Integer(), nullable=False),
        sa.Column("kill_switch_epoch", sa.Integer(), nullable=False),
        sa.Column("lifecycle_state", sa.String(32), nullable=False),
        sa.Column("lifecycle_sha256", sa.String(64), nullable=False),
        sa.Column("lifecycle_payload", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("valid_until", sa.DateTime(timezone=True)),
        sa.Column("revoked_at", sa.DateTime(timezone=True)),
        sa.Column("reason_code", sa.String(100)),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "execution_run_id", "campaign_id"),
            (
                "campaign_execution_runs.tenant_id",
                "campaign_execution_runs.id",
                "campaign_execution_runs.campaign_id",
            ),
            name="fk_campaign_execution_observation_tenant_run_campaign",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "execution_run_id",
            "observation_sequence",
            name="uq_campaign_execution_authority_observation_sequence",
        ),
        sa.CheckConstraint(
            "observation_sequence BETWEEN 1 AND 2147483647",
            name="campaign_execution_authority_observation_sequence_bounded",
        ),
        sa.CheckConstraint(
            "lifecycle_epoch BETWEEN 0 AND 2147483647 AND "
            "policy_revocation_epoch BETWEEN 0 AND 2147483647 AND "
            "roe_revocation_epoch BETWEEN 0 AND 2147483647 AND "
            "kill_switch_epoch BETWEEN 0 AND 2147483647",
            name="campaign_execution_authority_observation_epochs_bounded",
        ),
        sa.CheckConstraint(
            "lifecycle_state IN ('active','suspended','revoked','expired')",
            name="campaign_execution_authority_observation_state_closed",
        ),
    )

    op.alter_column("campaign_effects", "strategy_revision_id", nullable=True)
    for column in (
        sa.Column("execution_run_id", sa.String(64)),
        sa.Column("pre_io_policy_decision_id", sa.String(64)),
        sa.Column("pre_io_policy_input_sha256", sa.String(64)),
        sa.Column("pre_io_policy_valid_until", sa.DateTime(timezone=True)),
        sa.Column("pre_io_authorized_at", sa.DateTime(timezone=True)),
    ):
        op.add_column("campaign_effects", column)
    op.create_foreign_key(
        "fk_campaign_effect_tenant_execution_run_campaign",
        "campaign_effects",
        "campaign_execution_runs",
        ["tenant_id", "execution_run_id", "campaign_id"],
        ["tenant_id", "id", "campaign_id"],
    )
    op.create_unique_constraint(
        "uq_campaign_effect_execution_node",
        "campaign_effects",
        ["tenant_id", "execution_run_id", "node_id"],
    )
    op.create_check_constraint(
        "campaign_effect_lineage_exactly_one",
        "campaign_effects",
        "(strategy_revision_id IS NOT NULL AND execution_run_id IS NULL) OR "
        "(strategy_revision_id IS NULL AND execution_run_id IS NOT NULL)",
    )

    op.add_column("jobs", sa.Column("execution_run_id", sa.String(64)))
    op.create_foreign_key(
        "fk_jobs_tenant_execution_run_campaign",
        "jobs",
        "campaign_execution_runs",
        ["tenant_id", "execution_run_id", "campaign_id"],
        ["tenant_id", "id", "campaign_id"],
    )
    op.create_unique_constraint(
        "uq_jobs_campaign_execution_node",
        "jobs",
        ["tenant_id", "execution_run_id", "node_id"],
    )
    op.create_check_constraint(
        "jobs_campaign_lineage_not_ambiguous",
        "jobs",
        "NOT (strategy_revision_id IS NOT NULL AND execution_run_id IS NOT NULL)",
    )

    # CRITICAL: execution authority remains tenant-owned across every retry and recheck.
    for statement in (
        "ALTER TABLE campaign_execution_runs ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE campaign_execution_runs FORCE ROW LEVEL SECURITY",
        "CREATE POLICY campaign_execution_runs_tenant_isolation ON campaign_execution_runs "
        "USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE campaign_execution_nodes ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE campaign_execution_nodes FORCE ROW LEVEL SECURITY",
        "CREATE POLICY campaign_execution_nodes_tenant_isolation ON campaign_execution_nodes "
        "USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE campaign_execution_authority_observations ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE campaign_execution_authority_observations FORCE ROW LEVEL SECURITY",
        "CREATE POLICY campaign_execution_authority_observations_tenant_isolation ON "
        "campaign_execution_authority_observations USING "
        "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
    ):
        op.execute(statement)

    # IMPORTANT: admitted identities are immutable; operational state remains updateable.
    op.execute(
        "CREATE FUNCTION redagent_guard_campaign_execution_run_input() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN "
        "IF ROW(OLD.tenant_id, OLD.campaign_id, OLD.admission_receipt_id, OLD.reservation_id, "
        "OLD.execution_id, OLD.principal_id, OLD.workflow_id, OLD.idempotency_key, OLD.request_sha256, "
        "OLD.input_sha256, OLD.input_payload::jsonb, OLD.signed_authority_sha256, "
        "OLD.authority_sha256, OLD.domain_sha256, "
        "OLD.plan_sha256, OLD.certificate_sha256, OLD.admission_receipt_sha256, "
        "OLD.reserved_budget_sha256, OLD.lifecycle_epoch, OLD.policy_revocation_epoch, "
        "OLD.roe_revocation_epoch, OLD.kill_switch_epoch, OLD.max_transitions) "
        "IS DISTINCT FROM ROW(NEW.tenant_id, NEW.campaign_id, NEW.admission_receipt_id, "
        "NEW.reservation_id, NEW.execution_id, NEW.principal_id, NEW.workflow_id, "
        "NEW.idempotency_key, "
        "NEW.request_sha256, NEW.input_sha256, NEW.input_payload::jsonb, "
        "NEW.signed_authority_sha256, NEW.authority_sha256, NEW.domain_sha256, "
        "NEW.plan_sha256, NEW.certificate_sha256, NEW.admission_receipt_sha256, "
        "NEW.reserved_budget_sha256, NEW.lifecycle_epoch, "
        "NEW.policy_revocation_epoch, NEW.roe_revocation_epoch, NEW.kill_switch_epoch, "
        "NEW.max_transitions) THEN "
        "RAISE EXCEPTION 'campaign_execution_run_input_immutable'; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER campaign_execution_run_input_immutable BEFORE UPDATE ON "
        "campaign_execution_runs FOR EACH ROW EXECUTE FUNCTION "
        "redagent_guard_campaign_execution_run_input()"
    )
    op.execute(
        "CREATE FUNCTION redagent_guard_campaign_execution_node_input() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN "
        "IF ROW(OLD.tenant_id, OLD.execution_run_id, OLD.campaign_id, OLD.node_id, "
        "OLD.node_order, OLD.operator_id, OLD.capability_id, OLD.capability_revision, "
        "OLD.target_id, OLD.environment, OLD.arguments_sha256, OLD.incoming_edges_sha256, "
        "OLD.join_sha256, OLD.node_sha256) IS DISTINCT FROM "
        "ROW(NEW.tenant_id, NEW.execution_run_id, NEW.campaign_id, NEW.node_id, "
        "NEW.node_order, NEW.operator_id, NEW.capability_id, NEW.capability_revision, "
        "NEW.target_id, NEW.environment, NEW.arguments_sha256, NEW.incoming_edges_sha256, "
        "NEW.join_sha256, NEW.node_sha256) THEN "
        "RAISE EXCEPTION 'campaign_execution_node_input_immutable'; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER campaign_execution_node_input_immutable BEFORE UPDATE ON "
        "campaign_execution_nodes FOR EACH ROW EXECUTE FUNCTION "
        "redagent_guard_campaign_execution_node_input()"
    )
    op.execute(
        "REVOKE UPDATE, DELETE ON campaign_execution_authority_observations FROM PUBLIC"
    )
    op.execute(
        "CREATE FUNCTION redagent_reject_campaign_execution_authority_observation_mutation() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "RAISE EXCEPTION 'campaign_execution_authority_observation_immutable'; END $$"
    )
    op.execute(
        "CREATE TRIGGER campaign_execution_authority_observation_immutable "
        "BEFORE UPDATE OR DELETE ON campaign_execution_authority_observations FOR EACH ROW "
        "EXECUTE FUNCTION redagent_reject_campaign_execution_authority_observation_mutation()"
    )


def downgrade() -> None:
    # CRITICAL: never erase execution lineage by silently downgrading live Phase 25 effects.
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM campaign_effects "
        "WHERE execution_run_id IS NOT NULL) THEN "
        "RAISE EXCEPTION 'campaign_execution_downgrade_requires_empty_execution_effects'; "
        "END IF; END $$"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS campaign_execution_authority_observation_immutable ON "
        "campaign_execution_authority_observations"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS redagent_reject_campaign_execution_authority_observation_mutation()"
    )
    op.execute(
        "DROP TRIGGER IF EXISTS campaign_execution_node_input_immutable ON campaign_execution_nodes"
    )
    op.execute("DROP FUNCTION IF EXISTS redagent_guard_campaign_execution_node_input()")
    op.execute(
        "DROP TRIGGER IF EXISTS campaign_execution_run_input_immutable ON campaign_execution_runs"
    )
    op.execute("DROP FUNCTION IF EXISTS redagent_guard_campaign_execution_run_input()")

    op.drop_constraint("jobs_campaign_lineage_not_ambiguous", "jobs", type_="check")
    op.drop_constraint("uq_jobs_campaign_execution_node", "jobs", type_="unique")
    op.drop_constraint("fk_jobs_tenant_execution_run_campaign", "jobs", type_="foreignkey")
    op.drop_column("jobs", "execution_run_id")

    op.drop_constraint(
        "campaign_effect_lineage_exactly_one", "campaign_effects", type_="check"
    )
    op.drop_constraint(
        "uq_campaign_effect_execution_node", "campaign_effects", type_="unique"
    )
    op.drop_constraint(
        "fk_campaign_effect_tenant_execution_run_campaign",
        "campaign_effects",
        type_="foreignkey",
    )
    for column in (
        "pre_io_authorized_at",
        "pre_io_policy_valid_until",
        "pre_io_policy_input_sha256",
        "pre_io_policy_decision_id",
        "execution_run_id",
    ):
        op.drop_column("campaign_effects", column)
    op.alter_column("campaign_effects", "strategy_revision_id", nullable=False)

    op.drop_table("campaign_execution_authority_observations")
    op.drop_table("campaign_execution_nodes")
    op.drop_table("campaign_execution_runs")
    op.drop_constraint(
        "uq_plan_admission_receipt_tenant_campaign_identity",
        "plan_admission_receipts",
        type_="unique",
    )
    op.drop_constraint(
        "uq_campaign_budget_reservation_tenant_campaign_identity",
        "campaign_budget_reservations",
        type_="unique",
    )
