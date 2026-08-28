"""Add atomic plan-admission receipts and campaign budget ledger."""

from alembic import op
import sqlalchemy as sa


revision = "0026_campaign_plan_admission"
down_revision = "0025_r123_closed_loop"
branch_labels = None
depends_on = None

_VECTOR_FIELDS = (
    "duration_seconds",
    "requests",
    "rate_per_minute",
    "concurrency",
    "risk_micropoints",
    "cost_microunits",
    "evidence_bytes",
    "data_bytes",
)


def _owned_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def _vector_columns() -> tuple[sa.Column, ...]:
    return tuple(sa.Column(name, sa.BigInteger(), nullable=False) for name in _VECTOR_FIELDS)


def upgrade() -> None:
    op.create_table(
        "campaign_budget_ledgers",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("campaign_id", sa.String(64), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("envelope_sha256", sa.String(64), nullable=False),
        *_vector_columns(),
        *_owned_columns(),
        sa.UniqueConstraint("tenant_id", "campaign_id", name="uq_campaign_budget_ledger_tenant_campaign"),
        sa.CheckConstraint(
            " AND ".join(f"{name} BETWEEN 0 AND 1000000000000000000" for name in _VECTOR_FIELDS),
            name="campaign_budget_vector_non_negative",
        ),
    )
    op.create_table(
        "campaign_budget_reservations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("ledger_id", sa.String(64), sa.ForeignKey("campaign_budget_ledgers.id"), nullable=False),
        sa.Column("campaign_id", sa.String(64), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("reservation_state", sa.String(32), nullable=False),
        sa.Column("lease_expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("effect_started", sa.Boolean(), nullable=False, server_default=sa.false()),
        sa.Column("reconciliation_code", sa.String(100)),
        *_vector_columns(),
        *_owned_columns(),
        sa.UniqueConstraint("tenant_id", "campaign_id", "plan_sha256", name="uq_campaign_budget_reservation_plan"),
        sa.UniqueConstraint(
            "tenant_id",
            "campaign_id",
            "idempotency_key",
            name="uq_campaign_budget_reservation_idempotency",
        ),
        sa.CheckConstraint(
            "reservation_state IN ('reserved','held','consumed','released','expired')",
            name="campaign_budget_reservation_state_closed",
        ),
        sa.CheckConstraint(
            " AND ".join(f"{name} BETWEEN 0 AND 1000000000000000000" for name in _VECTOR_FIELDS),
            name="campaign_budget_reservation_vector_non_negative",
        ),
    )
    op.create_table(
        "campaign_budget_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("ledger_id", sa.String(64), sa.ForeignKey("campaign_budget_ledgers.id"), nullable=False),
        sa.Column("reservation_id", sa.String(64), sa.ForeignKey("campaign_budget_reservations.id")),
        sa.Column("campaign_id", sa.String(64), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("previous_state", sa.String(32)),
        sa.Column("next_state", sa.String(32), nullable=False),
        sa.Column("before_residual_sha256", sa.String(64), nullable=False),
        sa.Column("after_residual_sha256", sa.String(64), nullable=False),
        sa.Column("receipt_sha256", sa.String(64)),
        *_owned_columns(),
    )
    op.create_table(
        "plan_admission_receipts",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("campaign_id", sa.String(64), sa.ForeignKey("campaigns.id"), nullable=False),
        sa.Column("reservation_id", sa.String(64), sa.ForeignKey("campaign_budget_reservations.id")),
        sa.Column("policy_decision_id", sa.String(64)),
        sa.Column("policy_boundary_receipt_id", sa.String(64)),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("receipt_sha256", sa.String(64), nullable=False),
        sa.Column("receipt_payload", sa.JSON(), nullable=False),
        *_owned_columns(),
        sa.UniqueConstraint(
            "tenant_id", "campaign_id", "idempotency_key", name="uq_plan_admission_receipt_idempotency"
        ),
        sa.UniqueConstraint("tenant_id", "request_sha256", name="uq_plan_admission_receipt_request"),
        sa.CheckConstraint("outcome IN ('admitted','denied')", name="plan_admission_outcome_closed"),
    )

    # CRITICAL: every admission record stays tenant-owned even during lock/replay paths.
    for statement in (
        "ALTER TABLE campaign_budget_ledgers ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE campaign_budget_ledgers FORCE ROW LEVEL SECURITY",
        "CREATE POLICY campaign_budget_ledgers_tenant_isolation ON campaign_budget_ledgers USING "
        "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE campaign_budget_reservations ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE campaign_budget_reservations FORCE ROW LEVEL SECURITY",
        "CREATE POLICY campaign_budget_reservations_tenant_isolation ON "
        "campaign_budget_reservations USING "
        "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE campaign_budget_events ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE campaign_budget_events FORCE ROW LEVEL SECURITY",
        "CREATE POLICY campaign_budget_events_tenant_isolation ON campaign_budget_events USING "
        "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
        "ALTER TABLE plan_admission_receipts ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE plan_admission_receipts FORCE ROW LEVEL SECURITY",
        "CREATE POLICY plan_admission_receipts_tenant_isolation ON plan_admission_receipts USING "
        "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
    ):
        op.execute(statement)

    op.execute("REVOKE UPDATE, DELETE ON campaign_budget_events FROM PUBLIC")
    op.execute("REVOKE UPDATE, DELETE ON plan_admission_receipts FROM PUBLIC")
    op.execute(
        "CREATE FUNCTION redagent_reject_campaign_budget_event_mutation() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'campaign_budget_event_immutable'; END $$"
    )
    op.execute(
        "CREATE TRIGGER campaign_budget_event_immutable BEFORE UPDATE OR DELETE ON "
        "campaign_budget_events FOR EACH ROW EXECUTE FUNCTION "
        "redagent_reject_campaign_budget_event_mutation()"
    )
    op.execute(
        "CREATE FUNCTION redagent_reject_plan_admission_receipt_mutation() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'plan_admission_receipt_immutable'; END $$"
    )
    op.execute(
        "CREATE TRIGGER plan_admission_receipt_immutable BEFORE UPDATE OR DELETE ON "
        "plan_admission_receipts FOR EACH ROW EXECUTE FUNCTION "
        "redagent_reject_plan_admission_receipt_mutation()"
    )


def downgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS plan_admission_receipt_immutable ON plan_admission_receipts")
    op.execute("DROP FUNCTION IF EXISTS redagent_reject_plan_admission_receipt_mutation()")
    op.execute("DROP TRIGGER IF EXISTS campaign_budget_event_immutable ON campaign_budget_events")
    op.execute("DROP FUNCTION IF EXISTS redagent_reject_campaign_budget_event_mutation()")
    op.drop_table("plan_admission_receipts")
    op.drop_table("campaign_budget_events")
    op.drop_table("campaign_budget_reservations")
    op.drop_table("campaign_budget_ledgers")
