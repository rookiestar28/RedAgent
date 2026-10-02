"""Add canonical one-child lineage, verified peak settlement and bounded application mode."""

from alembic import op
from sqlalchemy import (
    CheckConstraint, Column, DateTime, ForeignKeyConstraint, Integer, JSON, String, UniqueConstraint,
)


revision = "0033_bounded_child_replanning"
down_revision = "0032_owned_execution_mode"
branch_labels = None
depends_on = None
_TABLES = ("campaign_child_capacity_settlements", "autonomous_campaign_child_replans")


def _owned_columns():
    return (Column("tenant_id", String(64), nullable=False, index=True),
            Column("version", Integer, nullable=False, server_default="1"),
            Column("created_at", DateTime(timezone=True), nullable=False),
            Column("updated_at", DateTime(timezone=True), nullable=False))


def upgrade() -> None:
    op.drop_constraint("autonomous_campaign_application_mode_closed", "autonomous_campaign_applications", type_="check")
    op.create_check_constraint("autonomous_campaign_application_mode_closed", "autonomous_campaign_applications", "mode IN ('plan_only','owned_loopback_auto','bounded_replan')")
    op.create_unique_constraint("uq_autonomous_campaign_preview_application_identity", "autonomous_campaign_plan_previews", ("tenant_id", "id", "application_id"))
    op.create_table(
        "campaign_child_capacity_settlements",
        Column("id", String(64), primary_key=True),
        Column("application_id", String(64), nullable=False),
        Column("parent_execution_run_id", String(64), nullable=False),
        Column("parent_run_version", Integer, nullable=False),
        Column("parent_reservation_id", String(64), nullable=False),
        Column("parent_admission_receipt_id", String(64), nullable=False),
        Column("source_provenance_sha256", String(64), nullable=False),
        Column("parent_effect_receipt_sha256", String(64), nullable=False),
        Column("latest_effect_completed_at", DateTime(timezone=True), nullable=False),
        Column("capacity_available_at", DateTime(timezone=True), nullable=False),
        Column("child_revision_sha256", String(64), nullable=False),
        Column("proposal_id", String(64), nullable=False),
        Column("proposal_sha256", String(64), nullable=False),
        Column("settlement_sha256", String(64), nullable=False),
        Column("settlement_payload", JSON, nullable=False),
        *_owned_columns(),
        ForeignKeyConstraint(
            ("tenant_id", "application_id"),
            ("autonomous_campaign_applications.tenant_id", "autonomous_campaign_applications.id"),
            name="fk_child_capacity_application",
        ),
        ForeignKeyConstraint(
            ("tenant_id", "parent_execution_run_id", "application_id"),
            ("campaign_execution_runs.tenant_id", "campaign_execution_runs.id", "campaign_execution_runs.campaign_id"),
            name="fk_child_capacity_parent_run",
        ),
        ForeignKeyConstraint(
            ("tenant_id", "parent_reservation_id", "application_id"),
            ("campaign_budget_reservations.tenant_id", "campaign_budget_reservations.id", "campaign_budget_reservations.campaign_id"),
            name="fk_child_capacity_parent_reservation",
        ),
        ForeignKeyConstraint(
            ("tenant_id", "parent_admission_receipt_id", "application_id"),
            ("plan_admission_receipts.tenant_id", "plan_admission_receipts.id", "plan_admission_receipts.campaign_id"),
            name="fk_child_capacity_parent_admission",
        ),
        ForeignKeyConstraint(
            ("tenant_id", "proposal_id", "application_id", "proposal_sha256"),
            ("campaign_replan_proposals.tenant_id", "campaign_replan_proposals.id", "campaign_replan_proposals.campaign_id", "campaign_replan_proposals.proposal_sha256"),
            name="fk_child_capacity_proposal",
        ),
        UniqueConstraint("tenant_id", "parent_reservation_id", name="uq_child_capacity_parent_reservation"),
        UniqueConstraint("tenant_id", "application_id", name="uq_child_capacity_application"),
        UniqueConstraint("tenant_id", "id", "application_id", "settlement_sha256", name="uq_child_capacity_identity"),
        CheckConstraint("parent_run_version BETWEEN 1 AND 2147483647", name="child_capacity_parent_version_bounded"),
        CheckConstraint("capacity_available_at >= latest_effect_completed_at + INTERVAL '60 seconds'", name="child_capacity_full_window_cooldown"),
    )

    op.create_table(
        "autonomous_campaign_child_replans",
        Column("id", String(64), primary_key=True),
        Column("application_id", String(64), nullable=False),
        Column("request_sha256", String(64), nullable=False),
        Column("idempotency_key", String(200), nullable=False),
        Column("parent_execution_run_id", String(64), nullable=False),
        Column("parent_run_version", Integer, nullable=False),
        Column("parent_revision_sha256", String(64), nullable=False),
        Column("parent_admission_receipt_sha256", String(64), nullable=False),
        Column("observation_history_sha256", String(64), nullable=False),
        Column("proposal_id", String(64), nullable=False),
        Column("proposal_sha256", String(64), nullable=False),
        Column("strict_subset_proof_sha256", String(64), nullable=False),
        Column("strict_subset_proof_payload", JSON, nullable=False),
        Column("settlement_id", String(64), nullable=False),
        Column("settlement_sha256", String(64), nullable=False),
        Column("child_revision_sha256", String(64), nullable=False),
        Column("lineage_sha256", String(64), nullable=False),
        Column("lineage_payload", JSON, nullable=False),
        Column("source_payload", JSON, nullable=False),
        Column("preview_id", String(64), nullable=False),
        Column("preview_sha256", String(64), nullable=False),
        Column("replan_sequence", Integer, nullable=False),
        *_owned_columns(),
        ForeignKeyConstraint(
            ("tenant_id", "application_id"),
            ("autonomous_campaign_applications.tenant_id", "autonomous_campaign_applications.id"),
            name="fk_canonical_child_application",
        ),
        ForeignKeyConstraint(
            ("tenant_id", "parent_execution_run_id", "application_id"),
            ("campaign_execution_runs.tenant_id", "campaign_execution_runs.id", "campaign_execution_runs.campaign_id"),
            name="fk_canonical_child_parent_run",
        ),
        ForeignKeyConstraint(
            ("tenant_id", "proposal_id", "application_id", "proposal_sha256"),
            ("campaign_replan_proposals.tenant_id", "campaign_replan_proposals.id", "campaign_replan_proposals.campaign_id", "campaign_replan_proposals.proposal_sha256"),
            name="fk_canonical_child_proposal",
        ),
        ForeignKeyConstraint(
            ("tenant_id", "settlement_id", "application_id", "settlement_sha256"),
            ("campaign_child_capacity_settlements.tenant_id", "campaign_child_capacity_settlements.id", "campaign_child_capacity_settlements.application_id", "campaign_child_capacity_settlements.settlement_sha256"),
            name="fk_canonical_child_settlement",
        ),
        ForeignKeyConstraint(
            ("tenant_id", "preview_id", "application_id"),
            ("autonomous_campaign_plan_previews.tenant_id", "autonomous_campaign_plan_previews.id", "autonomous_campaign_plan_previews.application_id"),
            name="fk_canonical_child_preview",
        ),
        UniqueConstraint("tenant_id", "application_id", name="uq_canonical_child_once"),
        UniqueConstraint("tenant_id", "lineage_sha256", name="uq_canonical_child_lineage"),
        CheckConstraint("replan_sequence = 1", name="canonical_child_sequence_one"),
        CheckConstraint("parent_run_version BETWEEN 1 AND 2147483647", name="canonical_child_parent_version_bounded"),
    )

    for name in _TABLES:
        op.execute(f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY")
        op.execute(f"CREATE POLICY {name}_tenant_isolation ON {name} USING (tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))")
        op.execute(f"CREATE FUNCTION redagent_reject_{name}_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '{name}_immutable'; END $$")
        op.execute(f"CREATE TRIGGER {name}_immutable BEFORE UPDATE OR DELETE ON {name} FOR EACH ROW EXECUTE FUNCTION redagent_reject_{name}_mutation()")


def _has_persisted_child_state(connection) -> bool:
    import sqlalchemy as sa
    # CRITICAL: FORCE RLS can hide another tenant from the migration owner; restore it even when refusing rollback.
    relaxed = []
    try:
        for name in _TABLES:
            connection.execute(sa.text(f"ALTER TABLE {name} NO FORCE ROW LEVEL SECURITY"))
            relaxed.append(name)
        return any(connection.execute(sa.text(f"SELECT 1 FROM {name} LIMIT 1")).first() is not None for name in _TABLES)
    finally:
        for name in reversed(relaxed):
            connection.execute(sa.text(f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY"))


def downgrade() -> None:
    if _has_persisted_child_state(op.get_bind()):
        raise RuntimeError("bounded_child_downgrade_requires_empty_lineage")
    # Validating a CHECK covers all rows, including hidden bounded-mode history.
    op.create_check_constraint("autonomous_campaign_application_mode_before_child", "autonomous_campaign_applications", "mode IN ('plan_only','owned_loopback_auto')")
    op.drop_constraint("autonomous_campaign_application_mode_closed", "autonomous_campaign_applications", type_="check")
    for name in reversed(_TABLES):
        op.execute(f"DROP TRIGGER {name}_immutable ON {name}")
        op.execute(f"DROP FUNCTION redagent_reject_{name}_mutation()")
        op.drop_table(name)
    op.drop_constraint("uq_autonomous_campaign_preview_application_identity", "autonomous_campaign_plan_previews", type_="unique")
    op.drop_constraint("autonomous_campaign_application_mode_before_child", "autonomous_campaign_applications", type_="check")
    op.create_check_constraint("autonomous_campaign_application_mode_closed", "autonomous_campaign_applications", "mode IN ('plan_only','owned_loopback_auto')")
