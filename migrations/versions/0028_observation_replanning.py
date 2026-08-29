"""Add append-only trusted observation and bounded replan lineage."""

from alembic import op
import sqlalchemy as sa


revision = "0028_observation_replanning"
down_revision = "0027_campaign_dag_execution"
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
        "uq_plan_admission_receipt_tenant_campaign_digest",
        "plan_admission_receipts",
        ("tenant_id", "id", "campaign_id", "receipt_sha256"),
    )
    op.create_table(
        "campaign_observation_decisions",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("campaign_id", sa.String(64), nullable=False),
        sa.Column("candidate_sha256", sa.String(64), nullable=False),
        sa.Column("decision_sha256", sa.String(64), nullable=False),
        sa.Column("outcome", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(100), nullable=False),
        sa.Column("candidate_payload", sa.JSON(), nullable=False),
        sa.Column("decision_payload", sa.JSON(), nullable=False),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=False),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "campaign_id"),
            ("campaigns.tenant_id", "campaigns.id"),
            name="fk_campaign_observation_decision_tenant_campaign",
        ),
        sa.UniqueConstraint(
            "tenant_id", "id", "campaign_id", name="uq_campaign_observation_decision_identity"
        ),
        sa.UniqueConstraint(
            "tenant_id", "campaign_id", "candidate_sha256", name="uq_campaign_observation_candidate"
        ),
        sa.UniqueConstraint("tenant_id", "decision_sha256", name="uq_campaign_observation_decision_digest"),
        sa.CheckConstraint(
            "outcome IN ('trusted','producer_denied','scope_mismatch','campaign_drift',"
            "'provenance_invalid','future','stale','expired')",
            name="campaign_observation_decision_outcome_closed",
        ),
    )
    op.create_table(
        "trusted_campaign_observations",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("decision_id", sa.String(64), nullable=False),
        sa.Column("campaign_id", sa.String(64), nullable=False),
        sa.Column("target_id", sa.String(150), nullable=False),
        sa.Column("fact_id", sa.String(150), nullable=False),
        sa.Column("producer_kind", sa.String(32), nullable=False),
        sa.Column("producer_id", sa.String(150), nullable=False),
        sa.Column("producer_version", sa.String(150), nullable=False),
        sa.Column("source_record_id", sa.String(150), nullable=False),
        sa.Column("source_execution_run_id", sa.String(64)),
        sa.Column("source_node_id", sa.String(100)),
        sa.Column("observation_sha256", sa.String(64), nullable=False),
        sa.Column("provenance_sha256", sa.String(64), nullable=False),
        sa.Column("source_result_sha256", sa.String(64), nullable=False),
        sa.Column("evidence_sha256", sa.String(64), nullable=False),
        sa.Column("trusted_payload", sa.JSON(), nullable=False),
        sa.Column("observed_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("received_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("promoted_at", sa.DateTime(timezone=True), nullable=False),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "decision_id", "campaign_id"),
            (
                "campaign_observation_decisions.tenant_id",
                "campaign_observation_decisions.id",
                "campaign_observation_decisions.campaign_id",
            ),
            name="fk_trusted_campaign_observation_tenant_decision_campaign",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "source_execution_run_id", "source_node_id"),
            (
                "campaign_execution_nodes.tenant_id",
                "campaign_execution_nodes.execution_run_id",
                "campaign_execution_nodes.node_id",
            ),
            name="fk_trusted_observation_tenant_execution_node",
        ),
        sa.CheckConstraint(
            "(source_execution_run_id IS NULL) = (source_node_id IS NULL)",
            name="trusted_observation_execution_source_complete",
        ),
        sa.UniqueConstraint("tenant_id", "observation_sha256", name="uq_trusted_campaign_observation_digest"),
    )
    op.create_table(
        "campaign_replan_proposals",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("campaign_id", sa.String(64), nullable=False),
        sa.Column("engagement_id", sa.String(64), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("proposal_sha256", sa.String(64), nullable=False),
        sa.Column("parent_revision_id", sa.String(150), nullable=False),
        sa.Column("parent_revision_sha256", sa.String(64), nullable=False),
        sa.Column("parent_plan_sha256", sa.String(64), nullable=False),
        sa.Column("parent_authority_sha256", sa.String(64), nullable=False),
        sa.Column("parent_domain_sha256", sa.String(64), nullable=False),
        sa.Column("parent_admission_receipt_id", sa.String(64), nullable=False),
        sa.Column("parent_admission_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("child_revision_id", sa.String(150), nullable=False),
        sa.Column("child_revision_sha256", sa.String(64), nullable=False),
        sa.Column("observation_history_sha256", sa.String(64), nullable=False),
        sa.Column("residual_budget_sha256", sa.String(64), nullable=False),
        sa.Column("planned_budget_sha256", sa.String(64), nullable=False),
        sa.Column("certificate_sha256", sa.String(64), nullable=False),
        sa.Column("subset_proof_sha256", sa.String(64), nullable=False),
        sa.Column("search_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("replan_sequence", sa.Integer(), nullable=False),
        sa.Column("lifecycle_epoch", sa.Integer(), nullable=False),
        sa.Column("policy_revocation_epoch", sa.Integer(), nullable=False),
        sa.Column("roe_revocation_epoch", sa.Integer(), nullable=False),
        sa.Column("kill_switch_epoch", sa.Integer(), nullable=False),
        sa.Column("proposal_payload", sa.JSON(), nullable=False),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "campaign_id"),
            ("campaigns.tenant_id", "campaigns.id"),
            name="fk_campaign_replan_proposal_tenant_campaign",
        ),
        sa.ForeignKeyConstraint(
            (
                "tenant_id",
                "parent_admission_receipt_id",
                "campaign_id",
                "parent_admission_receipt_sha256",
            ),
            (
                "plan_admission_receipts.tenant_id",
                "plan_admission_receipts.id",
                "plan_admission_receipts.campaign_id",
                "plan_admission_receipts.receipt_sha256",
            ),
            name="fk_campaign_replan_proposal_tenant_parent_admission_campaign",
        ),
        sa.UniqueConstraint(
            "tenant_id", "id", "campaign_id", "proposal_sha256", name="uq_campaign_replan_proposal_identity"
        ),
        sa.UniqueConstraint("tenant_id", "request_sha256", name="uq_campaign_replan_request"),
        sa.UniqueConstraint("tenant_id", "proposal_sha256", name="uq_campaign_replan_proposal_digest"),
        sa.UniqueConstraint(
            "tenant_id", "campaign_id", "replan_sequence", name="uq_campaign_replan_sequence"
        ),
        sa.UniqueConstraint("tenant_id", "child_revision_sha256", name="uq_campaign_replan_child_revision"),
        sa.CheckConstraint(
            "replan_sequence BETWEEN 1 AND 10000",
            name="campaign_replan_sequence_bounded",
        ),
        sa.CheckConstraint(
            "lifecycle_epoch BETWEEN 0 AND 2147483647 AND "
            "policy_revocation_epoch BETWEEN 0 AND 2147483647 AND "
            "roe_revocation_epoch BETWEEN 0 AND 2147483647 AND "
            "kill_switch_epoch BETWEEN 0 AND 2147483647",
            name="campaign_replan_epochs_bounded",
        ),
    )
    op.create_table(
        "campaign_replan_acceptances",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("proposal_id", sa.String(64), nullable=False),
        sa.Column("proposal_sha256", sa.String(64), nullable=False),
        sa.Column("campaign_id", sa.String(64), nullable=False),
        sa.Column("admission_receipt_id", sa.String(64), nullable=False),
        sa.Column("admission_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("reservation_id", sa.String(64), nullable=False),
        sa.Column("accepted_replan_sha256", sa.String(64), nullable=False),
        sa.Column("acceptance_payload", sa.JSON(), nullable=False),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "proposal_id", "campaign_id", "proposal_sha256"),
            (
                "campaign_replan_proposals.tenant_id",
                "campaign_replan_proposals.id",
                "campaign_replan_proposals.campaign_id",
                "campaign_replan_proposals.proposal_sha256",
            ),
            name="fk_campaign_replan_acceptance_tenant_proposal_campaign",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "admission_receipt_id", "campaign_id", "admission_receipt_sha256"),
            (
                "plan_admission_receipts.tenant_id",
                "plan_admission_receipts.id",
                "plan_admission_receipts.campaign_id",
                "plan_admission_receipts.receipt_sha256",
            ),
            name="fk_campaign_replan_acceptance_tenant_admission_campaign",
        ),
        sa.UniqueConstraint("tenant_id", "proposal_id", name="uq_campaign_replan_acceptance_proposal"),
        sa.UniqueConstraint(
            "tenant_id", "accepted_replan_sha256", name="uq_campaign_replan_acceptance_digest"
        ),
    )

    for table_name in (
        "campaign_observation_decisions",
        "trusted_campaign_observations",
        "campaign_replan_proposals",
        "campaign_replan_acceptances",
    ):
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {table_name}_tenant_isolation ON {table_name} USING "
            "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
            "(tenant_id = current_setting('redagent.tenant_id', true))"
        )
        # CRITICAL: trust and replan lineage is evidence; mutation would permit coherent history replacement.
        op.execute(f"REVOKE UPDATE, DELETE ON {table_name} FROM PUBLIC")
        op.execute(
            f"CREATE FUNCTION redagent_reject_{table_name}_mutation() RETURNS trigger "
            f"LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION '{table_name}_immutable'; END $$"
        )
        op.execute(
            f"CREATE TRIGGER {table_name}_immutable BEFORE UPDATE OR DELETE ON {table_name} "
            f"FOR EACH ROW EXECUTE FUNCTION redagent_reject_{table_name}_mutation()"
        )


def downgrade() -> None:
    connection = op.get_bind()
    populated = tuple(
        table_name
        for table_name in (
            "campaign_observation_decisions",
            "trusted_campaign_observations",
            "campaign_replan_proposals",
            "campaign_replan_acceptances",
        )
        if connection.execute(sa.text(f"SELECT 1 FROM {table_name} LIMIT 1")).first()
        is not None
    )
    # CRITICAL: immutable observation/replan evidence survives rollback; populated downgrade refuses.
    if populated:
        raise RuntimeError("observation_replanning_downgrade_requires_empty_lineage")
    for table_name in reversed(
        (
            "campaign_observation_decisions",
            "trusted_campaign_observations",
            "campaign_replan_proposals",
            "campaign_replan_acceptances",
        )
    ):
        op.execute(f"DROP TRIGGER IF EXISTS {table_name}_immutable ON {table_name}")
        op.execute(f"DROP FUNCTION IF EXISTS redagent_reject_{table_name}_mutation()")
    op.drop_table("campaign_replan_acceptances")
    op.drop_table("campaign_replan_proposals")
    op.drop_table("trusted_campaign_observations")
    op.drop_table("campaign_observation_decisions")
    op.drop_constraint(
        "uq_plan_admission_receipt_tenant_campaign_digest",
        "plan_admission_receipts",
        type_="unique",
    )
