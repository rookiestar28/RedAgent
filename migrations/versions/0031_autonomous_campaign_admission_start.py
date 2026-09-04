"""Add the atomic autonomous campaign admission/start bridge."""

from alembic import op
import sqlalchemy as sa


revision = "0031_autonomous_admission_start"
down_revision = "0030_autonomous_plan_approval"
branch_labels = None
depends_on = None


_TABLE = "autonomous_campaign_execution_starts"
_EVENT_TYPE = "autonomous_campaign.start_bridge.requested.v1"


def _owned_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def upgrade() -> None:
    op.drop_constraint(
        op.f("ck_outbox_events_outbox_r123_reconciliation_state_closed"),
        "outbox_events",
        type_="check",
    )
    op.create_check_constraint(
        "outbox_r123_reconciliation_state_closed",
        "outbox_events",
        "reconciliation_state IN "
        "('none','duplicate_confirmed','manual_review_required','start_outcome_unknown')",
    )
    op.create_table(
        _TABLE,
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("application_id", sa.String(64), nullable=False),
        sa.Column("approved_revision", sa.BigInteger(), nullable=False),
        sa.Column("admitted_revision", sa.BigInteger(), nullable=False),
        sa.Column("preview_id", sa.String(64), nullable=False),
        sa.Column("approval_receipt_id", sa.String(64), nullable=False),
        sa.Column("approval_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("admission_receipt_id", sa.String(64), nullable=False),
        sa.Column("admission_receipt_sha256", sa.String(64), nullable=False),
        sa.Column("reservation_id", sa.String(64), nullable=False),
        sa.Column("execution_run_id", sa.String(64), nullable=False),
        sa.Column("workflow_id", sa.String(100), nullable=False),
        sa.Column("workflow_run_id", sa.String(100)),
        sa.Column("idempotency_key", sa.String(200), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("workflow_request_sha256", sa.String(64), nullable=False),
        sa.Column("workflow_input_payload", sa.JSON(), nullable=False),
        sa.Column("input_sha256", sa.String(64), nullable=False),
        sa.Column("signed_authority_sha256", sa.String(64), nullable=False),
        sa.Column("authority_sha256", sa.String(64), nullable=False),
        sa.Column("domain_sha256", sa.String(64), nullable=False),
        sa.Column("plan_sha256", sa.String(64), nullable=False),
        sa.Column("certificate_sha256", sa.String(64), nullable=False),
        sa.Column("reserved_budget_sha256", sa.String(64), nullable=False),
        sa.Column("policy_revision", sa.String(150), nullable=False),
        sa.Column("policy_bundle_sha256", sa.String(64), nullable=False),
        sa.Column("lifecycle_epoch", sa.BigInteger(), nullable=False),
        sa.Column("policy_revocation_epoch", sa.BigInteger(), nullable=False),
        sa.Column("roe_revocation_epoch", sa.BigInteger(), nullable=False),
        sa.Column("kill_switch_epoch", sa.BigInteger(), nullable=False),
        sa.Column("outbox_event_id", sa.String(64), nullable=False),
        sa.Column("outbox_event_type", sa.String(100), nullable=False),
        sa.Column("application_audit_id", sa.String(64), nullable=False),
        sa.Column("application_event_id", sa.String(64), nullable=False),
        sa.Column("start_state", sa.String(32), nullable=False),
        sa.Column("reason_code", sa.String(100)),
        sa.Column("issued_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "application_id"),
            (
                "autonomous_campaign_applications.tenant_id",
                "autonomous_campaign_applications.id",
            ),
            name="fk_autonomous_campaign_start_tenant_application",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "preview_id"),
            (
                "autonomous_campaign_plan_previews.tenant_id",
                "autonomous_campaign_plan_previews.id",
            ),
            name="fk_autonomous_campaign_start_tenant_preview",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "approval_receipt_id"),
            (
                "autonomous_campaign_plan_approval_receipts.tenant_id",
                "autonomous_campaign_plan_approval_receipts.id",
            ),
            name="fk_autonomous_campaign_start_tenant_approval",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "admission_receipt_id", "application_id"),
            (
                "plan_admission_receipts.tenant_id",
                "plan_admission_receipts.id",
                "plan_admission_receipts.campaign_id",
            ),
            name="fk_autonomous_campaign_start_tenant_admission",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "reservation_id", "application_id"),
            (
                "campaign_budget_reservations.tenant_id",
                "campaign_budget_reservations.id",
                "campaign_budget_reservations.campaign_id",
            ),
            name="fk_autonomous_campaign_start_tenant_reservation",
        ),
        sa.ForeignKeyConstraint(
            ("tenant_id", "execution_run_id", "application_id"),
            (
                "campaign_execution_runs.tenant_id",
                "campaign_execution_runs.id",
                "campaign_execution_runs.campaign_id",
            ),
            name="fk_autonomous_campaign_start_tenant_execution",
        ),
        sa.ForeignKeyConstraint(
            ("application_audit_id",),
            ("audit_events.id",),
            name="fk_autonomous_campaign_start_application_audit",
        ),
        sa.ForeignKeyConstraint(
            ("application_event_id",),
            ("autonomous_campaign_application_events.id",),
            name="fk_autonomous_campaign_start_application_event",
        ),
        sa.UniqueConstraint(
            "tenant_id", "id", name="uq_autonomous_campaign_start_tenant_identity"
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "application_id",
            "approval_receipt_id",
            name="uq_autonomous_campaign_start_approval",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "application_id",
            "idempotency_key",
            name="uq_autonomous_campaign_start_idempotency",
        ),
        sa.UniqueConstraint(
            "tenant_id", "execution_run_id", name="uq_autonomous_campaign_start_execution"
        ),
        sa.UniqueConstraint(
            "tenant_id", "workflow_id", name="uq_autonomous_campaign_start_workflow"
        ),
        sa.UniqueConstraint(
            "tenant_id", "outbox_event_id", name="uq_autonomous_campaign_start_outbox"
        ),
        sa.CheckConstraint(
            "approved_revision BETWEEN 1 AND 2147483647 AND "
            "admitted_revision = approved_revision + 1",
            name="autonomous_campaign_start_revision_bounded",
        ),
        sa.CheckConstraint(
            f"outbox_event_type = '{_EVENT_TYPE}'",
            name="autonomous_campaign_start_event_type_closed",
        ),
        sa.CheckConstraint(
            "start_state IN ('start_pending','execution_queued','reconciliation_required',"
            "'manual_review_required','failed_before_io')",
            name="autonomous_campaign_start_state_closed",
        ),
        sa.CheckConstraint(
            "expires_at > issued_at",
            name="autonomous_campaign_start_expiry_ordered",
        ),
        sa.CheckConstraint(
            "lifecycle_epoch BETWEEN 0 AND 2147483647 AND "
            "policy_revocation_epoch BETWEEN 0 AND 2147483647 AND "
            "roe_revocation_epoch BETWEEN 0 AND 2147483647 AND "
            "kill_switch_epoch BETWEEN 0 AND 2147483647",
            name="autonomous_campaign_start_epochs_bounded",
        ),
    )

    for statement in (
        "ALTER TABLE autonomous_campaign_execution_starts ENABLE ROW LEVEL SECURITY",
        "ALTER TABLE autonomous_campaign_execution_starts FORCE ROW LEVEL SECURITY",
        "CREATE POLICY autonomous_campaign_execution_starts_tenant_isolation ON "
        "autonomous_campaign_execution_starts USING "
        "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
        "(tenant_id = current_setting('redagent.tenant_id', true))",
        "REVOKE DELETE ON autonomous_campaign_execution_starts FROM PUBLIC",
    ):
        op.execute(statement)

    # CRITICAL: the exact approval/admission/execution/start identity is immutable after charge.
    op.execute(
        "CREATE FUNCTION redagent_guard_autonomous_campaign_execution_start_input() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN "
        "IF TG_OP = 'DELETE' THEN RAISE EXCEPTION "
        "'autonomous_campaign_execution_start_input_immutable'; END IF; "
        "IF ROW(OLD.tenant_id, OLD.application_id, OLD.approved_revision, "
        "OLD.admitted_revision, OLD.preview_id, OLD.approval_receipt_id, "
        "OLD.approval_receipt_sha256, OLD.admission_receipt_id, "
        "OLD.admission_receipt_sha256, OLD.reservation_id, OLD.execution_run_id, "
        "OLD.workflow_id, OLD.idempotency_key, OLD.request_sha256, "
        "OLD.workflow_request_sha256, OLD.workflow_input_payload::jsonb, "
        "OLD.input_sha256, OLD.signed_authority_sha256, OLD.authority_sha256, "
        "OLD.domain_sha256, OLD.plan_sha256, OLD.certificate_sha256, "
        "OLD.reserved_budget_sha256, OLD.policy_revision, OLD.policy_bundle_sha256, "
        "OLD.lifecycle_epoch, OLD.policy_revocation_epoch, OLD.roe_revocation_epoch, "
        "OLD.kill_switch_epoch, OLD.outbox_event_id, OLD.outbox_event_type, "
        "OLD.application_audit_id, OLD.application_event_id, "
        "OLD.issued_at, OLD.expires_at) IS DISTINCT FROM "
        "ROW(NEW.tenant_id, NEW.application_id, NEW.approved_revision, "
        "NEW.admitted_revision, NEW.preview_id, NEW.approval_receipt_id, "
        "NEW.approval_receipt_sha256, NEW.admission_receipt_id, "
        "NEW.admission_receipt_sha256, NEW.reservation_id, NEW.execution_run_id, "
        "NEW.workflow_id, NEW.idempotency_key, NEW.request_sha256, "
        "NEW.workflow_request_sha256, NEW.workflow_input_payload::jsonb, "
        "NEW.input_sha256, NEW.signed_authority_sha256, NEW.authority_sha256, "
        "NEW.domain_sha256, NEW.plan_sha256, NEW.certificate_sha256, "
        "NEW.reserved_budget_sha256, NEW.policy_revision, NEW.policy_bundle_sha256, "
        "NEW.lifecycle_epoch, NEW.policy_revocation_epoch, NEW.roe_revocation_epoch, "
        "NEW.kill_switch_epoch, NEW.outbox_event_id, NEW.outbox_event_type, "
        "NEW.application_audit_id, NEW.application_event_id, "
        "NEW.issued_at, NEW.expires_at) THEN RAISE EXCEPTION "
        "'autonomous_campaign_execution_start_input_immutable'; END IF; "
        "RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER autonomous_campaign_execution_start_input_immutable "
        "BEFORE UPDATE OR DELETE ON autonomous_campaign_execution_starts FOR EACH ROW "
        "EXECUTE FUNCTION redagent_guard_autonomous_campaign_execution_start_input()"
    )


def _has_persisted_admission_start_state(connection: sa.Connection) -> bool:
    try:
        # CRITICAL: FORCE RLS must not hide charged admission/start lineage during downgrade.
        connection.execute(
            sa.text(
                "ALTER TABLE autonomous_campaign_execution_starts "
                "NO FORCE ROW LEVEL SECURITY"
            )
        )
        return connection.execute(sa.text(f"SELECT 1 FROM {_TABLE} LIMIT 1")).first() is not None
    finally:
        connection.execute(
            sa.text(
                "ALTER TABLE autonomous_campaign_execution_starts "
                "FORCE ROW LEVEL SECURITY"
            )
        )


def downgrade() -> None:
    connection = op.get_bind()
    if _has_persisted_admission_start_state(connection):
        raise RuntimeError("autonomous_campaign_admission_start_downgrade_requires_empty_state")
    op.execute(
        "DROP TRIGGER IF EXISTS autonomous_campaign_execution_start_input_immutable "
        "ON autonomous_campaign_execution_starts"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS redagent_guard_autonomous_campaign_execution_start_input()"
    )
    op.drop_table(_TABLE)
    op.drop_constraint(
        op.f("ck_outbox_events_outbox_r123_reconciliation_state_closed"),
        "outbox_events",
        type_="check",
    )
    op.create_check_constraint(
        "outbox_r123_reconciliation_state_closed",
        "outbox_events",
        "reconciliation_state IN "
        "('none','duplicate_confirmed','manual_review_required')",
    )
