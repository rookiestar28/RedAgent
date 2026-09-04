"""Add the canonical autonomous campaign application lifecycle."""

from alembic import op
import sqlalchemy as sa


revision = "0029_autonomous_campaign_app"
down_revision = "0028_observation_replanning"
branch_labels = None
depends_on = None


_LIFECYCLE_SQL = (
    "'INTENT_CREATED','PLAN_VALIDATED','AWAITING_APPROVAL','APPROVED','ADMITTED',"
    "'EXECUTION_QUEUED','RUNNING','EVIDENCE_PENDING','VERIFIED','DENIED','EXPIRED',"
    "'REVOKED','MANUAL_REVIEW_REQUIRED','RECONCILIATION_REQUIRED','FAILED_CONTAINED',"
    "'CLEANUP_INCOMPLETE','EVIDENCE_INCOMPLETE'"
)
_TENANT_SECURITY_STATEMENTS = (
    "ALTER TABLE autonomous_campaign_applications ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE autonomous_campaign_applications FORCE ROW LEVEL SECURITY",
    "CREATE POLICY autonomous_campaign_applications_tenant_isolation ON "
    "autonomous_campaign_applications USING "
    "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
    "(tenant_id = current_setting('redagent.tenant_id', true))",
    "ALTER TABLE autonomous_campaign_application_events ENABLE ROW LEVEL SECURITY",
    "ALTER TABLE autonomous_campaign_application_events FORCE ROW LEVEL SECURITY",
    "CREATE POLICY autonomous_campaign_application_events_tenant_isolation ON "
    "autonomous_campaign_application_events USING "
    "(tenant_id = current_setting('redagent.tenant_id', true)) WITH CHECK "
    "(tenant_id = current_setting('redagent.tenant_id', true))",
)
_APPLICATION_TABLES = (
    "autonomous_campaign_application_events",
    "autonomous_campaign_applications",
)


def _owned_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def upgrade() -> None:
    op.create_table(
        "autonomous_campaign_applications",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("contract_version", sa.String(100), nullable=False),
        sa.Column("engagement_id", sa.String(64), sa.ForeignKey("engagements.id"), nullable=False),
        sa.Column("target_id", sa.String(64), sa.ForeignKey("targets.id"), nullable=False),
        sa.Column("created_by_user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False),
        sa.Column("intent_sha256", sa.String(64), nullable=False),
        sa.Column("source_binding_sha256", sa.String(64), nullable=False),
        sa.Column("mode", sa.String(32), nullable=False),
        sa.Column("lifecycle_state", sa.String(32), nullable=False),
        sa.Column("aggregate_revision", sa.BigInteger(), nullable=False),
        sa.Column("attention_reason", sa.String(100)),
        *_owned_columns(),
        sa.UniqueConstraint("tenant_id", "id", name="uq_autonomous_campaign_application_tenant_identity"),
        sa.UniqueConstraint("tenant_id", "intent_sha256", name="uq_autonomous_campaign_application_tenant_intent"),
        sa.CheckConstraint(
            "contract_version = 'redagent.autonomous-campaign-application/v1'",
            name="autonomous_campaign_application_contract_version_closed",
        ),
        sa.CheckConstraint("mode = 'plan_only'", name="autonomous_campaign_application_mode_plan_only"),
        sa.CheckConstraint(
            f"lifecycle_state IN ({_LIFECYCLE_SQL})",
            name="autonomous_campaign_application_lifecycle_closed",
        ),
        sa.CheckConstraint(
            "aggregate_revision BETWEEN 1 AND 2147483647",
            name="autonomous_campaign_application_revision_bounded",
        ),
    )
    op.create_table(
        "autonomous_campaign_application_events",
        sa.Column("id", sa.String(64), primary_key=True),
        sa.Column("application_id", sa.String(64), nullable=False),
        sa.Column("audit_event_id", sa.String(64), nullable=False),
        sa.Column("event_sequence", sa.BigInteger(), nullable=False),
        sa.Column("event_type", sa.String(100), nullable=False),
        sa.Column("previous_state", sa.String(32)),
        sa.Column("next_state", sa.String(32), nullable=False),
        sa.Column("actor_user_id", sa.String(64), nullable=False),
        sa.Column("request_sha256", sa.String(64), nullable=False),
        sa.Column("lifecycle_sha256", sa.String(64), nullable=False),
        sa.Column("event_payload", sa.JSON(), nullable=False),
        sa.Column("occurred_at", sa.DateTime(timezone=True), nullable=False),
        *_owned_columns(),
        sa.ForeignKeyConstraint(
            ("tenant_id", "application_id"),
            ("autonomous_campaign_applications.tenant_id", "autonomous_campaign_applications.id"),
            name="fk_autonomous_campaign_event_tenant_application",
        ),
        sa.ForeignKeyConstraint(
            ("audit_event_id",),
            ("audit_events.id",),
            name="fk_autonomous_campaign_event_audit",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "application_id",
            "event_sequence",
            name="uq_autonomous_campaign_application_event_sequence",
        ),
        sa.UniqueConstraint(
            "tenant_id",
            "audit_event_id",
            name="uq_autonomous_campaign_application_event_audit",
        ),
        sa.CheckConstraint(
            f"previous_state IS NULL OR previous_state IN ({_LIFECYCLE_SQL})",
            name="autonomous_campaign_application_event_previous_state_closed",
        ),
        sa.CheckConstraint(
            f"next_state IN ({_LIFECYCLE_SQL})",
            name="autonomous_campaign_application_event_next_state_closed",
        ),
        sa.CheckConstraint(
            "event_sequence BETWEEN 1 AND 2147483647",
            name="autonomous_campaign_application_event_sequence_bounded",
        ),
    )

    for statement in _TENANT_SECURITY_STATEMENTS:
        op.execute(statement)

    # CRITICAL: lifecycle history is acceptance evidence; mutation would permit coherent rewrite.
    op.execute("REVOKE UPDATE, DELETE ON autonomous_campaign_application_events FROM PUBLIC")
    op.execute(
        "CREATE FUNCTION redagent_reject_autonomous_campaign_application_event_mutation() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
        "'autonomous_campaign_application_event_immutable'; END $$"
    )
    op.execute(
        "CREATE TRIGGER autonomous_campaign_application_event_immutable BEFORE UPDATE OR DELETE "
        "ON autonomous_campaign_application_events FOR EACH ROW EXECUTE FUNCTION "
        "redagent_reject_autonomous_campaign_application_event_mutation()"
    )


def _has_persisted_application_state(connection: sa.Connection) -> bool:
    relaxed_tables: list[str] = []
    try:
        for table_name in _APPLICATION_TABLES:
            # CRITICAL: FORCE RLS can hide populated state from a non-bypass owner and permit data loss.
            connection.execute(sa.text(f"ALTER TABLE {table_name} NO FORCE ROW LEVEL SECURITY"))
            relaxed_tables.append(table_name)
        return any(
            connection.execute(sa.text(f"SELECT 1 FROM {table_name} LIMIT 1")).first() is not None
            for table_name in _APPLICATION_TABLES
        )
    finally:
        for table_name in reversed(relaxed_tables):
            connection.execute(sa.text(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY"))


def downgrade() -> None:
    connection = op.get_bind()
    # CRITICAL: never erase accepted lifecycle or audit-linked event state during rollback.
    if _has_persisted_application_state(connection):
        raise RuntimeError("autonomous_campaign_application_downgrade_requires_empty_state")
    op.execute(
        "DROP TRIGGER IF EXISTS autonomous_campaign_application_event_immutable "
        "ON autonomous_campaign_application_events"
    )
    op.execute("DROP FUNCTION IF EXISTS redagent_reject_autonomous_campaign_application_event_mutation()")
    op.drop_table("autonomous_campaign_application_events")
    op.drop_table("autonomous_campaign_applications")
