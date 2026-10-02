"""Allow immutable, explicitly approved owned execution applications."""

from alembic import op


revision = "0032_owned_execution_mode"
down_revision = "0031_autonomous_admission_start"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.drop_constraint("autonomous_campaign_application_mode_plan_only", "autonomous_campaign_applications", type_="check")
    op.create_check_constraint("autonomous_campaign_application_mode_closed", "autonomous_campaign_applications", "mode IN ('plan_only','owned_loopback_auto')")


def downgrade() -> None:
    # CRITICAL: adding the old constraint validates all rows even under FORCE RLS;
    # populated auto-mode history must refuse downgrade rather than silently lose authority.
    op.create_check_constraint("autonomous_campaign_application_mode_plan_only", "autonomous_campaign_applications", "mode = 'plan_only'")
    op.drop_constraint("autonomous_campaign_application_mode_closed", "autonomous_campaign_applications", type_="check")
