"""Add compat_094 durable enterprise identity and authorization state."""

from alembic import op
import sqlalchemy as sa


revision = "0002_r094_enterprise_identity"
down_revision = "0001_r093_control_plane"
branch_labels = None
depends_on = None


IDENTITY_TABLES = (
    "identity_providers",
    "tenant_memberships",
    "role_assignments",
    "login_transactions",
    "browser_sessions",
    "identity_replay_records",
    "jit_grants",
    "break_glass_reviews",
    "service_identities",
)


def _owned_columns() -> tuple[sa.Column, ...]:
    return (
        sa.Column("tenant_id", sa.String(64), nullable=False, index=True),
        sa.Column("version", sa.Integer(), nullable=False, server_default="1"),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )


def upgrade() -> None:
    op.create_table("identity_providers", sa.Column("id", sa.String(64), primary_key=True), sa.Column("issuer", sa.String(500), nullable=False), sa.Column("client_id", sa.String(200), nullable=False), sa.Column("enabled", sa.Boolean(), nullable=False, server_default=sa.true()), *_owned_columns(), sa.UniqueConstraint("tenant_id", "issuer", "client_id"))
    op.create_table("tenant_memberships", sa.Column("id", sa.String(64), primary_key=True), sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False), sa.Column("status", sa.String(32), nullable=False), sa.Column("generation", sa.Integer(), nullable=False, server_default="1"), sa.Column("last_validated_at", sa.DateTime(timezone=True), nullable=False), *_owned_columns(), sa.UniqueConstraint("tenant_id", "user_id"))
    op.create_table("role_assignments", sa.Column("id", sa.String(64), primary_key=True), sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False), sa.Column("role", sa.String(64), nullable=False), sa.Column("active", sa.Boolean(), nullable=False, server_default=sa.true()), sa.Column("generation", sa.Integer(), nullable=False, server_default="1"), *_owned_columns(), sa.UniqueConstraint("tenant_id", "user_id", "role"))
    op.create_table("login_transactions", sa.Column("id", sa.String(64), primary_key=True), sa.Column("provider_id", sa.String(64), nullable=False), sa.Column("state_hash", sa.String(64), nullable=False), sa.Column("nonce_hash", sa.String(64), nullable=False), sa.Column("nonce_ciphertext", sa.Text(), nullable=False), sa.Column("verifier_ciphertext", sa.Text(), nullable=False), sa.Column("redirect_uri", sa.String(600), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("consumed_at", sa.DateTime(timezone=True)), *_owned_columns(), sa.UniqueConstraint("tenant_id", "state_hash"))
    op.create_table("browser_sessions", sa.Column("id", sa.String(64), primary_key=True), sa.Column("provider_id", sa.String(64), nullable=False), sa.Column("user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False), sa.Column("handle_hash", sa.String(64), nullable=False), sa.Column("csrf_hash", sa.String(64), nullable=False), sa.Column("oidc_session_id", sa.String(200)), sa.Column("last_seen_at", sa.DateTime(timezone=True), nullable=False), sa.Column("idle_expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("absolute_expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("generation", sa.Integer(), nullable=False, server_default="1"), *_owned_columns(), sa.UniqueConstraint("tenant_id", "handle_hash"))
    op.create_table("identity_replay_records", sa.Column("id", sa.String(64), primary_key=True), sa.Column("replay_type", sa.String(64), nullable=False), sa.Column("replay_key_hash", sa.String(64), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), *_owned_columns(), sa.UniqueConstraint("tenant_id", "replay_type", "replay_key_hash"))
    op.create_table("jit_grants", sa.Column("id", sa.String(64), primary_key=True), sa.Column("requester_user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False), sa.Column("approver_user_id", sa.String(64), sa.ForeignKey("users.id")), sa.Column("role", sa.String(64), nullable=False), sa.Column("permission", sa.String(100), nullable=False), sa.Column("scope_type", sa.String(64), nullable=False), sa.Column("scope_id", sa.String(64), nullable=False), sa.Column("reason", sa.String(500), nullable=False), sa.Column("approved_at", sa.DateTime(timezone=True)), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("break_glass", sa.Boolean(), nullable=False, server_default=sa.false()), *_owned_columns())
    op.create_table("break_glass_reviews", sa.Column("id", sa.String(64), primary_key=True), sa.Column("grant_id", sa.String(64), sa.ForeignKey("jit_grants.id"), nullable=False), sa.Column("reviewer_user_id", sa.String(64), sa.ForeignKey("users.id"), nullable=False), sa.Column("outcome", sa.String(32), nullable=False), sa.Column("reviewed_at", sa.DateTime(timezone=True), nullable=False), *_owned_columns(), sa.UniqueConstraint("tenant_id", "grant_id"))
    op.create_table("service_identities", sa.Column("id", sa.String(64), primary_key=True), sa.Column("client_id", sa.String(200), nullable=False), sa.Column("name", sa.String(200), nullable=False), sa.Column("secret_hash", sa.String(128), nullable=False), sa.Column("roles", sa.JSON(), nullable=False), sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False), sa.Column("revoked_at", sa.DateTime(timezone=True)), sa.Column("generation", sa.Integer(), nullable=False, server_default="1"), *_owned_columns(), sa.UniqueConstraint("tenant_id", "client_id"))

    # CRITICAL: every identity table is FORCE RLS; the application runtime must remain a non-owner without BYPASSRLS.
    for table_name in IDENTITY_TABLES:
        op.execute(f"ALTER TABLE {table_name} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table_name} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY {table_name}_tenant_isolation ON {table_name} "
            "USING (tenant_id = current_setting('redagent.tenant_id', true)) "
            "WITH CHECK (tenant_id = current_setting('redagent.tenant_id', true))"
        )


def downgrade() -> None:
    for table_name in reversed(IDENTITY_TABLES):
        op.drop_table(table_name)
