"""SQLAlchemy table registrations for the enterprise identity domain."""

from __future__ import annotations

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    JSON,
    String,
    Table,
    Text,
    UniqueConstraint,
)

from ._base import _owned_columns, metadata


Table(
    "identity_providers",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("issuer", String(500), nullable=False),
    Column("client_id", String(200), nullable=False),
    Column("enabled", Boolean, nullable=False, default=True),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "issuer", "client_id"),
)

Table(
    "tenant_memberships",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("user_id", String(64), ForeignKey("users.id"), nullable=False),
    Column("status", String(32), nullable=False),
    Column("generation", Integer, nullable=False, default=1),
    Column("last_validated_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "user_id"),
)

Table(
    "role_assignments",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("user_id", String(64), ForeignKey("users.id"), nullable=False),
    Column("role", String(64), nullable=False),
    Column("active", Boolean, nullable=False, default=True),
    Column("generation", Integer, nullable=False, default=1),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "user_id", "role"),
)

Table(
    "login_transactions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("provider_id", String(64), nullable=False),
    Column("state_hash", String(64), nullable=False),
    Column("nonce_hash", String(64), nullable=False),
    Column("nonce_ciphertext", Text, nullable=False),
    Column("verifier_ciphertext", Text, nullable=False),
    Column("redirect_uri", String(600), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("consumed_at", DateTime(timezone=True)),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "state_hash"),
)

Table(
    "browser_sessions",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("provider_id", String(64), nullable=False),
    Column("user_id", String(64), ForeignKey("users.id"), nullable=False),
    Column("handle_hash", String(64), nullable=False),
    Column("csrf_hash", String(64), nullable=False),
    Column("oidc_session_id", String(200)),
    Column("last_seen_at", DateTime(timezone=True), nullable=False),
    Column("idle_expires_at", DateTime(timezone=True), nullable=False),
    Column("absolute_expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("generation", Integer, nullable=False, default=1),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "handle_hash"),
)

Table(
    "identity_replay_records",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("replay_type", String(64), nullable=False),
    Column("replay_key_hash", String(64), nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "replay_type", "replay_key_hash"),
)

Table(
    "jit_grants",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("requester_user_id", String(64), ForeignKey("users.id"), nullable=False),
    Column("approver_user_id", String(64), ForeignKey("users.id")),
    Column("role", String(64), nullable=False),
    Column("permission", String(100), nullable=False),
    Column("scope_type", String(64), nullable=False),
    Column("scope_id", String(64), nullable=False),
    Column("reason", String(500), nullable=False),
    Column("approved_at", DateTime(timezone=True)),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("break_glass", Boolean, nullable=False, default=False),
    *_owned_columns(),
)

Table(
    "break_glass_reviews",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("grant_id", String(64), ForeignKey("jit_grants.id"), nullable=False),
    Column("reviewer_user_id", String(64), ForeignKey("users.id"), nullable=False),
    Column("outcome", String(32), nullable=False),
    Column("reviewed_at", DateTime(timezone=True), nullable=False),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "grant_id"),
)

Table(
    "service_identities",
    metadata,
    Column("id", String(64), primary_key=True),
    Column("client_id", String(200), nullable=False),
    Column("name", String(200), nullable=False),
    Column("secret_hash", String(128), nullable=False),
    Column("roles", JSON, nullable=False),
    Column("expires_at", DateTime(timezone=True), nullable=False),
    Column("revoked_at", DateTime(timezone=True)),
    Column("generation", Integer, nullable=False, default=1),
    *_owned_columns(),
    UniqueConstraint("tenant_id", "client_id"),
)
