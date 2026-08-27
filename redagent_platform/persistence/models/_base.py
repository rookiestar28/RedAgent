"""Shared SQLAlchemy metadata for all persistence model domains."""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Integer, MetaData, String


metadata = MetaData(
    naming_convention={
        "ix": "ix_%(column_0_label)s",
        "uq": "uq_%(table_name)s_%(column_0_name)s",
        "ck": "ck_%(table_name)s_%(constraint_name)s",
        "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
        "pk": "pk_%(table_name)s",
    }
)


def _owned_columns() -> tuple[Column, ...]:
    return (
        Column("tenant_id", String(64), nullable=False, index=True),
        Column("version", Integer, nullable=False, default=1),
        Column("created_at", DateTime(timezone=True), nullable=False),
        Column("updated_at", DateTime(timezone=True), nullable=False),
    )
