"""Secret-safe database settings for R093."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping

from sqlalchemy.engine import URL, make_url


class DatabaseConfigError(ValueError):
    """Raised before engine creation when database configuration is unsafe."""


@dataclass(frozen=True)
class DatabaseSettings:
    url: URL = field(repr=False)
    driver: str
    host: str
    database: str
    expected_revision: str = "0029_autonomous_campaign_app"
    pool_size: int = 10
    max_overflow: int = 10
    pool_timeout_seconds: int = 30


def load_database_settings(workspace: Path, *, env: Mapping[str, str] | None = None) -> DatabaseSettings:
    values = dict(os.environ if env is None else env)
    if values.get("REDAGENT_DATABASE_URL"):
        raise DatabaseConfigError("inline_database_url_forbidden")
    raw_path = values.get("REDAGENT_DATABASE_URL_FILE", "").strip()
    if not raw_path:
        raise DatabaseConfigError("database_url_file_required")
    root = workspace.resolve()
    path = Path(raw_path)
    path = (path if path.is_absolute() else root / path).resolve()
    if not path.is_relative_to(root):
        raise DatabaseConfigError("database_url_file_outside_workspace")
    if not path.is_file():
        raise DatabaseConfigError("database_url_file_missing")
    raw_url = path.read_text(encoding="utf-8").strip()
    try:
        url = make_url(raw_url)
    except Exception as exc:
        raise DatabaseConfigError("database_url_invalid") from exc
    if url.drivername != "postgresql+asyncpg":
        raise DatabaseConfigError("database_driver_must_be_asyncpg")
    if not url.host or not url.database or not url.username or url.password is None:
        raise DatabaseConfigError("database_url_fields_required")
    try:
        if not ipaddress.ip_address(url.host).is_loopback:
            raise DatabaseConfigError("local_database_host_must_be_loopback")
    except ValueError as exc:
        raise DatabaseConfigError("local_database_host_must_be_loopback") from exc
    pool_size = _pool_integer(values, "REDAGENT_DATABASE_POOL_SIZE", default=10, minimum=1, maximum=50)
    max_overflow = _pool_integer(
        values,
        "REDAGENT_DATABASE_MAX_OVERFLOW",
        default=10,
        minimum=0,
        maximum=49,
    )
    pool_timeout = _pool_integer(
        values,
        "REDAGENT_DATABASE_POOL_TIMEOUT_SECONDS",
        default=30,
        minimum=1,
        maximum=60,
    )
    # SQLAlchemy 2.0 AsyncAdaptedQueuePool uses pool_size + max_overflow as its
    # simultaneous connection ceiling. PostgreSQL reserves administrative slots.
    # Sources: https://docs.sqlalchemy.org/en/20/core/pooling.html#sqlalchemy.pool.QueuePool.params.max_overflow
    # https://www.postgresql.org/docs/18/runtime-config-connection.html#GUC-MAX-CONNECTIONS
    if pool_size + max_overflow > 50:
        raise DatabaseConfigError("database_pool_connection_budget_exceeded")
    return DatabaseSettings(
        url=url,
        driver=url.drivername,
        host=url.host,
        database=url.database,
        pool_size=pool_size,
        max_overflow=max_overflow,
        pool_timeout_seconds=pool_timeout,
    )


def async_engine_options(settings: DatabaseSettings) -> dict[str, object]:
    return {
        "pool_pre_ping": True,
        "pool_size": settings.pool_size,
        "max_overflow": settings.max_overflow,
        "pool_timeout": settings.pool_timeout_seconds,
    }


def _pool_integer(
    values: Mapping[str, str],
    name: str,
    *,
    default: int,
    minimum: int,
    maximum: int,
) -> int:
    raw = values.get(name, str(default))
    try:
        value = int(raw)
    except (TypeError, ValueError) as exc:
        raise DatabaseConfigError("database_pool_configuration_invalid") from exc
    if isinstance(raw, bool) or not minimum <= value <= maximum:
        raise DatabaseConfigError("database_pool_configuration_invalid")
    return value
