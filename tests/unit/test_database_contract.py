from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy.engine import URL

from redagent_platform.persistence.database import (
    DatabaseConfigError,
    async_engine_options,
    load_database_settings,
)


def test_database_settings_load_asyncpg_url_from_workspace_file(tmp_path: Path) -> None:
    secret_file = tmp_path / ".local" / "database-url"
    secret_file.parent.mkdir(parents=True)
    secret_file.write_text(_synthetic_url() + "\n", encoding="utf-8")

    settings = load_database_settings(
        tmp_path,
        env={"REDAGENT_DATABASE_URL_FILE": str(secret_file)},
    )

    assert settings.driver == "postgresql+asyncpg"
    assert settings.host == "127.0.0.1"
    assert settings.database == "redagent"
    assert settings.pool_size == 10
    assert settings.max_overflow == 10
    assert settings.pool_timeout_seconds == 30
    assert async_engine_options(settings) == {
        "pool_pre_ping": True,
        "pool_size": 10,
        "max_overflow": 10,
        "pool_timeout": 30,
    }
    assert "synthetic" not in repr(settings)


def test_database_pool_is_explicit_bounded_and_environment_configurable(tmp_path: Path) -> None:
    secret_file = tmp_path / "database-url"
    secret_file.write_text(_synthetic_url() + "\n", encoding="utf-8")
    settings = load_database_settings(
        tmp_path,
        env={
            "REDAGENT_DATABASE_URL_FILE": str(secret_file),
            "REDAGENT_DATABASE_POOL_SIZE": "20",
            "REDAGENT_DATABASE_MAX_OVERFLOW": "30",
            "REDAGENT_DATABASE_POOL_TIMEOUT_SECONDS": "10",
        },
    )
    assert settings.pool_size + settings.max_overflow == 50
    assert async_engine_options(settings)["pool_timeout"] == 10


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("REDAGENT_DATABASE_POOL_SIZE", "0"),
        ("REDAGENT_DATABASE_MAX_OVERFLOW", "-1"),
        ("REDAGENT_DATABASE_POOL_TIMEOUT_SECONDS", "0"),
        ("REDAGENT_DATABASE_POOL_SIZE", "not-an-int"),
    ],
)
def test_database_pool_rejects_unbounded_or_invalid_values(
    name: str,
    value: str,
    tmp_path: Path,
) -> None:
    secret_file = tmp_path / "database-url"
    secret_file.write_text(_synthetic_url() + "\n", encoding="utf-8")
    with pytest.raises(DatabaseConfigError, match="database_pool_configuration_invalid"):
        load_database_settings(
            tmp_path,
            env={"REDAGENT_DATABASE_URL_FILE": str(secret_file), name: value},
        )


def test_database_pool_rejects_total_connection_budget_above_fifty(tmp_path: Path) -> None:
    secret_file = tmp_path / "database-url"
    secret_file.write_text(_synthetic_url() + "\n", encoding="utf-8")
    with pytest.raises(DatabaseConfigError, match="database_pool_connection_budget_exceeded"):
        load_database_settings(
            tmp_path,
            env={
                "REDAGENT_DATABASE_URL_FILE": str(secret_file),
                "REDAGENT_DATABASE_POOL_SIZE": "30",
                "REDAGENT_DATABASE_MAX_OVERFLOW": "21",
            },
        )


def test_inline_database_url_is_forbidden(tmp_path: Path) -> None:
    with pytest.raises(DatabaseConfigError, match="inline_database_url_forbidden"):
        load_database_settings(
            tmp_path,
            env={"REDAGENT_DATABASE_URL": _synthetic_url()},
        )


def test_database_url_file_must_remain_inside_workspace(tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-database-url"
    outside.write_text(_synthetic_url() + "\n", encoding="utf-8")
    try:
        with pytest.raises(DatabaseConfigError, match="database_url_file_outside_workspace"):
            load_database_settings(tmp_path, env={"REDAGENT_DATABASE_URL_FILE": str(outside)})
    finally:
        outside.unlink(missing_ok=True)


@pytest.mark.parametrize(
    ("driver", "host"),
    [
        ("postgresql+asyncpg", "db.internal"),
        ("postgresql", "127.0.0.1"),
        ("sqlite+aiosqlite", None),
    ],
)
def test_local_database_requires_loopback_asyncpg(driver: str, host: str | None, tmp_path: Path) -> None:
    secret_file = tmp_path / "database-url"
    url = "sqlite+aiosqlite:///state.db" if host is None else _synthetic_url(driver=driver, host=host)
    secret_file.write_text(url + "\n", encoding="utf-8")

    with pytest.raises(DatabaseConfigError):
        load_database_settings(tmp_path, env={"REDAGENT_DATABASE_URL_FILE": str(secret_file)})


def _synthetic_url(*, driver: str = "postgresql+asyncpg", host: str = "127.0.0.1") -> str:
    return URL.create(
        driver,
        "runtime",
        "synthetic",
        host,
        55432,
        "redagent",
    ).render_as_string(hide_password=False)
