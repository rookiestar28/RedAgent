"""Resolve checkout-local service coordinates for live integration tests."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

from redagent_platform.local_stack import LocalStackError
from redagent_platform.local_stack_config import is_reparse_path, load_local_stack_config


_PERSISTED_PUBLIC_COORDINATES = frozenset(
    {
        "REDAGENT_COMPOSE_PROJECT_NAME",
        "REDAGENT_BIND_HOST",
        "REDAGENT_POSTGRES_PORT",
        "REDAGENT_KEYCLOAK_PORT",
        "REDAGENT_TEMPORAL_PORT",
        "REDAGENT_RUSTFS_PORT",
    }
)
_REQUIRED_PERSISTED_COORDINATES = frozenset(
    {
        "REDAGENT_COMPOSE_PROJECT_NAME",
        "REDAGENT_BIND_HOST",
        "REDAGENT_TEMPORAL_PORT",
    }
)


def persisted_temporal_target(workspace: Path) -> str:
    """Return the validated Temporal endpoint owned by this checkout's runtime."""

    configured = load_local_stack_config(workspace, env={})
    runtime_dir = configured.state_dir / "runtime"
    runtime_env = runtime_dir / "local-stack.env"
    try:
        if (
            not runtime_dir.is_dir()
            or is_reparse_path(runtime_dir)
            or not runtime_env.is_file()
            or is_reparse_path(runtime_env)
        ):
            raise LocalStackError("integration_runtime_coordinates_invalid")
        counts: Counter[str] = Counter()
        persisted: dict[str, str] = {}
        with runtime_env.open("r", encoding="utf-8") as handle:
            for line in handle:
                name, separator, value = line.partition("=")
                if separator and name in _PERSISTED_PUBLIC_COORDINATES:
                    counts[name] += 1
                    persisted[name] = value.rstrip("\r\n")
        if (
            is_reparse_path(runtime_dir)
            or is_reparse_path(runtime_env)
            or any(count != 1 for count in counts.values())
            or any(counts[name] != 1 for name in _REQUIRED_PERSISTED_COORDINATES)
        ):
            raise LocalStackError("integration_runtime_coordinates_invalid")
    except LocalStackError:
        raise
    except (OSError, UnicodeError) as exc:
        raise LocalStackError("integration_runtime_coordinates_invalid") from exc
    # IMPORTANT: validate one owned snapshot; a second path read could fall back after a local race.
    effective = load_local_stack_config(
        workspace,
        env={
            "REDAGENT_PROFILE": configured.profile,
            "REDAGENT_STATE_DIR": str(configured.state_dir),
            **persisted,
        },
    )
    return f"{effective.bind_host}:{effective.temporal_port}"
