from __future__ import annotations

import json
from pathlib import Path

import pytest

from redagent_platform import local_stack_config as local_stack_config_module
from redagent_platform.local_stack_config import ConfigError, load_local_stack_config


ROOT = Path(__file__).resolve().parents[2]


def test_repository_local_config_is_safe_and_digest_pinned() -> None:
    config = load_local_stack_config(ROOT, env={})

    assert config.profile == "local"
    assert config.compose_project_name == "redagent-local"
    assert config.bind_host == "127.0.0.1"
    assert config.state_dir.is_relative_to(ROOT)
    assert {image.service for image in config.images} == {"postgres", "keycloak", "temporal", "rustfs"}
    assert all("@sha256:" in image.reference for image in config.images)
    assert config.active_target_access is False
    assert config.real_scanners is False
    assert config.privileged_runners is False
    assert config.external_delivery is False


def test_local_config_accepts_bounded_compose_project_override() -> None:
    config = load_local_stack_config(
        ROOT,
        env={"REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-local"},
    )

    assert config.compose_project_name == "redagent-public-local"


@pytest.mark.parametrize(
    "name",
    ("", "RedAgent-Public", "-redagent", "redagent.public", "redagent/public", "x" * 64),
)
def test_local_config_rejects_unsafe_compose_project_override(name: str) -> None:
    with pytest.raises(ConfigError, match="compose_project_name_invalid"):
        load_local_stack_config(ROOT, env={"REDAGENT_COMPOSE_PROJECT_NAME": name})


@pytest.mark.parametrize("bind", ["0.0.0.0", "::", "::1", "192.168.1.20", "redagent.local"])
def test_local_config_rejects_non_loopback_bind(bind: str) -> None:
    with pytest.raises(ConfigError, match="local_bind_must_be_loopback"):
        load_local_stack_config(ROOT, env={"REDAGENT_BIND_HOST": bind})


def test_local_config_accepts_ipv4_loopback_alias() -> None:
    config = load_local_stack_config(ROOT, env={"REDAGENT_BIND_HOST": "127.0.0.2"})

    assert config.bind_host == "127.0.0.2"


def test_local_config_rejects_unsupported_profile() -> None:
    with pytest.raises(ConfigError, match="unsupported_profile:enterprise"):
        load_local_stack_config(ROOT, env={"REDAGENT_PROFILE": "enterprise"})


def test_local_config_rejects_duplicate_or_privileged_ports() -> None:
    with pytest.raises(ConfigError, match="service_ports_must_be_unique"):
        load_local_stack_config(
            ROOT,
            env={"REDAGENT_POSTGRES_PORT": "55432", "REDAGENT_KEYCLOAK_PORT": "55432"},
        )
    with pytest.raises(ConfigError, match="port_out_of_range"):
        load_local_stack_config(ROOT, env={"REDAGENT_POSTGRES_PORT": "543"})


def test_local_config_rejects_state_path_outside_workspace() -> None:
    outside_state_dir = ROOT.parent / f".{ROOT.name}-outside-workspace-state"
    assert not outside_state_dir.is_relative_to(ROOT)

    with pytest.raises(ConfigError, match="state_dir_outside_workspace"):
        load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": str(outside_state_dir)})


@pytest.mark.parametrize("state_dir", [".local/r118-runtime-guard"])
def test_local_config_accepts_only_approved_runtime_roots(state_dir: str) -> None:
    config = load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": state_dir})

    assert config.state_dir.is_relative_to(ROOT)


@pytest.mark.parametrize("state_dir", [".", "docs", ".locality/r118-runtime-guard", ".tmp/r118-runtime-guard"])
def test_local_config_rejects_unapproved_workspace_state_roots(state_dir: str) -> None:
    with pytest.raises(ConfigError, match="state_dir_runtime_root_invalid"):
        load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": state_dir})


def test_local_config_rejects_reparse_state_ancestor(monkeypatch: pytest.MonkeyPatch) -> None:
    original = local_stack_config_module.is_reparse_path

    def is_reparse(path: Path) -> bool:
        return path == ROOT / ".local" or original(path)

    monkeypatch.setattr(local_stack_config_module, "is_reparse_path", is_reparse)

    with pytest.raises(ConfigError, match="state_dir_reparse_point"):
        load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": ".local/r118-runtime-guard"})


@pytest.mark.parametrize("relative_path", ("config", "docs", ".local"))
def test_local_config_rejects_state_path_outside_the_ignored_local_runtime(
    relative_path: str,
) -> None:
    with pytest.raises(ConfigError, match="state_dir_runtime_root_invalid"):
        load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": relative_path})


@pytest.mark.parametrize(
    "name",
    [
        "REDAGENT_POSTGRES_PASSWORD",
        "REDAGENT_KEYCLOAK_ADMIN_TOKEN",
        "REDAGENT_CLIENT_SECRET",
    ],
)
def test_local_config_rejects_embedded_secret_environment(name: str) -> None:
    with pytest.raises(ConfigError, match=f"embedded_secret_forbidden:{name}"):
        load_local_stack_config(ROOT, env={name: "not-a-real-secret"})


@pytest.mark.parametrize(
    "flag",
    [
        "REDAGENT_ACTIVE_TARGET_ACCESS",
        "REDAGENT_REAL_SCANNERS",
        "REDAGENT_PRIVILEGED_RUNNERS",
        "REDAGENT_EXTERNAL_DELIVERY",
    ],
)
def test_r092_dangerous_capabilities_cannot_be_enabled(flag: str) -> None:
    with pytest.raises(ConfigError, match="dangerous_capability_must_remain_disabled"):
        load_local_stack_config(ROOT, env={flag: "true"})


def test_image_lock_rejects_floating_or_wrong_platform_reference(tmp_path: Path) -> None:
    lock = {
        "schema_version": "1.0",
        "platform": "linux/amd64",
        "images": [
            {
                "service": "postgres",
                "registry": "docker.io/library/postgres",
                "tag": "18.3",
                "index_digest": "sha256:" + "a" * 64,
                "platform_digest": "sha256:" + "b" * 64,
                "platform": "linux/arm64",
                "reference": "docker.io/library/postgres:18.3",
                "license_security_status": "reviewed",
            }
        ],
    }
    path = tmp_path / "images.json"
    path.write_text(json.dumps(lock), encoding="utf-8")

    with pytest.raises(ConfigError) as error:
        load_local_stack_config(ROOT, env={}, image_lock_path=path)

    message = str(error.value)
    assert "required_image_missing:keycloak" in message
    assert "image_platform_mismatch:postgres" in message
    assert "image_reference_not_digest_pinned:postgres" in message
