from __future__ import annotations

from dataclasses import replace
from pathlib import Path
import base64
import json
import os
import shutil
import subprocess
import sys

import pytest

from redagent_platform import local_stack as local_stack_module
from redagent_platform.identity.config import REQUIRED_FIELDS, load_oidc_provider_config
from redagent_platform.local_stack import (
    LocalStackError,
    allocate_available_runtime_ports,
    build_compose_command,
    create_runtime_env,
    effective_runtime_config,
    parse_prerequisite_versions,
    redact_diagnostics,
    require_reset_confirmation,
    requires_port_preflight,
)
from redagent_platform.local_stack_config import load_local_stack_config
from scripts import redagent_local_stack


ROOT = Path(__file__).resolve().parents[2]


def _test_runtime_state_dir(tmp_path: Path) -> Path:
    """Keep generated test artifacts under the reviewed ignored local runtime root."""

    return ROOT / ".local" / "r118-runtime-tests" / tmp_path.parent.name / tmp_path.name


def test_start_command_is_closed_set_pull_then_wait() -> None:
    config = load_local_stack_config(ROOT, env={})
    env_file = config.state_dir / "runtime" / "local-stack.env"

    pull = build_compose_command("pull", config, env_file)
    start = build_compose_command("start", config, env_file)

    prefix = (
        "docker",
        "compose",
        "--project-name",
        "redagent-local",
        "--env-file",
        str(env_file),
        "--file",
        str(ROOT / "compose.yaml"),
    )
    assert pull == prefix + ("pull",)
    assert start == prefix + (
        "up",
        "--detach",
        "--wait",
        "--wait-timeout",
        "180",
        "--pull",
        "never",
    )


def test_compose_project_override_reaches_every_lifecycle_command() -> None:
    config = load_local_stack_config(
        ROOT,
        env={"REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-local"},
    )
    env_file = config.state_dir / "runtime" / "local-stack.env"

    for action in ("config", "pull", "start", "status", "stop", "reset"):
        command = build_compose_command(action, config, env_file)
        project_index = command.index("--project-name") + 1
        assert command[project_index] == "redagent-public-local"


def test_runtime_env_persists_compose_project_identity(tmp_path: Path) -> None:
    state_dir = _test_runtime_state_dir(tmp_path)
    config = load_local_stack_config(
        ROOT,
        env={
            "REDAGENT_STATE_DIR": str(state_dir),
            "REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-local",
        },
    )
    env_file = state_dir / "runtime" / "local-stack.env"
    try:
        assert create_runtime_env(config, env_file, secret_factory=lambda: "fixture-secret") is True
        assert "REDAGENT_COMPOSE_PROJECT_NAME=redagent-public-local" in env_file.read_text(  # pragma: allowlist secret
            encoding="utf-8"
        )
        assert effective_runtime_config(config, env_file).compose_project_name == "redagent-public-local"
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)


def test_legacy_runtime_without_project_identity_rejects_default_start(tmp_path: Path) -> None:
    state_dir = _test_runtime_state_dir(tmp_path)
    config = load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": str(state_dir)})
    env_file = state_dir / "runtime" / "local-stack.env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("REDAGENT_BIND_HOST=127.0.0.1\n", encoding="utf-8")
    try:
        with pytest.raises(LocalStackError, match="runtime_compose_project_missing"):
            effective_runtime_config(config, env_file)
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)


def test_legacy_runtime_allows_explicit_nondefault_start_migration(tmp_path: Path) -> None:
    state_dir = _test_runtime_state_dir(tmp_path)
    initial = load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": str(state_dir)})
    env_file = state_dir / "runtime" / "local-stack.env"
    generated = iter(("synthetic-postgres", "synthetic-keycloak", "synthetic-rustfs"))
    try:
        create_runtime_env(initial, env_file, secret_factory=lambda: next(generated))
        text = env_file.read_text(encoding="utf-8")
        env_file.write_text(
            "\n".join(
                line
                for line in text.splitlines()
                if not line.startswith("REDAGENT_COMPOSE_PROJECT_NAME=")
            )
            + "\n",
            encoding="utf-8",
        )
        requested = load_local_stack_config(
            ROOT,
            env={
                "REDAGENT_STATE_DIR": str(state_dir),
                "REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-migrated",
            },
        )

        effective = effective_runtime_config(requested, env_file)
        assert effective.compose_project_name == "redagent-public-migrated"
        assert create_runtime_env(effective, env_file, secret_factory=lambda: "unused") is False
        assert "REDAGENT_COMPOSE_PROJECT_NAME=redagent-public-migrated" in env_file.read_text(  # pragma: allowlist secret
            encoding="utf-8"
        )
        assert (
            effective_runtime_config(
                requested,
                env_file,
                require_persisted_project=True,
            ).compose_project_name
            == "redagent-public-migrated"
        )
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)


def test_legacy_runtime_lifecycle_rejects_even_nondefault_process_override(tmp_path: Path) -> None:
    state_dir = _test_runtime_state_dir(tmp_path)
    requested = load_local_stack_config(
        ROOT,
        env={
            "REDAGENT_STATE_DIR": str(state_dir),
            "REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-requested",
        },
    )
    env_file = state_dir / "runtime" / "local-stack.env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("REDAGENT_BIND_HOST=127.0.0.1\n", encoding="utf-8")
    try:
        with pytest.raises(LocalStackError, match="runtime_compose_project_missing"):
            effective_runtime_config(
                requested,
                env_file,
                require_persisted_project=True,
            )
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)


def test_status_stop_and_reset_commands_are_fixed_project_only() -> None:
    config = load_local_stack_config(ROOT, env={})
    env_file = config.state_dir / "runtime" / "local-stack.env"

    assert build_compose_command("status", config, env_file)[-3:] == ("ps", "--format", "json")
    assert build_compose_command("stop", config, env_file)[-3:] == ("stop", "--timeout", "30")
    assert build_compose_command("reset", config, env_file)[-3:] == (
        "down",
        "--volumes",
        "--remove-orphans",
    )
    with pytest.raises(LocalStackError, match="unsupported_lifecycle_action"):
        build_compose_command("exec", config, env_file)


def test_reset_requires_explicit_confirmation_and_contained_state() -> None:
    config = load_local_stack_config(ROOT, env={})

    with pytest.raises(LocalStackError, match="local_reset_confirmation_required"):
        require_reset_confirmation(config, confirmed=False)
    require_reset_confirmation(config, confirmed=True)

    unsafe = replace(config, state_dir=ROOT / "docs")
    with pytest.raises(LocalStackError, match="local_reset_scope_invalid"):
        require_reset_confirmation(unsafe, confirmed=True)


def test_port_preflight_runs_only_before_first_runtime_env(tmp_path: Path) -> None:
    env_file = tmp_path / "local-stack.env"

    assert requires_port_preflight(env_file) is True
    env_file.write_text("existing local stack\n", encoding="utf-8")
    assert requires_port_preflight(env_file) is False


def test_fresh_runtime_allocates_a_bounded_fallback_for_an_unavailable_default_port() -> None:
    config = load_local_stack_config(ROOT, env={})

    allocated = allocate_available_runtime_ports(
        config,
        port_available=lambda _host, port: port != config.postgres_port,
    )

    assert allocated.postgres_port == config.postgres_port + 1
    assert allocated.keycloak_port == config.keycloak_port
    assert allocated.temporal_port == config.temporal_port
    assert allocated.rustfs_port == config.rustfs_port


def test_fresh_runtime_refuses_fallback_when_operator_ports_are_explicit() -> None:
    config = load_local_stack_config(ROOT, env={})

    with pytest.raises(LocalStackError, match=r"local_runtime_port_unavailable:postgres:55432"):
        allocate_available_runtime_ports(
            config,
            port_available=lambda _host, port: port != config.postgres_port,
            allow_fallback=False,
        )


def test_fresh_runtime_port_selection_is_bounded() -> None:
    config = load_local_stack_config(ROOT, env={})

    with pytest.raises(LocalStackError, match=r"local_runtime_port_unavailable:postgres:55432"):
        allocate_available_runtime_ports(config, port_available=lambda _host, _port: False)


def test_operator_port_override_is_detected_before_fresh_port_allocation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name in (
        "REDAGENT_POSTGRES_PORT",
        "REDAGENT_KEYCLOAK_PORT",
        "REDAGENT_TEMPORAL_PORT",
        "REDAGENT_RUSTFS_PORT",
    ):
        monkeypatch.delenv(name, raising=False)
    assert redagent_local_stack._operator_port_override() is False

    monkeypatch.setenv("REDAGENT_POSTGRES_PORT", "55432")
    assert redagent_local_stack._operator_port_override() is True


def test_existing_runtime_uses_allowlisted_persisted_ports_without_loading_secrets(tmp_path: Path) -> None:
    config = load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": str(ROOT / ".local" / "test")})
    env_file = tmp_path / "local-stack.env"
    env_file.write_text(
        "REDAGENT_COMPOSE_PROJECT_NAME=redagent-local\n"  # pragma: allowlist secret
        "REDAGENT_BIND_HOST=127.0.0.1\n"
        "REDAGENT_POSTGRES_PORT=55432\n"
        "REDAGENT_KEYCLOAK_PORT=18080\n"
        "REDAGENT_TEMPORAL_PORT=57233\n"
        "REDAGENT_POSTGRES_PASSWORD=must-not-load\n",  # pragma: allowlist secret
        encoding="utf-8",
    )

    effective = effective_runtime_config(config, env_file)

    assert effective.keycloak_port == 18080
    assert effective.postgres_port == 55432
    assert effective.temporal_port == 57233


@pytest.mark.parametrize(
    ("action", "extra_args"),
    (("status", ()), ("stop", ()), ("reset", ("--confirm-local-reset",))),
)
def test_cli_legacy_lifecycle_refuses_before_compose_even_with_process_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    action: str,
    extra_args: tuple[str, ...],
) -> None:
    state_dir = _test_runtime_state_dir(tmp_path)
    config = load_local_stack_config(
        ROOT,
        env={
            "REDAGENT_STATE_DIR": str(state_dir),
            "REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-requested",
        },
    )
    env_file = state_dir / "runtime" / "local-stack.env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("REDAGENT_BIND_HOST=127.0.0.1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redagent_local_stack.py", action, *extra_args, "--json"])
    monkeypatch.setattr(redagent_local_stack, "load_local_stack_config", lambda _root: config)

    def forbidden_compose(*_args: object) -> dict[str, object]:
        raise AssertionError("compose must not run for unowned legacy runtime state")

    monkeypatch.setattr(redagent_local_stack, "_compose", forbidden_compose)
    try:
        assert redagent_local_stack.main() == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["error"] == "runtime_compose_project_missing"
        assert "REDAGENT_COMPOSE_PROJECT_NAME=" not in env_file.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)


def test_cli_legacy_default_start_refuses_before_migration_or_compose(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    state_dir = _test_runtime_state_dir(tmp_path)
    config = load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": str(state_dir)})
    env_file = state_dir / "runtime" / "local-stack.env"
    env_file.parent.mkdir(parents=True)
    env_file.write_text("REDAGENT_BIND_HOST=127.0.0.1\n", encoding="utf-8")
    monkeypatch.setattr(sys, "argv", ["redagent_local_stack.py", "start", "--json"])
    monkeypatch.setattr(redagent_local_stack, "load_local_stack_config", lambda _root: config)

    def forbidden_compose(*_args: object) -> dict[str, object]:
        raise AssertionError("compose must not run for unowned legacy runtime state")

    monkeypatch.setattr(redagent_local_stack, "_compose", forbidden_compose)
    try:
        assert redagent_local_stack.main() == 1
        payload = json.loads(capsys.readouterr().out)
        assert payload["error"] == "runtime_compose_project_missing"
        assert "REDAGENT_COMPOSE_PROJECT_NAME=" not in env_file.read_text(encoding="utf-8")
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)


def test_runtime_oidc_config_tracks_the_effective_keycloak_port(tmp_path: Path) -> None:
    state_dir = _test_runtime_state_dir(tmp_path)
    base = load_local_stack_config(
        ROOT,
        env={
            "REDAGENT_STATE_DIR": str(state_dir),
        },
    )
    config = allocate_available_runtime_ports(
        base,
        port_available=lambda _host, port: port != base.keycloak_port,
    )
    env_file = config.state_dir / "runtime" / "local-stack.env"
    try:
        create_runtime_env(
            config,
            env_file,
            secret_factory=lambda: "synthetic-runtime-value",
        )
        effective = effective_runtime_config(base, env_file)
        runtime_config = local_stack_module.create_runtime_oidc_provider_config(effective)
        provider = load_oidc_provider_config(ROOT, runtime_config, provider_id="local-keycloak")

        assert runtime_config == effective.state_dir / "runtime" / "identity-providers.json"
        assert provider.issuer == "http://127.0.0.1:58081/realms/redagent-local"
        assert provider.discovery_url == provider.issuer + "/.well-known/openid-configuration"
        rendered = runtime_config.read_text(encoding="utf-8").lower()
        assert "password" not in rendered
        assert "secret" not in rendered
        payload = json.loads(runtime_config.read_text(encoding="utf-8"))
        assert set(payload) == {"schema_version", "providers"}
        assert payload["schema_version"] == "1.0"
        assert isinstance(payload["providers"], list) and len(payload["providers"]) == 1
        assert set(payload["providers"][0]) == REQUIRED_FIELDS
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)


def test_runtime_oidc_config_rejects_a_state_directory_outside_workspace(tmp_path: Path) -> None:
    config = replace(load_local_stack_config(ROOT, env={}), state_dir=tmp_path)

    with pytest.raises(LocalStackError, match="runtime_oidc_config_outside_workspace"):
        local_stack_module.create_runtime_oidc_provider_config(config)


def test_runtime_env_rejects_a_non_runtime_target_before_secret_generation(tmp_path: Path) -> None:
    state_dir = _test_runtime_state_dir(tmp_path)
    config = load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": str(state_dir)})
    target = ROOT / "docs" / f".r118-runtime-{tmp_path.name}" / "local-stack.env"
    generated = False

    def secret_factory() -> str:
        nonlocal generated
        generated = True
        return "must-not-be-created"

    try:
        with pytest.raises(LocalStackError, match="runtime_artifact_invalid"):
            create_runtime_env(config, target, secret_factory=secret_factory)
        assert generated is False
        assert not target.exists()
    finally:
        shutil.rmtree(state_dir, ignore_errors=True)
        shutil.rmtree(target.parent, ignore_errors=True)


def test_runtime_oidc_config_rejects_a_state_directory_outside_ignored_local_runtime() -> None:
    config = replace(load_local_stack_config(ROOT, env={}), state_dir=ROOT / "config")

    with pytest.raises(LocalStackError, match="runtime_oidc_config_outside_local_runtime"):
        local_stack_module.create_runtime_oidc_provider_config(config)


def test_runtime_oidc_config_rejects_extra_template_content_before_rendering(tmp_path: Path) -> None:
    workspace = _oidc_workspace(tmp_path)
    template = workspace / "config" / "identity-providers.json"
    payload = json.loads(template.read_text(encoding="utf-8"))
    payload["session_cookie"] = "must-not-copy"
    template.write_text(json.dumps(payload), encoding="utf-8")
    config = load_local_stack_config(workspace, env={})

    with pytest.raises(LocalStackError, match="runtime_oidc_template_invalid"):
        local_stack_module.create_runtime_oidc_provider_config(config)


def test_runtime_oidc_config_rejects_secondary_provider_before_rendering(tmp_path: Path) -> None:
    workspace = _oidc_workspace(tmp_path)
    template = workspace / "config" / "identity-providers.json"
    payload = json.loads(template.read_text(encoding="utf-8"))
    secondary = dict(payload["providers"][0])
    secondary["provider_id"] = "other-provider"
    secondary["client_id"] = "token-must-not-copy"
    payload["providers"].append(secondary)
    template.write_text(json.dumps(payload), encoding="utf-8")
    config = load_local_stack_config(workspace, env={})

    with pytest.raises(LocalStackError, match="runtime_oidc_template_invalid"):
        local_stack_module.create_runtime_oidc_provider_config(config)


def test_runtime_oidc_config_rejects_a_symlinked_template_parent(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    outside_config = tmp_path / "outside-config"
    outside_config.mkdir()
    shutil.copyfile(ROOT / "config" / "local-stack-images.json", outside_config / "local-stack-images.json")
    shutil.copyfile(ROOT / "config" / "identity-providers.json", outside_config / "identity-providers.json")
    workspace.mkdir()
    try:
        os.symlink(outside_config, workspace / "config", target_is_directory=True)
    except OSError:
        pytest.skip("directory symlinks are unavailable in this test environment")
    config = load_local_stack_config(workspace, env={})

    with pytest.raises(LocalStackError, match="runtime_oidc_template_invalid"):
        local_stack_module.create_runtime_oidc_provider_config(config)


def _oidc_workspace(tmp_path: Path) -> Path:
    workspace = tmp_path / "workspace"
    config_dir = workspace / "config"
    config_dir.mkdir(parents=True)
    shutil.copyfile(ROOT / "config" / "local-stack-images.json", config_dir / "local-stack-images.json")
    shutil.copyfile(ROOT / "config" / "identity-providers.json", config_dir / "identity-providers.json")
    return workspace


def test_runtime_env_uses_generated_values_and_is_not_overwritten(tmp_path: Path) -> None:
    config = load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": str(_test_runtime_state_dir(tmp_path))})
    target = config.state_dir / "runtime" / "local-stack.env"
    pg_value = "pg-" + "generated-value"
    kc_value = "kc-" + "generated-value"
    rustfs_value = "rustfs-" + "generated-value"
    generated = iter((pg_value, kc_value, rustfs_value))

    try:
        created = create_runtime_env(config, target, secret_factory=lambda: next(generated))
        second = create_runtime_env(config, target, secret_factory=lambda: "replacement")

        assert created is True
        assert second is False
        text = target.read_text(encoding="utf-8")
        database_url_file = target.parent / "database-url"
        assert "REDAGENT_POSTGRES_IMAGE=" in text
        assert "REDAGENT_KEYCLOAK_IMAGE=" in text
        assert "REDAGENT_TEMPORAL_IMAGE=" in text
        assert "REDAGENT_TEMPORAL_TARGET=127.0.0.1:57233" in text
        assert "REDAGENT_TEMPORAL_NAMESPACE=redagent-local" in text
        assert "REDAGENT_TEMPORAL_TASK_QUEUE=redagent-r096-v1" in text  # pragma: allowlist secret
        assert "REDAGENT_TEMPORAL_CODEC_KEY_FILE=" in text
        assert "REDAGENT_TEMPORAL_CODEC_KEY=" not in text
        assert "REDAGENT_RUSTFS_IMAGE=" in text
        assert "REDAGENT_EVIDENCE_ENDPOINT=http://127.0.0.1:59000" in text
        assert "AWS_ACCESS_KEY_ID=redagent-local" in text
        assert f"AWS_SECRET_ACCESS_KEY={rustfs_value}" in text
        assert f"REDAGENT_POSTGRES_PASSWORD={pg_value}" in text
        assert f"KC_BOOTSTRAP_ADMIN_PASSWORD={kc_value}" in text
        assert "replacement" not in text
        assert database_url_file.read_text(encoding="utf-8") == (
            f"postgresql+asyncpg://redagent:{pg_value}@127.0.0.1:55432/redagent\n"
        )
        codec_key = target.parent / "temporal-codec-key"
        assert len(base64.urlsafe_b64decode(codec_key.read_text(encoding="ascii").strip())) == 32
    finally:
        shutil.rmtree(config.state_dir, ignore_errors=True)


def test_prerequisite_versions_fail_on_missing_engine_or_old_compose() -> None:
    with pytest.raises(LocalStackError, match="docker_engine_unavailable"):
        parse_prerequisite_versions("29.5.3||linux|amd64", "5.1.4")
    with pytest.raises(LocalStackError, match="docker_compose_version_unsupported"):
        parse_prerequisite_versions("29.5.3|29.5.3|linux|amd64", "2.19.9")


def test_prerequisite_versions_accept_supported_linux_amd64() -> None:
    result = parse_prerequisite_versions("29.5.3|29.5.3|linux|amd64", "5.1.4")

    assert result.engine_os == "linux"
    assert result.engine_arch == "amd64"


def test_diagnostics_redact_all_generated_secret_values() -> None:
    output = "failed password=pg-generated-value token kc-generated-value"

    redacted = redact_diagnostics(output, ("pg-generated-value", "kc-generated-value"))

    assert "pg-generated-value" not in redacted
    assert "kc-generated-value" not in redacted
    assert redacted.count("[REDACTED]") == 2


def test_post_start_host_endpoint_probe_checks_all_loopback_services() -> None:
    config = load_local_stack_config(ROOT, env={})
    attempted: list[tuple[tuple[str, int], float]] = []

    class Connection:
        def close(self) -> None:
            return None

    def connect(address: tuple[str, int], timeout: float) -> Connection:
        attempted.append((address, timeout))
        return Connection()

    endpoints = local_stack_module.verify_host_endpoints(config, connector=connect)

    assert endpoints == (
        ("postgres", "127.0.0.1", 55432),
        ("keycloak", "127.0.0.1", 58080),
        ("temporal", "127.0.0.1", 57233),
        ("rustfs", "127.0.0.1", 59000),
    )
    assert attempted == [
        (("127.0.0.1", 55432), 2.0),
        (("127.0.0.1", 58080), 2.0),
        (("127.0.0.1", 57233), 2.0),
        (("127.0.0.1", 59000), 2.0),
    ]


def test_post_start_host_endpoint_probe_fails_closed_with_service_and_port() -> None:
    config = load_local_stack_config(ROOT, env={})

    def refused(address: tuple[str, int], timeout: float) -> object:
        raise ConnectionRefusedError(address)

    with pytest.raises(LocalStackError, match=r"host_endpoint_unreachable:postgres:55432"):
        local_stack_module.verify_host_endpoints(config, connector=refused)


def test_compose_manifest_expands_with_digest_pins_and_loopback(tmp_path: Path) -> None:
    config = load_local_stack_config(ROOT, env={"REDAGENT_STATE_DIR": str(_test_runtime_state_dir(tmp_path))})
    env_file = config.state_dir / "runtime" / "local-stack.env"
    generated = iter(("synthetic-postgres-value", "synthetic-keycloak-value", "synthetic-rustfs-value"))
    try:
        create_runtime_env(config, env_file, secret_factory=lambda: next(generated))

        completed = subprocess.run(
            build_compose_command("config", config, env_file)[:-1],
            check=False,
            capture_output=True,
            text=True,
        )

        assert completed.returncode == 0, completed.stderr
        assert completed.stdout.count("host_ip: 127.0.0.1") == 4
        assert 'published: "55432"' in completed.stdout
        assert 'published: "58080"' in completed.stdout
        assert 'published: "59000"' in completed.stdout
        assert 'published: "57233"' in completed.stdout
        assert "@sha256:" in completed.stdout
        assert "privileged: true" not in completed.stdout
        assert "internal: true" not in completed.stdout
        assert "driver: bridge" in completed.stdout
    finally:
        shutil.rmtree(config.state_dir, ignore_errors=True)


def test_compose_manifest_scopes_volume_names_to_project_override(tmp_path: Path) -> None:
    config = load_local_stack_config(
        ROOT,
        env={
            "REDAGENT_STATE_DIR": str(_test_runtime_state_dir(tmp_path)),
            "REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-test",
        },
    )
    env_file = config.state_dir / "runtime" / "local-stack.env"
    generated = iter(("synthetic-postgres-value", "synthetic-keycloak-value", "synthetic-rustfs-value"))
    try:
        create_runtime_env(config, env_file, secret_factory=lambda: next(generated))
        completed = subprocess.run(
            build_compose_command("config", config, env_file)[:-1],
            check=False,
            capture_output=True,
            text=True,
        )

        assert completed.returncode == 0, completed.stderr
        for service in ("postgres", "keycloak", "temporal", "rustfs"):
            assert f"name: redagent-public-test-{service}-data" in completed.stdout
            assert f"name: redagent-local-{service}-data" not in completed.stdout
    finally:
        shutil.rmtree(config.state_dir, ignore_errors=True)


def test_synthetic_realm_has_no_users_passwords_or_client_secrets() -> None:
    realm = json.loads((ROOT / "config" / "keycloak" / "redagent-local-realm.json").read_text(encoding="utf-8"))

    assert realm["realm"] == "redagent-local"
    assert realm["users"] == []
    assert realm["clients"][0]["publicClient"] is True
    assert "credentials" not in realm
    assert "secret" not in realm["clients"][0]


def test_cli_config_succeeds_without_docker_engine_or_secret_creation() -> None:
    env_file = ROOT / ".local" / "redagent" / "runtime" / "local-stack.env"
    before = env_file.read_bytes() if env_file.exists() else None
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "redagent_local_stack.py"), "config", "--json"],
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    payload = json.loads(completed.stdout)
    assert payload["ok"] is True
    assert payload["config"]["bind_host"] == "127.0.0.1"
    after = env_file.read_bytes() if env_file.exists() else None
    assert after == before


def test_cli_start_generates_runtime_identity_config_before_any_compose_action(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_local_stack_config(ROOT, env={})
    generated_config = config.state_dir / "runtime" / "identity-providers.json"
    events: list[str] = []
    monkeypatch.setattr(sys, "argv", ["redagent_local_stack.py", "start", "--json"])
    monkeypatch.setattr(redagent_local_stack, "load_local_stack_config", lambda _root: config)
    monkeypatch.setattr(
        redagent_local_stack,
        "effective_runtime_config",
        lambda current, _env, **_kwargs: current,
    )
    monkeypatch.setattr(redagent_local_stack, "_doctor", lambda: events.append("doctor") or {})
    monkeypatch.setattr(redagent_local_stack, "requires_port_preflight", lambda _env: False)
    monkeypatch.setattr(redagent_local_stack, "create_runtime_env", lambda *_args, **_kwargs: events.append("env") or False)
    monkeypatch.setattr(
        redagent_local_stack,
        "create_runtime_oidc_provider_config",
        lambda _config: events.append("oidc") or generated_config,
    )
    monkeypatch.setattr(
        redagent_local_stack,
        "_compose",
        lambda action, *_args: events.append(f"compose:{action}") or {"action": action},
    )
    monkeypatch.setattr(
        redagent_local_stack,
        "verify_host_endpoints",
        lambda _config: events.append("endpoints") or (),
    )
    monkeypatch.setattr(
        redagent_local_stack,
        "_provision_evidence_bucket",
        lambda _env: events.append("bucket") or "redagent-evidence",
    )

    assert redagent_local_stack.main() == 0
    assert events == [
        "doctor",
        "env",
        "oidc",
        "compose:config",
        "compose:pull",
        "compose:start",
        "endpoints",
        "bucket",
    ]


def test_cli_start_refuses_before_compose_when_runtime_identity_generation_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = load_local_stack_config(ROOT, env={})
    compose_called = False
    monkeypatch.setattr(sys, "argv", ["redagent_local_stack.py", "start", "--json"])
    monkeypatch.setattr(redagent_local_stack, "load_local_stack_config", lambda _root: config)
    monkeypatch.setattr(
        redagent_local_stack,
        "effective_runtime_config",
        lambda current, _env, **_kwargs: current,
    )
    monkeypatch.setattr(redagent_local_stack, "_doctor", lambda: {})
    monkeypatch.setattr(redagent_local_stack, "requires_port_preflight", lambda _env: False)
    monkeypatch.setattr(redagent_local_stack, "create_runtime_env", lambda *_args, **_kwargs: False)
    monkeypatch.setattr(
        redagent_local_stack,
        "create_runtime_oidc_provider_config",
        lambda _config: (_ for _ in ()).throw(LocalStackError("runtime_oidc_template_invalid")),
    )

    def forbidden_compose(*_args: object) -> dict[str, object]:
        nonlocal compose_called
        compose_called = True
        return {}

    monkeypatch.setattr(redagent_local_stack, "_compose", forbidden_compose)

    assert redagent_local_stack.main() == 1
    assert compose_called is False


def test_full_gate_scripts_use_leased_exact_python_lock_and_node_lock() -> None:
    registry = json.loads(
        (ROOT / "config/validation/r118-stage-registry.json").read_text(encoding="utf-8")
    )["stages"]
    commands = {stage["id"]: stage["argv"] for stage in registry}
    installer = (ROOT / "scripts" / "install_validation_dependencies.py").read_text(
        encoding="utf-8"
    )
    for script_name in ("run_full_tests_windows.ps1", "run_full_tests_linux.sh"):
        text = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
        assert "install_validation_dependencies.py" not in text
        assert "scripts/run_validation_gate.py" in text
        assert "npm install\n" not in text
    assert "requirements-runtime.lock" in installer
    assert "requirements-dev.lock" in installer
    assert commands["frontend-install"] == ["npm", "ci", "--audit=false"]
    assert commands["backend-tests"] == ["python", "-m", "pytest", "tests"]
    assert commands["local-stack"] == ["python", "scripts/redagent_local_stack.py", "start"]
    assert commands["openbao-conformance"] == [
        "python",
        "scripts/openbao_conformance.py",
        "provision",
    ]
    assert commands["opa-provision"] == ["python", "scripts/opa_conformance.py", "provision"]
