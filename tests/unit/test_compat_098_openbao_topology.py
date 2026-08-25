from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest
import yaml

from scripts import openbao_conformance


ROOT = Path(__file__).resolve().parents[2]


def test_openbao_direct_script_entrypoint_has_no_package_import_trap() -> None:
    completed = subprocess.run(
        (str(Path(openbao_conformance.sys.executable)), "scripts/openbao_conformance.py", "--help"),
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )

    assert completed.returncode == 0, completed.stderr


def test_openbao_conformance_image_is_exact_digest_pinned_and_local_only() -> None:
    lock = json.loads((ROOT / "config" / "openbao-conformance-image.json").read_text(encoding="utf-8"))
    assert lock["tag"] == "2.5.5"
    assert lock["index_digest"] == "sha256:6150c4a6b62067db6141c8da7a6a6b5763f4f47c315343d0c848b40fecdfd452"
    assert lock["platform_digest"] == "sha256:e59b4c73cfce6875363d25548222819433c6ce0af9c6d3ec9ede220e905723f9"
    assert lock["reference"] == f"ghcr.io/openbao/openbao:2.5.5@{lock['index_digest']}"
    assert lock["purpose"] == "local-conformance-only"
    assert lock["production_qualified"] is False


def test_openbao_conformance_compose_is_loopback_persistent_and_non_dev() -> None:
    compose = (ROOT / "compose.openbao-conformance.yaml").read_text(encoding="utf-8")
    stack = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    config = (ROOT / "config" / "openbao" / "openbao-local.hcl").read_text(encoding="utf-8")
    assert "REDAGENT_OPENBAO_IMAGE" in compose
    assert "127.0.0.1" in compose and "58200:8200" in compose
    assert 'command: ["server"]' in compose
    assert "-dev" not in compose.lower()
    assert "read_only: true" in compose
    assert "cap_drop:" in compose and "no-new-privileges:true" in compose
    assert "redagent_openbao_data" in compose and "redagent_openbao_audit" in compose
    assert "host.docker.internal" not in compose
    assert stack["networks"]["redagent_openbao_db"]["internal"] is True
    assert "redagent_openbao_db" in stack["services"]["postgres"]["networks"]
    for service in ("keycloak", "temporal", "rustfs"):
        assert "redagent_openbao_db" not in stack["services"][service]["networks"]
    assert 'storage "file"' in config
    assert 'tls_disable = true' in config
    assert "disable_mlock = true" in config
    assert 'audit "file" "audit-file-1"' in config
    assert 'audit "file" "audit-file-2"' in config
    assert "unsafe_allow_api_audit_creation" not in config
    assert not compose.startswith("name:")
    assert "name: redagent-openbao-conformance" not in compose


def test_openbao_compose_uses_workspace_project_and_strips_ambient_compose_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "ambient-hijack")
    monkeypatch.setenv("compose_file", "outside-compose.yaml")
    monkeypatch.setenv("COMPOSE_PROFILES", "unsafe-profile")
    monkeypatch.setattr(
        openbao_conformance.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs))
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    openbao_conformance._compose("down", "--volumes")

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:4] == ["docker", "--context", "default", "compose"]
    assert command[command.index("--project-directory") + 1] == str(ROOT.resolve())
    assert command[command.index("--project-name") + 1] == openbao_conformance._compose_project_name()
    assert command[command.index("--file") + 1] == str(openbao_conformance.COMPOSE)
    assert "ambient-hijack" not in kwargs["env"].values()
    assert not any(key.upper().startswith("COMPOSE_") for key in kwargs["env"])


def test_openbao_project_name_is_deterministic_and_workspace_unique(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    first = openbao_conformance._compose_project_name()
    assert first == openbao_conformance._compose_project_name()

    other_workspace = tmp_path / "other-workspace"
    other_workspace.mkdir()
    monkeypatch.setattr(openbao_conformance, "ROOT", other_workspace)

    assert first != openbao_conformance._compose_project_name()
    assert first.startswith("redagent-openbao-")
    assert len(first) == len("redagent-openbao-") + 16


@pytest.mark.parametrize("value", ("", "UPPERCASE", "../other", "project.with.dot"))
def test_openbao_rejects_invalid_persisted_local_stack_project(value: str) -> None:
    with pytest.raises(openbao_conformance.ConformanceError, match="openbao_local_stack_project_invalid"):
        openbao_conformance._verified_local_stack_network({"REDAGENT_COMPOSE_PROJECT_NAME": value})


def test_openbao_accepts_only_the_exact_database_bridge_network_labels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []

    def docker(*arguments: str) -> str:
        commands.append(arguments)
        return json.dumps(
            {
                "com.docker.compose.project": "redagent-public-gate-default",
                "com.docker.compose.network": "redagent_openbao_db",
            }
        )

    monkeypatch.setattr(openbao_conformance, "_docker", docker)

    network = openbao_conformance._verified_local_stack_network(
        {"REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-gate-default"}
    )

    assert network == "redagent-public-gate-default_redagent_openbao_db"
    assert commands == [
        (
            "network",
            "inspect",
            "--format",
            "{{json .Labels}}",
            "redagent-public-gate-default_redagent_openbao_db",
        )
    ]


@pytest.mark.parametrize(
    "labels",
    (
        {},
        {"com.docker.compose.project": "other", "com.docker.compose.network": "redagent_openbao_db"},
        {
            "com.docker.compose.project": "redagent-public-gate-default",
            "com.docker.compose.network": "other",
        },
    ),
)
def test_openbao_rejects_mismatched_local_stack_network_labels(
    monkeypatch: pytest.MonkeyPatch,
    labels: dict[str, str],
) -> None:
    monkeypatch.setattr(openbao_conformance, "_docker", lambda *_args: json.dumps(labels))

    with pytest.raises(openbao_conformance.ConformanceError, match="openbao_local_stack_network_invalid"):
        openbao_conformance._verified_local_stack_network(
            {"REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-gate-default"}
        )


def test_openbao_attaches_only_the_exact_container_to_the_verified_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    container_id = "a" * 64
    docker_calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(
        openbao_conformance,
        "_verified_local_stack_network",
        lambda _values: "redagent-public-gate-default_redagent_openbao_db",
    )
    monkeypatch.setattr(
        openbao_conformance,
        "_compose",
        lambda *arguments: f"{container_id}\n" if arguments == ("ps", "--quiet", "openbao") else "",
    )
    monkeypatch.setattr(
        openbao_conformance,
        "_docker",
        lambda *arguments: docker_calls.append(arguments) or "",
    )

    openbao_conformance._attach_to_local_stack_network(
        {"REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-gate-default"}
    )

    assert docker_calls == [
        ("network", "connect", "redagent-public-gate-default_redagent_openbao_db", container_id)
    ]


@pytest.mark.parametrize("container_ids", ("", "short", f"{'a' * 64}\n{'b' * 64}\n"))
def test_openbao_rejects_missing_ambiguous_or_invalid_container_identity(
    monkeypatch: pytest.MonkeyPatch,
    container_ids: str,
) -> None:
    monkeypatch.setattr(
        openbao_conformance,
        "_verified_local_stack_network",
        lambda _values: "redagent-public-gate-default_redagent_openbao_db",
    )
    monkeypatch.setattr(openbao_conformance, "_compose", lambda *_args: container_ids)

    with pytest.raises(openbao_conformance.ConformanceError, match="openbao_container_identity_invalid"):
        openbao_conformance._attach_to_local_stack_network(
            {"REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-gate-default"}
        )


def test_openbao_provision_uses_the_verified_local_stack_network(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "openbao"
    health = iter(
        (
            {"initialized": False, "sealed": True, "version": "fixture"},
            {"initialized": True, "sealed": False, "version": "fixture"},
        )
    )
    requests: list[tuple[str, str, dict[str, object] | None]] = []
    network_attachments: list[dict[str, str]] = []
    root.mkdir()
    monkeypatch.setattr(openbao_conformance, "ROOT", root)
    monkeypatch.setattr(openbao_conformance, "RUNTIME", runtime)
    monkeypatch.setattr(openbao_conformance, "_compose", lambda *_args: None)
    monkeypatch.setattr(openbao_conformance, "_wait_ready", lambda: next(health))
    monkeypatch.setattr(
        openbao_conformance,
        "_runtime_values",
        lambda: {
            "REDAGENT_POSTGRES_PASSWORD": "fixture-database-value",  # pragma: allowlist secret
            "REDAGENT_POSTGRES_PORT": "55433",
            "REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-gate-default",
        },
    )
    monkeypatch.setattr(openbao_conformance, "_token_is_valid", lambda _token: False)
    monkeypatch.setattr(
        openbao_conformance,
        "_attach_to_local_stack_network",
        lambda values: network_attachments.append(values),
        raising=False,
    )

    def request(
        method: str,
        path: str,
        *,
        token: str | None = None,
        payload: dict[str, object] | None = None,
        expected: tuple[int, ...] = (200, 204),
    ) -> dict[str, object]:
        del token, expected
        requests.append((method, path, payload))
        if path == "/sys/init":
            return {"root_token": "fixture-root", "keys_base64": ["fixture-unseal"]}
        if path == "/sys/audit":
            return {"data": {"audit-file-1/": {}, "audit-file-2/": {}}}
        if path == "/sys/mounts":
            return {"data": {"database/": {}}}
        if path == "/auth/token/create":
            return {"auth": {"client_token": "fixture-application"}}
        return {}

    monkeypatch.setattr(openbao_conformance, "_request", request)

    result = openbao_conformance.provision()

    database_request = next(row for row in requests if row[1] == "/database/config/redagent-r098")
    assert database_request[2] is not None
    assert database_request[2]["connection_url"] == (
        "postgresql://{{username}}:{{password}}@postgres:5432/redagent?sslmode=disable"
    )
    assert network_attachments == [
        {
            "REDAGENT_POSTGRES_PASSWORD": "fixture-database-value",  # pragma: allowlist secret
            "REDAGENT_POSTGRES_PORT": "55433",
            "REDAGENT_COMPOSE_PROJECT_NAME": "redagent-public-gate-default",
        }
    ]
    assert result["ok"] is True


@pytest.mark.parametrize(
    ("name", "value"),
    (
        ("DOCKER_CONTEXT", "remote-context"),
        ("docker_host", "tcp://203.0.113.9:2375"),
        ("DOCKER_TLS", "1"),
        ("docker_tls_verify", "1"),
        ("DOCKER_CERT_PATH", "outside-certificates"),
    ),
)
def test_openbao_rejects_ambient_remote_docker_targets(
    monkeypatch: pytest.MonkeyPatch,
    name: str,
    value: str,
) -> None:
    monkeypatch.setenv(name, value)

    with pytest.raises(openbao_conformance.ConformanceError, match="openbao_docker_target_override_forbidden"):
        openbao_conformance._safe_compose_environment()


@pytest.mark.parametrize("redirected_component", ("runtime", "target"))
def test_openbao_runtime_reparse_rejected_before_write(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    redirected_component: str,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "openbao"
    runtime.mkdir(parents=True)
    monkeypatch.setattr(openbao_conformance, "ROOT", root)
    monkeypatch.setattr(openbao_conformance, "RUNTIME", runtime)
    target = runtime / "root-token"
    if redirected_component == "target":
        target.write_text("sentinel\n", encoding="utf-8")
    redirected = runtime if redirected_component == "runtime" else target
    monkeypatch.setattr(
        openbao_conformance,
        "_path_is_reparse",
        lambda path: path == redirected,
        raising=False,
    )

    with pytest.raises(openbao_conformance.ConformanceError, match="openbao_runtime_path_invalid"):
        openbao_conformance._write_private(target, "fixture")
    if redirected_component == "target":
        assert target.read_text(encoding="utf-8") == "sentinel\n"
    else:
        assert not target.exists()


def test_openbao_reset_reparse_rejected_before_compose(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "openbao"
    runtime.mkdir(parents=True)
    compose_called = False
    monkeypatch.setattr(openbao_conformance, "ROOT", root)
    monkeypatch.setattr(openbao_conformance, "RUNTIME", runtime)
    monkeypatch.setattr(
        openbao_conformance,
        "_path_is_reparse",
        lambda path: path == runtime,
        raising=False,
    )

    def compose(*_args: str) -> str:
        nonlocal compose_called
        compose_called = True
        return ""

    monkeypatch.setattr(openbao_conformance, "_compose", compose)

    with pytest.raises(openbao_conformance.ConformanceError, match="openbao_runtime_path_invalid"):
        openbao_conformance.reset()
    assert compose_called is False
    assert runtime.is_dir()


def test_openbao_reset_rechecks_reparse_before_delete(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "openbao"
    runtime.mkdir(parents=True)
    redirected = False
    monkeypatch.setattr(openbao_conformance, "ROOT", root)
    monkeypatch.setattr(openbao_conformance, "RUNTIME", runtime)
    monkeypatch.setattr(
        openbao_conformance,
        "_path_is_reparse",
        lambda path: redirected and path == runtime,
        raising=False,
    )

    def compose(*_args: str) -> str:
        nonlocal redirected
        redirected = True
        return ""

    monkeypatch.setattr(openbao_conformance, "_compose", compose)

    with pytest.raises(openbao_conformance.ConformanceError, match="openbao_runtime_path_invalid"):
        openbao_conformance.reset()
    assert runtime.is_dir()


def test_openbao_status_requires_workspace_project_service_ownership(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    health_called = False
    monkeypatch.setattr(openbao_conformance, "_compose", lambda *_args: "")

    def health() -> dict[str, object]:
        nonlocal health_called
        health_called = True
        return {"initialized": True, "sealed": False}

    monkeypatch.setattr(openbao_conformance, "_wait_ready", health)

    with pytest.raises(openbao_conformance.ConformanceError, match="openbao_project_service_not_running"):
        openbao_conformance.status()
    assert health_called is False


def test_openbao_status_accepts_health_after_workspace_project_service_proof(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(openbao_conformance, "_compose", lambda *_args: "openbao\n")
    monkeypatch.setattr(
        openbao_conformance,
        "_wait_ready",
        lambda: {"initialized": True, "sealed": False, "version": "fixture"},
    )

    result = openbao_conformance.status()

    assert result["ok"] is True


def test_openbao_provisioner_uses_exact_closed_routes_and_never_legacy_or_force_revoke() -> None:
    source = (ROOT / "scripts" / "openbao_conformance.py").read_text(encoding="utf-8")
    for path in (
        "/sys/init", "/sys/unseal", "/sys/audit", "audit-file-1", "audit-file-2",
        "/sys/mounts/database", "/database/config/redagent-r098", "/database/roles/redagent-r098",
        "/sys/policies/acl/redagent-r098", "/auth/token/create",
    ):
        assert path in source
    for forbidden in ("/sys/renew", "/sys/revoke", "revoke-prefix", "revoke-force", "/sys/leases/tidy"):
        assert forbidden not in source
