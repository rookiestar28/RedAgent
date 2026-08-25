from __future__ import annotations

from contextlib import nullcontext
import json
from pathlib import Path
import subprocess
import sys
import time

import pytest

from scripts import opa_conformance


PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _workspace_runtime(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> tuple[Path, Path]:
    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "opa"
    runtime.mkdir(parents=True)
    compose = root / "compose.opa-conformance.yaml"
    compose.write_text("services: {}\n", encoding="utf-8")
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", runtime)
    monkeypatch.setattr(opa_conformance, "COMPOSE", compose)
    return root, runtime


def test_direct_opa_cli_imports_the_repository_package_before_any_docker_action() -> None:
    completed = subprocess.run(
        (sys.executable, str(PROJECT_ROOT / "scripts" / "opa_conformance.py"), "--help"),
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "Build and operate the closed synthetic-only compat_099 OPA fixture" in completed.stdout


def test_opa_host_port_allocator_skips_an_occupied_loopback_port(
    monkeypatch,
) -> None:
    first = opa_conformance.OPA_HOST_PORT_START
    second = first + 1
    monkeypatch.setattr(
        opa_conformance,
        "_loopback_port_available",
        lambda port: port == second,
    )

    assert opa_conformance._allocate_opa_host_port() == second


def test_locked_images_are_closed_to_the_reviewed_registry_tag_digest_and_platform() -> None:
    assert opa_conformance._image() == (
        "docker.io/openpolicyagent/opa:1.18.2-static@"
        "sha256:57f7d06808fff6de3ea1d698e6430990973ca1370be0e54975f0083d615521da"
    )
    assert opa_conformance._bundle_server_image() == (
        "docker.io/library/python:3.13-alpine@"
        "sha256:399babc8b49529dabfd9c922f2b5eea81d611e4512e3ed250d75bd2e7683f4b0"
    )


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("registry", "docker.io/library/python"),
        ("tag", "1.18.3-static"),
        ("index_digest", "sha256:" + "f" * 64),
        ("platform", "linux/arm64"),
    ),
)
def test_locked_opa_image_rejects_tampered_identity_before_docker(
    tmp_path: Path,
    field: str,
    value: str,
) -> None:
    payload = json.loads(opa_conformance.IMAGE_LOCK.read_text(encoding="utf-8"))
    payload[field] = value
    if field in {"registry", "tag", "index_digest"}:
        payload["reference"] = (
            f"{payload['registry']}:{payload['tag']}@{payload['index_digest']}"
        )
    path = tmp_path / field / opa_conformance.IMAGE_LOCK.name
    path.parent.mkdir()
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(opa_conformance.ConformanceError, match="opa_image_lock_invalid"):
        opa_conformance._locked_image(path)


def test_opa_rejects_a_bad_lock_before_starting_docker(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    payload = json.loads(opa_conformance.IMAGE_LOCK.read_text(encoding="utf-8"))
    payload["platform"] = "linux/arm64"
    path = tmp_path / opa_conformance.IMAGE_LOCK.name
    path.write_text(json.dumps(payload), encoding="utf-8")
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(opa_conformance, "IMAGE_LOCK", path)
    monkeypatch.setattr(
        opa_conformance.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs))
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    with pytest.raises(opa_conformance.ConformanceError, match="opa_image_lock_invalid"):
        opa_conformance._opa("fmt", "--fail", "/policy")

    assert calls == []


def test_opa_fixture_lease_rejects_a_concurrent_owner_and_releases(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setattr(opa_conformance, "ROOT", tmp_path)
    lock_path = opa_conformance.opa_fixture_lease_path()
    ready_path = tmp_path / "owner-ready"
    owner_code = (
        "from pathlib import Path\n"
        "import time\n"
        "from redagent_platform.gate_lease import ValidationLease\n"
        f"with ValidationLease(Path({str(lock_path)!r})):\n"
        f"    Path({str(ready_path)!r}).write_text('ready', encoding='utf-8')\n"
        "    time.sleep(60)\n"
    )
    owner = subprocess.Popen(
        (sys.executable, "-c", owner_code),
        cwd=PROJECT_ROOT,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        deadline = time.monotonic() + 5
        while not ready_path.is_file() and owner.poll() is None and time.monotonic() < deadline:
            time.sleep(0.05)
        assert ready_path.is_file(), owner.stderr.read()
        with pytest.raises(opa_conformance.ConformanceError, match="opa_fixture_already_active"):
            with opa_conformance.opa_fixture_lease():
                pass
    finally:
        if owner.poll() is None:
            owner.terminate()
        owner.wait(timeout=5)

    release_deadline = time.monotonic() + 5
    while True:
        try:
            with opa_conformance.opa_fixture_lease():
                break
        except opa_conformance.ConformanceError:
            if time.monotonic() >= release_deadline:
                pytest.fail("OPA fixture lease did not release after owner termination")
            time.sleep(0.05)


def test_compose_uses_a_workspace_scoped_project_and_sanitizes_ambient_project_name(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root, _runtime = _workspace_runtime(monkeypatch, tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setenv("COMPOSE_PROJECT_NAME", "ambient-hijack")
    monkeypatch.setenv("COMPOSE_FILE", "outside-compose.yaml")
    monkeypatch.setenv("COMPOSE_PROFILES", "unsafe-profile")
    monkeypatch.setenv("compose_file", "lowercase-outside-compose.yaml")
    monkeypatch.setenv("docker_config", "hostile-docker-config")
    monkeypatch.setattr(
        opa_conformance.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs))
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    opa_conformance._compose("down", "--volumes", "--remove-orphans")

    assert len(calls) == 1
    command, kwargs = calls[0]
    assert command[:4] == ["docker", "--context", "default", "compose"]
    assert command[command.index("--project-directory") + 1] == str(root)
    assert command[command.index("-p") + 1] == opa_conformance._compose_project_name()
    assert command[command.index("-f") + 1] == str(opa_conformance.COMPOSE)
    assert "ambient-hijack" not in kwargs["env"].values()
    assert not any(key.upper().startswith("COMPOSE_") for key in kwargs["env"])
    assert not any(key.upper() == "DOCKER_CONFIG" for key in kwargs["env"])


def test_compose_project_name_is_deterministic_and_workspace_unique(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, _runtime = _workspace_runtime(monkeypatch, tmp_path)
    first = opa_conformance._compose_project_name()
    assert first == opa_conformance._compose_project_name()

    other_root = tmp_path / "other-workspace"
    other_root.mkdir()
    monkeypatch.setattr(opa_conformance, "ROOT", other_root)

    assert first != opa_conformance._compose_project_name()
    assert first.startswith("redagent-opa-")
    assert len(first) == len("redagent-opa-") + 16


@pytest.mark.parametrize(
    ("environment_key", "environment_value"),
    (
        ("DOCKER_HOST", "ssh://nonlocal.example.invalid"),
        ("docker_host", "ssh://nonlocal.example.invalid"),
        ("DOCKER_CONTEXT", "remote-context"),
        ("docker_context", "remote-context"),
        ("DOCKER_TLS", "1"),
        ("docker_tls", "1"),
        ("DOCKER_TLS_VERIFY", "1"),
        ("docker_tls_verify", "1"),
        ("DOCKER_CERT_PATH", "nonlocal-certificates"),
        ("docker_cert_path", "nonlocal-certificates"),
    ),
)
def test_compose_rejects_a_nonlocal_docker_target_before_docker_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    environment_key: str,
    environment_value: str,
) -> None:
    _workspace_runtime(monkeypatch, tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setenv(environment_key, environment_value)
    monkeypatch.setattr(
        opa_conformance.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs))
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    with pytest.raises(opa_conformance.ConformanceError, match="opa_docker_target_override_forbidden"):
        opa_conformance._compose("down")

    assert calls == []


def test_compose_rejects_a_reparse_bundle_mount_parent_before_docker_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, runtime = _workspace_runtime(monkeypatch, tmp_path)
    server = runtime / "server"
    server.mkdir()
    bundle = server / "redagent.tar.gz"
    bundle.write_bytes(b"synthetic bundle")
    (runtime / "config.yaml").write_text("services: {}\n", encoding="utf-8")
    (runtime / "persist").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "redagent.tar.gz").write_bytes(b"outside")
    try:
        bundle.unlink()
        server.rmdir()
        server.symlink_to(outside, target_is_directory=True)
    except OSError:
        if not server.exists():
            server.mkdir()
        bundle.write_bytes(b"synthetic bundle")
        is_link_or_reparse = opa_conformance._path_is_link_or_reparse
        monkeypatch.setattr(
            opa_conformance,
            "_path_is_link_or_reparse",
            lambda path: path == server or is_link_or_reparse(path),
        )
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(
        opa_conformance.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs))
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    with pytest.raises(opa_conformance.ConformanceError, match="opa_runtime_path_invalid"):
        opa_conformance._compose("up", "-d")

    assert calls == []


def test_compose_rechecks_mount_sources_after_snapshot_before_docker_runs(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, runtime = _workspace_runtime(monkeypatch, tmp_path)
    server = runtime / "server"
    server.mkdir()
    bundle = server / "redagent.tar.gz"
    bundle.write_bytes(b"synthetic bundle")
    (runtime / "config.yaml").write_text("services: {}\n", encoding="utf-8")
    (runtime / "persist").mkdir()
    snapshots = opa_conformance._compose_mount_snapshots

    def mutate_after_snapshot():
        captured = snapshots()
        bundle.write_bytes(b"mutated bundle")
        return captured

    calls: list[tuple[object, ...]] = []
    monkeypatch.setattr(opa_conformance, "_compose_mount_snapshots", mutate_after_snapshot)
    monkeypatch.setattr(
        opa_conformance.subprocess,
        "run",
        lambda *arguments, **_kwargs: calls.append(arguments) or None,
    )

    with pytest.raises(opa_conformance.ConformanceError, match="opa_runtime_path_race_detected"):
        opa_conformance._compose("up", "-d")

    assert calls == []


def test_provision_cleans_scoped_project_and_endpoint_after_readiness_timeout(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, runtime = _workspace_runtime(monkeypatch, tmp_path)
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
    monkeypatch.setattr(opa_conformance, "_build", lambda: {"ok": True})
    monkeypatch.setattr(opa_conformance, "_prepare_bundle_server", lambda: runtime / "server" / "redagent.tar.gz")
    monkeypatch.setattr(opa_conformance, "_write_runtime_config", lambda: None)
    monkeypatch.setattr(opa_conformance, "_allocate_opa_host_port", lambda *, excluded: 58181)
    monkeypatch.setattr(
        opa_conformance,
        "_compose",
        lambda *arguments, **kwargs: calls.append((arguments, kwargs))
        or subprocess.CompletedProcess(arguments, 0, "", ""),
    )
    monkeypatch.setattr(
        opa_conformance,
        "status",
        lambda: (_ for _ in ()).throw(opa_conformance.ConformanceError("opa_status_unavailable")),
    )
    monotonic = iter((0.0, 61.0))
    monkeypatch.setattr(opa_conformance.time, "monotonic", lambda: next(monotonic))

    with pytest.raises(opa_conformance.ConformanceError, match="opa_startup_timeout"):
        opa_conformance._provision()

    assert ("down", "--volumes", "--remove-orphans") in [arguments for arguments, _kwargs in calls]
    assert not (runtime / opa_conformance.OPA_ENDPOINT_STATE).exists()


def test_reset_fails_closed_when_an_invalid_fixture_lock_could_hide_an_active_owner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A corrupt lock gives no proof that another fixture worker is absent."""

    root, runtime = _workspace_runtime(monkeypatch, tmp_path)
    (runtime / "runtime-artifact").write_text("fixture", encoding="utf-8")
    corrupt_lock = root / ".tmp" / "validation" / opa_conformance._OPA_FIXTURE_LEASE_FILENAME
    corrupt_lock.mkdir(parents=True)
    calls: list[tuple[tuple[str, ...], dict[str, object]]] = []
    monkeypatch.setattr(
        opa_conformance,
        "_compose",
        lambda *arguments, **kwargs: calls.append((arguments, kwargs))
        or subprocess.CompletedProcess(arguments, 0, "", ""),
    )

    with pytest.raises(opa_conformance.ConformanceError, match="opa_fixture_lease_path_invalid"):
        opa_conformance.reset()

    assert calls == []
    assert runtime.exists()


def test_provision_refuses_a_stale_legacy_implicit_compose_project_before_fixture_mutation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A new scoped project must not hide an old implicit-project port/container leak."""

    stale_container_id = "a" * 64
    monkeypatch.setattr(opa_conformance, "opa_fixture_lease", lambda: nullcontext())
    monkeypatch.setattr(
        opa_conformance,
        "_legacy_fixture_container_ids",
        lambda: (stale_container_id,),
        raising=False,
    )
    monkeypatch.setattr(
        opa_conformance,
        "_provision",
        lambda: (_ for _ in ()).throw(AssertionError("fixture mutation must not start")),
    )

    with pytest.raises(opa_conformance.ConformanceError, match="legacy_fixture_reconciliation_required"):
        opa_conformance.provision()


def test_reset_preserves_runtime_and_never_recursively_deletes_workspace_content(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, runtime = _workspace_runtime(monkeypatch, tmp_path)
    (runtime / "runtime-artifact").write_text("fixture", encoding="utf-8")
    monkeypatch.setattr(opa_conformance, "opa_fixture_lease", lambda: nullcontext())
    monkeypatch.setattr(
        opa_conformance,
        "_compose",
        lambda *arguments, **_kwargs: subprocess.CompletedProcess(arguments, 0, "", ""),
    )
    monkeypatch.setattr(
        opa_conformance.shutil,
        "rmtree",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("unsafe recursive delete")),
    )

    assert opa_conformance.reset() == {
        "ok": True,
        "action": "reset",
        "runtime_preserved": True,
    }
    assert (runtime / "runtime-artifact").read_text(encoding="utf-8") == "fixture"


def test_reset_without_runtime_does_not_create_ignored_runtime_state(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """An inert reset must not create mutable fixture directories as a side effect."""

    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", root / ".local" / "redagent" / "opa")
    monkeypatch.setattr(opa_conformance, "opa_fixture_lease", lambda: nullcontext())
    monkeypatch.setattr(
        opa_conformance,
        "_compose",
        lambda *arguments, **_kwargs: subprocess.CompletedProcess(arguments, 0, "", ""),
    )

    assert opa_conformance.reset()["runtime_preserved"] is True
    assert not (root / ".local").exists()


def test_status_does_not_create_runtime_state_without_the_fixture_lease(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", root / ".local" / "redagent" / "opa")

    class Response:
        status_code = 200

        def __init__(self, payload: dict[str, object]) -> None:
            self._payload = payload

        def json(self) -> dict[str, object]:
            return self._payload

    responses = iter(
        (
            Response({"ok": True}),
            Response(
                {
                    "result": {
                        "bundles": {"redagent": {"active_revision": "r099-v1"}},
                        "plugins": {"bundle": {"state": "OK"}},
                        "labels": {"version": "1"},
                    }
                }
            ),
        )
    )
    monkeypatch.setattr(
        opa_conformance.httpx,
        "get",
        lambda *_args, **_kwargs: next(responses),
    )

    assert opa_conformance.status()["ok"] is True
    assert not (root / ".local").exists()


def test_scoped_cleanup_does_not_depend_on_image_locks(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    _root, _runtime = _workspace_runtime(monkeypatch, tmp_path)
    calls: list[tuple[list[str], dict[str, object]]] = []
    monkeypatch.setattr(
        opa_conformance,
        "_image",
        lambda: (_ for _ in ()).throw(opa_conformance.ConformanceError("opa_image_lock_invalid")),
    )
    monkeypatch.setattr(
        opa_conformance,
        "_bundle_server_image",
        lambda: (_ for _ in ()).throw(opa_conformance.ConformanceError("opa_image_lock_invalid")),
    )
    monkeypatch.setattr(
        opa_conformance.subprocess,
        "run",
        lambda command, **kwargs: calls.append((command, kwargs))
        or subprocess.CompletedProcess(command, 0, "", ""),
    )

    opa_conformance._scoped_cleanup()

    assert len(calls) == 2
    assert all(
        "local.invalid/redagent-opa-cleanup:noop" in values["env"].values()
        for _command, values in calls
    )


def test_runtime_config_uses_the_internal_bundle_server(
    monkeypatch,
    tmp_path,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "opa"
    runtime.mkdir(parents=True)
    (runtime / "signing-public.pem").write_text("PUBLIC KEY", encoding="utf-8")
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", runtime)

    opa_conformance._write_runtime_config()

    config = (runtime / "config.yaml").read_text(encoding="utf-8")
    assert "url: http://bundle-server:8080" in config


def test_opa_compose_keeps_the_bundle_server_unpublished_without_blocking_loopback_opa() -> None:
    compose = opa_conformance.COMPOSE.read_text(encoding="utf-8")

    assert "bundle-server:" in compose
    assert "REDAGENT_OPA_BUNDLE_SERVER_IMAGE" in compose
    assert "host.docker.internal" not in compose
    assert "internal: true" not in compose
    assert compose.count("platform: linux/amd64") == 2
    assert "${REDAGENT_OPA_HOST_PORT:-58181}" in compose
    assert "./.local/redagent/opa/server/redagent.tar.gz:/bundles/redagent.tar.gz:ro" in compose
    assert "./.local/redagent/opa/server:/bundles:ro" not in compose


def test_prepare_bundle_server_copies_only_the_generated_bundle(
    monkeypatch,
    tmp_path,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "opa"
    runtime.mkdir(parents=True)
    (runtime / "redagent.tar.gz").write_bytes(b"synthetic bundle")
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", runtime)

    bundle = opa_conformance._prepare_bundle_server()

    assert bundle == runtime / "server" / "redagent.tar.gz"
    assert bundle.read_bytes() == b"synthetic bundle"


def test_prepare_bundle_server_rejects_a_descriptor_swapped_bundle_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A validated bundle pathname must not be reopened through a replacement target."""

    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "opa"
    runtime.mkdir(parents=True)
    source = runtime / "redagent.tar.gz"
    source.write_bytes(b"expected bundle")
    replacement = tmp_path / "replacement-bundle.tar.gz"
    replacement.write_bytes(b"replacement bundle")
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", runtime)
    real_open = opa_conformance.os.open

    def swapped_open(path: str | Path, flags: int, *args: object, **kwargs: object) -> int:
        if Path(path) == source:
            return real_open(replacement, flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(opa_conformance.os, "open", swapped_open)

    with pytest.raises(opa_conformance.ConformanceError, match="opa_runtime_path_race_detected"):
        opa_conformance._prepare_bundle_server()


def test_runtime_config_rejects_a_descriptor_swapped_public_key_source(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """A replacement public key must not be rendered into the local OPA config."""

    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "opa"
    runtime.mkdir(parents=True)
    source = runtime / "signing-public.pem"
    source.write_text("EXPECTED PUBLIC KEY\n", encoding="utf-8")
    replacement = tmp_path / "replacement-public.pem"
    replacement.write_text("REPLACEMENT PUBLIC KEY\n", encoding="utf-8")
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", runtime)
    real_open = opa_conformance.os.open

    def swapped_open(path: str | Path, flags: int, *args: object, **kwargs: object) -> int:
        if Path(path) == source:
            return real_open(replacement, flags, *args, **kwargs)
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(opa_conformance.os, "open", swapped_open)

    with pytest.raises(opa_conformance.ConformanceError, match="opa_runtime_path_race_detected"):
        opa_conformance._write_runtime_config()


def test_prepare_bundle_server_rejects_a_runtime_outside_the_workspace(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    runtime = tmp_path / "outside" / "opa"
    runtime.mkdir(parents=True)
    (runtime / "redagent.tar.gz").write_bytes(b"synthetic bundle")
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", runtime)

    with pytest.raises(opa_conformance.ConformanceError, match="opa_runtime_path_invalid"):
        opa_conformance._prepare_bundle_server()

    assert not (runtime / "server").exists()


def test_prepare_bundle_server_rejects_a_reparse_server_before_copy(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "opa"
    runtime.mkdir(parents=True)
    (runtime / "redagent.tar.gz").write_bytes(b"synthetic bundle")
    outside = tmp_path / "outside"
    outside.mkdir()
    server = runtime / "server"
    try:
        server.symlink_to(outside, target_is_directory=True)
    except OSError:
        # Windows CI can deny symlink creation; still cover the fail-closed reparse branch.
        server.mkdir()
        is_link_or_reparse = opa_conformance._path_is_link_or_reparse
        monkeypatch.setattr(
            opa_conformance,
            "_path_is_link_or_reparse",
            lambda path: path == server or is_link_or_reparse(path),
        )
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", runtime)

    with pytest.raises(opa_conformance.ConformanceError, match="opa_runtime_path_invalid"):
        opa_conformance._prepare_bundle_server()

    assert not (outside / "redagent.tar.gz").exists()


def test_opa_endpoint_uses_the_workspace_recorded_port(
    monkeypatch,
    tmp_path,
) -> None:
    root = tmp_path / "workspace"
    runtime = root / ".local" / "redagent" / "opa"
    runtime.mkdir(parents=True)
    (runtime / opa_conformance.OPA_ENDPOINT_STATE).write_text(
        '{"port": 58182}\n',
        encoding="utf-8",
    )
    monkeypatch.setattr(opa_conformance, "ROOT", root)
    monkeypatch.setattr(opa_conformance, "RUNTIME", runtime)

    assert opa_conformance.opa_endpoint() == "http://127.0.0.1:58182"


def test_live_conformance_integration_uses_the_workspace_recorded_endpoint() -> None:
    source = (
        opa_conformance.ROOT / "tests" / "integration" / "test_compat_099_opa_conformance.py"
    ).read_text(encoding="utf-8")

    assert "from scripts import opa_conformance" in source
    assert "endpoint = opa_conformance.opa_endpoint()" in source


def test_live_lifecycle_integration_reads_the_endpoint_when_the_scenario_runs() -> None:
    source = (
        opa_conformance.ROOT / "tests" / "integration" / "test_compat_099_opa_lifecycle.py"
    ).read_text(encoding="utf-8")

    assert "endpoint = opa_conformance.opa_endpoint()" in source
    assert "ENDPOINT = opa_conformance.opa_endpoint()" not in source


def test_live_lifecycle_integration_reads_the_recorded_endpoint_at_execution_time() -> None:
    source = (
        opa_conformance.ROOT / "tests" / "integration" / "test_compat_099_opa_lifecycle.py"
    ).read_text(encoding="utf-8")

    assert "    endpoint = opa_conformance.opa_endpoint()" in source
    assert "ENDPOINT = " not in source
    assert "with opa_conformance.opa_fixture_lease():" in source
    assert "opa_conformance._build_rollback_fixture()" in source
    assert "opa_conformance._provision()" in source
    assert "return opa_conformance._compose(*arguments)" in source
    assert "subprocess.run" not in source
    finally_body = source[source.index("    finally:"):]
    assert 'await _wait_revision(endpoint, "r099-v1", require_error=False)' in finally_body
