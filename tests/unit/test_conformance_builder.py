from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
from types import SimpleNamespace

import pytest

import redagent_platform.conformance_builder as conformance_builder
from redagent_platform.conformance_builder import (
    attest_docker_image_config,
    isolated_runtime_directory,
    pinned_conformance_builder,
)


def _write_lock(root: Path) -> None:
    config = root / "config"
    config.mkdir()
    (config / "conformance-buildkit.json").write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "name": "moby/buildkit",
                "version": "v0.32.2",
                "index_digest": "sha256:" + "a" * 64,
                "linux_amd64_digest": "sha256:" + "b" * 64,
                "reference": "docker.io/moby/buildkit:v0.32.2@sha256:" + "a" * 64,
                "platform": "linux/amd64",
                "purpose": "local-conformance-builder-only",
                "production_qualified": False,
            }
        ),
        encoding="utf-8",
    )


def test_pinned_builder_uses_exact_image_isolated_config_and_exact_cleanup(tmp_path: Path) -> None:
    _write_lock(tmp_path)
    calls: list[tuple[tuple[str, ...], dict[str, str]]] = []

    def fake_run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        environment = dict(kwargs["env"])  # type: ignore[arg-type]
        calls.append((tuple(argv), environment))
        returncode = 1 if argv[1:4] == ["buildx", "inspect", "redagent-runner-aaaaaaaaaaaaaaaa"] else 0
        return subprocess.CompletedProcess(argv, returncode, "", "")

    inherited = {
        "PATH": "/safe/bin",
        "DOCKER_HOST": "tcp://remote.example.invalid:2375",
        "DOCKER_CONTEXT": "remote",
        "DOCKER_AUTH_CONFIG": "sensitive",
        "BUILDX_BUILDER": "ambient",
        "BUILDKIT_HOST": "tcp://remote.example.invalid:1234",
        "docker_host": "tcp://remote.example.invalid:2376",
        "Docker_Context": "mixed-case-remote",
        "docker_auth_config": "mixed-case-sensitive",
        "Docker_Cert_Path": "/unsafe/certs",
        "docker_tls_verify": "1",
        "BuildKit_Host": "tcp://remote.example.invalid:4321",
        "BuildX_Builder": "mixed-case-ambient",
    }
    with pinned_conformance_builder(
        tmp_path,
        purpose="runner",
        inherited_environment=inherited,
        token_factory=lambda: "a" * 16,
        run=fake_run,
    ) as builder:
        assert builder.name == "redagent-runner-aaaaaaaaaaaaaaaa"
        assert builder.build_prefix == ("buildx", "build", "--builder", builder.name)
        config_root = Path(builder.environment["DOCKER_CONFIG"])
        assert json.loads((config_root / "config.json").read_text(encoding="utf-8")) == {}
        assert set(builder.environment) == {"PATH", "DOCKER_CONFIG"}

    commands = [call[0] for call in calls]
    assert commands[0] == ("docker", "buildx", "inspect", "redagent-runner-aaaaaaaaaaaaaaaa")
    assert commands[1] == (
        "docker",
        "buildx",
        "create",
        "--name",
        "redagent-runner-aaaaaaaaaaaaaaaa",
        "--driver",
        "docker-container",
        "--driver-opt",
        "image=docker.io/moby/buildkit:v0.32.2@sha256:" + "a" * 64,
    )
    assert commands[2] == (
        "docker",
        "buildx",
        "inspect",
        "--bootstrap",
        "redagent-runner-aaaaaaaaaaaaaaaa",
    )
    assert commands[-1] == ("docker", "buildx", "rm", "redagent-runner-aaaaaaaaaaaaaaaa")
    assert not Path(calls[1][1]["DOCKER_CONFIG"]).exists()


def test_runtime_rejects_a_windows_reparse_ancestor_before_child_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _write_lock(tmp_path)
    runtime_parent = tmp_path / ".tmp"
    runtime_parent.mkdir()
    original_lstat = Path.lstat

    def reparse_lstat(path: Path):
        metadata = original_lstat(path)
        if path == runtime_parent:
            return SimpleNamespace(
                st_mode=metadata.st_mode,
                st_dev=metadata.st_dev,
                st_ino=metadata.st_ino,
                st_file_attributes=0x00000400,
            )
        return metadata

    monkeypatch.setattr(Path, "lstat", reparse_lstat)

    with pytest.raises(RuntimeError, match="runtime_reparse_forbidden"):
        with pinned_conformance_builder(
            tmp_path,
            purpose="runner",
            inherited_environment={"PATH": "/safe/bin"},
        ):
            raise AssertionError("reparse ancestor must fail before Docker")

    assert not (runtime_parent / "conformance-builders").exists()


def test_runtime_detects_parent_identity_change_across_child_creation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    changed = False
    original_identity = conformance_builder._directory_identity
    original_mkdir = os.mkdir

    def drifting_identity(path: Path) -> tuple[int, int, int]:
        identity = original_identity(path)
        if changed and path == tmp_path:
            return (identity[0], identity[1] + 1, identity[2])
        return identity

    def replacing_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal changed
        if dir_fd is None:
            original_mkdir(path, mode)
        else:
            original_mkdir(path, mode, dir_fd=dir_fd)
        if Path(path).name == ".tmp":
            changed = True

    monkeypatch.setattr(conformance_builder, "_directory_identity", drifting_identity)
    monkeypatch.setattr(os, "mkdir", replacing_mkdir)

    with pytest.raises(RuntimeError, match="runtime_parent_changed"):
        conformance_builder._ensure_real_child(tmp_path, ".tmp")


def test_isolated_runtime_directory_is_contained_pinned_and_removed(tmp_path: Path) -> None:
    with isolated_runtime_directory(tmp_path, prefix="receipt-") as directory:
        created = directory
        assert directory.parent == tmp_path / ".tmp" / "conformance-builders"
        assert directory.name.startswith("receipt-")
        assert directory.is_dir()
        assert not directory.is_symlink()
        if os.name == "posix":
            assert directory.stat().st_mode & 0o777 == 0o733
        (directory / "synthetic.json").write_text("{}\n", encoding="utf-8")

    assert not created.exists()


def test_isolated_runtime_directory_surfaces_cleanup_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingTemporaryDirectory:
        def __init__(self, *, prefix: str, dir: Path) -> None:
            self.path = Path(dir) / f"{prefix}exact"

        def __enter__(self) -> str:
            self.path.mkdir()
            return str(self.path)

        def __exit__(self, *_args: object) -> None:
            raise OSError("synthetic_cleanup_failure")

    monkeypatch.setattr(tempfile, "TemporaryDirectory", FailingTemporaryDirectory)
    with pytest.raises(OSError, match="synthetic_cleanup_failure"):
        with isolated_runtime_directory(tmp_path, prefix="receipt-"):
            pass


def test_builder_lock_is_exact_public_dependency_metadata() -> None:
    root = Path(__file__).resolve().parents[2]
    lock = json.loads((root / "config" / "conformance-buildkit.json").read_text(encoding="utf-8"))

    assert lock == {
        "schema_version": "1.0",
        "name": "moby/buildkit",
        "version": "v0.32.2",
        "index_digest": "sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8",
        "linux_amd64_digest": "sha256:040d34121c27906c4ff9ac152a30d52bf2c5d328d3bb748916bb3d2743c02528",
        "reference": "docker.io/moby/buildkit:v0.32.2@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8",
        "platform": "linux/amd64",
        "purpose": "local-conformance-builder-only",
        "production_qualified": False,
    }


def test_bootstrap_failure_still_removes_the_exact_builder(tmp_path: Path) -> None:
    _write_lock(tmp_path)
    commands: list[tuple[str, ...]] = []

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        command = tuple(argv)
        commands.append(command)
        if argv[1:4] == ["buildx", "inspect", "redagent-runner-aaaaaaaaaaaaaaaa"]:
            return subprocess.CompletedProcess(argv, 1, "", "missing")
        if argv[1:4] == ["buildx", "inspect", "--bootstrap"]:
            return subprocess.CompletedProcess(argv, 1, "", "bootstrap failed")
        return subprocess.CompletedProcess(argv, 0, "", "")

    try:
        with pinned_conformance_builder(
            tmp_path,
            purpose="runner",
            inherited_environment={"PATH": "/safe/bin"},
            token_factory=lambda: "a" * 16,
            run=fake_run,
        ):
            raise AssertionError("builder body must not run")
    except RuntimeError as exc:
        assert "conformance_builder_bootstrap_failed" in str(exc)
    else:  # pragma: no cover - assertion branch
        raise AssertionError("bootstrap failure must be surfaced")

    assert commands[-1] == ("docker", "buildx", "rm", "redagent-runner-aaaaaaaaaaaaaaaa")


def test_image_attestation_reads_the_portable_config_object_not_store_id(tmp_path: Path) -> None:
    expected_bytes = b'{"architecture":"amd64","config":{"User":"65532:65532"}}'
    expected = hashlib.sha256(expected_bytes).hexdigest()

    def fake_run(argv: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        output = Path(argv[argv.index("--output") + 1])
        manifest = json.dumps(
            [{"Config": f"blobs/sha256/{expected}", "RepoTags": ["redagent/test:1.0.0"], "Layers": []}]
        ).encode()
        with tarfile.open(output, "w") as archive:
            for name, content in (("manifest.json", manifest), (f"blobs/sha256/{expected}", expected_bytes)):
                member = tarfile.TarInfo(name)
                member.size = len(content)
                archive.addfile(member, io.BytesIO(content))
        return subprocess.CompletedProcess(argv, 0, "", "")

    observed = attest_docker_image_config(
        tmp_path,
        "redagent/test:1.0.0",
        "sha256:" + expected,
        inherited_environment={"PATH": "/safe/bin"},
        run=fake_run,
    )

    assert observed == "sha256:" + expected
