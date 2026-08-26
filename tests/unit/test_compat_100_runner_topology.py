from __future__ import annotations

import ast
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_synthetic_image_lock_pins_official_base_index_platform_and_derived_digest() -> None:
    lock = json.loads((ROOT / "config" / "runner-conformance-image.json").read_text(encoding="utf-8"))
    assert lock["schema_version"] == "1.0"
    assert lock["base_image"] == "docker.io/library/python:3.13.9-alpine3.22"
    assert lock["base_index_digest"] == "sha256:e5fa639e49b85986c4481e28faa2564b45aa8021413f31026c3856e5911618b1"
    assert lock["base_linux_amd64_digest"] == "sha256:53739acebd52a300f19f52d93f2a6165f63300689bdf6f8af2bff0d63780e5e6"
    assert lock["derived_image_id"] == "sha256:9700b0b2dc12b00c7b8e8bb902a747a1f23bdb1e38b876bd3d18e406cb07266c"
    assert lock["source_date_epoch"] == 1760544000
    assert lock["buildkit_compatibility_version"] == "20"
    assert lock["local_tag"] == "redagent/r100-synthetic:1.0.0"
    assert lock["production_qualified"] is False


def test_dockerfile_is_digest_pinned_numeric_nonroot_and_has_only_fixed_entrypoint() -> None:
    source = (ROOT / "containers" / "runner-synthetic" / "Dockerfile").read_text(encoding="utf-8")
    assert source.startswith("FROM docker.io/library/python@sha256:53739acebd52a300f19f52d93f2a6165f63300689bdf6f8af2bff0d63780e5e6")
    assert "USER 65532:65532" in source
    assert "COPY --chown=0:0 --chmod=0555 containers/runner-synthetic/synthetic_entry.py" in source
    assert 'ENTRYPOINT ["python", "-I", "/app/synthetic_entry.py"]' in source
    for forbidden in ("apt", "apk", "curl", "wget", "ADD ", "latest", "sudo", "HEALTHCHECK", "CMD "):
        assert forbidden not in source


def test_synthetic_entry_has_no_network_subprocess_dynamic_code_or_external_input() -> None:
    path = ROOT / "containers" / "runner-synthetic" / "synthetic_entry.py"
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        alias.name.split(".", 1)[0]
        for node in ast.walk(tree)
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    }
    assert imports <= {"hashlib", "json", "os", "pathlib"}
    for forbidden in ("subprocess", "socket", "requests", "urllib", "eval(", "exec(", "input(", "sys.argv", "http"):
        assert forbidden not in source
    assert 'pathlib.Path("/work/result.json")' in source


def test_conformance_script_exposes_only_fixed_actions_and_restricted_docker_flags() -> None:
    source = (ROOT / "scripts" / "runner_conformance.py").read_text(encoding="utf-8")
    for required in (
        'choices=("validate", "build", "provision", "run", "inspect", "stop", "reset")',
        'builder.build_prefix', "attest_docker_image_config", '"--no-cache", "--network", "none", "--provenance=false"',
        '"type=docker"', '"rewrite-timestamp=true"', '"compatibility-version={compatibility_version}"',
        '"SOURCE_DATE_EPOCH={source_date_epoch}"',
        '"--network", "none"', '"--read-only"', '"--cap-drop", "ALL"',
        '"--security-opt", "no-new-privileges:true"', '"--pids-limit", "32"',
        '"--memory", "128m"', '"--cpus", "0.5"', '"--user", "65532:65532"',
        '"--runtime", "runc"', '"--tmpfs", "/work:rw,noexec,nosuid,nodev,size=1m"',
    ):
        assert required in source
    for forbidden in (
        "shell=True", "docker.sock", '"--privileged",', '"host"',
        '"--pid",', '"--ipc",', '"--device",',
    ):
        assert forbidden not in source


def test_conformance_artifacts_are_ignored_and_secure_sdlc_tracks_runner_image_lock() -> None:
    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    validator = (ROOT / "scripts" / "validate_secure_sdlc.py").read_text(encoding="utf-8")
    assert ".local/" in gitignore
    assert "runner-conformance-image.json" in validator
