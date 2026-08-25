from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_application_image_is_digest_pinned_hash_locked_and_non_root() -> None:
    dockerfile = (ROOT / "deploy/images/redagent-app.Dockerfile").read_text(encoding="utf-8")
    assert dockerfile.count("FROM ") == 2
    assert dockerfile.count("@sha256:") == 2
    assert "npm ci --ignore-scripts" in dockerfile
    assert "pip install --require-hashes --no-deps" in dockerfile
    assert "USER 10001:10001" in dockerfile
    assert "--private-cluster-bind" in dockerfile
    assert "COPY .venv" not in dockerfile and "COPY .local" not in dockerfile


def test_container_lock_covers_every_runtime_pin_with_hashes() -> None:
    runtime = (ROOT / "requirements-runtime.lock").read_text(encoding="utf-8")
    container = (ROOT / "requirements-control-plane.lock").read_text(encoding="utf-8")
    runtime_pins = {
        line.strip()
        for line in runtime.splitlines()
        if line and not line.startswith((" ", "#")) and "==" in line
    }
    assert runtime_pins
    container_pins = {
        line.removesuffix(" \\").strip()
        for line in container.splitlines()
        if line and not line.startswith((" ", "#")) and "==" in line
    }
    direct_control_plane_pins = {
        line.strip().lower()
        for line in (ROOT / "requirements-control-plane.in").read_text(encoding="utf-8").splitlines()
        if line.strip()
    }
    assert direct_control_plane_pins.issubset({pin.lower() for pin in container_pins})
    assert "schemathesis==4.22.4" not in container_pins
    assert container.count("--hash=sha256:") >= len(runtime_pins)
