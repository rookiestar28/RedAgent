"""Fail-closed verification for the exact compat_106 Schemathesis artifact inputs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from redagent_platform.api_differential_service.contracts import SCHEMATHESIS_VERSION


EXPECTED_WHEEL_SHA256 = "62ff5d1657e823fc485ac9083e24995f497ae1aba6957b86b310d399317f21cb"


def verify_schemathesis_artifact(workspace: Path, *, wheel_path: Path | None = None) -> dict[str, object]:
    config_path = workspace / "config/r106-schemathesis-runtime.json"
    lock_path = workspace / "requirements-runtime.lock"
    review_path = workspace / "config/python-runtime-dependencies.json"
    try:
        config = json.loads(config_path.read_text(encoding="utf-8"))
        reviews = json.loads(review_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("api_engine_artifact_input_invalid") from exc
    locked = _locked_components(lock_path)
    reviewed = {
        _canonical(item.get("name")): item
        for item in reviews.get("packages", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    }
    if (
        config.get("schema") != "redagent.r106-engine-artifact/v1"
        or config.get("version") != SCHEMATHESIS_VERSION
        # CRITICAL: control-plane verification inspects signed artifact metadata;
        # importing the execution engine here would couple API startup to runner-only code.
        or config.get("wheel_sha256") != EXPECTED_WHEEL_SHA256
        or config.get("runtime_lock_sha256") != _sha(lock_path)
        or config.get("dependency_review_sha256") != _sha(review_path)
        or config.get("locked_component_count") != len(locked)
        or locked.get("schemathesis") != SCHEMATHESIS_VERSION
        or locked.get("pytest") != "9.1.1"
        or config.get("pypi_known_vulnerabilities") != 0
        or config.get("yanked") is not False
        or config.get("direct_license") != "MIT"
        or config.get("unexpected_methods_enabled") is not False
        or config.get("external_references_enabled") is not False
        or config.get("callbacks_enabled") is not False
        or config.get("restler_included") is not False
        or config.get("production_qualified") is not False
    ):
        raise ValueError("api_engine_artifact_drift")
    for name, version in locked.items():
        review = reviewed.get(name)
        if (
            review is None or review.get("version") != version or review.get("yanked") is not False
            or review.get("known_vulnerabilities") != 0 or review.get("status") != "reviewed"
            or not review.get("license")
        ):
            raise ValueError("api_engine_dependency_review_invalid")
    if wheel_path is not None and _sha(wheel_path) != EXPECTED_WHEEL_SHA256:
        raise ValueError("api_engine_wheel_mismatch")
    return config


def _locked_components(path: Path) -> dict[str, str]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ValueError("api_engine_lock_invalid") from exc
    result: dict[str, str] = {}
    for raw in lines:
        line = raw.strip()
        if line and not line.startswith("#") and "==" in line:
            name, version = line.split("==", 1)
            result[_canonical(name)] = version
    return result


def _canonical(value: object) -> str:
    return str(value).strip().lower().replace("_", "-").replace(".", "-")


def _sha(path: Path) -> str:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError as exc:
        raise ValueError("api_engine_artifact_input_invalid") from exc
