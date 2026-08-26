from __future__ import annotations

import json
import os
from pathlib import Path

import yaml
import pytest

from scripts import otel_conformance


ROOT = Path(__file__).resolve().parents[2]


def test_collector_image_and_compose_are_digest_pinned_private_and_hardened() -> None:
    lock = json.loads((ROOT / "config" / "otel-collector-conformance-image.json").read_text(encoding="utf-8"))
    assert lock["version"] == "0.153.0"
    assert lock["platform_digest"] == "sha256:388054389612c69d0387ecac256338e4086f6cf072fc8feafb6ce7968dc6946c"
    assert lock["reference"].endswith("@" + lock["index_digest"])
    assert lock["purpose"] == "local-conformance-only"
    assert lock["production_qualified"] is False
    compose = yaml.safe_load((ROOT / "compose.otel-conformance.yaml").read_text(encoding="utf-8"))
    service = compose["services"]["otel-collector"]
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["ports"] == ["127.0.0.1:58431:4317", "127.0.0.1:51318:13133"]
    assert service["tmpfs"] == ["/tmp"]
    assert service["volumes"][-1] == {
        "type": "bind",
        "source": "${REDAGENT_OTEL_RECEIPT_DIR:?conformance-owned receipt directory required}",
        "target": "/receipt",
    }
    assert "extra_hosts" not in service
    assert compose["networks"]["telemetry-conformance"]["internal"] is True


def test_collector_pipeline_is_closed_redacted_bounded_and_has_no_debug_exporter() -> None:
    config_path = ROOT / "config" / "otel-collector" / "collector-conformance.yaml"
    config_text = config_path.read_text(encoding="utf-8")
    config = yaml.safe_load(config_text)
    assert config["processors"]["redaction"]["allow_all_keys"] is False
    assert config["processors"]["redaction"]["summary"] == "silent"
    assert config["processors"]["memory_limiter"]["limit_mib"] == 128
    assert set(config["exporters"]) == {"file/fixed_siem"}
    exporter = config["exporters"]["file/fixed_siem"]
    assert exporter["path"] == "/receipt/redagent-otel-receipt.json"
    assert exporter["flush_interval"] == "100ms"
    assert "host.docker.internal" not in config_text
    assert not any(name.startswith("debug") for name in config["exporters"])
    pipelines = config["service"]["pipelines"]
    assert set(pipelines) == {"traces", "metrics"}
    for pipeline in pipelines.values():
        assert pipeline["processors"] == ["memory_limiter", "redaction", "batch"]
        assert pipeline["exporters"] == ["file/fixed_siem"]


def test_collector_receipt_requires_one_exact_bounded_regular_file(tmp_path: Path) -> None:
    payload = b'{"resourceSpans":[]}\n'
    receipt = tmp_path / "redagent-otel-receipt.json"
    receipt.write_bytes(payload)
    assert otel_conformance._read_receipt(tmp_path) == payload

    (tmp_path / "unexpected.json").write_text("{}\n", encoding="utf-8")
    with pytest.raises(otel_conformance.ConformanceError, match="collector_receipt_entries_invalid"):
        otel_conformance._read_receipt(tmp_path)
    (tmp_path / "unexpected.json").unlink()

    receipt.write_bytes(b"x" * (64 * 1024 + 1))
    with pytest.raises(otel_conformance.ConformanceError, match="collector_receipt_payload_too_large"):
        otel_conformance._read_receipt(tmp_path)


def test_collector_receipt_rejects_a_link(tmp_path: Path) -> None:
    target = tmp_path.parent / f"{tmp_path.name}-target.json"
    target.write_text("{}\n", encoding="utf-8")
    receipt = tmp_path / "redagent-otel-receipt.json"
    try:
        receipt.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink unavailable: {exc}")

    with pytest.raises(otel_conformance.ConformanceError, match="collector_receipt_member_invalid"):
        otel_conformance._read_receipt(tmp_path)


def test_collector_receipt_rejects_simulated_windows_reparse_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "redagent-otel-receipt.json"
    receipt.write_text("{}\n", encoding="utf-8")
    original = otel_conformance._is_linklike

    def simulated_reparse(path: Path, metadata: os.stat_result) -> bool:
        return path == receipt or original(path, metadata)

    monkeypatch.setattr(otel_conformance, "_is_linklike", simulated_reparse)
    with pytest.raises(otel_conformance.ConformanceError, match="collector_receipt_member_invalid"):
        otel_conformance._read_receipt(tmp_path)


def test_collector_receipt_rejects_open_identity_drift(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    receipt = tmp_path / "redagent-otel-receipt.json"
    receipt.write_text("{}\n", encoding="utf-8")
    original_fstat = os.fstat

    def drifting_fstat(descriptor: int):
        metadata = original_fstat(descriptor)
        return type(metadata)(
            (
                metadata.st_mode,
                metadata.st_ino + 1,
                metadata.st_dev,
                metadata.st_nlink,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_size,
                metadata.st_atime,
                metadata.st_mtime,
                metadata.st_ctime,
            )
        )

    monkeypatch.setattr(os, "fstat", drifting_fstat)
    with pytest.raises(otel_conformance.ConformanceError, match="collector_receipt_identity_changed"):
        otel_conformance._read_receipt(tmp_path)


def test_missing_collector_is_pulled_by_exact_digest_then_reverified(monkeypatch) -> None:
    lock = json.loads((ROOT / "config" / "otel-collector-conformance-image.json").read_text(encoding="utf-8"))
    calls: list[tuple[tuple[str, ...], bool]] = []

    def fake_docker(*args: str, check: bool = True) -> str:
        calls.append((args, check))
        if args[:2] == ("image", "inspect") and "RepoDigests" in args[-1]:
            return "" if len(calls) == 1 else f"docker.io/otel/opentelemetry-collector-contrib@{lock['index_digest']}"
        if args[:2] == ("image", "inspect"):
            return "linux/amd64"
        return "pulled"

    monkeypatch.setattr(otel_conformance, "_docker", fake_docker)

    otel_conformance._ensure_collector_image(lock)

    assert calls == [
        (("image", "inspect", lock["reference"], "--format", "{{index .RepoDigests 0}}"), False),
        (("pull", "--platform", "linux/amd64", lock["reference"]), True),
        (("image", "inspect", lock["reference"], "--format", "{{index .RepoDigests 0}}"), True),
        (("image", "inspect", lock["reference"], "--format", "{{.Os}}/{{.Architecture}}"), True),
    ]


def test_started_collector_cleanup_is_required_and_uses_the_isolated_environment(monkeypatch) -> None:
    environment = {"PATH": "/safe/bin", "DOCKER_CONFIG": "/contained/docker"}

    def failing_docker(*args: str, **kwargs: object) -> str:
        assert args == ("rm", "--force", "collector-exact")
        assert kwargs == {"environment": environment}
        raise otel_conformance.ConformanceError("docker_failed:rm:denied")

    monkeypatch.setattr(otel_conformance, "_docker", failing_docker)

    with pytest.raises(otel_conformance.ConformanceError, match="collector_cleanup_failed"):
        otel_conformance._remove_collector(
            "collector-exact",
            environment=environment,
            required=True,
            body_error=None,
        )


def test_cleanup_failure_preserves_the_primary_collector_failure(monkeypatch) -> None:
    environment = {"PATH": "/safe/bin", "DOCKER_CONFIG": "/contained/docker"}

    def failing_docker(*_args: str, **_kwargs: object) -> str:
        raise otel_conformance.ConformanceError("docker_failed:rm:denied")

    monkeypatch.setattr(otel_conformance, "_docker", failing_docker)

    primary = otel_conformance.ConformanceError("collector_receipt_timeout")
    with pytest.raises(
        otel_conformance.ConformanceError,
        match="collector_receipt_timeout:collector_cleanup_failed",
    ):
        otel_conformance._remove_collector(
            "collector-exact",
            environment=environment,
            required=True,
            body_error=primary,
        )
