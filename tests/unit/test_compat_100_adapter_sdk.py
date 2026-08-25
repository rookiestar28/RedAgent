from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from redagent_platform.runner_service.contracts import (
    CredentialClass,
    ExecutionCapabilityManifest,
    NetworkMode,
    ResourceLimits,
)
from redagent_platform.runner_service.sdk import (
    AdapterArtifact,
    AdapterExecutionRequest,
    RunnerExecutionCoordinator,
    RunnerExecutionFailed,
    SyntheticConformanceAdapter,
)
from redagent_platform.secret_service.contracts import SecretMaterial


NOW = datetime(2026, 7, 10, 15, 0, tzinfo=timezone.utc)


def capability(*, timeout: int = 2, evidence_schema: tuple[str, ...] = ("synthetic-result-v1",)) -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(
        schema_version="1.0", capability_id="synthetic-conformance", revision=1,
        adapter_id="synthetic-conformance", adapter_version="1.0.0",
        image_digest="sha256:" + "a" * 64, input_schema_id="redagent.synthetic-job.v1",
        supported_modes=("synthetic",),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="synthetic-standard-v1", network_mode=NetworkMode.NONE,
        credential_class=CredentialClass.DYNAMIC_DATABASE, evidence_schema=evidence_schema,
        unsupported_features=("arbitrary_command", "native_template", "plugin_loading"),
        limits=ResourceLimits(cpu_millis=500, memory_mib=128, pids=32, timeout_seconds=timeout, evidence_bytes=65_536),
        artifact_receipt_id="artifact-r100", reviewed_by="reviewer-r100", status="certified",
    )


def request(tmp_path: Path, **overrides: object) -> AdapterExecutionRequest:
    values: dict[str, object] = {
        "execution_id": "execution-r100-1", "tenant_id": "tenant-a", "runner_id": "runner-1",
        "lease_id": "lease-1", "job_id": "job-1", "manifest_sha256": "1" * 64,
        "policy_decision_id": "decision-1", "capability": capability(),
        "workspace_root": tmp_path / "runner-work", "requested_at": NOW,
        "deadline": NOW + timedelta(seconds=5), "cancel_requested": False,
    }
    values.update(overrides)
    return AdapterExecutionRequest(**values)  # type: ignore[arg-type]


def test_successful_synthetic_adapter_runs_closed_phases_and_removes_isolated_workdir(tmp_path: Path) -> None:
    adapter = SyntheticConformanceAdapter()
    result = asyncio.run(RunnerExecutionCoordinator().run(request(tmp_path), adapter))
    assert result.outcome == "succeeded" and result.cleanup_completed
    assert result.phase_names == ("preflight", "prepare", "execute", "monitor", "collect", "normalize", "cleanup")
    assert result.artifact.schema_id == "synthetic-result-v1"
    assert result.artifact.content == b'{"result":"synthetic-ok"}'
    assert not (tmp_path / "runner-work" / "execution-r100-1").exists()


def test_secret_material_is_exposed_only_during_execute_then_cleared_and_never_in_receipts(tmp_path: Path) -> None:
    material = SecretMaterial({"password": bytearray(b"R100-SYNTHETIC-SDK-CANARY")})  # pragma: allowlist secret
    adapter = SyntheticConformanceAdapter(require_secret=True)
    result = asyncio.run(RunnerExecutionCoordinator().run(request(tmp_path), adapter, secret_material=material))
    assert material.cleared and adapter.secret_observation_sha256
    rendered = repr(result)
    assert "R100-SYNTHETIC-SDK-CANARY" not in rendered
    with pytest.raises(RuntimeError, match="already_consumed"):
        with material.expose_once():
            pass


def test_adapter_crash_invokes_cancel_and_cleanup_and_returns_no_partial_artifact(tmp_path: Path) -> None:
    adapter = SyntheticConformanceAdapter(fail_phase="execute")
    with pytest.raises(RunnerExecutionFailed, match="runner_adapter_execute_failed") as captured:
        asyncio.run(RunnerExecutionCoordinator().run(request(tmp_path), adapter))
    receipt = captured.value.receipt
    assert receipt.outcome == "failed" and receipt.cleanup_completed and receipt.artifact is None
    assert receipt.phase_names == ("preflight", "prepare", "execute", "cancel", "cleanup")
    assert not (tmp_path / "runner-work" / "execution-r100-1").exists()


def test_pre_requested_cancel_never_executes_or_collects_and_still_cleans_up(tmp_path: Path) -> None:
    adapter = SyntheticConformanceAdapter()
    with pytest.raises(RunnerExecutionFailed, match="runner_execution_cancelled") as captured:
        asyncio.run(RunnerExecutionCoordinator().run(request(tmp_path, cancel_requested=True), adapter))
    assert captured.value.receipt.phase_names == ("preflight", "prepare", "cancel", "cleanup")
    assert adapter.execution_count == 0 and captured.value.receipt.cleanup_completed


def test_timeout_invokes_cancel_cleanup_and_does_not_report_success(tmp_path: Path) -> None:
    adapter = SyntheticConformanceAdapter(execute_delay_seconds=1.1)
    timed = request(
        tmp_path,
        capability=capability(timeout=1),
        deadline=NOW + timedelta(seconds=1),
    )
    with pytest.raises(RunnerExecutionFailed, match="runner_adapter_timeout") as captured:
        asyncio.run(RunnerExecutionCoordinator().run(timed, adapter))
    assert captured.value.receipt.outcome == "failed" and captured.value.receipt.cleanup_completed
    assert "cancel" in captured.value.receipt.phase_names


def test_collect_rejects_undeclared_schema_oversize_or_hash_mismatch_and_cleans_up(tmp_path: Path) -> None:
    cases = (
        SyntheticConformanceAdapter(artifact=AdapterArtifact("unexpected-v1", "application/json", b"{}")),
        SyntheticConformanceAdapter(artifact=AdapterArtifact("synthetic-result-v1", "application/json", b"x" * 70_000)),
        SyntheticConformanceAdapter(artifact=AdapterArtifact("synthetic-result-v1", "application/json", b"{}", claimed_sha256="0" * 64)),
    )
    for index, adapter in enumerate(cases):
        current = request(tmp_path, execution_id=f"execution-r100-{index + 2}")
        with pytest.raises(RunnerExecutionFailed, match="runner_artifact_") as captured:
            asyncio.run(RunnerExecutionCoordinator().run(current, adapter))
        assert captured.value.receipt.cleanup_completed and captured.value.receipt.artifact is None
