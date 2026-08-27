"""Closed compat_100 adapter lifecycle and deterministic synthetic conformance adapter."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime
import hashlib
from pathlib import Path
import shutil
from typing import Mapping

from redagent_platform.runner_service.contracts import ExecutionCapabilityManifest
from redagent_platform.secret_service.contracts import SecretMaterial


@dataclass(frozen=True)
class AdapterArtifact:
    schema_id: str
    content_type: str
    content: bytes
    claimed_sha256: str | None = None

    def __post_init__(self) -> None:
        if not self.schema_id or len(self.schema_id) > 100:
            raise ValueError("runner_artifact_schema_invalid")
        if self.content_type != "application/json":
            raise ValueError("runner_artifact_content_type_invalid")
        if not isinstance(self.content, bytes) or not self.content:
            raise ValueError("runner_artifact_content_invalid")
        if self.claimed_sha256 is not None and (
            len(self.claimed_sha256) != 64
            or any(character not in "0123456789abcdef" for character in self.claimed_sha256)
        ):
            raise ValueError("runner_artifact_claimed_hash_invalid")

    @property
    def content_sha256(self) -> str:
        return hashlib.sha256(self.content).hexdigest()


@dataclass(frozen=True, kw_only=True)
class AdapterExecutionRequest:
    execution_id: str
    tenant_id: str
    runner_id: str
    lease_id: str
    job_id: str
    manifest_sha256: str
    policy_decision_id: str
    capability: ExecutionCapabilityManifest
    workspace_root: Path
    requested_at: datetime
    deadline: datetime
    cancel_requested: bool

    def __post_init__(self) -> None:
        for name in ("execution_id", "tenant_id", "runner_id", "lease_id", "job_id", "policy_decision_id"):
            value = getattr(self, name)
            if not isinstance(value, str) or not value or len(value) > 100:
                raise ValueError(f"runner_{name}_invalid")
        if len(self.manifest_sha256) != 64 or any(value not in "0123456789abcdef" for value in self.manifest_sha256):
            raise ValueError("runner_manifest_sha256_invalid")
        if not isinstance(self.workspace_root, Path):
            raise ValueError("runner_workspace_root_invalid")
        _aware(self.requested_at)
        _aware(self.deadline)
        if not self.requested_at < self.deadline:
            raise ValueError("runner_execution_deadline_invalid")
        if not isinstance(self.cancel_requested, bool):
            raise ValueError("runner_cancel_state_invalid")


@dataclass(frozen=True, slots=True)
class PhaseReceipt:
    phase: str
    state: str
    reason: str


@dataclass(frozen=True, kw_only=True)
class AdapterExecutionReceipt:
    execution_id: str
    outcome: str
    phases: tuple[PhaseReceipt, ...]
    cleanup_completed: bool
    artifact: AdapterArtifact | None
    failure_code: str | None

    @property
    def phase_names(self) -> tuple[str, ...]:
        return tuple(item.phase for item in self.phases)

    def __repr__(self) -> str:
        artifact = None if self.artifact is None else {
            "schema_id": self.artifact.schema_id,
            "content_type": self.artifact.content_type,
            "size": len(self.artifact.content),
            "sha256": self.artifact.content_sha256,
        }
        return (
            f"AdapterExecutionReceipt(execution_id={self.execution_id!r}, outcome={self.outcome!r}, "
            f"phases={self.phases!r}, cleanup_completed={self.cleanup_completed!r}, "
            f"artifact={artifact!r}, failure_code={self.failure_code!r})"
        )


class RunnerExecutionFailed(RuntimeError):
    def __init__(self, reason: str, receipt: AdapterExecutionReceipt) -> None:
        super().__init__(reason)
        self.receipt = receipt


class SyntheticConformanceAdapter:
    """Benign no-network adapter used only to prove the runner lifecycle."""

    adapter_id = "synthetic-conformance"
    adapter_version = "1.0.0"

    def __init__(
        self,
        *,
        require_secret: bool = False,
        fail_phase: str | None = None,
        execute_delay_seconds: float = 0,
        artifact: AdapterArtifact | None = None,
    ) -> None:
        self.require_secret = require_secret
        self.fail_phase = fail_phase
        self.execute_delay_seconds = execute_delay_seconds
        self.artifact = artifact or AdapterArtifact(
            schema_id="synthetic-result-v1",
            content_type="application/json",
            content=b'{"result":"synthetic-ok"}',
        )
        self.execution_count = 0
        self.secret_observation_sha256: str | None = None

    async def preflight(self, request: AdapterExecutionRequest, workdir: Path) -> None:
        self._fail("preflight")
        if request.capability.adapter_id != self.adapter_id or request.capability.adapter_version != self.adapter_version:
            raise RuntimeError("runner_adapter_identity_mismatch")
        if request.capability.network_mode.value != "none":
            raise RuntimeError("runner_adapter_network_forbidden")

    async def prepare(self, request: AdapterExecutionRequest, workdir: Path) -> None:
        self._fail("prepare")
        if not workdir.is_dir():
            raise RuntimeError("runner_adapter_workdir_missing")

    async def execute(
        self,
        request: AdapterExecutionRequest,
        workdir: Path,
        secret_fields: Mapping[str, memoryview] | None,
    ) -> None:
        self._fail("execute")
        self.execution_count += 1
        if self.require_secret and not secret_fields:
            raise RuntimeError("runner_adapter_secret_required")
        if secret_fields:
            digest = hashlib.sha256()
            for name in sorted(secret_fields):
                digest.update(name.encode("utf-8"))
                digest.update(secret_fields[name])
            self.secret_observation_sha256 = digest.hexdigest()
        if self.execute_delay_seconds:
            await asyncio.sleep(self.execute_delay_seconds)

    async def monitor(self, request: AdapterExecutionRequest, workdir: Path) -> None:
        self._fail("monitor")

    async def cancel(self, request: AdapterExecutionRequest, workdir: Path) -> None:
        self._fail("cancel")

    async def collect(self, request: AdapterExecutionRequest, workdir: Path) -> AdapterArtifact:
        self._fail("collect")
        return self.artifact

    async def normalize(
        self, request: AdapterExecutionRequest, workdir: Path, artifact: AdapterArtifact,
    ) -> AdapterArtifact:
        self._fail("normalize")
        return artifact

    async def cleanup(self, request: AdapterExecutionRequest, workdir: Path) -> None:
        self._fail("cleanup")

    def _fail(self, phase: str) -> None:
        if self.fail_phase == phase:
            raise RuntimeError(f"runner_adapter_{phase}_failed")


class RunnerExecutionCoordinator:
    async def run(
        self,
        request: AdapterExecutionRequest,
        adapter: SyntheticConformanceAdapter,
        *,
        secret_material: SecretMaterial | None = None,
    ) -> AdapterExecutionReceipt:
        root = request.workspace_root.resolve()
        workdir = (root / request.execution_id).resolve()
        if not workdir.is_relative_to(root) or workdir == root:
            raise ValueError("runner_workdir_scope_invalid")
        phases: list[PhaseReceipt] = []
        artifact: AdapterArtifact | None = None
        cleanup_completed = False
        prepared = False
        failure_code: str | None = None
        root.mkdir(parents=True, exist_ok=True)
        workdir.mkdir(parents=False, exist_ok=False)
        try:
            await self._phase("preflight", phases, adapter.preflight(request, workdir))
            await self._phase("prepare", phases, adapter.prepare(request, workdir))
            prepared = True
            if request.cancel_requested:
                raise RuntimeError("runner_execution_cancelled")
            timeout = min(
                request.capability.limits.timeout_seconds,
                max(0.001, (request.deadline - request.requested_at).total_seconds()),
            )
            phases.append(PhaseReceipt("execute", "started", "runner_phase_started"))
            try:
                if secret_material is None:
                    await asyncio.wait_for(adapter.execute(request, workdir, None), timeout=timeout)
                else:
                    with secret_material.expose_once() as fields:
                        await asyncio.wait_for(adapter.execute(request, workdir, fields), timeout=timeout)
            except TimeoutError as exc:
                raise RuntimeError("runner_adapter_timeout") from exc
            except RuntimeError:
                raise
            phases[-1] = PhaseReceipt("execute", "completed", "runner_phase_completed")
            await self._phase("monitor", phases, adapter.monitor(request, workdir))
            phases.append(PhaseReceipt("collect", "started", "runner_phase_started"))
            artifact = await adapter.collect(request, workdir)
            self._validate_artifact(request, artifact)
            phases[-1] = PhaseReceipt("collect", "completed", "runner_phase_completed")
            await self._phase("normalize", phases, adapter.normalize(request, workdir, artifact))
        except BaseException as exc:
            failure_code = str(exc) if isinstance(exc, RuntimeError) and str(exc).startswith("runner_") else "runner_adapter_failed"
            if secret_material is not None and not secret_material.cleared:
                try:
                    with secret_material.expose_once():
                        pass
                except RuntimeError:
                    pass
            if prepared:
                phases.append(PhaseReceipt("cancel", "started", "runner_phase_started"))
                try:
                    await adapter.cancel(request, workdir)
                    phases[-1] = PhaseReceipt("cancel", "completed", "runner_phase_completed")
                except BaseException:  # noqa: BLE001
                    phases[-1] = PhaseReceipt("cancel", "failed", "runner_adapter_cancel_failed")
            cleanup_completed = await self._cleanup(request, adapter, workdir, phases)
            receipt = AdapterExecutionReceipt(
                execution_id=request.execution_id, outcome="failed", phases=tuple(phases),
                cleanup_completed=cleanup_completed, artifact=None, failure_code=failure_code,
            )
            raise RunnerExecutionFailed(failure_code, receipt) from exc
        cleanup_completed = await self._cleanup(request, adapter, workdir, phases)
        if not cleanup_completed:
            receipt = AdapterExecutionReceipt(
                execution_id=request.execution_id, outcome="failed", phases=tuple(phases),
                cleanup_completed=False, artifact=None, failure_code="runner_cleanup_failed",
            )
            raise RunnerExecutionFailed("runner_cleanup_failed", receipt)
        return AdapterExecutionReceipt(
            execution_id=request.execution_id, outcome="succeeded", phases=tuple(phases),
            cleanup_completed=True, artifact=artifact, failure_code=None,
        )

    async def _phase(self, name: str, phases: list[PhaseReceipt], awaitable) -> object:
        phases.append(PhaseReceipt(name, "started", "runner_phase_started"))
        try:
            result = await awaitable
        except BaseException:
            phases[-1] = PhaseReceipt(name, "failed", f"runner_adapter_{name}_failed")
            raise
        phases[-1] = PhaseReceipt(name, "completed", "runner_phase_completed")
        return result

    async def _cleanup(
        self,
        request: AdapterExecutionRequest,
        adapter: SyntheticConformanceAdapter,
        workdir: Path,
        phases: list[PhaseReceipt],
    ) -> bool:
        phases.append(PhaseReceipt("cleanup", "started", "runner_phase_started"))
        completed = True
        try:
            await adapter.cleanup(request, workdir)
        except BaseException:  # noqa: BLE001
            completed = False
        finally:
            shutil.rmtree(workdir, ignore_errors=False)
        phases[-1] = PhaseReceipt(
            "cleanup", "completed" if completed else "failed",
            "runner_phase_completed" if completed else "runner_adapter_cleanup_failed",
        )
        return completed and not workdir.exists()

    @staticmethod
    def _validate_artifact(request: AdapterExecutionRequest, artifact: AdapterArtifact) -> None:
        if artifact.schema_id not in request.capability.evidence_schema:
            raise RuntimeError("runner_artifact_schema_undeclared")
        if len(artifact.content) > request.capability.limits.evidence_bytes:
            raise RuntimeError("runner_artifact_size_exceeded")
        if artifact.claimed_sha256 is not None and artifact.claimed_sha256 != artifact.content_sha256:
            raise RuntimeError("runner_artifact_hash_mismatch")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
