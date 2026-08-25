"""Fail-closed compat_100 synthetic dispatch across policy, secret, adapter, and evidence."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from typing import Any

from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    RunnerDispatchCommand,
    RunnerDispatchResult,
)
from redagent_platform.runner_service.sdk import (
    AdapterExecutionReceipt,
    AdapterExecutionRequest,
    RunnerExecutionCoordinator,
    RunnerExecutionFailed,
    SyntheticConformanceAdapter,
)
from redagent_platform.secret_service.contracts import SecretMaterial


_STAGE_PERMISSIONS = {
    "runner.manifest.issue": "runner:issue",
    "runner.manifest.claim": "runner:claim",
    "runner.secret.resolve": "runner:secret",
    "runner.execute": "runner:execute",
    "runner.evidence.submit": "runner:evidence",
}


@dataclass(frozen=True, slots=True, kw_only=True)
class RunnerCurrentFacts:
    tenant_id: str
    runner_id: str
    job_id: str
    registration_state: str
    capability_status: str
    artifact_status: str
    manifest_state: str
    lease_state: str
    identity_generation: int
    runner_generation: int
    sandbox_status: str
    cleanup_required: bool
    policy_reference: str
    roe_version_id: str

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.runner_id, self.job_id, self.roe_version_id):
            if not isinstance(value, str) or not value or len(value) > 100:
                raise ValueError("runner_current_facts_invalid")
        if not isinstance(self.cleanup_required, bool):
            raise ValueError("runner_current_facts_invalid")
        for value in (self.identity_generation, self.runner_generation):
            if isinstance(value, bool) or value < 1:
                raise ValueError("runner_current_facts_invalid")


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class PreparedSyntheticDispatch:
    request: AdapterExecutionRequest
    adapter: SyntheticConformanceAdapter
    requires_secret: bool
    manifest_record_id: str | None = None
    lease_token: bytearray | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.request, AdapterExecutionRequest):
            raise ValueError("runner_prepared_request_invalid")
        if not isinstance(self.adapter, SyntheticConformanceAdapter) or not isinstance(self.requires_secret, bool):
            raise ValueError("runner_prepared_adapter_invalid")
        if self.manifest_record_id is not None and (not self.manifest_record_id or len(self.manifest_record_id) > 100):
            raise ValueError("runner_prepared_manifest_invalid")
        if self.lease_token is not None and not isinstance(self.lease_token, bytearray):
            raise ValueError("runner_prepared_lease_invalid")

    def __repr__(self) -> str:
        return (
            f"<PreparedSyntheticDispatch execution_id={self.request.execution_id!r} "
            f"job_id={self.request.job_id!r} manifest_record_id={self.manifest_record_id!r} "
            f"lease_token=<redacted> requires_secret={self.requires_secret!r}>"
        )


class SyntheticRunnerDispatcher:
    """Coordinates only the certified synthetic compat_100 path through injected authoritative services."""

    def __init__(self, policy_sdk: Any, backend: Any, coordinator: RunnerExecutionCoordinator) -> None:
        if policy_sdk is None or backend is None or not isinstance(coordinator, RunnerExecutionCoordinator):
            raise ValueError("runner_dispatch_dependencies_required")
        self._policy = policy_sdk
        self._backend = backend
        self._coordinator = coordinator

    async def dispatch(
        self,
        command: RunnerDispatchCommand,
        *,
        occurred_at: datetime,
        correlation_id: str,
    ) -> RunnerDispatchResult:
        if not isinstance(command, RunnerDispatchCommand):
            raise ValueError("runner_dispatch_command_invalid")
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("runner_dispatch_timezone_required")
        prepared: PreparedSyntheticDispatch | None = None
        execution_receipt: AdapterExecutionReceipt | None = None
        secret_material: SecretMaterial | None = None
        policy_receipts: list[str] = []
        failure_code: str | None = None
        evidence_ids: tuple[str, ...] = ()
        try:
            issue_auth = await self._authorize(command, "runner.manifest.issue", occurred_at, correlation_id)
            policy_receipts.append(issue_auth.receipt_id)
            prepared = await self._backend.issue_manifest(
                command, authorization=issue_auth, occurred_at=occurred_at,
                correlation_id=correlation_id,
            )
            if not isinstance(prepared, PreparedSyntheticDispatch) or prepared.request.job_id != command.job_id:
                raise RuntimeError("runner_prepare_result_invalid")

            claim_auth = await self._authorize(command, "runner.manifest.claim", occurred_at, correlation_id)
            policy_receipts.append(claim_auth.receipt_id)
            claimed = await self._backend.claim_manifest(
                prepared, authorization=claim_auth, occurred_at=occurred_at,
                correlation_id=correlation_id,
            )
            if claimed is not None:
                if not isinstance(claimed, PreparedSyntheticDispatch):
                    raise RuntimeError("runner_claim_result_invalid")
                prepared = claimed

            if prepared.requires_secret:
                secret_auth = await self._authorize(command, "runner.secret.resolve", occurred_at, correlation_id)
                policy_receipts.append(secret_auth.receipt_id)
                secret_material = await self._backend.resolve_secret(
                    prepared, authorization=secret_auth, occurred_at=occurred_at,
                    correlation_id=correlation_id,
                )
                if not isinstance(secret_material, SecretMaterial):
                    raise RuntimeError("runner_secret_resolution_invalid")

            execute_auth = await self._authorize(command, "runner.execute", occurred_at, correlation_id)
            policy_receipts.append(execute_auth.receipt_id)
            prepared = replace(
                prepared,
                request=replace(prepared.request, policy_decision_id=execute_auth.decision_id),
            )
            execution_receipt = await self._coordinator.run(
                prepared.request, prepared.adapter, secret_material=secret_material,
            )
            await self._backend.mark_running(
                prepared, execution_receipt=execution_receipt, occurred_at=occurred_at,
                correlation_id=correlation_id,
            )

            evidence_auth = await self._authorize(command, "runner.evidence.submit", occurred_at, correlation_id)
            policy_receipts.append(evidence_auth.receipt_id)
            if execution_receipt.artifact is None or not execution_receipt.cleanup_completed:
                raise RuntimeError("runner_evidence_submission_not_ready")
            evidence_ids = await self._backend.submit_evidence(
                prepared, execution_receipt.artifact, execution_receipt=execution_receipt,
                authorization=evidence_auth, occurred_at=occurred_at,
                correlation_id=correlation_id,
            )
            if not isinstance(evidence_ids, tuple) or not evidence_ids:
                raise RuntimeError("runner_evidence_receipt_invalid")
        except RunnerExecutionFailed as exc:
            execution_receipt = exc.receipt
            failure_code = str(exc)
        except Exception as exc:
            failure_code = (
                "runner_policy_denied" if "policy" in str(exc)
                else str(exc) if str(exc).startswith("runner_")
                else "runner_dispatch_failed"
            )
        finally:
            if secret_material is not None:
                if not secret_material.cleared:
                    try:
                        with secret_material.expose_once():
                            pass
                    except RuntimeError:
                        pass
                try:
                    if prepared is not None:
                        await self._backend.revoke_secret(
                            prepared, occurred_at=occurred_at, correlation_id=correlation_id,
                        )
                except Exception:
                    failure_code = "runner_secret_revoke_unconfirmed"

        if prepared is None:
            raise RuntimeError(failure_code or "runner_dispatch_failed")
        if failure_code is not None:
            try:
                await self._backend.fail(
                    prepared, failure_code=failure_code, execution_receipt=execution_receipt,
                    occurred_at=occurred_at, correlation_id=correlation_id,
                )
            except Exception as exc:
                # CRITICAL: a failed terminal receipt must never be hidden behind a normal workflow result.
                raise RuntimeError("runner_failure_persistence_failed") from exc
            return RunnerDispatchResult(
                schema_version=CONTRACT_SCHEMA_VERSION, job_id=command.job_id,
                execution_id=prepared.request.execution_id,
                manifest_sha256=prepared.request.manifest_sha256, evidence_ids=(),
                state="failed",
                cleanup_completed=execution_receipt.cleanup_completed if execution_receipt else True,
                failure_code=failure_code,
            )

        await self._backend.finalize(
            prepared, evidence_ids=evidence_ids, execution_receipt=execution_receipt,
            policy_receipt_ids=tuple(policy_receipts), occurred_at=occurred_at,
            correlation_id=correlation_id,
        )
        return RunnerDispatchResult(
            schema_version=CONTRACT_SCHEMA_VERSION, job_id=command.job_id,
            execution_id=prepared.request.execution_id,
            manifest_sha256=prepared.request.manifest_sha256,
            evidence_ids=evidence_ids, state="succeeded", cleanup_completed=True,
            failure_code=None,
        )

    async def _authorize(
        self, command: RunnerDispatchCommand, action: str,
        occurred_at: datetime, correlation_id: str,
    ) -> Any:
        facts = await self._backend.current_facts(
            command, action=action, occurred_at=occurred_at,
        )
        if not isinstance(facts, RunnerCurrentFacts):
            raise RuntimeError("runner_current_facts_invalid")
        return await self._policy.enforce_runner(
            tenant_id=facts.tenant_id, subject_id=facts.runner_id, action=action,
            permissions=(_STAGE_PERMISSIONS[action],), job_id=facts.job_id,
            registration_state=facts.registration_state,
            capability_status=facts.capability_status,
            artifact_status=facts.artifact_status,
            manifest_state=facts.manifest_state, lease_state=facts.lease_state,
            identity_generation=facts.identity_generation,
            runner_generation=facts.runner_generation,
            sandbox_status=facts.sandbox_status,
            cleanup_required=facts.cleanup_required,
            policy_reference=facts.policy_reference,
            roe_version_id=facts.roe_version_id,
            correlation_id=correlation_id, requested_at=occurred_at,
        )
