"""PostgreSQL-backed adapters that bind the compat_100 dispatcher to compat_097/compat_098 services."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib
from pathlib import Path
from typing import Any, Callable

from sqlalchemy import select, text, update

from redagent_platform.evidence_service.contracts import ArtifactWriteRequest
from redagent_platform.containment_service.repository import ContainmentRepository
from redagent_platform.evidence_service.service import EvidenceIngestResult, EvidenceService
from redagent_platform.orchestration.contracts import RunnerDispatchCommand
from redagent_platform.persistence.models import metadata
from redagent_platform.runner_service.contracts import (
    ExecutionCapabilityManifest,
    SignedJobManifest,
)
from redagent_platform.runner_service.dispatch import (
    PreparedSyntheticDispatch,
    RunnerCurrentFacts,
)
from redagent_platform.runner_service.identity import PeerCertificateIdentity
from redagent_platform.runner_service.repository import RunnerRepository
from redagent_platform.runner_service.sdk import (
    AdapterArtifact,
    AdapterExecutionReceipt,
    AdapterExecutionRequest,
    SyntheticConformanceAdapter,
)
from redagent_platform.runner_service.secret_mailbox import EphemeralSecretMailbox
from redagent_platform.secret_service.broker import SecretLeaseBroker
from redagent_platform.secret_service.contracts import LeaseIssueRequest, SecretMaterial


@dataclass(frozen=True, slots=True, kw_only=True)
class PersistentRunnerBinding:
    tenant_id: str
    actor_user_id: str
    runner_registration_id: str
    identity: PeerCertificateIdentity
    environment: str
    runner_class_id: str
    policy_revision: str
    generation: int
    capability_revision: int
    capability: ExecutionCapabilityManifest
    adapter: SyntheticConformanceAdapter
    workspace_root: Path
    sandbox_verified: bool

    def __post_init__(self) -> None:
        for value in (
            self.tenant_id, self.actor_user_id, self.runner_registration_id,
            self.environment, self.runner_class_id, self.policy_revision,
        ):
            if not isinstance(value, str) or not value or len(value) > 100:
                raise ValueError("runner_persistent_binding_invalid")
        if isinstance(self.generation, bool) or self.generation < 1:
            raise ValueError("runner_persistent_binding_invalid")
        if isinstance(self.capability_revision, bool) or self.capability_revision < 1:
            raise ValueError("runner_persistent_binding_invalid")
        if not isinstance(self.workspace_root, Path) or not isinstance(self.sandbox_verified, bool):
            raise ValueError("runner_persistent_binding_invalid")


class PersistentSyntheticRunnerBackend:
    """Authoritative local/conformance assembly; all executable choices are pre-bound."""

    def __init__(
        self,
        sessions: Any,
        binding: PersistentRunnerBinding,
        *,
        manifest_factory: Callable[..., SignedJobManifest],
        secret_broker: SecretLeaseBroker | None,
        secret_mailbox: EphemeralSecretMailbox | None,
        secret_request_factory: Callable[..., LeaseIssueRequest] | None,
        evidence_service: EvidenceService,
        evidence_request_factory: Callable[..., ArtifactWriteRequest],
    ) -> None:
        if sessions is None or not isinstance(binding, PersistentRunnerBinding):
            raise ValueError("runner_persistent_backend_dependencies_required")
        if not callable(manifest_factory) or not callable(evidence_request_factory):
            raise ValueError("runner_persistent_backend_factories_required")
        if any(value is not None for value in (secret_broker, secret_mailbox, secret_request_factory)) and any(
            value is None for value in (secret_broker, secret_mailbox, secret_request_factory)
        ):
            raise ValueError("runner_persistent_secret_dependencies_incomplete")
        self._sessions = sessions
        self._binding = binding
        self._manifest_factory = manifest_factory
        self._secret_broker = secret_broker
        self._secret_mailbox = secret_mailbox
        self._secret_request_factory = secret_request_factory
        self._evidence_service = evidence_service
        self._evidence_request_factory = evidence_request_factory
        self._prepared: PreparedSyntheticDispatch | None = None
        self._secret_lease: dict[str, object] | None = None
        self._evidence: EvidenceIngestResult | None = None

    async def current_facts(
        self, command: RunnerDispatchCommand, *, action: str, occurred_at: datetime,
    ) -> RunnerCurrentFacts:
        binding = self._binding
        if command.tenant_id != binding.tenant_id:
            raise RuntimeError("runner_dispatch_tenant_mismatch")
        async with self._sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": binding.tenant_id})
            jobs = metadata.tables["jobs"]
            job = (await session.execute(select(jobs.c.campaign_id).where(
                jobs.c.tenant_id == binding.tenant_id, jobs.c.id == command.job_id,
            ))).mappings().one_or_none()
            if job is None:
                raise RuntimeError("runner_job_not_found")
            active_control = await ContainmentRepository(
                session, tenant_id=binding.tenant_id,
                actor_user_id=binding.actor_user_id,
                correlation_id=f"runner-containment:{command.job_id}",
            ).active_control(
                campaign_id=str(job["campaign_id"]) if job["campaign_id"] else None,
                job_id=command.job_id,
                capability_id=binding.capability.capability_id,
            )
            if active_control is not None:
                raise RuntimeError("runner_containment_active")
            registrations = metadata.tables["runner_registrations"]
            capabilities = metadata.tables["execution_capability_manifests"]
            artifacts = metadata.tables["artifact_verification_receipts"]
            registration = (await session.execute(select(registrations).where(
                registrations.c.tenant_id == binding.tenant_id,
                registrations.c.id == binding.runner_registration_id,
            ))).mappings().one_or_none()
            capability = (await session.execute(select(capabilities).where(
                capabilities.c.tenant_id == binding.tenant_id,
                capabilities.c.capability_id == binding.capability.capability_id,
                capabilities.c.capability_revision == binding.capability_revision,
            ))).mappings().one_or_none()
            artifact = None
            if capability is not None:
                artifact = (await session.execute(select(artifacts).where(
                    artifacts.c.tenant_id == binding.tenant_id,
                    artifacts.c.receipt_id == capability["artifact_receipt_id"],
                    artifacts.c.image_digest == capability["image_digest"],
                ))).mappings().one_or_none()
            manifest_state, lease_state = await self._current_work_state(session, action)
        if registration is None:
            raise RuntimeError("runner_registration_not_found")
        artifact_status = "verified" if (
            artifact is not None and artifact["signature_verified"] and artifact["expires_at"] > occurred_at
        ) else "unverified"
        capability_status = str(capability["capability_status"]) if capability is not None else "missing"
        sandbox_status = "certified" if action in {"runner.manifest.issue", "runner.manifest.claim"} else (
            "verified" if binding.sandbox_verified else "degraded"
        )
        return RunnerCurrentFacts(
            tenant_id=binding.tenant_id, runner_id=str(registration["runner_id"]),
            job_id=command.job_id, registration_state=str(registration["registration_state"]),
            capability_status=capability_status, artifact_status=artifact_status,
            manifest_state=manifest_state, lease_state=lease_state,
            identity_generation=binding.generation, runner_generation=int(registration["generation"]),
            sandbox_status=sandbox_status,
            cleanup_required="cleanup" in tuple(binding.capability.phases),
            policy_reference=command.policy_reference, roe_version_id=command.roe_version_id,
        )

    async def issue_manifest(
        self, command: RunnerDispatchCommand, *, authorization: Any,
        occurred_at: datetime, correlation_id: str,
    ) -> PreparedSyntheticDispatch:
        signed = self._manifest_factory(
            command=command, authorization=authorization, occurred_at=occurred_at,
        )
        if not isinstance(signed, SignedJobManifest):
            raise RuntimeError("runner_manifest_factory_invalid")
        manifest = signed.manifest
        if (
            manifest.tenant_id != command.tenant_id or manifest.job_id != command.job_id
            or manifest.policy_decision_id != authorization.decision_id
        ):
            raise RuntimeError("runner_manifest_factory_mismatch")
        async with self._sessions() as session, session.begin():
            row = await self._repository(session, correlation_id).issue_manifest(
                signed, runner_registration_id=self._binding.runner_registration_id,
                capability_revision=self._binding.capability_revision,
                idempotency_key=command.dispatch_id, occurred_at=occurred_at,
            )
        request = AdapterExecutionRequest(
            execution_id=f"execution-{command.dispatch_id}", tenant_id=command.tenant_id,
            runner_id=self._binding.identity.runner_id, lease_id="pending-lease",
            job_id=command.job_id, manifest_sha256=signed.manifest_sha256,
            policy_decision_id=authorization.decision_id,
            capability=self._binding.capability, workspace_root=self._binding.workspace_root,
            requested_at=occurred_at, deadline=manifest.expires_at, cancel_requested=False,
        )
        prepared = PreparedSyntheticDispatch(
            request=request, adapter=self._binding.adapter,
            requires_secret=bool(manifest.secret_reference_ids),
            manifest_record_id=str(row["id"]),
        )
        self._prepared = prepared
        return prepared

    async def claim_manifest(
        self, prepared: PreparedSyntheticDispatch, *, authorization: Any,
        occurred_at: datetime, correlation_id: str,
    ) -> PreparedSyntheticDispatch:
        if prepared.manifest_record_id is None:
            raise RuntimeError("runner_manifest_record_missing")
        async with self._sessions() as session, session.begin():
            grant = await self._repository(session, correlation_id).claim_manifest(
                manifest_record_id=prepared.manifest_record_id,
                identity=self._binding.identity, claim_id=f"claim-{prepared.request.job_id}",
                environment=self._binding.environment, runner_class_id=self._binding.runner_class_id,
                policy_revision=self._binding.policy_revision, generation=self._binding.generation,
                occurred_at=occurred_at,
            )
        if grant.lease_token is None:
            raise RuntimeError("runner_pull_token_unavailable")
        claimed = replace(
            prepared,
            request=replace(prepared.request, lease_id=grant.lease_id),
            lease_token=grant.lease_token,
        )
        self._prepared = claimed
        return claimed

    async def resolve_secret(
        self, prepared: PreparedSyntheticDispatch, *, authorization: Any,
        occurred_at: datetime, correlation_id: str,
    ) -> SecretMaterial:
        if self._secret_broker is None or self._secret_mailbox is None or self._secret_request_factory is None:
            raise RuntimeError("runner_secret_service_unavailable")
        request = self._secret_request_factory(prepared=prepared, occurred_at=occurred_at)
        issued = await self._secret_broker.issue(
            request, actor_user_id=self._binding.actor_user_id,
            correlation_id=_stage_correlation(correlation_id, "secret-issue"),
        )
        self._secret_lease = issued.lease
        return self._secret_mailbox.take_once()

    async def mark_running(
        self, prepared: PreparedSyntheticDispatch, *, execution_receipt: AdapterExecutionReceipt,
        occurred_at: datetime, correlation_id: str,
    ) -> None:
        token = self._lease_token(prepared)
        async with self._sessions() as session, session.begin():
            repository = self._repository(session, correlation_id)
            await repository.begin_execution(
                lease_id=prepared.request.lease_id, lease_token=token,
                generation=self._binding.generation, occurred_at=occurred_at,
            )
            for index, phase in enumerate(execution_receipt.phases):
                await repository.record_lifecycle_event(
                    lease_id=prepared.request.lease_id, lease_token=token,
                    generation=self._binding.generation,
                    event_id=f"{prepared.request.execution_id}-{index}", phase=phase.phase,
                    phase_state=phase.state, reason_code=phase.reason,
                    metadata_values={"cleanup_completed": execution_receipt.cleanup_completed}
                    if phase.phase == "cleanup" else {},
                    occurred_at=occurred_at,
                )

    async def submit_evidence(
        self, prepared: PreparedSyntheticDispatch, artifact: AdapterArtifact, *,
        execution_receipt: AdapterExecutionReceipt, authorization: Any,
        occurred_at: datetime, correlation_id: str,
    ) -> tuple[str, ...]:
        request = self._evidence_request_factory(
            prepared=prepared, artifact=artifact, authorization=authorization,
            occurred_at=occurred_at,
        )
        if not isinstance(request, ArtifactWriteRequest) or request.content != artifact.content:
            raise RuntimeError("runner_evidence_request_invalid")
        self._evidence = await self._evidence_service.ingest(
            request, actor_user_id=self._binding.actor_user_id,
            correlation_id=_stage_correlation(correlation_id, "evidence-ingest"),
            occurred_at=occurred_at,
        )
        return (str(self._evidence.artifact["artifact_id"]),)

    async def revoke_secret(
        self, prepared: PreparedSyntheticDispatch, *, occurred_at: datetime, correlation_id: str,
    ) -> None:
        if self._secret_lease is None:
            return
        if self._secret_broker is None:
            raise RuntimeError("runner_secret_service_unavailable")
        result = await self._secret_broker.revoke(
            tenant_id=self._binding.tenant_id,
            lease_id=str(self._secret_lease["id"]),
            expected_version=int(self._secret_lease["version"]),
            actor_user_id=self._binding.actor_user_id,
            correlation_id=_stage_correlation(correlation_id, "secret-revoke"),
            occurred_at=occurred_at,
        )
        self._secret_lease = result.lease

    async def finalize(
        self, prepared: PreparedSyntheticDispatch, *, evidence_ids: tuple[str, ...],
        execution_receipt: AdapterExecutionReceipt, policy_receipt_ids: tuple[str, ...],
        occurred_at: datetime, correlation_id: str,
    ) -> None:
        if self._evidence is None or evidence_ids != (str(self._evidence.artifact["artifact_id"]),):
            raise RuntimeError("runner_evidence_finalization_mismatch")
        token = self._lease_token(prepared)
        async with self._sessions() as session, session.begin():
            await self._repository(session, correlation_id).finalize_execution(
                lease_id=prepared.request.lease_id, lease_token=token,
                generation=self._binding.generation,
                execution_id=prepared.request.execution_id,
                evidence_artifact_id=evidence_ids[0], outcome="succeeded", final_phase="cleanup",
                policy_decision_id=prepared.request.policy_decision_id,
                evidence_sha256=str(self._evidence.artifact["content_sha256"]),
                cleanup_completed=execution_receipt.cleanup_completed, residual_risk=None,
                occurred_at=occurred_at,
            )
            jobs = metadata.tables["jobs"]
            # CRITICAL: compat_101 persists dispatch_started before the Activity; finalization must consume dispatching.
            changed = await session.execute(update(jobs).where(
                jobs.c.tenant_id == self._binding.tenant_id,
                jobs.c.id == prepared.request.job_id,
                jobs.c.orchestration_state == "dispatching",
            ).values(
                status="succeeded", orchestration_state="succeeded",
                orchestration_revision=jobs.c.orchestration_revision + 1,
                current_gate="runner_evidence_finalized", dispatch_blocked=True,
                failure_code=None, version=jobs.c.version + 1, updated_at=occurred_at,
            ))
            if changed.rowcount != 1:
                raise RuntimeError("runner_job_finalization_conflict")
        self._clear_token(prepared)

    async def fail(
        self, prepared: PreparedSyntheticDispatch, *, failure_code: str,
        execution_receipt: AdapterExecutionReceipt | None,
        occurred_at: datetime, correlation_id: str,
    ) -> None:
        if prepared.lease_token is None:
            return
        token = self._lease_token(prepared)
        async with self._sessions() as session, session.begin():
            repository = self._repository(session, correlation_id)
            if self._evidence is not None:
                await repository.finalize_execution(
                    lease_id=prepared.request.lease_id, lease_token=token,
                    generation=self._binding.generation,
                    execution_id=prepared.request.execution_id,
                    evidence_artifact_id=str(self._evidence.artifact["artifact_id"]),
                    outcome="failed", final_phase="cleanup",
                    policy_decision_id=prepared.request.policy_decision_id,
                    evidence_sha256=str(self._evidence.artifact["content_sha256"]),
                    cleanup_completed=execution_receipt.cleanup_completed if execution_receipt else True,
                    residual_risk=failure_code, occurred_at=occurred_at,
                )
            else:
                await repository.fail_execution(
                    lease_id=prepared.request.lease_id, lease_token=token,
                    generation=self._binding.generation,
                    execution_id=prepared.request.execution_id,
                    policy_decision_id=prepared.request.policy_decision_id,
                    failure_code=failure_code,
                    cleanup_completed=execution_receipt.cleanup_completed if execution_receipt else True,
                    occurred_at=occurred_at,
                )
        self._clear_token(prepared)

    async def _current_work_state(self, session: Any, action: str) -> tuple[str, str]:
        if action == "runner.manifest.issue":
            return "draft", "absent"
        if self._prepared is None or self._prepared.manifest_record_id is None:
            return "missing", "absent"
        manifests = metadata.tables["runner_job_manifests"]
        leases = metadata.tables["runner_pull_leases"]
        manifest_state = await session.scalar(select(manifests.c.manifest_state).where(
            manifests.c.tenant_id == self._binding.tenant_id,
            manifests.c.id == self._prepared.manifest_record_id,
        ))
        lease_state = await session.scalar(select(leases.c.lease_state).where(
            leases.c.tenant_id == self._binding.tenant_id,
            leases.c.manifest_id == self._prepared.manifest_record_id,
        ))
        return str(manifest_state or "missing"), str(lease_state or "absent")

    def _repository(self, session: Any, correlation_id: str) -> RunnerRepository:
        return RunnerRepository(
            session, tenant_id=self._binding.tenant_id,
            actor_user_id=self._binding.actor_user_id,
            correlation_id=_stage_correlation(correlation_id, "repository"),
        )

    @staticmethod
    def _lease_token(prepared: PreparedSyntheticDispatch) -> bytearray:
        if prepared.lease_token is None:
            raise RuntimeError("runner_pull_token_unavailable")
        return prepared.lease_token

    @staticmethod
    def _clear_token(prepared: PreparedSyntheticDispatch) -> None:
        if prepared.lease_token is not None:
            prepared.lease_token[:] = b"\x00" * len(prepared.lease_token)


def _stage_correlation(correlation_id: str, stage: str) -> str:
    digest = hashlib.sha256(f"{correlation_id}\0{stage}".encode("utf-8")).hexdigest()
    return f"runner-{stage[:20]}-{digest[:48]}"
