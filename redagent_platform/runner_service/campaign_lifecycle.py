"""PostgreSQL runner lifecycle ownership for compat_123 closed adapter dispatch."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
from typing import Protocol

from sqlalchemy import and_, select

from redagent_platform.persistence.models import metadata
from redagent_platform.runner_service.identity import PeerCertificateIdentity
from redagent_platform.runner_service.campaign_dispatch import (
    AdapterTerminalReceipt,
    CampaignAdapterRequest,
)
from redagent_platform.runner_service.repository import (
    RunnerRepository,
    RunnerRepositoryConflict,
)


class RunnerIdentityOwner(Protocol):
    async def read_current_identity(
        self,
        *,
        tenant_id: str,
        runner_id: str,
        now: datetime,
    ) -> PeerCertificateIdentity: ...


@dataclass(frozen=True, slots=True)
class PostgresRunnerLifecycleHandle:
    tenant_id: str
    lease_id: str
    generation: int
    policy_decision_id: str
    expires_at: datetime
    lease_token: bytearray = field(repr=False)


class PostgresRunnerLifecycleOwner:
    """Claim, run, and finalize the already-issued v2 manifest through compat_100 owners."""

    def __init__(
        self,
        sessions: object,
        identity_owner: RunnerIdentityOwner,
        *,
        actor_user_id: str = "redagent-r123-runner",
    ) -> None:
        self._sessions = sessions
        self._identity_owner = identity_owner
        self._actor_user_id = actor_user_id

    def execution_deadline(self, handle: object) -> datetime:
        if not isinstance(handle, PostgresRunnerLifecycleHandle):
            raise RunnerRepositoryConflict("r123_runner_handle_invalid")
        return handle.expires_at

    async def begin(
        self,
        request: CampaignAdapterRequest,
        *,
        occurred_at: datetime,
    ) -> PostgresRunnerLifecycleHandle:
        async with self._sessions() as session, session.begin():
            row = await _manifest_runtime_row(session, request)
        identity = await self._identity_owner.read_current_identity(
            tenant_id=request.tenant_id,
            runner_id=str(row["runner_id"]),
            now=occurred_at,
        )
        stable = hashlib.sha256(
            f"{request.tenant_id}\0{request.effect_id}".encode("utf-8")
        ).hexdigest()[:24]
        async with self._sessions() as session, session.begin():
            lease = await _repository(
                session,
                request.tenant_id,
                self._actor_user_id,
                f"r123-runner-claim-{stable}",
            ).claim_manifest(
                manifest_record_id=str(row["manifest_record_id"]),
                identity=identity,
                claim_id=f"r123-claim-{stable}",
                environment=str(row["environment"]),
                runner_class_id=str(row["runner_class_id"]),
                policy_revision=str(row["required_policy_revision"]),
                generation=int(row["generation"]),
                occurred_at=occurred_at,
            )
        if lease.lease_token is None:
            # CRITICAL: an ephemeral lease token is never reconstructed from PostgreSQL.
            raise RunnerRepositoryConflict("r123_runner_claim_token_unavailable")
        handle = PostgresRunnerLifecycleHandle(
            tenant_id=request.tenant_id,
            lease_id=lease.lease_id,
            generation=int(row["generation"]),
            policy_decision_id=str(row["policy_decision_id"]),
            lease_token=lease.lease_token,
            expires_at=lease.expires_at,
        )
        async with self._sessions() as session, session.begin():
            repository = _repository(
                session,
                request.tenant_id,
                self._actor_user_id,
                f"r123-runner-begin-{stable}",
            )
            await repository.begin_execution(
                lease_id=handle.lease_id,
                lease_token=handle.lease_token,
                generation=handle.generation,
                occurred_at=occurred_at,
            )
            await repository.record_lifecycle_event(
                lease_id=handle.lease_id,
                lease_token=handle.lease_token,
                generation=handle.generation,
                event_id=f"r123-preflight-{stable}",
                phase="preflight",
                phase_state="completed",
                reason_code=None,
                metadata_values={},
                occurred_at=occurred_at,
            )
        return handle

    async def complete(
        self,
        request: CampaignAdapterRequest,
        handle: PostgresRunnerLifecycleHandle,
        receipt: AdapterTerminalReceipt,
        *,
        occurred_at: datetime,
    ) -> AdapterTerminalReceipt:
        _validate_handle(request, handle)
        if (
            receipt.state != "confirmed"
            or receipt.external_receipt_id is None
            or receipt.cleanup_receipt_id is None
            or len(receipt.evidence_ids) != 1
        ):
            raise RunnerRepositoryConflict("r123_runner_terminal_receipt_invalid")
        evidence_id = receipt.evidence_ids[0]
        async with self._sessions() as session, session.begin():
            evidence_sha256 = await _evidence_sha256(
                session,
                tenant_id=request.tenant_id,
                lease_id=handle.lease_id,
                evidence_id=evidence_id,
            )
            stable = hashlib.sha256(
                f"{request.tenant_id}\0{request.effect_id}".encode("utf-8")
            ).hexdigest()[:24]
            repository = _repository(
                session,
                request.tenant_id,
                self._actor_user_id,
                f"r123-runner-finalize-{stable}",
            )
            for phase, values in (
                ("collect", {"artifact_sha256": evidence_sha256}),
                ("normalize", {"artifact_sha256": evidence_sha256}),
                ("cleanup", {"cleanup_completed": True}),
            ):
                await repository.record_lifecycle_event(
                    lease_id=handle.lease_id,
                    lease_token=handle.lease_token,
                    generation=handle.generation,
                    event_id=f"r123-{phase}-{stable}",
                    phase=phase,
                    phase_state="completed",
                    reason_code=None,
                    metadata_values=values,
                    occurred_at=occurred_at,
                )
            await repository.finalize_execution(
                lease_id=handle.lease_id,
                lease_token=handle.lease_token,
                generation=handle.generation,
                execution_id=receipt.external_receipt_id,
                evidence_artifact_id=evidence_id,
                outcome="succeeded",
                final_phase="cleanup",
                policy_decision_id=handle.policy_decision_id,
                evidence_sha256=evidence_sha256,
                cleanup_completed=True,
                residual_risk=None,
                occurred_at=occurred_at,
            )
        _clear(handle.lease_token)
        return receipt

    async def ambiguity(
        self,
        request: CampaignAdapterRequest,
        handle: PostgresRunnerLifecycleHandle,
        *,
        failure_code: str,
        occurred_at: datetime,
    ) -> None:
        _validate_handle(request, handle)
        stable = hashlib.sha256(
            f"{request.tenant_id}\0{request.effect_id}".encode("utf-8")
        ).hexdigest()[:24]
        async with self._sessions() as session, session.begin():
            await _repository(
                session,
                request.tenant_id,
                self._actor_user_id,
                f"r123-runner-ambiguous-{stable}",
            ).record_lifecycle_event(
                lease_id=handle.lease_id,
                lease_token=handle.lease_token,
                generation=handle.generation,
                event_id=f"r123-monitor-{stable}",
                phase="monitor",
                phase_state="failed",
                reason_code=failure_code,
                metadata_values={},
                occurred_at=occurred_at,
            )
        _clear(handle.lease_token)


async def _manifest_runtime_row(session: object, request: CampaignAdapterRequest):
    manifests = metadata.tables["runner_job_manifests"]
    registrations = metadata.tables["runner_registrations"]
    classes = metadata.tables["runner_classes"]
    row = (
        await session.execute(
            select(
                manifests.c.id.label("manifest_record_id"),
                manifests.c.policy_decision_id,
                registrations.c.runner_id,
                registrations.c.environment,
                registrations.c.required_policy_revision,
                registrations.c.generation,
                classes.c.class_id.label("runner_class_id"),
            )
            .join(
                registrations,
                and_(
                    registrations.c.tenant_id == manifests.c.tenant_id,
                    registrations.c.id == manifests.c.runner_registration_id,
                ),
            )
            .join(
                classes,
                and_(
                    classes.c.tenant_id == registrations.c.tenant_id,
                    classes.c.id == registrations.c.runner_class_record_id,
                ),
            )
            .where(
                manifests.c.tenant_id == request.tenant_id,
                manifests.c.manifest_sha256 == request.manifest_v2_sha256,
                manifests.c.capability_id == request.capability_id,
                manifests.c.capability_revision == request.capability_revision,
            )
        )
    ).mappings().one_or_none()
    if row is None:
        raise RunnerRepositoryConflict("r123_runner_manifest_not_found")
    return row


async def _evidence_sha256(
    session: object,
    *,
    tenant_id: str,
    lease_id: str,
    evidence_id: str,
) -> str:
    artifacts = metadata.tables["evidence_artifacts"]
    leases = metadata.tables["runner_pull_leases"]
    manifests = metadata.tables["runner_job_manifests"]
    value = await session.scalar(
        select(artifacts.c.content_sha256)
        .join(manifests, manifests.c.job_id == artifacts.c.job_id)
        .join(leases, leases.c.manifest_id == manifests.c.id)
        .where(
            artifacts.c.tenant_id == tenant_id,
            artifacts.c.id == evidence_id,
            artifacts.c.artifact_class.in_(("report_safe", "export_safe")),
            artifacts.c.quarantine_reason.is_(None),
            artifacts.c.finalized_at.is_not(None),
            leases.c.tenant_id == tenant_id,
            leases.c.id == lease_id,
        )
    )
    if value is None:
        raise RunnerRepositoryConflict("r123_runner_evidence_not_owned")
    return str(value)


def _validate_handle(
    request: CampaignAdapterRequest,
    handle: PostgresRunnerLifecycleHandle,
) -> None:
    if not isinstance(handle, PostgresRunnerLifecycleHandle) or (
        handle.tenant_id != request.tenant_id
    ):
        raise RunnerRepositoryConflict("r123_runner_handle_mismatch")


def _repository(
    session: object,
    tenant_id: str,
    actor_user_id: str,
    correlation_id: str,
) -> RunnerRepository:
    return RunnerRepository(
        session,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        correlation_id=correlation_id,
    )


def _clear(value: bytearray) -> None:
    for index in range(len(value)):
        value[index] = 0
