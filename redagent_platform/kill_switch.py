"""Kill-switch and cancellation enforcement contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from redagent_platform.credentials import CredentialBroker, CredentialLease, CredentialRevocationReason
from redagent_platform.domain import JobStatus, TestMode
from redagent_platform.evidence_chain import AuditAction
from redagent_platform.job_queue import JobQueueState, JobRecord, JobTransitionDecision
from redagent_platform.scope_authorization import ScopeTarget


class RunnerCancellationStatus(str, Enum):
    TERMINATED = "terminated"
    TIMEOUT = "timeout"
    CLEANUP_FAILED = "cleanup_failed"
    NOT_DISPATCHED = "not_dispatched"


@dataclass(frozen=True, kw_only=True)
class KillSwitchScope:
    engagement_id: str
    target: ScopeTarget | None
    modes: tuple[TestMode, ...]


@dataclass(frozen=True, kw_only=True)
class RunnerCancellationResponse:
    job_id: str
    runner_id: str | None
    status: RunnerCancellationStatus
    cleanup_attempted: bool
    cleanup_succeeded: bool
    responded_at: datetime


@dataclass(frozen=True, kw_only=True)
class CancellationEvidence:
    job_id: str
    actor_user_id: str
    reason: str
    occurred_at: datetime
    runner_status: RunnerCancellationStatus
    cleanup_attempted: bool
    cleanup_succeeded: bool
    credential_revoked: bool
    residual_risk: str


@dataclass(frozen=True, kw_only=True)
class KillSwitchEnforcementResult:
    state: JobQueueState
    credential_broker: CredentialBroker
    cancelled_job_ids: tuple[str, ...]
    evidence: tuple[CancellationEvidence, ...]
    dispatch_block: JobTransitionDecision


CANCELLABLE_STATUSES = frozenset({JobStatus.QUEUED, JobStatus.DISPATCHED, JobStatus.RUNNING, JobStatus.CLEANUP})


def kill_switch_blocks_dispatch(scope: KillSwitchScope, job: JobRecord) -> JobTransitionDecision:
    _validate_scope(scope)
    if _job_matches_scope(scope, job):
        return JobTransitionDecision(allowed=False, reason="kill_switch_active")
    return JobTransitionDecision(allowed=True, reason="not_affected")


def enforce_kill_switch(
    *,
    scope: KillSwitchScope,
    state: JobQueueState,
    credential_broker: CredentialBroker,
    leases_by_job_id: Mapping[str, CredentialLease],
    runner_responses: Mapping[str, RunnerCancellationResponse],
    reason: str,
    actor_user_id: str,
    event_id: str,
    occurred_at: datetime,
) -> KillSwitchEnforcementResult:
    _validate_scope(scope)
    _require_non_empty("reason", reason)
    _require_non_empty("actor_user_id", actor_user_id)
    _require_non_empty("event_id", event_id)
    _require_timezone(occurred_at)
    next_state = state
    next_broker = credential_broker
    cancelled: list[str] = []
    evidence: list[CancellationEvidence] = []
    for job in state.jobs:
        if not _job_matches_scope(scope, job) or job.status not in CANCELLABLE_STATUSES:
            continue
        next_state, decision = next_state.cancel_job(
            job.job_id,
            reason=f"kill_switch:{reason}",
            actor_user_id=actor_user_id,
            event_id=f"{event_id}:cancel:{job.job_id}",
            occurred_at=occurred_at,
        )
        if not decision.allowed:
            continue
        cancelled.append(job.job_id)
        lease = leases_by_job_id.get(job.job_id)
        credential_revoked = False
        if lease is not None:
            next_broker, _ = next_broker.revoke_lease(
                lease,
                reason=CredentialRevocationReason.KILL_SWITCH,
                actor_user_id=actor_user_id,
                audit_event_id=f"{event_id}:credential:{job.job_id}",
                revoked_at=occurred_at,
            )
            credential_revoked = True
        response = runner_responses.get(job.job_id) or RunnerCancellationResponse(
            job_id=job.job_id,
            runner_id=job.runner_id,
            status=RunnerCancellationStatus.NOT_DISPATCHED,
            cleanup_attempted=False,
            cleanup_succeeded=False,
            responded_at=occurred_at,
        )
        evidence.append(_evidence(job, actor_user_id, reason, occurred_at, response, credential_revoked))

    audited_chain = next_state.audit_chain.append_audit_event(
        event_id=event_id,
        organization_id="kill_switch",
        actor_user_id=actor_user_id,
        action=AuditAction.SCHEDULER_CONTROL,
        subject_type="kill_switch",
        subject_id=scope.engagement_id,
        occurred_at=occurred_at,
        details={
            "reason": reason,
            "cancelled_job_ids": tuple(cancelled),
            "evidence_count": len(evidence),
        },
    )
    next_state = JobQueueState(
        jobs=next_state.jobs,
        processed_callback_ids=next_state.processed_callback_ids,
        audit_chain=audited_chain,
    )
    return KillSwitchEnforcementResult(
        state=next_state,
        credential_broker=next_broker,
        cancelled_job_ids=tuple(cancelled),
        evidence=tuple(evidence),
        dispatch_block=JobTransitionDecision(allowed=False, reason="kill_switch_active"),
    )


def _evidence(
    job: JobRecord,
    actor_user_id: str,
    reason: str,
    occurred_at: datetime,
    response: RunnerCancellationResponse,
    credential_revoked: bool,
) -> CancellationEvidence:
    if response.status is RunnerCancellationStatus.TERMINATED and response.cleanup_succeeded and credential_revoked:
        residual_risk = "none_identified"
    elif response.status is RunnerCancellationStatus.TIMEOUT:
        residual_risk = "runner_timeout_requires_operator_review"
    elif response.status is RunnerCancellationStatus.CLEANUP_FAILED:
        residual_risk = "cleanup_failed_requires_manual_verification"
    else:
        residual_risk = "credential_or_cleanup_follow_up_required"
    return CancellationEvidence(
        job_id=job.job_id,
        actor_user_id=actor_user_id,
        reason=reason,
        occurred_at=occurred_at,
        runner_status=response.status,
        cleanup_attempted=response.cleanup_attempted,
        cleanup_succeeded=response.cleanup_succeeded,
        credential_revoked=credential_revoked,
        residual_risk=residual_risk,
    )


def _job_matches_scope(scope: KillSwitchScope, job: JobRecord) -> bool:
    if job.engagement_id != scope.engagement_id:
        return False
    if scope.modes and job.mode not in scope.modes:
        return False
    if scope.target is not None and job.target.normalized() != scope.target.normalized():
        return False
    return True


def _validate_scope(scope: KillSwitchScope) -> None:
    _require_non_empty("engagement_id", scope.engagement_id)
    if not scope.modes:
        raise ValueError("kill_switch_modes_required")


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
