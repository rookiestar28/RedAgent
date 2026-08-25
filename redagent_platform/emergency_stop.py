"""Emergency-stop operations workflow contracts.

This module orchestrates local stop records and review decisions. It does not
deliver notifications, terminate runner processes, dispatch jobs, or publish
reports.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from redagent_platform.credentials import CredentialBroker, CredentialLease
from redagent_platform.domain import JobStatus
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.job_queue import JobQueueState, JobRecord, JobTransitionDecision
from redagent_platform.kill_switch import (
    CANCELLABLE_STATUSES,
    CancellationEvidence,
    KillSwitchEnforcementResult,
    KillSwitchScope,
    RunnerCancellationResponse,
    RunnerCancellationStatus,
    enforce_kill_switch,
)


class EmergencyStopMode(str, Enum):
    LIVE = "live"
    REHEARSAL = "rehearsal"


class NotificationStatus(str, Enum):
    SENT = "sent"
    FAILED = "failed"


class RecoveryDecisionStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


@dataclass(frozen=True, kw_only=True)
class EmergencyStopRunbook:
    runbook_id: str
    notification_method: str
    stakeholder_user_ids: tuple[str, ...]
    recovery_reviewer_user_ids: tuple[str, ...]
    stop_sla_seconds: int


@dataclass(frozen=True, kw_only=True)
class StakeholderNotification:
    stakeholder_user_id: str
    method: str
    status: NotificationStatus
    reason: str
    notified_at: datetime
    notification_hash: str


@dataclass(frozen=True, kw_only=True)
class EmergencyStopRequest:
    stop_id: str
    mode: EmergencyStopMode
    scope: KillSwitchScope
    initiated_by_user_id: str
    reason: str
    requested_at: datetime
    runbook: EmergencyStopRunbook
    policy_simulation_hash: str | None = None
    notification_failure_user_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class RecoveryApproval:
    approval_id: str
    stop_id: str
    status: RecoveryDecisionStatus
    reviewer_user_id: str
    reason: str
    approved_at: datetime
    audit_event_hash: str
    approval_hash: str


@dataclass(frozen=True, kw_only=True)
class EmergencyStopRecord:
    stop_id: str
    mode: EmergencyStopMode
    engagement_id: str
    initiated_by_user_id: str
    reason: str
    requested_at: datetime
    affected_job_ids: tuple[str, ...]
    affected_credential_lease_ids: tuple[str, ...]
    notifications: tuple[StakeholderNotification, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...]
    policy_simulation_hash: str | None
    recovery: RecoveryApproval | None
    stop_hash: str


@dataclass(frozen=True, kw_only=True)
class EmergencyStopWorkflowResult:
    record: EmergencyStopRecord
    state: JobQueueState
    credential_broker: CredentialBroker
    dispatch_block: JobTransitionDecision


def execute_emergency_stop_workflow(
    *,
    request: EmergencyStopRequest,
    state: JobQueueState,
    credential_broker: CredentialBroker,
    leases_by_job_id: Mapping[str, CredentialLease],
    runner_responses: Mapping[str, RunnerCancellationResponse],
) -> EmergencyStopWorkflowResult:
    _validate_request(request)
    notifications = _notifications(request)
    if request.mode is EmergencyStopMode.LIVE:
        enforcement = enforce_kill_switch(
            scope=request.scope,
            state=state,
            credential_broker=credential_broker,
            leases_by_job_id=leases_by_job_id,
            runner_responses=runner_responses,
            reason=request.reason,
            actor_user_id=request.initiated_by_user_id,
            event_id=f"{request.stop_id}:kill-switch",
            occurred_at=request.requested_at,
        )
        affected_credentials = tuple(
            sorted(lease.id for job_id, lease in leases_by_job_id.items() if job_id in enforcement.cancelled_job_ids)
        )
        record = _record(
            request=request,
            affected_job_ids=enforcement.cancelled_job_ids,
            affected_credential_lease_ids=affected_credentials,
            notifications=notifications,
            cancellation_evidence=enforcement.evidence,
            recovery=None,
        )
        return EmergencyStopWorkflowResult(
            record=record,
            state=enforcement.state,
            credential_broker=enforcement.credential_broker,
            dispatch_block=enforcement.dispatch_block,
        )

    affected_jobs = tuple(sorted(job.job_id for job in state.jobs if _job_matches_scope(request.scope, job)))
    evidence = tuple(
        _rehearsal_evidence(
            job=job,
            request=request,
            response=runner_responses.get(job.job_id),
            credential_planned=job.job_id in leases_by_job_id,
        )
        for job in sorted(state.jobs, key=lambda item: item.job_id)
        if job.job_id in affected_jobs and job.status in CANCELLABLE_STATUSES
    )
    affected_credentials = tuple(sorted(lease.id for job_id, lease in leases_by_job_id.items() if job_id in affected_jobs))
    record = _record(
        request=request,
        affected_job_ids=affected_jobs,
        affected_credential_lease_ids=affected_credentials,
        notifications=notifications,
        cancellation_evidence=evidence,
        recovery=None,
    )
    return EmergencyStopWorkflowResult(
        record=record,
        state=state,
        credential_broker=credential_broker,
        dispatch_block=JobTransitionDecision(allowed=False, reason="emergency_stop_rehearsal_validated"),
    )


def emergency_stop_blocks_dispatch(record: EmergencyStopRecord, job: JobRecord) -> JobTransitionDecision:
    if record.recovery is not None and record.recovery.status is RecoveryDecisionStatus.APPROVED:
        return JobTransitionDecision(allowed=True, reason="emergency_stop_recovered")
    if job.engagement_id == record.engagement_id and job.job_id in record.affected_job_ids:
        return JobTransitionDecision(allowed=False, reason="emergency_stop_pending_review")
    return JobTransitionDecision(allowed=True, reason="not_affected")


def emergency_stop_blocks_publication(record: EmergencyStopRecord, report_id: str) -> JobTransitionDecision:
    _require_non_empty("report_id", report_id)
    if record.recovery is not None and record.recovery.status is RecoveryDecisionStatus.APPROVED:
        return JobTransitionDecision(allowed=True, reason="emergency_stop_recovered")
    return JobTransitionDecision(allowed=False, reason="emergency_stop_pending_review")


def approve_recovery(
    *,
    record: EmergencyStopRecord,
    approval_id: str,
    reviewer_user_id: str,
    reason: str,
    approved_at: datetime,
    notifications_reviewed: bool,
    cancellation_reviewed: bool,
    audit_chain: EvidenceChain,
) -> tuple[EmergencyStopRecord, EvidenceChain]:
    _require_non_empty("approval_id", approval_id)
    _require_non_empty("reviewer_user_id", reviewer_user_id)
    _require_non_empty("reason", reason)
    _require_timezone(approved_at)
    if _has_notification_failure(record) and not notifications_reviewed:
        raise ValueError("notification_failure_review_required")
    if _has_residual_cancellation_risk(record) and not cancellation_reviewed:
        raise ValueError("cancellation_evidence_review_required")
    next_chain = audit_chain.append_audit_event(
        event_id=f"{approval_id.strip()}:recovery",
        organization_id="emergency-stop",
        actor_user_id=reviewer_user_id.strip(),
        action=AuditAction.POLICY_DECISION,
        subject_type="emergency_stop_recovery",
        subject_id=record.stop_id,
        occurred_at=approved_at,
        details={
            "reason_hash": _sha256_text(reason.strip()),
            "notifications_reviewed": notifications_reviewed,
            "cancellation_reviewed": cancellation_reviewed,
            "stop_hash": record.stop_hash,
        },
    )
    payload = {
        "approval_id": approval_id.strip(),
        "stop_id": record.stop_id,
        "status": RecoveryDecisionStatus.APPROVED.value,
        "reviewer_user_id": reviewer_user_id.strip(),
        "reason_hash": _sha256_text(reason.strip()),
        "approved_at": approved_at.isoformat(),
        "audit_event_hash": next_chain.audit_events[-1].event_hash,
    }
    approval = RecoveryApproval(
        approval_id=approval_id.strip(),
        stop_id=record.stop_id,
        status=RecoveryDecisionStatus.APPROVED,
        reviewer_user_id=reviewer_user_id.strip(),
        reason=reason.strip(),
        approved_at=approved_at,
        audit_event_hash=next_chain.audit_events[-1].event_hash,
        approval_hash=_canonical_sha256(payload),
    )
    recovered = _record(
        request=_request_from_record(record),
        affected_job_ids=record.affected_job_ids,
        affected_credential_lease_ids=record.affected_credential_lease_ids,
        notifications=record.notifications,
        cancellation_evidence=record.cancellation_evidence,
        recovery=approval,
    )
    return recovered, next_chain


def _record(
    *,
    request: EmergencyStopRequest,
    affected_job_ids: tuple[str, ...],
    affected_credential_lease_ids: tuple[str, ...],
    notifications: tuple[StakeholderNotification, ...],
    cancellation_evidence: tuple[CancellationEvidence, ...],
    recovery: RecoveryApproval | None,
) -> EmergencyStopRecord:
    affected_job_ids = tuple(sorted(affected_job_ids))
    affected_credential_lease_ids = tuple(sorted(affected_credential_lease_ids))
    payload = {
        "stop_id": request.stop_id,
        "mode": request.mode.value,
        "engagement_id": request.scope.engagement_id,
        "initiated_by_user_id": request.initiated_by_user_id,
        "reason_hash": _sha256_text(request.reason),
        "requested_at": request.requested_at.isoformat(),
        "affected_job_ids": affected_job_ids,
        "affected_credential_lease_ids": affected_credential_lease_ids,
        "notifications": tuple(notification.notification_hash for notification in notifications),
        "cancellation_evidence": tuple(_cancellation_payload(item) for item in cancellation_evidence),
        "policy_simulation_hash": request.policy_simulation_hash,
        "recovery_hash": recovery.approval_hash if recovery else None,
    }
    return EmergencyStopRecord(
        stop_id=request.stop_id,
        mode=request.mode,
        engagement_id=request.scope.engagement_id,
        initiated_by_user_id=request.initiated_by_user_id,
        reason=request.reason,
        requested_at=request.requested_at,
        affected_job_ids=affected_job_ids,
        affected_credential_lease_ids=affected_credential_lease_ids,
        notifications=notifications,
        cancellation_evidence=cancellation_evidence,
        policy_simulation_hash=request.policy_simulation_hash,
        recovery=recovery,
        stop_hash=_canonical_sha256(payload),
    )


def _notifications(request: EmergencyStopRequest) -> tuple[StakeholderNotification, ...]:
    failures = set(request.notification_failure_user_ids)
    notifications = []
    for stakeholder in sorted(request.runbook.stakeholder_user_ids):
        status = NotificationStatus.FAILED if stakeholder in failures else NotificationStatus.SENT
        reason = "notification_failed" if status is NotificationStatus.FAILED else "notification_recorded"
        payload = {
            "stakeholder_user_id": stakeholder,
            "method": request.runbook.notification_method,
            "status": status.value,
            "reason": reason,
            "notified_at": request.requested_at.isoformat(),
        }
        notifications.append(
            StakeholderNotification(
                stakeholder_user_id=stakeholder,
                method=request.runbook.notification_method,
                status=status,
                reason=reason,
                notified_at=request.requested_at,
                notification_hash=_canonical_sha256(payload),
            )
        )
    return tuple(notifications)


def _rehearsal_evidence(
    *,
    job: JobRecord,
    request: EmergencyStopRequest,
    response: RunnerCancellationResponse | None,
    credential_planned: bool,
) -> CancellationEvidence:
    response = response or RunnerCancellationResponse(
        job_id=job.job_id,
        runner_id=job.runner_id,
        status=RunnerCancellationStatus.NOT_DISPATCHED,
        cleanup_attempted=False,
        cleanup_succeeded=False,
        responded_at=request.requested_at,
    )
    residual = "rehearsal_no_live_residual_risk" if response.status is RunnerCancellationStatus.TERMINATED else "rehearsal_follow_up_required"
    return CancellationEvidence(
        job_id=job.job_id,
        actor_user_id=request.initiated_by_user_id,
        reason=f"rehearsal:{request.reason}",
        occurred_at=request.requested_at,
        runner_status=response.status,
        cleanup_attempted=response.cleanup_attempted,
        cleanup_succeeded=response.cleanup_succeeded,
        credential_revoked=False,
        residual_risk=residual if not credential_planned else f"{residual}:credential_revocation_planned",
    )


def _job_matches_scope(scope: KillSwitchScope, job: JobRecord) -> bool:
    if job.engagement_id != scope.engagement_id:
        return False
    if scope.modes and job.mode not in scope.modes:
        return False
    if scope.target is not None and job.target.normalized() != scope.target.normalized():
        return False
    return True


def _request_from_record(record: EmergencyStopRecord) -> EmergencyStopRequest:
    return EmergencyStopRequest(
        stop_id=record.stop_id,
        mode=record.mode,
        scope=KillSwitchScope(engagement_id=record.engagement_id, target=None, modes=()),
        initiated_by_user_id=record.initiated_by_user_id,
        reason=record.reason,
        requested_at=record.requested_at,
        runbook=EmergencyStopRunbook(
            runbook_id="recovered-record",
            notification_method="recorded",
            stakeholder_user_ids=tuple(notification.stakeholder_user_id for notification in record.notifications),
            recovery_reviewer_user_ids=(),
            stop_sla_seconds=1,
        ),
        policy_simulation_hash=record.policy_simulation_hash,
    )


def _has_notification_failure(record: EmergencyStopRecord) -> bool:
    return any(notification.status is NotificationStatus.FAILED for notification in record.notifications)


def _has_residual_cancellation_risk(record: EmergencyStopRecord) -> bool:
    return any(item.residual_risk != "none_identified" for item in record.cancellation_evidence)


def _validate_request(request: EmergencyStopRequest) -> None:
    for field_name, value in (
        ("stop_id", request.stop_id),
        ("initiated_by_user_id", request.initiated_by_user_id),
        ("reason", request.reason),
        ("runbook_id", request.runbook.runbook_id),
        ("notification_method", request.runbook.notification_method),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    if not request.scope.modes:
        raise ValueError("emergency_stop_modes_required")
    if not request.runbook.stakeholder_user_ids:
        raise ValueError("stakeholders_required")
    if not request.runbook.recovery_reviewer_user_ids:
        raise ValueError("recovery_reviewers_required")
    if request.runbook.stop_sla_seconds <= 0:
        raise ValueError("stop_sla_invalid")


def _cancellation_payload(item: CancellationEvidence) -> dict[str, object]:
    return {
        "job_id": item.job_id,
        "actor_user_id": item.actor_user_id,
        "reason_hash": _sha256_text(item.reason),
        "occurred_at": item.occurred_at.isoformat(),
        "runner_status": item.runner_status.value,
        "cleanup_attempted": item.cleanup_attempted,
        "cleanup_succeeded": item.cleanup_succeeded,
        "credential_revoked": item.credential_revoked,
        "residual_risk": item.residual_risk,
    }


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
