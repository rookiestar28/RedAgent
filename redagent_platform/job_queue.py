"""Job queue state machine and runner callback contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum

from redagent_platform.domain import JobStatus, PolicyDecisionOutcome, TestMode
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.scheduler import ScheduleDecision
from redagent_platform.scope_authorization import ScopeTarget


class RunnerCallbackKind(str, Enum):
    STARTED = "started"
    HEARTBEAT = "heartbeat"
    RESULT = "result"
    CLEANUP_STARTED = "cleanup_started"
    CLEANUP_COMPLETED = "cleanup_completed"
    COMPLETED = "completed"
    FAILED = "failed"


@dataclass(frozen=True, kw_only=True)
class PolicyGrant:
    decision_id: str
    organization_id: str
    outcome: PolicyDecisionOutcome
    decided_at: datetime
    expires_at: datetime
    reason: str


@dataclass(frozen=True, kw_only=True)
class RunnerContract:
    runner_id: str
    organization_id: str
    capabilities: tuple[TestMode, ...]
    policy_token_reference: str
    target_scope: ScopeTarget
    timeout_seconds: int
    heartbeat_interval_seconds: int
    result_schema: tuple[str, ...]
    cleanup_callback: str
    credential_lease_id: str | None = None


@dataclass(frozen=True, kw_only=True)
class JobRecord:
    job_id: str
    organization_id: str
    engagement_id: str
    test_definition_id: str
    target: ScopeTarget
    mode: TestMode
    status: JobStatus
    projected_interactions: int
    timeout_seconds: int
    cleanup_required: bool
    max_attempts: int
    attempts: int = 0
    runner_id: str | None = None
    policy_decision_id: str | None = None
    policy_expires_at: datetime | None = None
    last_transition_at: datetime | None = None
    last_heartbeat_at: datetime | None = None
    evidence_ids: tuple[str, ...] = ()
    failure_reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class RunnerCallback:
    callback_id: str
    runner_id: str
    job_id: str
    kind: RunnerCallbackKind
    occurred_at: datetime
    evidence_ids: tuple[str, ...] = ()
    message: str | None = None


@dataclass(frozen=True, kw_only=True)
class JobTransitionDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class JobQueueState:
    jobs: tuple[JobRecord, ...] = ()
    processed_callback_ids: frozenset[str] = frozenset()
    audit_chain: EvidenceChain = EvidenceChain()

    def authorize_job(
        self,
        job: JobRecord,
        grant: PolicyGrant,
        *,
        actor_user_id: str,
        event_id: str,
        occurred_at: datetime,
    ) -> tuple["JobQueueState", JobTransitionDecision]:
        _validate_job(job)
        _validate_policy_grant(grant, job, occurred_at)
        if job.status is not JobStatus.PLANNED:
            return self, JobTransitionDecision(allowed=False, reason="job_must_be_planned")
        authorized = _replace_job(
            job,
            status=JobStatus.AUTHORIZED,
            policy_decision_id=grant.decision_id,
            policy_expires_at=grant.expires_at,
            last_transition_at=occurred_at,
        )
        return self._upsert_job(authorized, actor_user_id, event_id, occurred_at, "authorized"), JobTransitionDecision(
            allowed=True, reason="authorized"
        )

    def queue_authorized_job(
        self,
        job_id: str,
        schedule_decision: ScheduleDecision,
        *,
        actor_user_id: str,
        event_id: str,
        occurred_at: datetime,
    ) -> tuple["JobQueueState", JobTransitionDecision]:
        job = self._require_job(job_id)
        if not schedule_decision.allowed:
            return self, JobTransitionDecision(allowed=False, reason=f"scheduler_{schedule_decision.reason}")
        if not _policy_is_current(job, occurred_at):
            return self, JobTransitionDecision(allowed=False, reason="current_policy_decision_required")
        if job.status is not JobStatus.AUTHORIZED:
            return self, JobTransitionDecision(allowed=False, reason="job_must_be_authorized")
        queued = _replace_job(job, status=JobStatus.QUEUED, last_transition_at=occurred_at)
        return self._upsert_job(queued, actor_user_id, event_id, occurred_at, "queued"), JobTransitionDecision(
            allowed=True, reason="queued"
        )

    def dispatch_job(
        self,
        job_id: str,
        runner: RunnerContract,
        *,
        actor_user_id: str,
        event_id: str,
        occurred_at: datetime,
    ) -> tuple["JobQueueState", JobTransitionDecision]:
        job = self._require_job(job_id)
        _validate_runner_contract(runner)
        if not _policy_is_current(job, occurred_at):
            return self, JobTransitionDecision(allowed=False, reason="current_policy_decision_required")
        if job.status is not JobStatus.QUEUED:
            return self, JobTransitionDecision(allowed=False, reason="job_must_be_queued")
        if runner.organization_id != job.organization_id:
            return self, JobTransitionDecision(allowed=False, reason="runner_organization_mismatch")
        if job.mode not in runner.capabilities:
            return self, JobTransitionDecision(allowed=False, reason="runner_capability_missing")
        if runner.target_scope.normalized() != job.target.normalized():
            return self, JobTransitionDecision(allowed=False, reason="runner_target_scope_mismatch")
        dispatched = _replace_job(
            job,
            status=JobStatus.DISPATCHED,
            runner_id=runner.runner_id,
            last_transition_at=occurred_at,
        )
        return self._upsert_job(dispatched, actor_user_id, event_id, occurred_at, "dispatched"), JobTransitionDecision(
            allowed=True, reason="dispatched"
        )

    def handle_callback(
        self,
        callback: RunnerCallback,
        *,
        actor_user_id: str,
        event_id: str,
    ) -> tuple["JobQueueState", JobTransitionDecision]:
        _validate_callback(callback)
        if callback.callback_id in self.processed_callback_ids:
            return self, JobTransitionDecision(allowed=False, reason="duplicate_callback")
        job = self._require_job(callback.job_id)
        if job.runner_id != callback.runner_id:
            return self, JobTransitionDecision(allowed=False, reason="runner_mismatch")
        if job.status in TERMINAL_STATUSES:
            return self, JobTransitionDecision(allowed=False, reason="terminal_job_rejects_callback")
        next_job, reason = _apply_callback(job, callback)
        return (
            self._upsert_job(
                next_job,
                actor_user_id,
                event_id,
                callback.occurred_at,
                reason,
                processed_callback_id=callback.callback_id,
            ),
            JobTransitionDecision(allowed=True, reason=reason),
        )

    def cancel_job(
        self,
        job_id: str,
        *,
        reason: str,
        actor_user_id: str,
        event_id: str,
        occurred_at: datetime,
    ) -> tuple["JobQueueState", JobTransitionDecision]:
        _require_non_empty("cancel_reason", reason)
        job = self._require_job(job_id)
        if job.status in TERMINAL_STATUSES:
            return self, JobTransitionDecision(allowed=False, reason="terminal_job_cannot_cancel")
        if job.status in {JobStatus.DISPATCHED, JobStatus.RUNNING} and job.cleanup_required:
            next_job = _replace_job(job, status=JobStatus.CLEANUP, failure_reason=reason, last_transition_at=occurred_at)
            transition = "cancelled_cleanup_required"
        else:
            next_job = _replace_job(job, status=JobStatus.CANCELLED, failure_reason=reason, last_transition_at=occurred_at)
            transition = "cancelled"
        return self._upsert_job(next_job, actor_user_id, event_id, occurred_at, transition), JobTransitionDecision(
            allowed=True, reason=transition
        )

    def fail_timed_out_jobs(
        self,
        *,
        now: datetime,
        actor_user_id: str,
        event_id_prefix: str,
    ) -> "JobQueueState":
        state = self
        for job in self.jobs:
            if job.status in {JobStatus.DISPATCHED, JobStatus.RUNNING} and _timed_out(job, now):
                next_status = JobStatus.CLEANUP if job.cleanup_required else JobStatus.FAILED
                next_job = _replace_job(job, status=next_status, failure_reason="timeout", last_transition_at=now)
                state = state._upsert_job(
                    next_job,
                    actor_user_id,
                    f"{event_id_prefix}-{job.job_id}",
                    now,
                    "timeout_cleanup_required" if next_status is JobStatus.CLEANUP else "timeout_failed",
                )
        return state

    def retry_failed_job(
        self,
        job_id: str,
        *,
        actor_user_id: str,
        event_id: str,
        occurred_at: datetime,
    ) -> tuple["JobQueueState", JobTransitionDecision]:
        job = self._require_job(job_id)
        if job.status is not JobStatus.FAILED:
            return self, JobTransitionDecision(allowed=False, reason="job_must_be_failed")
        if job.attempts >= job.max_attempts:
            return self, JobTransitionDecision(allowed=False, reason="max_attempts_exceeded")
        if not _policy_is_current(job, occurred_at):
            return self, JobTransitionDecision(allowed=False, reason="current_policy_decision_required")
        retried = _replace_job(
            job,
            status=JobStatus.QUEUED,
            attempts=job.attempts + 1,
            failure_reason=None,
            last_transition_at=occurred_at,
        )
        return self._upsert_job(retried, actor_user_id, event_id, occurred_at, "retry_queued"), JobTransitionDecision(
            allowed=True, reason="retry_queued"
        )

    def _require_job(self, job_id: str) -> JobRecord:
        for job in self.jobs:
            if job.job_id == job_id:
                return job
        raise ValueError("job_not_found")

    def _upsert_job(
        self,
        job: JobRecord,
        actor_user_id: str,
        event_id: str,
        occurred_at: datetime,
        transition: str,
        *,
        processed_callback_id: str | None = None,
    ) -> "JobQueueState":
        _require_non_empty("actor_user_id", actor_user_id)
        _require_non_empty("event_id", event_id)
        jobs = tuple(existing for existing in self.jobs if existing.job_id != job.job_id) + (job,)
        callbacks = self.processed_callback_ids
        if processed_callback_id:
            callbacks = callbacks | {processed_callback_id}
        next_audit = self.audit_chain.append_audit_event(
            event_id=event_id,
            organization_id=job.organization_id,
            actor_user_id=actor_user_id,
            action=AuditAction.JOB_LIFECYCLE,
            subject_type="job",
            subject_id=job.job_id,
            occurred_at=occurred_at,
            details={"transition": transition, "status": job.status.value},
        )
        return JobQueueState(jobs=jobs, processed_callback_ids=callbacks, audit_chain=next_audit)


TERMINAL_STATUSES = frozenset({JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.CANCELLED, JobStatus.EVIDENCE_LOCKED})


def _apply_callback(job: JobRecord, callback: RunnerCallback) -> tuple[JobRecord, str]:
    if callback.kind is RunnerCallbackKind.STARTED:
        if job.status is not JobStatus.DISPATCHED:
            raise ValueError("callback_requires_dispatched_job")
        return _replace_job(job, status=JobStatus.RUNNING, last_heartbeat_at=callback.occurred_at, last_transition_at=callback.occurred_at), "running"
    if callback.kind is RunnerCallbackKind.HEARTBEAT:
        if job.status not in {JobStatus.DISPATCHED, JobStatus.RUNNING}:
            raise ValueError("callback_requires_active_job")
        return _replace_job(job, last_heartbeat_at=callback.occurred_at), "heartbeat"
    if callback.kind is RunnerCallbackKind.RESULT:
        if job.status is not JobStatus.RUNNING:
            raise ValueError("callback_requires_running_job")
        next_status = JobStatus.CLEANUP if job.cleanup_required else JobStatus.COMPLETED
        return (
            _replace_job(
                job,
                status=next_status,
                evidence_ids=_merge_evidence(job.evidence_ids, callback.evidence_ids),
                last_transition_at=callback.occurred_at,
            ),
            "result_cleanup_required" if next_status is JobStatus.CLEANUP else "completed",
        )
    if callback.kind is RunnerCallbackKind.CLEANUP_STARTED:
        if job.status not in {JobStatus.RUNNING, JobStatus.CLEANUP, JobStatus.FAILED, JobStatus.CANCELLED}:
            raise ValueError("callback_requires_cleanup_capable_job")
        return _replace_job(job, status=JobStatus.CLEANUP, last_transition_at=callback.occurred_at), "cleanup"
    if callback.kind is RunnerCallbackKind.CLEANUP_COMPLETED:
        if job.status is not JobStatus.CLEANUP:
            raise ValueError("callback_requires_cleanup_job")
        return _replace_job(job, status=JobStatus.EVIDENCE_LOCKED, last_transition_at=callback.occurred_at), "evidence_locked"
    if callback.kind is RunnerCallbackKind.COMPLETED:
        if job.status not in {JobStatus.RUNNING, JobStatus.CLEANUP}:
            raise ValueError("callback_requires_running_or_cleanup_job")
        return _replace_job(job, status=JobStatus.COMPLETED, last_transition_at=callback.occurred_at), "completed"
    if callback.kind is RunnerCallbackKind.FAILED:
        if job.status not in {JobStatus.DISPATCHED, JobStatus.RUNNING, JobStatus.CLEANUP}:
            raise ValueError("callback_requires_active_job")
        next_status = JobStatus.CLEANUP if job.cleanup_required else JobStatus.FAILED
        return (
            _replace_job(job, status=next_status, failure_reason=callback.message or "runner_failed", last_transition_at=callback.occurred_at),
            "failed_cleanup_required" if next_status is JobStatus.CLEANUP else "failed",
        )
    raise ValueError("unsupported_callback_kind")


def lifecycle_contains_required_states() -> bool:
    required = {
        JobStatus.PLANNED,
        JobStatus.AUTHORIZED,
        JobStatus.QUEUED,
        JobStatus.DISPATCHED,
        JobStatus.RUNNING,
        JobStatus.CLEANUP,
        JobStatus.COMPLETED,
        JobStatus.FAILED,
        JobStatus.CANCELLED,
        JobStatus.EVIDENCE_LOCKED,
    }
    return required.issubset(set(JobStatus))


def _validate_policy_grant(grant: PolicyGrant, job: JobRecord, occurred_at: datetime) -> None:
    _require_non_empty("decision_id", grant.decision_id)
    _require_non_empty("organization_id", grant.organization_id)
    _require_non_empty("policy_reason", grant.reason)
    _require_timezone(grant.decided_at)
    _require_timezone(grant.expires_at)
    _require_timezone(occurred_at)
    if grant.organization_id != job.organization_id:
        raise ValueError("policy_organization_mismatch")
    if grant.outcome is not PolicyDecisionOutcome.ALLOW:
        raise ValueError("policy_decision_must_allow")
    if not (grant.decided_at <= occurred_at < grant.expires_at):
        raise ValueError("current_policy_decision_required")


def _validate_runner_contract(runner: RunnerContract) -> None:
    for field_name, value in (
        ("runner_id", runner.runner_id),
        ("organization_id", runner.organization_id),
        ("policy_token_reference", runner.policy_token_reference),
        ("cleanup_callback", runner.cleanup_callback),
    ):
        _require_non_empty(field_name, value)
    if not runner.capabilities:
        raise ValueError("runner_capabilities_required")
    if runner.timeout_seconds <= 0:
        raise ValueError("runner_timeout_invalid")
    if runner.heartbeat_interval_seconds <= 0:
        raise ValueError("runner_heartbeat_invalid")
    if not runner.result_schema:
        raise ValueError("runner_result_schema_required")


def _validate_job(job: JobRecord) -> None:
    for field_name, value in (
        ("job_id", job.job_id),
        ("organization_id", job.organization_id),
        ("engagement_id", job.engagement_id),
        ("test_definition_id", job.test_definition_id),
    ):
        _require_non_empty(field_name, value)
    if job.projected_interactions <= 0:
        raise ValueError("invalid_projected_interactions")
    if job.timeout_seconds <= 0:
        raise ValueError("invalid_timeout_seconds")
    if job.max_attempts < 0:
        raise ValueError("invalid_max_attempts")


def _validate_callback(callback: RunnerCallback) -> None:
    for field_name, value in (
        ("callback_id", callback.callback_id),
        ("runner_id", callback.runner_id),
        ("job_id", callback.job_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(callback.occurred_at)


def _policy_is_current(job: JobRecord, now: datetime) -> bool:
    _require_timezone(now)
    return job.policy_decision_id is not None and job.policy_expires_at is not None and now < job.policy_expires_at


def _timed_out(job: JobRecord, now: datetime) -> bool:
    _require_timezone(now)
    baseline = job.last_heartbeat_at or job.last_transition_at
    if baseline is None:
        return False
    return now - baseline > timedelta(seconds=job.timeout_seconds)


def _merge_evidence(existing: tuple[str, ...], additional: tuple[str, ...]) -> tuple[str, ...]:
    merged: list[str] = list(existing)
    for evidence_id in additional:
        _require_non_empty("evidence_id", evidence_id)
        if evidence_id not in merged:
            merged.append(evidence_id)
    return tuple(merged)


def _replace_job(
    job: JobRecord,
    *,
    status: JobStatus | None = None,
    attempts: int | None = None,
    runner_id: str | None = None,
    policy_decision_id: str | None = None,
    policy_expires_at: datetime | None = None,
    last_transition_at: datetime | None = None,
    last_heartbeat_at: datetime | None = None,
    evidence_ids: tuple[str, ...] | None = None,
    failure_reason: str | None = None,
) -> JobRecord:
    return JobRecord(
        job_id=job.job_id,
        organization_id=job.organization_id,
        engagement_id=job.engagement_id,
        test_definition_id=job.test_definition_id,
        target=job.target,
        mode=job.mode,
        status=status or job.status,
        projected_interactions=job.projected_interactions,
        timeout_seconds=job.timeout_seconds,
        cleanup_required=job.cleanup_required,
        max_attempts=job.max_attempts,
        attempts=job.attempts if attempts is None else attempts,
        runner_id=runner_id if runner_id is not None else job.runner_id,
        policy_decision_id=policy_decision_id if policy_decision_id is not None else job.policy_decision_id,
        policy_expires_at=policy_expires_at if policy_expires_at is not None else job.policy_expires_at,
        last_transition_at=last_transition_at if last_transition_at is not None else job.last_transition_at,
        last_heartbeat_at=last_heartbeat_at if last_heartbeat_at is not None else job.last_heartbeat_at,
        evidence_ids=evidence_ids if evidence_ids is not None else job.evidence_ids,
        failure_reason=failure_reason,
    )


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
