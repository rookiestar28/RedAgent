"""Scheduling, quota, and safety-control contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime

from redagent_platform.domain import JobStatus
from redagent_platform.evidence_chain import AuditAction, EvidenceChain


ACTIVE_JOB_STATUSES = frozenset(
    {
        JobStatus.AUTHORIZED,
        JobStatus.QUEUED,
        JobStatus.DISPATCHED,
        JobStatus.RUNNING,
    }
)


@dataclass(frozen=True, kw_only=True)
class SchedulerPolicy:
    max_active_jobs: int
    max_active_per_engagement: int
    max_active_per_target: int
    max_active_per_module: int
    max_active_per_runner: int
    max_requests_per_job: int
    max_duration_seconds_per_job: int


@dataclass(frozen=True, kw_only=True)
class ScheduledJob:
    job_id: str
    engagement_id: str
    target_key: str
    module_id: str
    runner_id: str
    projected_requests: int
    projected_duration_seconds: int
    requested_at: datetime
    status: JobStatus


@dataclass(frozen=True, kw_only=True)
class CooldownWindow:
    engagement_id: str
    target_key: str
    module_id: str
    until: datetime


@dataclass(frozen=True, kw_only=True)
class ScheduleDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class SchedulerState:
    jobs: tuple[ScheduledJob, ...] = ()
    cooldowns: tuple[CooldownWindow, ...] = ()
    paused: bool = False
    audit_chain: EvidenceChain = EvidenceChain()

    def queue_job(self, policy: SchedulerPolicy, job: ScheduledJob) -> tuple["SchedulerState", ScheduleDecision]:
        decision = decide_queue(policy, self, job)
        if not decision.allowed:
            return self, decision
        queued = _replace_job_status(job, JobStatus.QUEUED)
        return (
            SchedulerState(
                jobs=self.jobs + (queued,),
                cooldowns=self.cooldowns,
                paused=self.paused,
                audit_chain=self.audit_chain,
            ),
            decision,
        )

    def queue_batch(
        self,
        policy: SchedulerPolicy,
        jobs: tuple[ScheduledJob, ...],
    ) -> tuple["SchedulerState", tuple[ScheduleDecision, ...]]:
        state = self
        decisions: list[ScheduleDecision] = []
        for job in jobs:
            state, decision = state.queue_job(policy, job)
            decisions.append(decision)
        return state, tuple(decisions)

    def start_cooldown(self, cooldown: CooldownWindow) -> "SchedulerState":
        return SchedulerState(
            jobs=self.jobs,
            cooldowns=self.cooldowns + (cooldown,),
            paused=self.paused,
            audit_chain=self.audit_chain,
        )

    def pause(self, *, reason: str, actor_user_id: str, event_id: str, occurred_at: datetime) -> "SchedulerState":
        return self._control("pause", reason, actor_user_id, event_id, occurred_at, paused=True)

    def resume(self, *, reason: str, actor_user_id: str, event_id: str, occurred_at: datetime) -> "SchedulerState":
        return self._control("resume", reason, actor_user_id, event_id, occurred_at, paused=False)

    def cancel_job(self, *, job_id: str, reason: str, actor_user_id: str, event_id: str, occurred_at: datetime) -> "SchedulerState":
        _require_non_empty("job_id", job_id)
        jobs = tuple(_replace_job_status(job, JobStatus.CANCELLED) if job.job_id == job_id else job for job in self.jobs)
        return SchedulerState(
            jobs=jobs,
            cooldowns=self.cooldowns,
            paused=self.paused,
            audit_chain=_append_control_event(self.audit_chain, "cancel", reason, actor_user_id, event_id, occurred_at, job_id),
        )

    def _control(
        self,
        control: str,
        reason: str,
        actor_user_id: str,
        event_id: str,
        occurred_at: datetime,
        *,
        paused: bool,
    ) -> "SchedulerState":
        return SchedulerState(
            jobs=self.jobs,
            cooldowns=self.cooldowns,
            paused=paused,
            audit_chain=_append_control_event(self.audit_chain, control, reason, actor_user_id, event_id, occurred_at, "scheduler"),
        )


def decide_queue(policy: SchedulerPolicy, state: SchedulerState, job: ScheduledJob) -> ScheduleDecision:
    _validate_policy(policy)
    _validate_job(job)
    if state.paused:
        return ScheduleDecision(allowed=False, reason="scheduler_paused")
    if job.projected_requests > policy.max_requests_per_job:
        return ScheduleDecision(allowed=False, reason="request_quota_exceeded")
    if job.projected_duration_seconds > policy.max_duration_seconds_per_job:
        return ScheduleDecision(allowed=False, reason="duration_quota_exceeded")
    if _in_cooldown(state.cooldowns, job):
        return ScheduleDecision(allowed=False, reason="cooldown_active")
    active_jobs = tuple(existing for existing in state.jobs if existing.status in ACTIVE_JOB_STATUSES)
    if len(active_jobs) >= policy.max_active_jobs:
        return ScheduleDecision(allowed=False, reason="max_active_jobs_exceeded")
    if _count(active_jobs, "engagement_id", job.engagement_id) >= policy.max_active_per_engagement:
        return ScheduleDecision(allowed=False, reason="engagement_concurrency_exceeded")
    if _count(active_jobs, "target_key", job.target_key) >= policy.max_active_per_target:
        return ScheduleDecision(allowed=False, reason="target_concurrency_exceeded")
    if _count(active_jobs, "module_id", job.module_id) >= policy.max_active_per_module:
        return ScheduleDecision(allowed=False, reason="module_concurrency_exceeded")
    if _count(active_jobs, "runner_id", job.runner_id) >= policy.max_active_per_runner:
        return ScheduleDecision(allowed=False, reason="runner_concurrency_exceeded")
    return ScheduleDecision(allowed=True, reason="queued")


def _append_control_event(
    audit_chain: EvidenceChain,
    control: str,
    reason: str,
    actor_user_id: str,
    event_id: str,
    occurred_at: datetime,
    subject_id: str,
) -> EvidenceChain:
    _require_non_empty("reason", reason)
    _require_non_empty("actor_user_id", actor_user_id)
    _require_non_empty("event_id", event_id)
    return audit_chain.append_audit_event(
        event_id=event_id,
        organization_id="scheduler",
        actor_user_id=actor_user_id,
        action=AuditAction.SCHEDULER_CONTROL,
        subject_type="scheduler_control",
        subject_id=subject_id,
        occurred_at=occurred_at,
        details={"control": control, "reason": reason},
    )


def _in_cooldown(cooldowns: tuple[CooldownWindow, ...], job: ScheduledJob) -> bool:
    return any(
        cooldown.engagement_id == job.engagement_id
        and cooldown.target_key == job.target_key
        and cooldown.module_id == job.module_id
        and job.requested_at < cooldown.until
        for cooldown in cooldowns
    )


def _count(jobs: tuple[ScheduledJob, ...], field_name: str, value: str) -> int:
    return sum(1 for job in jobs if getattr(job, field_name) == value)


def _replace_job_status(job: ScheduledJob, status: JobStatus) -> ScheduledJob:
    return ScheduledJob(
        job_id=job.job_id,
        engagement_id=job.engagement_id,
        target_key=job.target_key,
        module_id=job.module_id,
        runner_id=job.runner_id,
        projected_requests=job.projected_requests,
        projected_duration_seconds=job.projected_duration_seconds,
        requested_at=job.requested_at,
        status=status,
    )


def _validate_policy(policy: SchedulerPolicy) -> None:
    for field_name, value in (
        ("max_active_jobs", policy.max_active_jobs),
        ("max_active_per_engagement", policy.max_active_per_engagement),
        ("max_active_per_target", policy.max_active_per_target),
        ("max_active_per_module", policy.max_active_per_module),
        ("max_active_per_runner", policy.max_active_per_runner),
        ("max_requests_per_job", policy.max_requests_per_job),
        ("max_duration_seconds_per_job", policy.max_duration_seconds_per_job),
    ):
        if value <= 0:
            raise ValueError(f"invalid_{field_name}")


def _validate_job(job: ScheduledJob) -> None:
    for field_name, value in (
        ("job_id", job.job_id),
        ("engagement_id", job.engagement_id),
        ("target_key", job.target_key),
        ("module_id", job.module_id),
        ("runner_id", job.runner_id),
    ):
        _require_non_empty(field_name, value)
    if job.projected_requests <= 0:
        raise ValueError("invalid_projected_requests")
    if job.projected_duration_seconds <= 0:
        raise ValueError("invalid_projected_duration")
    if job.requested_at.tzinfo is None or job.requested_at.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
