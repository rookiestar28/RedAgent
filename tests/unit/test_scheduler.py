from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import domain, evidence_chain, scheduler


NOW = datetime(2026, 7, 8, 15, 0, tzinfo=timezone.utc)


def policy(**overrides: object) -> scheduler.SchedulerPolicy:
    values = {
        "max_active_jobs": 5,
        "max_active_per_engagement": 2,
        "max_active_per_target": 1,
        "max_active_per_module": 2,
        "max_active_per_runner": 2,
        "max_requests_per_job": 50,
        "max_duration_seconds_per_job": 600,
    }
    values.update(overrides)
    return scheduler.SchedulerPolicy(**values)  # type: ignore[arg-type]


def job(**overrides: object) -> scheduler.ScheduledJob:
    values = {
        "job_id": "job-1",
        "engagement_id": "eng-1",
        "target_key": "target-1",
        "module_id": "module-1",
        "runner_id": "runner-1",
        "projected_requests": 10,
        "projected_duration_seconds": 60,
        "requested_at": NOW,
        "status": domain.JobStatus.PLANNED,
    }
    values.update(overrides)
    return scheduler.ScheduledJob(**values)  # type: ignore[arg-type]


def test_scheduler_enforces_per_dimension_concurrency_limits() -> None:
    state, first = scheduler.SchedulerState().queue_job(policy(), job(job_id="job-1"))
    _, target_denied = state.queue_job(policy(), job(job_id="job-2", target_key="target-1"))
    _, engagement_denied = state.queue_job(
        policy(max_active_per_engagement=1, max_active_per_target=2),
        job(job_id="job-3", target_key="target-2"),
    )
    _, module_denied = state.queue_job(
        policy(max_active_per_module=1, max_active_per_target=2),
        job(job_id="job-4", target_key="target-2", engagement_id="eng-2"),
    )
    _, runner_denied = state.queue_job(
        policy(max_active_per_runner=1, max_active_per_target=2),
        job(job_id="job-5", target_key="target-2", engagement_id="eng-2", module_id="module-2"),
    )

    assert first.allowed
    assert target_denied.reason == "target_concurrency_exceeded"
    assert engagement_denied.reason == "engagement_concurrency_exceeded"
    assert module_denied.reason == "module_concurrency_exceeded"
    assert runner_denied.reason == "runner_concurrency_exceeded"


def test_scheduler_enforces_request_duration_active_job_and_cooldown_quotas() -> None:
    _, request_denied = scheduler.SchedulerState().queue_job(policy(), job(projected_requests=51))
    _, duration_denied = scheduler.SchedulerState().queue_job(policy(), job(projected_duration_seconds=601))
    state, _ = scheduler.SchedulerState().queue_job(policy(max_active_jobs=1), job(job_id="job-1"))
    _, active_denied = state.queue_job(
        policy(max_active_jobs=1, max_active_per_target=2),
        job(job_id="job-2", target_key="target-2", engagement_id="eng-2", module_id="module-2", runner_id="runner-2"),
    )
    cooldown_state = scheduler.SchedulerState().start_cooldown(
        scheduler.CooldownWindow(
            engagement_id="eng-1",
            target_key="target-1",
            module_id="module-1",
            until=NOW + timedelta(minutes=5),
        )
    )
    _, cooldown_denied = cooldown_state.queue_job(policy(), job())

    assert request_denied.reason == "request_quota_exceeded"
    assert duration_denied.reason == "duration_quota_exceeded"
    assert active_denied.reason == "max_active_jobs_exceeded"
    assert cooldown_denied.reason == "cooldown_active"


def test_pause_resume_and_cancel_require_audited_reason() -> None:
    state = scheduler.SchedulerState()
    paused = state.pause(reason="maintenance window", actor_user_id="operator-1", event_id="audit-1", occurred_at=NOW)
    resumed = paused.resume(reason="maintenance complete", actor_user_id="operator-1", event_id="audit-2", occurred_at=NOW)
    with_job, _ = resumed.queue_job(policy(), job())
    cancelled = with_job.cancel_job(job_id="job-1", reason="owner stop", actor_user_id="operator-1", event_id="audit-3", occurred_at=NOW)

    assert paused.paused
    assert not resumed.paused
    assert cancelled.jobs[0].status is domain.JobStatus.CANCELLED
    assert [event.action for event in cancelled.audit_chain.audit_events] == [
        evidence_chain.AuditAction.SCHEDULER_CONTROL,
        evidence_chain.AuditAction.SCHEDULER_CONTROL,
        evidence_chain.AuditAction.SCHEDULER_CONTROL,
    ]


def test_pause_without_reason_fails_closed() -> None:
    with pytest.raises(ValueError, match="missing_reason"):
        scheduler.SchedulerState().pause(reason="", actor_user_id="operator-1", event_id="audit-1", occurred_at=NOW)


def test_paused_scheduler_denies_queueing() -> None:
    paused = scheduler.SchedulerState().pause(
        reason="emergency stop",
        actor_user_id="operator-1",
        event_id="audit-1",
        occurred_at=NOW,
    )

    _, decision = paused.queue_job(policy(), job())

    assert decision.reason == "scheduler_paused"


def test_concurrent_queue_load_accepts_only_within_limits() -> None:
    jobs = tuple(
        job(
            job_id=f"job-{index}",
            target_key=f"target-{index}",
            runner_id=f"runner-{index}",
            module_id=f"module-{index}",
            engagement_id=f"eng-{index}",
        )
        for index in range(1, 5)
    )

    state, decisions = scheduler.SchedulerState().queue_batch(policy(max_active_jobs=2), jobs)

    assert [decision.allowed for decision in decisions] == [True, True, False, False]
    assert [job.status for job in state.jobs] == [domain.JobStatus.QUEUED, domain.JobStatus.QUEUED]
