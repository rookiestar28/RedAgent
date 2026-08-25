from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import domain, evidence_chain, job_queue
from redagent_platform.scheduler import ScheduleDecision
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 8, 16, 0, tzinfo=timezone.utc)


def target() -> ScopeTarget:
    return ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://example.com")


def job(**overrides: object) -> job_queue.JobRecord:
    values = {
        "job_id": "job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "test_definition_id": "test-1",
        "target": target(),
        "mode": domain.TestMode.PASSIVE_SCAN,
        "status": domain.JobStatus.PLANNED,
        "projected_interactions": 10,
        "timeout_seconds": 60,
        "cleanup_required": True,
        "max_attempts": 1,
    }
    values.update(overrides)
    return job_queue.JobRecord(**values)  # type: ignore[arg-type]


def grant(**overrides: object) -> job_queue.PolicyGrant:
    values = {
        "decision_id": "decision-1",
        "organization_id": "org-1",
        "outcome": domain.PolicyDecisionOutcome.ALLOW,
        "decided_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=10),
        "reason": "scope_authorized",
    }
    values.update(overrides)
    return job_queue.PolicyGrant(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.PASSIVE_SCAN,),
        "policy_token_reference": "policy-token-ref-1",
        "target_scope": target(),
        "timeout_seconds": 60,
        "heartbeat_interval_seconds": 15,
        "result_schema": ("status", "evidence_ids"),
        "cleanup_callback": "cleanup://runner-1/job",
        "credential_lease_id": "lease-1",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def authorized_state() -> job_queue.JobQueueState:
    state, decision = job_queue.JobQueueState().authorize_job(
        job(),
        grant(),
        actor_user_id="operator-1",
        event_id="audit-1",
        occurred_at=NOW,
    )
    assert decision.allowed
    return state


def queued_state() -> job_queue.JobQueueState:
    state, decision = authorized_state().queue_authorized_job(
        "job-1",
        ScheduleDecision(allowed=True, reason="queued"),
        actor_user_id="operator-1",
        event_id="audit-2",
        occurred_at=NOW,
    )
    assert decision.allowed
    return state


def dispatched_state() -> job_queue.JobQueueState:
    state, decision = queued_state().dispatch_job(
        "job-1",
        runner(),
        actor_user_id="operator-1",
        event_id="audit-3",
        occurred_at=NOW,
    )
    assert decision.allowed
    return state


def running_state() -> job_queue.JobQueueState:
    state, decision = dispatched_state().handle_callback(
        job_queue.RunnerCallback(
            callback_id="cb-start",
            runner_id="runner-1",
            job_id="job-1",
            kind=job_queue.RunnerCallbackKind.STARTED,
            occurred_at=NOW,
        ),
        actor_user_id="runner-1",
        event_id="audit-4",
    )
    assert decision.allowed
    return state


def test_lifecycle_contains_required_r010_states() -> None:
    assert job_queue.lifecycle_contains_required_states()


def test_job_cannot_authorize_or_queue_without_current_allow_policy() -> None:
    with pytest.raises(ValueError, match="policy_decision_must_allow"):
        job_queue.JobQueueState().authorize_job(
            job(),
            grant(outcome=domain.PolicyDecisionOutcome.DENY),
            actor_user_id="operator-1",
            event_id="audit-1",
            occurred_at=NOW,
        )

    state = job_queue.JobQueueState(jobs=(job(status=domain.JobStatus.AUTHORIZED),))
    _, decision = state.queue_authorized_job(
        "job-1",
        ScheduleDecision(allowed=True, reason="queued"),
        actor_user_id="operator-1",
        event_id="audit-2",
        occurred_at=NOW,
    )

    assert decision.reason == "current_policy_decision_required"


def test_scheduler_denial_blocks_queueing() -> None:
    state = authorized_state()
    _, decision = state.queue_authorized_job(
        "job-1",
        ScheduleDecision(allowed=False, reason="max_active_jobs_exceeded"),
        actor_user_id="operator-1",
        event_id="audit-2",
        occurred_at=NOW,
    )

    assert decision.reason == "scheduler_max_active_jobs_exceeded"


def test_runner_contract_contains_required_fields_and_dispatch_checks_scope() -> None:
    state = queued_state()
    next_state, decision = state.dispatch_job(
        "job-1",
        runner(),
        actor_user_id="operator-1",
        event_id="audit-3",
        occurred_at=NOW,
    )
    _, denied = state.dispatch_job(
        "job-1",
        runner(target_scope=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://other.example")),
        actor_user_id="operator-1",
        event_id="audit-4",
        occurred_at=NOW,
    )

    assert decision.allowed
    assert next_state.jobs[0].status is domain.JobStatus.DISPATCHED
    assert next_state.jobs[0].runner_id == "runner-1"
    assert denied.reason == "runner_target_scope_mismatch"


def test_result_callback_moves_to_cleanup_then_evidence_locked() -> None:
    state = running_state()
    state, result = state.handle_callback(
        job_queue.RunnerCallback(
            callback_id="cb-result",
            runner_id="runner-1",
            job_id="job-1",
            kind=job_queue.RunnerCallbackKind.RESULT,
            occurred_at=NOW + timedelta(seconds=10),
            evidence_ids=("evidence-1",),
        ),
        actor_user_id="runner-1",
        event_id="audit-5",
    )
    state, cleanup = state.handle_callback(
        job_queue.RunnerCallback(
            callback_id="cb-cleanup",
            runner_id="runner-1",
            job_id="job-1",
            kind=job_queue.RunnerCallbackKind.CLEANUP_COMPLETED,
            occurred_at=NOW + timedelta(seconds=20),
        ),
        actor_user_id="runner-1",
        event_id="audit-6",
    )

    assert result.reason == "result_cleanup_required"
    assert cleanup.reason == "evidence_locked"
    assert state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert state.jobs[0].evidence_ids == ("evidence-1",)


def test_duplicate_callback_is_rejected() -> None:
    state = running_state()
    callback = job_queue.RunnerCallback(
        callback_id="cb-heartbeat",
        runner_id="runner-1",
        job_id="job-1",
        kind=job_queue.RunnerCallbackKind.HEARTBEAT,
        occurred_at=NOW + timedelta(seconds=5),
    )
    state, first = state.handle_callback(callback, actor_user_id="runner-1", event_id="audit-5")
    _, second = state.handle_callback(callback, actor_user_id="runner-1", event_id="audit-6")

    assert first.allowed
    assert second.reason == "duplicate_callback"


def test_timeout_moves_running_job_to_cleanup() -> None:
    state = running_state()
    timed_out = state.fail_timed_out_jobs(
        now=NOW + timedelta(seconds=61),
        actor_user_id="scheduler",
        event_id_prefix="timeout",
    )

    assert timed_out.jobs[0].status is domain.JobStatus.CLEANUP
    assert timed_out.jobs[0].failure_reason == "timeout"


def test_cancel_running_job_requires_cleanup_but_queued_job_cancels_directly() -> None:
    running = running_state()
    running_cancelled, running_decision = running.cancel_job(
        "job-1",
        reason="operator stop",
        actor_user_id="operator-1",
        event_id="audit-5",
        occurred_at=NOW,
    )
    queued = queued_state()
    queued_cancelled, queued_decision = queued.cancel_job(
        "job-1",
        reason="owner stop",
        actor_user_id="operator-1",
        event_id="audit-5",
        occurred_at=NOW,
    )

    assert running_decision.reason == "cancelled_cleanup_required"
    assert running_cancelled.jobs[0].status is domain.JobStatus.CLEANUP
    assert queued_decision.reason == "cancelled"
    assert queued_cancelled.jobs[0].status is domain.JobStatus.CANCELLED


def test_retry_failed_job_requeues_with_attempt_increment() -> None:
    failed = job_queue.JobRecord(
        **{
            **job(status=domain.JobStatus.FAILED, policy_decision_id="decision-1", policy_expires_at=NOW + timedelta(minutes=5)).__dict__,
            "failure_reason": "runner_failed",
        }
    )
    state = job_queue.JobQueueState(jobs=(failed,))
    state, decision = state.retry_failed_job(
        "job-1",
        actor_user_id="operator-1",
        event_id="audit-1",
        occurred_at=NOW,
    )

    assert decision.reason == "retry_queued"
    assert state.jobs[0].status is domain.JobStatus.QUEUED
    assert state.jobs[0].attempts == 1


def test_lifecycle_transitions_emit_audit_events() -> None:
    state = dispatched_state()

    assert [event.action for event in state.audit_chain.audit_events] == [
        evidence_chain.AuditAction.JOB_LIFECYCLE,
        evidence_chain.AuditAction.JOB_LIFECYCLE,
        evidence_chain.AuditAction.JOB_LIFECYCLE,
    ]
