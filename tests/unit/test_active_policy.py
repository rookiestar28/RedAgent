from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import active_policy, domain, evidence_chain
from redagent_platform.job_queue import JobRecord
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget


NOW = datetime(2026, 7, 8, 13, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")


def scope(**overrides: object) -> EngagementScope:
    values = {
        "engagement_id": "eng-1",
        "organization_id": "org-1",
        "authorization_status": domain.AuthorizationStatus.APPROVED,
        "approved_by_user_id": "lead-1",
        "allowed_targets": (TARGET,),
        "forbidden_targets": (),
        "allowed_modes": (domain.TestMode.ACTIVE_SCAN,),
        "window_start": NOW - timedelta(minutes=5),
        "window_end": NOW + timedelta(hours=1),
        "max_interactions": 20,
        "max_rate_per_second": 1.0,
        "emergency_contact_method": "email",
    }
    values.update(overrides)
    return EngagementScope(**values)  # type: ignore[arg-type]


def module_policy(**overrides: object) -> active_policy.ActiveModulePolicy:
    values = {
        "module_id": "zap-active",
        "allowed_modes": (domain.TestMode.ACTIVE_SCAN,),
        "allowed_payload_classes": (active_policy.PayloadClass.STANDARD_ACTIVE,),
        "max_rate_per_second": 1.0,
        "max_requests": 10,
        "max_duration_seconds": 300,
        "max_concurrent_per_engagement": 2,
        "max_concurrent_per_target": 1,
        "stop_conditions": active_policy.StopConditionPolicy(
            stop_on_scope_violation=True,
            stop_on_error_rate=True,
            max_error_count=3,
            emergency_contact_required=True,
        ),
    }
    values.update(overrides)
    return active_policy.ActiveModulePolicy(**values)  # type: ignore[arg-type]


def confirmation(**overrides: object) -> active_policy.OperatorConfirmation:
    values = {
        "confirmed_by_user_id": "operator-1",
        "confirmed_at": NOW - timedelta(minutes=1),
        "scope_acknowledged": True,
        "risk_acknowledged": True,
        "stop_conditions_acknowledged": True,
    }
    values.update(overrides)
    return active_policy.OperatorConfirmation(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> active_policy.ActiveJobRequest:
    values = {
        "job_id": "job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "module_id": "zap-active",
        "payload_class": active_policy.PayloadClass.STANDARD_ACTIVE,
        "requested_at": NOW,
        "projected_requests": 5,
        "projected_duration_seconds": 60,
        "requested_rate_per_second": 0.5,
        "operator_confirmation": confirmation(),
    }
    values.update(overrides)
    return active_policy.ActiveJobRequest(**values)  # type: ignore[arg-type]


def job(**overrides: object) -> JobRecord:
    values = {
        "job_id": "active-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "test_definition_id": "zap-active",
        "target": TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "status": domain.JobStatus.QUEUED,
        "projected_interactions": 5,
        "timeout_seconds": 60,
        "cleanup_required": True,
        "max_attempts": 1,
    }
    values.update(overrides)
    return JobRecord(**values)  # type: ignore[arg-type]


def evaluate(**overrides: object) -> active_policy.ActivePolicyResult:
    values = {
        "request": request(),
        "scope": scope(),
        "module_policy": module_policy(),
        "existing_jobs": (),
        "audit_chain": evidence_chain.EvidenceChain(),
        "decision_id": "decision-1",
        "policy_expires_at": NOW + timedelta(minutes=30),
    }
    values.update(overrides)
    return active_policy.evaluate_active_policy(**values)  # type: ignore[arg-type]


def test_active_policy_allows_when_required_inputs_are_present() -> None:
    result = evaluate()

    assert result.decision.allowed
    assert result.decision.policy_grant is not None
    assert result.decision.policy_grant.outcome is domain.PolicyDecisionOutcome.ALLOW
    assert result.audit_chain.audit_events[0].action is evidence_chain.AuditAction.POLICY_DECISION


@pytest.mark.parametrize(
    ("override", "expected_reason"),
    (
        ({"scope": scope(authorization_status=domain.AuthorizationStatus.DRAFT)}, "scope_authorization_not_approved"),
        ({"scope": scope(allowed_targets=())}, "scope_missing_target_allowlist"),
        ({"scope": scope(window_start=NOW + timedelta(minutes=1))}, "scope_outside_time_window"),
        ({"module_policy": module_policy(allowed_modes=(domain.TestMode.PASSIVE_SCAN,))}, "active_module_permission_required"),
        ({"request": request(operator_confirmation=None)}, "operator_confirmation_required"),
        ({"request": request(operator_confirmation=confirmation(scope_acknowledged=False))}, "operator_scope_acknowledgement_required"),
    ),
)
def test_active_policy_fails_closed_when_required_inputs_are_absent(
    override: dict[str, object],
    expected_reason: str,
) -> None:
    result = evaluate(**override)

    assert not result.decision.allowed
    assert result.decision.reason == expected_reason
    assert result.decision.policy_grant is None


@pytest.mark.parametrize(
    ("override", "expected_reason"),
    (
        ({"request": request(requested_rate_per_second=2.0)}, "rate_limit_exceeded"),
        ({"request": request(projected_requests=11)}, "request_count_exceeded"),
        ({"request": request(projected_duration_seconds=301)}, "duration_limit_exceeded"),
        ({"request": request(payload_class=active_policy.PayloadClass.DESTRUCTIVE)}, "destructive_payload_forbidden"),
        (
            {
                "module_policy": module_policy(
                    stop_conditions=active_policy.StopConditionPolicy(
                        stop_on_scope_violation=False,
                        stop_on_error_rate=True,
                        max_error_count=3,
                        emergency_contact_required=True,
                    )
                )
            },
            "stop_conditions_required",
        ),
        ({"existing_jobs": (job(),)}, "target_concurrency_exceeded"),
    ),
)
def test_active_policy_enforces_limits_payload_class_and_stop_conditions(
    override: dict[str, object],
    expected_reason: str,
) -> None:
    result = evaluate(**override)

    assert not result.decision.allowed
    assert result.decision.reason == expected_reason


def test_active_policy_ignores_passive_jobs_for_active_concurrency() -> None:
    passive_job = job(mode=domain.TestMode.PASSIVE_SCAN, status=domain.JobStatus.RUNNING)

    result = evaluate(existing_jobs=(passive_job,))

    assert result.decision.allowed


def test_kill_switch_cancels_queued_dispatched_and_running_active_jobs_with_audit() -> None:
    queued = job(job_id="queued", status=domain.JobStatus.QUEUED)
    dispatched = job(job_id="dispatched", status=domain.JobStatus.DISPATCHED)
    running = job(job_id="running", status=domain.JobStatus.RUNNING)
    passive = job(job_id="passive", mode=domain.TestMode.PASSIVE_SCAN, status=domain.JobStatus.RUNNING)
    completed = job(job_id="completed", status=domain.JobStatus.COMPLETED)

    plan = active_policy.build_kill_switch_plan(
        jobs=(queued, dispatched, running, passive, completed),
        reason="operator_stop",
        actor_user_id="lead-1",
        event_id="kill-1",
        occurred_at=NOW,
        audit_chain=evidence_chain.EvidenceChain(),
    )

    assert {cancelled.job_id for cancelled in plan.cancelled_jobs} == {"queued", "dispatched", "running"}
    assert all(cancelled.status is domain.JobStatus.CANCELLED for cancelled in plan.cancelled_jobs)
    assert {unaffected.job_id for unaffected in plan.unaffected_jobs} == {"passive", "completed"}
    assert plan.audit_chain.audit_events[0].action is evidence_chain.AuditAction.SCHEDULER_CONTROL
