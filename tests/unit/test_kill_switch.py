from datetime import datetime, timedelta, timezone

from redagent_platform import credentials, domain, evidence_chain, job_queue, kill_switch
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 17, 0, tzinfo=timezone.utc)


def target(value: str = "https://example.test") -> ScopeTarget:
    return ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value=value)


def job(job_id: str, status: domain.JobStatus, **overrides: object) -> job_queue.JobRecord:
    values = {
        "job_id": job_id,
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "test_definition_id": "test-1",
        "target": target(),
        "mode": domain.TestMode.ACTIVE_SCAN,
        "status": status,
        "projected_interactions": 1,
        "timeout_seconds": 30,
        "cleanup_required": True,
        "max_attempts": 1,
        "runner_id": "runner-1" if status in {domain.JobStatus.DISPATCHED, domain.JobStatus.RUNNING} else None,
        "policy_decision_id": "decision-1",
        "policy_expires_at": NOW + timedelta(minutes=10),
    }
    values.update(overrides)
    return job_queue.JobRecord(**values)  # type: ignore[arg-type]


def scope() -> kill_switch.KillSwitchScope:
    return kill_switch.KillSwitchScope(
        engagement_id="eng-1",
        target=target(),
        modes=(domain.TestMode.ACTIVE_SCAN,),
    )


def lease(job_id: str) -> credentials.CredentialLease:
    return credentials.CredentialLease(
        id=f"lease-{job_id}",
        credential_reference_id="cred-ref-1",
        job_id=job_id,
        runner_id="runner-1",
        target=target(),
        mode=domain.TestMode.ACTIVE_SCAN,
        scoped_permissions=("http:read",),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        redaction_label="credential:cred-ref-1",
    )


def response(job_id: str, status: kill_switch.RunnerCancellationStatus) -> kill_switch.RunnerCancellationResponse:
    return kill_switch.RunnerCancellationResponse(
        job_id=job_id,
        runner_id="runner-1",
        status=status,
        cleanup_attempted=True,
        cleanup_succeeded=status is kill_switch.RunnerCancellationStatus.TERMINATED,
        responded_at=NOW,
    )


def test_kill_switch_blocks_new_dispatch_for_matching_scope() -> None:
    blocked = kill_switch.kill_switch_blocks_dispatch(scope(), job("job-1", domain.JobStatus.QUEUED))
    unaffected = kill_switch.kill_switch_blocks_dispatch(
        scope(),
        job("job-2", domain.JobStatus.QUEUED, target=target("https://other.example.test")),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert unaffected.allowed


def test_kill_switch_cancels_active_jobs_revokes_credentials_and_records_audit() -> None:
    queued = job("queued", domain.JobStatus.QUEUED)
    running = job("running", domain.JobStatus.RUNNING)
    passive = job("passive", domain.JobStatus.RUNNING, mode=domain.TestMode.PASSIVE_SCAN)
    state = job_queue.JobQueueState(jobs=(queued, running, passive))

    result = kill_switch.enforce_kill_switch(
        scope=scope(),
        state=state,
        credential_broker=credentials.CredentialBroker(),
        leases_by_job_id={"running": lease("running")},
        runner_responses={"running": response("running", kill_switch.RunnerCancellationStatus.TERMINATED)},
        reason="operator emergency stop",
        actor_user_id="lead-1",
        event_id="kill-1",
        occurred_at=NOW,
    )

    assert set(result.cancelled_job_ids) == {"queued", "running"}
    assert result.state._require_job("queued").status is domain.JobStatus.CANCELLED
    assert result.state._require_job("running").status is domain.JobStatus.CLEANUP
    assert result.state._require_job("passive").status is domain.JobStatus.RUNNING
    assert result.evidence[1].credential_revoked
    assert result.evidence[1].residual_risk == "none_identified"
    assert result.credential_broker.audit_chain.audit_events[0].action is evidence_chain.AuditAction.CREDENTIAL_LEASE
    assert result.state.audit_chain.audit_events[-1].action is evidence_chain.AuditAction.SCHEDULER_CONTROL


def test_stuck_runner_timeout_and_cleanup_failure_record_residual_risk() -> None:
    timed_out = job("timeout", domain.JobStatus.RUNNING)
    cleanup_failed = job("cleanup", domain.JobStatus.RUNNING)
    state = job_queue.JobQueueState(jobs=(timed_out, cleanup_failed))

    result = kill_switch.enforce_kill_switch(
        scope=scope(),
        state=state,
        credential_broker=credentials.CredentialBroker(),
        leases_by_job_id={"timeout": lease("timeout"), "cleanup": lease("cleanup")},
        runner_responses={
            "timeout": response("timeout", kill_switch.RunnerCancellationStatus.TIMEOUT),
            "cleanup": response("cleanup", kill_switch.RunnerCancellationStatus.CLEANUP_FAILED),
        },
        reason="stuck runner",
        actor_user_id="lead-1",
        event_id="kill-2",
        occurred_at=NOW,
    )

    risk_by_job = {item.job_id: item.residual_risk for item in result.evidence}
    assert risk_by_job["timeout"] == "runner_timeout_requires_operator_review"
    assert risk_by_job["cleanup"] == "cleanup_failed_requires_manual_verification"
    assert all(item.credential_revoked for item in result.evidence)
    assert len(result.credential_broker.audit_chain.audit_events) == 2
