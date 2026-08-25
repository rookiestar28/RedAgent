from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import credentials, domain, emergency_stop, evidence_chain, job_queue, kill_switch
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 15, 40, tzinfo=timezone.utc)


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


def runbook() -> emergency_stop.EmergencyStopRunbook:
    return emergency_stop.EmergencyStopRunbook(
        runbook_id="runbook-1",
        notification_method="email",
        stakeholder_user_ids=("stakeholder-1", "stakeholder-2"),
        recovery_reviewer_user_ids=("reviewer-1",),
        stop_sla_seconds=300,
    )


def request(**overrides: object) -> emergency_stop.EmergencyStopRequest:
    values = {
        "stop_id": "stop-1",
        "mode": emergency_stop.EmergencyStopMode.LIVE,
        "scope": scope(),
        "initiated_by_user_id": "lead-1",
        "reason": "operator emergency stop",
        "requested_at": NOW,
        "runbook": runbook(),
        "policy_simulation_hash": "a" * 64,
        "notification_failure_user_ids": (),
    }
    values.update(overrides)
    return emergency_stop.EmergencyStopRequest(**values)  # type: ignore[arg-type]


def lease(job_id: str, runner_id: str = "runner-1") -> credentials.CredentialLease:
    return credentials.CredentialLease(
        id=f"lease-{job_id}",
        credential_reference_id="cred-ref-1",
        job_id=job_id,
        runner_id=runner_id,
        target=target(),
        mode=domain.TestMode.ACTIVE_SCAN,
        scoped_permissions=("http:read",),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        redaction_label="credential:cred-ref-1",
    )


def response(
    job_id: str,
    status: kill_switch.RunnerCancellationStatus = kill_switch.RunnerCancellationStatus.TERMINATED,
    *,
    runner_id: str = "runner-1",
) -> kill_switch.RunnerCancellationResponse:
    return kill_switch.RunnerCancellationResponse(
        job_id=job_id,
        runner_id=runner_id,
        status=status,
        cleanup_attempted=True,
        cleanup_succeeded=status is kill_switch.RunnerCancellationStatus.TERMINATED,
        responded_at=NOW,
    )


def test_live_stop_records_initiator_jobs_credentials_notifications_and_recovery_pending() -> None:
    running = job("running", domain.JobStatus.RUNNING)
    state = job_queue.JobQueueState(jobs=(running,))

    result = emergency_stop.execute_emergency_stop_workflow(
        request=request(),
        state=state,
        credential_broker=credentials.CredentialBroker(),
        leases_by_job_id={"running": lease("running")},
        runner_responses={"running": response("running")},
    )

    assert result.record.initiated_by_user_id == "lead-1"
    assert result.record.reason == "operator emergency stop"
    assert result.record.affected_job_ids == ("running",)
    assert result.record.affected_credential_lease_ids == ("lease-running",)
    assert {notification.status for notification in result.record.notifications} == {
        emergency_stop.NotificationStatus.SENT
    }
    assert result.record.cancellation_evidence[0].credential_revoked
    assert result.record.recovery is None
    assert result.record.stop_hash


def test_rehearsal_mode_proves_paths_without_mutating_live_state() -> None:
    running = job("running", domain.JobStatus.RUNNING)
    state = job_queue.JobQueueState(jobs=(running,))

    result = emergency_stop.execute_emergency_stop_workflow(
        request=request(mode=emergency_stop.EmergencyStopMode.REHEARSAL),
        state=state,
        credential_broker=credentials.CredentialBroker(),
        leases_by_job_id={"running": lease("running")},
        runner_responses={"running": response("running")},
    )

    assert result.state is state
    assert result.credential_broker.audit_chain.audit_events == ()
    assert result.record.mode is emergency_stop.EmergencyStopMode.REHEARSAL
    assert result.record.cancellation_evidence[0].credential_revoked is False
    assert "credential_revocation_planned" in result.record.cancellation_evidence[0].residual_risk


def test_notification_failure_blocks_recovery_until_reviewed() -> None:
    state = job_queue.JobQueueState(jobs=(job("running", domain.JobStatus.RUNNING),))
    result = emergency_stop.execute_emergency_stop_workflow(
        request=request(notification_failure_user_ids=("stakeholder-2",)),
        state=state,
        credential_broker=credentials.CredentialBroker(),
        leases_by_job_id={"running": lease("running")},
        runner_responses={"running": response("running")},
    )

    with pytest.raises(ValueError, match="notification_failure_review_required"):
        emergency_stop.approve_recovery(
            record=result.record,
            approval_id="approval-1",
            reviewer_user_id="reviewer-1",
            reason="Recovered after review.",
            approved_at=NOW,
            notifications_reviewed=False,
            cancellation_reviewed=True,
            audit_chain=evidence_chain.EvidenceChain(),
        )

    recovered, chain = emergency_stop.approve_recovery(
        record=result.record,
        approval_id="approval-1",
        reviewer_user_id="reviewer-1",
        reason="Recovered after notification review.",
        approved_at=NOW,
        notifications_reviewed=True,
        cancellation_reviewed=True,
        audit_chain=evidence_chain.EvidenceChain(),
    )

    assert recovered.recovery is not None
    assert recovered.recovery.audit_event_hash == chain.audit_events[-1].event_hash


def test_stop_blocks_dispatch_and_publication_until_recovery_approval() -> None:
    affected = job("running", domain.JobStatus.RUNNING)
    result = emergency_stop.execute_emergency_stop_workflow(
        request=request(),
        state=job_queue.JobQueueState(jobs=(affected,)),
        credential_broker=credentials.CredentialBroker(),
        leases_by_job_id={"running": lease("running")},
        runner_responses={"running": response("running")},
    )

    dispatch = emergency_stop.emergency_stop_blocks_dispatch(result.record, affected)
    publication = emergency_stop.emergency_stop_blocks_publication(result.record, "report-1")

    assert not dispatch.allowed
    assert dispatch.reason == "emergency_stop_pending_review"
    assert not publication.allowed
    assert publication.reason == "emergency_stop_pending_review"

    recovered, _ = emergency_stop.approve_recovery(
        record=result.record,
        approval_id="approval-1",
        reviewer_user_id="reviewer-1",
        reason="Recovery approved.",
        approved_at=NOW,
        notifications_reviewed=True,
        cancellation_reviewed=True,
        audit_chain=evidence_chain.EvidenceChain(),
    )

    assert emergency_stop.emergency_stop_blocks_dispatch(recovered, affected).allowed
    assert emergency_stop.emergency_stop_blocks_publication(recovered, "report-1").allowed


def test_cross_runner_cancellation_and_credential_revocation_evidence() -> None:
    first = job("runner-one", domain.JobStatus.RUNNING, runner_id="runner-1")
    second = job("runner-two", domain.JobStatus.RUNNING, runner_id="runner-2")

    result = emergency_stop.execute_emergency_stop_workflow(
        request=request(),
        state=job_queue.JobQueueState(jobs=(first, second)),
        credential_broker=credentials.CredentialBroker(),
        leases_by_job_id={"runner-one": lease("runner-one", "runner-1"), "runner-two": lease("runner-two", "runner-2")},
        runner_responses={
            "runner-one": response("runner-one", runner_id="runner-1"),
            "runner-two": response("runner-two", runner_id="runner-2"),
        },
    )

    assert set(result.record.affected_job_ids) == {"runner-one", "runner-two"}
    assert set(result.record.affected_credential_lease_ids) == {"lease-runner-one", "lease-runner-two"}
    assert {item.job_id for item in result.record.cancellation_evidence} == {"runner-one", "runner-two"}
    assert all(item.credential_revoked for item in result.record.cancellation_evidence)
