from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import domain, evidence_chain, evidence_store, job_queue, runner_execution
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 14, 0, tzinfo=timezone.utc)


def target(target_type: domain.TargetType = domain.TargetType.WEB_ORIGIN, value: str = "https://example.test") -> ScopeTarget:
    return ScopeTarget(target_type=target_type, value=value)


def queued_job(**overrides: object) -> job_queue.JobRecord:
    values = {
        "job_id": "job-r058",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "test_definition_id": "test-1",
        "target": target(),
        "mode": domain.TestMode.PASSIVE_SCAN,
        "status": domain.JobStatus.QUEUED,
        "projected_interactions": 1,
        "timeout_seconds": 30,
        "cleanup_required": True,
        "max_attempts": 1,
        "policy_decision_id": "decision-1",
        "policy_expires_at": NOW + timedelta(minutes=10),
    }
    values.update(overrides)
    return job_queue.JobRecord(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.PASSIVE_SCAN, domain.TestMode.LAB_ONLY_RUN),
        "policy_token_reference": "policy-ref-1",
        "target_scope": target(),
        "timeout_seconds": 30,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("stdout", "stderr", "evidence_ids"),
        "cleanup_callback": "cleanup://runner-1/job-r058",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def state(job: job_queue.JobRecord | None = None) -> job_queue.JobQueueState:
    return job_queue.JobQueueState(jobs=(job or queued_job(),))


def spec(
    job: job_queue.JobRecord | None = None,
    runner_contract: job_queue.RunnerContract | None = None,
    **overrides: object,
) -> runner_execution.RunnerJobSpec:
    job = job or queued_job()
    runner_contract = runner_contract or runner()
    values = {
        "spec_id": "spec-r058",
        "job": job,
        "runner": runner_contract,
        "adapter": runner_execution.RunnerAdapterKind.DRY_RUN,
        "requested_at": NOW,
        "evidence_id": "evidence-r058",
        "operator_user_id": "operator-1",
        "adapter_parameters": {},
    }
    values.update(overrides)
    return runner_execution.build_runner_job_spec(**values)  # type: ignore[arg-type]


def test_runner_dispatch_records_callbacks_evidence_cleanup_and_exit(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)

    result = runner_execution.dispatch_runner_job(
        state=state(),
        runner=runner(),
        spec=spec(),
        evidence_store=store,
        occurred_at=NOW,
    )

    assert result.allowed
    assert result.exit_classification is runner_execution.RunnerExitClassification.SUCCEEDED
    assert result.cleanup.succeeded
    assert result.evidence_manifest is not None
    assert result.evidence_manifest.evidence_id == "evidence-r058"
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert result.state.jobs[0].evidence_ids == ("evidence-r058",)
    assert any(event.subject_id == "job-r058" for event in result.state.audit_chain.audit_events)


def test_runner_denies_tampered_unscoped_expired_and_missing_controls(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    valid = spec()
    tampered = replace(valid, evidence_id="evidence-tampered")
    unscoped_runner = runner(target_scope=target(value="https://other.example.test"))
    expired_job = queued_job(policy_expires_at=NOW - timedelta(seconds=1))
    expired = spec(job=expired_job)
    no_timeout = spec(job=queued_job(timeout_seconds=0))
    no_cleanup = spec(job=queued_job(cleanup_required=False))
    no_evidence = spec(evidence_id="")

    cases = (
        (tampered, runner(), "runner_job_spec_hash_mismatch"),
        (valid, unscoped_runner, "unscoped_target"),
        (expired, runner(), "current_policy_decision_required"),
        (no_timeout, runner(), "missing_timeout"),
        (no_cleanup, runner(), "missing_cleanup_policy"),
        (no_evidence, runner(), "missing_evidence_id"),
    )

    for job_spec, runner_contract, reason in cases:
        result = runner_execution.dispatch_runner_job(
            state=state(expired_job if job_spec is expired else queued_job(timeout_seconds=job_spec.timeout_seconds)),
            runner=runner_contract,
            spec=job_spec,
            evidence_store=store,
            occurred_at=NOW,
        )
        assert not result.allowed
        assert result.reason == reason
        assert result.exit_classification is runner_execution.RunnerExitClassification.DENIED


def test_runner_payload_rejects_arbitrary_shell_url_and_unapproved_tool() -> None:
    payload = {
        "spec_id": "spec-r058",
        "job_id": "job-r058",
        "organization_id": "org-1",
        "runner_id": "runner-1",
        "adapter": runner_execution.RunnerAdapterKind.DRY_RUN.value,
        "mode": domain.TestMode.PASSIVE_SCAN.value,
        "target": {"target_type": domain.TargetType.WEB_ORIGIN.value, "value": "https://example.test"},
        "policy_decision_id": "decision-1",
        "policy_expires_at": (NOW + timedelta(minutes=10)).isoformat(),
        "requested_at": NOW.isoformat(),
        "timeout_seconds": 30,
        "cleanup_required": True,
        "evidence_id": "evidence-r058",
        "operator_user_id": "operator-1",
        "adapter_parameters": {},
        "spec_hash": "bad-hash",
    }

    with pytest.raises(ValueError, match="arbitrary_shell_or_url_forbidden"):
        runner_execution.build_runner_job_spec_from_payload({**payload, "command": "not allowed"})

    with pytest.raises(ValueError):
        runner_execution.build_runner_job_spec_from_payload({**payload, "adapter": "external_tool"})


def test_runner_timeout_cancellation_duplicate_callback_and_failed_cleanup(tmp_path) -> None:
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)
    timeout = runner_execution.dispatch_runner_job(
        state=state(),
        runner=runner(),
        spec=spec(adapter_parameters={"simulate_timeout": True}),
        evidence_store=store,
        occurred_at=NOW,
    )
    cancelled = runner_execution.dispatch_runner_job(
        state=state(queued_job(job_id="job-cancel")),
        runner=runner(),
        spec=spec(job=queued_job(job_id="job-cancel"), adapter_parameters={"cancel_requested": True}),
        evidence_store=store,
        occurred_at=NOW,
    )
    cleanup_failed = runner_execution.dispatch_runner_job(
        state=state(queued_job(job_id="job-cleanup", policy_decision_id="decision-cleanup")),
        runner=runner(),
        spec=spec(
            job=queued_job(job_id="job-cleanup", policy_decision_id="decision-cleanup"),
            evidence_id="evidence-cleanup",
            adapter_parameters={"cleanup_success": False},
        ),
        evidence_store=store,
        occurred_at=NOW,
    )
    duplicate_state, duplicate = cleanup_failed.state.handle_callback(
        job_queue.RunnerCallback(
            callback_id="spec-r058:heartbeat",
            runner_id="runner-1",
            job_id="job-cleanup",
            kind=job_queue.RunnerCallbackKind.HEARTBEAT,
            occurred_at=NOW,
        ),
        actor_user_id="runner-1",
        event_id="duplicate",
    )

    assert timeout.exit_classification is runner_execution.RunnerExitClassification.TIMED_OUT
    assert timeout.state.jobs[0].status is domain.JobStatus.CLEANUP
    assert cancelled.exit_classification is runner_execution.RunnerExitClassification.CANCELLED
    assert cancelled.state.jobs[0].status is domain.JobStatus.CLEANUP
    assert cleanup_failed.exit_classification is runner_execution.RunnerExitClassification.CLEANUP_FAILED
    assert cleanup_failed.cleanup.attempted
    assert duplicate.reason == "duplicate_callback"
    assert duplicate_state is cleanup_failed.state


def test_runner_redacts_stdout_before_artifact_persistence(tmp_path) -> None:
    lab_target = target(domain.TargetType.LAB_TARGET, "local-lab")
    job = queued_job(target=lab_target, mode=domain.TestMode.LAB_ONLY_RUN)
    runner_contract = runner(target_scope=lab_target)
    store = evidence_store.LocalEvidenceArtifactStore(tmp_path)

    result = runner_execution.dispatch_runner_job(
        state=state(job),
        runner=runner_contract,
        spec=spec(
            job=job,
            runner_contract=runner_contract,
            adapter=runner_execution.RunnerAdapterKind.LAB_ECHO,
            adapter_parameters={"stdout": "Authorization: Bearer sample-value"},
        ),
        evidence_store=store,
        occurred_at=NOW,
    )

    assert result.allowed
    assert "sample-value" not in result.sanitized_stdout
    assert result.evidence_manifest is not None
    assert result.evidence_manifest.redaction_status is evidence_chain.RedactionStatus.REDACTED
    artifact_text = (tmp_path / result.evidence_manifest.artifact_path).read_text(encoding="utf-8")
    assert "sample-value" not in artifact_text
