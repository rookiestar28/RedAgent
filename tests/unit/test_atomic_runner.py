from datetime import datetime, timedelta, timezone

from redagent_platform import atomic_runner, domain, evidence_chain


NOW = datetime(2026, 7, 8, 18, 0, tzinfo=timezone.utc)


def raw_atomic(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "test_id": "atomic-T1190-001",
        "name": "Web request telemetry validation",
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "supported_platforms": ("windows", "linux"),
        "executor_name": "manual-lab",
        "prerequisite_summary": "Approved local lab web target is available.",
        "execution_summary": "Send a controlled lab request and observe telemetry.",
        "cleanup_summary": "Remove temporary lab marker after validation.",
        "expected_telemetry": ("application_log", "network_sensor"),
        "command": "THIS RAW COMMAND BODY MUST NOT BE STORED",
    }
    values.update(overrides)
    return values


def metadata(**overrides: object) -> atomic_runner.AtomicTestMetadata:
    return atomic_runner.import_atomic_metadata(raw_atomic(**overrides))


def lab_target(**overrides: object) -> atomic_runner.LabTargetContext:
    values = {
        "target_id": "lab-target-1",
        "target_type": domain.TargetType.LAB_TARGET,
        "environment": "local-lab",
        "platform": "windows",
        "is_lab_target": True,
        "approved_by_user_id": "lead-1",
    }
    values.update(overrides)
    return atomic_runner.LabTargetContext(**values)  # type: ignore[arg-type]


def review(*flags: atomic_runner.AtomicSafetyFlag) -> atomic_runner.AtomicReview:
    return atomic_runner.AtomicReview(
        reviewed_by_user_id="reviewer-1",
        reviewed_at=NOW - timedelta(minutes=5),
        allowed_flags=flags,
        lab_environment_id="lab-env-1",
    )


def request(**overrides: object) -> atomic_runner.AtomicLabRunRequest:
    values = {
        "job_id": "atomic-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "metadata": metadata(),
        "target": lab_target(),
        "requested_at": NOW,
        "review": None,
    }
    values.update(overrides)
    return atomic_runner.AtomicLabRunRequest(**values)  # type: ignore[arg-type]


def test_atomic_import_defaults_to_metadata_only_and_drops_command_body() -> None:
    imported = metadata()

    assert imported.metadata_only
    assert imported.test_id == "atomic-T1190-001"
    assert imported.attack_mapping[0].technique_id == "T1190"
    assert imported.supported_platforms == ("windows", "linux")
    assert not hasattr(imported, "command")
    assert not hasattr(imported, "command_body")


def test_lab_runner_prepares_reviewed_phase_capture_for_lab_target() -> None:
    result = atomic_runner.prepare_lab_atomic_run(
        request=request(),
        audit_chain=evidence_chain.EvidenceChain(),
        event_id="atomic-run-1",
    )

    assert result.decision.allowed
    assert result.decision.reason == "lab_atomic_run_prepared"
    assert result.record is not None
    assert result.record.mode is domain.TestMode.LAB_ONLY_RUN
    assert result.record.risk_class is domain.TestRiskClass.LAB_ONLY
    assert result.record.execution_enabled
    assert [phase.phase for phase in result.record.phases] == [
        atomic_runner.AtomicRunPhase.PREREQUISITE,
        atomic_runner.AtomicRunPhase.EXECUTION,
        atomic_runner.AtomicRunPhase.CLEANUP,
        atomic_runner.AtomicRunPhase.TELEMETRY,
        atomic_runner.AtomicRunPhase.EVIDENCE,
    ]
    assert result.audit_chain.audit_events[0].action is evidence_chain.AuditAction.JOB_LIFECYCLE


def test_lab_runner_blocks_unsafe_flags_until_explicitly_reviewed() -> None:
    unsafe_metadata = metadata(
        requires_external_download=True,
        requires_elevation=True,
        destructive_potential=True,
        cleanup_summary=None,
        supported_platforms=("linux",),
    )

    denied = atomic_runner.evaluate_lab_run(request(metadata=unsafe_metadata))

    assert not denied.allowed
    assert denied.reason == "atomic_review_required"
    assert denied.blocked_flags == (
        atomic_runner.AtomicSafetyFlag.EXTERNAL_DOWNLOAD,
        atomic_runner.AtomicSafetyFlag.ELEVATED_PRIVILEGE,
        atomic_runner.AtomicSafetyFlag.DESTRUCTIVE,
        atomic_runner.AtomicSafetyFlag.MISSING_CLEANUP,
        atomic_runner.AtomicSafetyFlag.UNSUPPORTED_PLATFORM,
    )
    assert all(phase.status is atomic_runner.AtomicPhaseStatus.BLOCKED for phase in denied.phases)

    allowed = atomic_runner.evaluate_lab_run(
        request(
            metadata=unsafe_metadata,
            review=review(*denied.blocked_flags),
        )
    )

    assert allowed.allowed
    assert allowed.blocked_flags == ()


def test_non_lab_targets_cannot_run_atomic_jobs() -> None:
    non_lab_decision = atomic_runner.evaluate_lab_run(
        request(target=lab_target(target_type=domain.TargetType.WEB_ORIGIN, is_lab_target=False))
    )

    assert not non_lab_decision.allowed
    assert non_lab_decision.reason == "lab_target_required"

    wrong_type_decision = atomic_runner.evaluate_lab_run(
        request(target=lab_target(target_type=domain.TargetType.WEB_ORIGIN))
    )

    assert not wrong_type_decision.allowed
    assert wrong_type_decision.reason == "lab_target_type_required"


def test_no_atomic_execution_function_or_shell_payload_contract_exists() -> None:
    assert not hasattr(atomic_runner, "execute_atomic")
    assert not hasattr(atomic_runner, "run_command")
    assert not hasattr(atomic_runner, "shell")
