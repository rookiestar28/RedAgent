from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import cloud_lifecycle, cloud_posture
from redagent_platform.target_inventory import EnvironmentType


NOW = datetime(2026, 7, 8, 22, 0, tzinfo=timezone.utc)


def lifecycle_step(step_type: cloud_lifecycle.CloudLifecycleStepType) -> cloud_lifecycle.CloudLifecycleStep:
    return cloud_lifecycle.CloudLifecycleStep(
        step_type=step_type,
        name=f"{step_type.value} step",
        operator_intent=f"Local state transition for {step_type.value}.",
        idempotent=True,
        expected_log_sources=("cloudtrail", "siem"),
    )


def guardrails(**overrides: object) -> cloud_lifecycle.CloudAccountGuardrails:
    values = {
        "environment": EnvironmentType.TEST,
        "account_ids": ("aws:123456789012",),
        "project_ids": (),
        "allowed_regions": ("ap-northeast-1",),
        "owner_approved_by_user_id": "owner-1",
        "max_cost_usd": 20.0,
        "resource_tags": ("redteam:eng-1", "owner:security"),
    }
    values.update(overrides)
    return cloud_lifecycle.CloudAccountGuardrails(**values)  # type: ignore[arg-type]


def definition(**overrides: object) -> cloud_lifecycle.CloudTechniqueDefinition:
    values = {
        "technique_id": "cloud-technique-1",
        "provider": cloud_posture.CloudProvider.AWS,
        "guardrails": guardrails(),
        "required_permissions": ("sts:GetCallerIdentity", "iam:ListRoles"),
        "cost_estimate_usd": 5.0,
        "resource_tags": ("redteam:eng-1",),
        "warm_up": lifecycle_step(cloud_lifecycle.CloudLifecycleStepType.WARM_UP),
        "detonation": lifecycle_step(cloud_lifecycle.CloudLifecycleStepType.DETONATE),
        "revert": lifecycle_step(cloud_lifecycle.CloudLifecycleStepType.REVERT),
        "cleanup": lifecycle_step(cloud_lifecycle.CloudLifecycleStepType.CLEANUP),
        "idempotence_key": "cloud-technique-1:test",
        "expected_logs": ("cloudtrail:AssumeRole", "siem:cloud-technique-1"),
        "max_cleanup_attempts": 2,
    }
    values.update(overrides)
    return cloud_lifecycle.CloudTechniqueDefinition(**values)  # type: ignore[arg-type]


def event(
    step_type: cloud_lifecycle.CloudLifecycleStepType,
    result: cloud_lifecycle.CloudLifecycleEventResult = cloud_lifecycle.CloudLifecycleEventResult.SUCCEEDED,
    *,
    minutes: int = 1,
    evidence_ids: tuple[str, ...] = (),
) -> cloud_lifecycle.CloudLifecycleEvent:
    return cloud_lifecycle.CloudLifecycleEvent(
        step_type=step_type,
        result=result,
        occurred_at=NOW + timedelta(minutes=minutes),
        evidence_ids=evidence_ids,
    )


def started_run() -> cloud_lifecycle.CloudLifecycleRun:
    start = cloud_lifecycle.initialize_lifecycle_run(definition=definition(), run_id="run-1", started_at=NOW)
    assert start.run is not None
    return start.run


def test_definition_requires_guardrails_permissions_cost_tags_steps_idempotence_and_expected_logs() -> None:
    cloud_lifecycle.validate_cloud_technique_definition(definition())

    with pytest.raises(ValueError, match="cloud_account_or_project_guardrail_required"):
        cloud_lifecycle.validate_cloud_technique_definition(definition(guardrails=guardrails(account_ids=(), project_ids=())))
    with pytest.raises(ValueError, match="cloud_permissions_required"):
        cloud_lifecycle.validate_cloud_technique_definition(definition(required_permissions=()))
    with pytest.raises(ValueError, match="cloud_cost_guardrail_exceeded"):
        cloud_lifecycle.validate_cloud_technique_definition(definition(cost_estimate_usd=25.0))
    with pytest.raises(ValueError, match="cloud_resource_tags_required"):
        cloud_lifecycle.validate_cloud_technique_definition(definition(resource_tags=()))
    with pytest.raises(ValueError, match="cloud_detonate_must_be_idempotent"):
        cloud_lifecycle.validate_cloud_technique_definition(
            definition(
                detonation=cloud_lifecycle.CloudLifecycleStep(
                    step_type=cloud_lifecycle.CloudLifecycleStepType.DETONATE,
                    name="detonate",
                    operator_intent="test",
                    idempotent=False,
                    expected_log_sources=("cloudtrail",),
                )
            )
        )
    with pytest.raises(ValueError, match="cloud_expected_logs_required"):
        cloud_lifecycle.validate_cloud_technique_definition(definition(expected_logs=()))


def test_production_cloud_accounts_are_blocked_until_future_exception_policy_exists() -> None:
    result = cloud_lifecycle.initialize_lifecycle_run(
        definition=definition(guardrails=guardrails(environment=EnvironmentType.PRODUCTION)),
        run_id="run-1",
        started_at=NOW,
    )

    assert not result.allowed
    assert result.reason == "production_cloud_blocked"
    assert result.run is None


def test_lifecycle_success_requires_cleanup_verification_before_evidence_lock() -> None:
    run = started_run()
    run = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=run,
        event=event(cloud_lifecycle.CloudLifecycleStepType.WARM_UP),
    )
    run = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=run,
        event=event(cloud_lifecycle.CloudLifecycleStepType.DETONATE, evidence_ids=("detonation-evidence",)),
    )
    run = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=run,
        event=event(cloud_lifecycle.CloudLifecycleStepType.REVERT),
    )
    run = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=run,
        event=event(cloud_lifecycle.CloudLifecycleStepType.CLEANUP),
    )

    assert run.status is cloud_lifecycle.CloudLifecycleStatus.CLEANUP_COMPLETED
    with pytest.raises(ValueError, match="cleanup_verification_required_before_evidence_lock"):
        cloud_lifecycle.lock_evidence_after_cleanup(run, occurred_at=NOW + timedelta(minutes=5), evidence_id="evidence-lock-1")

    run = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=run,
        event=event(cloud_lifecycle.CloudLifecycleStepType.VERIFY_CLEANUP),
    )
    locked = cloud_lifecycle.lock_evidence_after_cleanup(run, occurred_at=NOW + timedelta(minutes=6), evidence_id="evidence-lock-1")

    assert locked.status is cloud_lifecycle.CloudLifecycleStatus.EVIDENCE_LOCKED
    assert locked.cleanup_verified
    assert "detonation-evidence" in locked.evidence_ids
    assert "evidence-lock-1" in locked.evidence_ids


def test_failed_warm_up_is_terminal_without_detonation() -> None:
    failed = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=started_run(),
        event=event(
            cloud_lifecycle.CloudLifecycleStepType.WARM_UP,
            cloud_lifecycle.CloudLifecycleEventResult.FAILED,
        ),
    )

    assert failed.status is cloud_lifecycle.CloudLifecycleStatus.FAILED
    assert failed.failure_stage is cloud_lifecycle.CloudLifecycleStepType.WARM_UP
    with pytest.raises(ValueError, match="terminal_cloud_lifecycle_rejects_event"):
        cloud_lifecycle.apply_lifecycle_event(
            definition=definition(),
            run=failed,
            event=event(cloud_lifecycle.CloudLifecycleStepType.DETONATE),
        )


def test_failed_detonation_and_failed_revert_force_cleanup_required() -> None:
    warmed = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=started_run(),
        event=event(cloud_lifecycle.CloudLifecycleStepType.WARM_UP),
    )
    detonation_failed = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=warmed,
        event=event(
            cloud_lifecycle.CloudLifecycleStepType.DETONATE,
            cloud_lifecycle.CloudLifecycleEventResult.FAILED,
            evidence_ids=("failed-detonation-evidence",),
        ),
    )

    assert detonation_failed.status is cloud_lifecycle.CloudLifecycleStatus.CLEANUP_REQUIRED
    assert detonation_failed.failure_stage is cloud_lifecycle.CloudLifecycleStepType.DETONATE
    assert detonation_failed.evidence_ids == ("failed-detonation-evidence",)

    detonated = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=warmed,
        event=event(cloud_lifecycle.CloudLifecycleStepType.DETONATE),
    )
    revert_failed = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=detonated,
        event=event(
            cloud_lifecycle.CloudLifecycleStepType.REVERT,
            cloud_lifecycle.CloudLifecycleEventResult.FAILED,
        ),
    )

    assert revert_failed.status is cloud_lifecycle.CloudLifecycleStatus.CLEANUP_REQUIRED
    assert revert_failed.failure_stage is cloud_lifecycle.CloudLifecycleStepType.REVERT


def test_cleanup_retry_behavior_is_bounded() -> None:
    warmed = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=started_run(),
        event=event(cloud_lifecycle.CloudLifecycleStepType.WARM_UP),
    )
    cleanup_required = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=warmed,
        event=event(
            cloud_lifecycle.CloudLifecycleStepType.DETONATE,
            cloud_lifecycle.CloudLifecycleEventResult.FAILED,
        ),
    )
    retry_ready = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=cleanup_required,
        event=event(
            cloud_lifecycle.CloudLifecycleStepType.CLEANUP,
            cloud_lifecycle.CloudLifecycleEventResult.FAILED,
        ),
    )

    assert retry_ready.status is cloud_lifecycle.CloudLifecycleStatus.CLEANUP_RETRY_READY
    assert retry_ready.cleanup_attempts == 1
    assert cloud_lifecycle.should_retry_cleanup(definition(), retry_ready)

    exhausted = cloud_lifecycle.apply_lifecycle_event(
        definition=definition(),
        run=retry_ready,
        event=event(
            cloud_lifecycle.CloudLifecycleStepType.CLEANUP,
            cloud_lifecycle.CloudLifecycleEventResult.FAILED,
        ),
    )

    assert exhausted.status is cloud_lifecycle.CloudLifecycleStatus.FAILED
    assert exhausted.cleanup_attempts == 2
    assert not cloud_lifecycle.should_retry_cleanup(definition(), exhausted)
