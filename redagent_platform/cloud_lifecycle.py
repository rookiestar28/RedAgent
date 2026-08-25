"""Local cloud technique lifecycle contracts and state transitions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.cloud_posture import CloudProvider
from redagent_platform.target_inventory import EnvironmentType


class CloudLifecycleStepType(str, Enum):
    WARM_UP = "warm_up"
    DETONATE = "detonate"
    REVERT = "revert"
    CLEANUP = "cleanup"
    VERIFY_CLEANUP = "verify_cleanup"


class CloudLifecycleEventResult(str, Enum):
    SUCCEEDED = "succeeded"
    FAILED = "failed"


class CloudLifecycleStatus(str, Enum):
    PLANNED = "planned"
    WARMED_UP = "warmed_up"
    DETONATED = "detonated"
    REVERTED = "reverted"
    CLEANUP_REQUIRED = "cleanup_required"
    CLEANUP_RETRY_READY = "cleanup_retry_ready"
    CLEANUP_COMPLETED = "cleanup_completed"
    CLEANUP_VERIFIED = "cleanup_verified"
    EVIDENCE_LOCKED = "evidence_locked"
    FAILED = "failed"


@dataclass(frozen=True, kw_only=True)
class CloudAccountGuardrails:
    environment: EnvironmentType
    account_ids: tuple[str, ...]
    project_ids: tuple[str, ...]
    allowed_regions: tuple[str, ...]
    owner_approved_by_user_id: str
    max_cost_usd: float
    resource_tags: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class CloudLifecycleStep:
    step_type: CloudLifecycleStepType
    name: str
    operator_intent: str
    idempotent: bool
    expected_log_sources: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class CloudTechniqueDefinition:
    technique_id: str
    provider: CloudProvider
    guardrails: CloudAccountGuardrails
    required_permissions: tuple[str, ...]
    cost_estimate_usd: float
    resource_tags: tuple[str, ...]
    warm_up: CloudLifecycleStep
    detonation: CloudLifecycleStep
    revert: CloudLifecycleStep
    cleanup: CloudLifecycleStep
    idempotence_key: str
    expected_logs: tuple[str, ...]
    max_cleanup_attempts: int = 3


@dataclass(frozen=True, kw_only=True)
class CloudLifecycleRun:
    run_id: str
    technique_id: str
    status: CloudLifecycleStatus
    cleanup_attempts: int
    cleanup_verified: bool
    started_at: datetime
    last_event_at: datetime
    failure_stage: CloudLifecycleStepType | None = None
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class CloudLifecycleStartResult:
    allowed: bool
    reason: str
    run: CloudLifecycleRun | None = None


@dataclass(frozen=True, kw_only=True)
class CloudLifecycleEvent:
    step_type: CloudLifecycleStepType
    result: CloudLifecycleEventResult
    occurred_at: datetime
    evidence_ids: tuple[str, ...] = ()
    message: str | None = None


def validate_cloud_technique_definition(definition: CloudTechniqueDefinition) -> None:
    for field_name, value in (
        ("technique_id", definition.technique_id),
        ("owner_approved_by_user_id", definition.guardrails.owner_approved_by_user_id),
        ("idempotence_key", definition.idempotence_key),
    ):
        _require_non_empty(field_name, value)
    if definition.guardrails.environment is EnvironmentType.UNKNOWN:
        raise ValueError("cloud_environment_classification_required")
    if not definition.guardrails.account_ids and not definition.guardrails.project_ids:
        raise ValueError("cloud_account_or_project_guardrail_required")
    if not definition.guardrails.allowed_regions:
        raise ValueError("cloud_region_guardrail_required")
    if not definition.required_permissions:
        raise ValueError("cloud_permissions_required")
    if definition.cost_estimate_usd < 0 or definition.guardrails.max_cost_usd < 0:
        raise ValueError("cloud_cost_estimate_invalid")
    if definition.cost_estimate_usd > definition.guardrails.max_cost_usd:
        raise ValueError("cloud_cost_guardrail_exceeded")
    if not definition.resource_tags or not definition.guardrails.resource_tags:
        raise ValueError("cloud_resource_tags_required")
    if definition.max_cleanup_attempts <= 0:
        raise ValueError("cloud_cleanup_attempts_invalid")
    _validate_step(definition.warm_up, CloudLifecycleStepType.WARM_UP)
    _validate_step(definition.detonation, CloudLifecycleStepType.DETONATE)
    _validate_step(definition.revert, CloudLifecycleStepType.REVERT)
    _validate_step(definition.cleanup, CloudLifecycleStepType.CLEANUP)
    if not definition.expected_logs:
        raise ValueError("cloud_expected_logs_required")


def initialize_lifecycle_run(
    *,
    definition: CloudTechniqueDefinition,
    run_id: str,
    started_at: datetime,
) -> CloudLifecycleStartResult:
    try:
        validate_cloud_technique_definition(definition)
        _require_non_empty("run_id", run_id)
        _require_timezone(started_at)
    except ValueError as exc:
        return CloudLifecycleStartResult(allowed=False, reason=str(exc))
    if definition.guardrails.environment is EnvironmentType.PRODUCTION:
        return CloudLifecycleStartResult(allowed=False, reason="production_cloud_blocked")
    return CloudLifecycleStartResult(
        allowed=True,
        reason="cloud_lifecycle_planned",
        run=CloudLifecycleRun(
            run_id=run_id.strip(),
            technique_id=definition.technique_id.strip(),
            status=CloudLifecycleStatus.PLANNED,
            cleanup_attempts=0,
            cleanup_verified=False,
            started_at=started_at,
            last_event_at=started_at,
        ),
    )


def apply_lifecycle_event(
    *,
    definition: CloudTechniqueDefinition,
    run: CloudLifecycleRun,
    event: CloudLifecycleEvent,
) -> CloudLifecycleRun:
    validate_cloud_technique_definition(definition)
    _validate_run(run)
    _validate_event(event)
    if run.technique_id != definition.technique_id:
        raise ValueError("cloud_lifecycle_technique_mismatch")
    if run.status in {CloudLifecycleStatus.EVIDENCE_LOCKED, CloudLifecycleStatus.FAILED}:
        raise ValueError("terminal_cloud_lifecycle_rejects_event")
    if event.result is CloudLifecycleEventResult.FAILED:
        return _handle_failed_event(definition, run, event)
    return _handle_success_event(run, event)


def should_retry_cleanup(definition: CloudTechniqueDefinition, run: CloudLifecycleRun) -> bool:
    validate_cloud_technique_definition(definition)
    _validate_run(run)
    return run.status is CloudLifecycleStatus.CLEANUP_RETRY_READY and run.cleanup_attempts < definition.max_cleanup_attempts


def lock_evidence_after_cleanup(run: CloudLifecycleRun, *, occurred_at: datetime, evidence_id: str) -> CloudLifecycleRun:
    _validate_run(run)
    _require_timezone(occurred_at)
    _require_non_empty("evidence_id", evidence_id)
    if run.status is not CloudLifecycleStatus.CLEANUP_VERIFIED or not run.cleanup_verified:
        raise ValueError("cleanup_verification_required_before_evidence_lock")
    return _replace_run(
        run,
        status=CloudLifecycleStatus.EVIDENCE_LOCKED,
        last_event_at=occurred_at,
        evidence_ids=_merge_evidence(run.evidence_ids, (evidence_id,)),
    )


def _handle_failed_event(
    definition: CloudTechniqueDefinition,
    run: CloudLifecycleRun,
    event: CloudLifecycleEvent,
) -> CloudLifecycleRun:
    if event.step_type is CloudLifecycleStepType.WARM_UP:
        _require_status(run, {CloudLifecycleStatus.PLANNED})
        return _replace_run(run, status=CloudLifecycleStatus.FAILED, last_event_at=event.occurred_at, failure_stage=event.step_type)
    if event.step_type is CloudLifecycleStepType.DETONATE:
        _require_status(run, {CloudLifecycleStatus.WARMED_UP})
        return _replace_run(
            run,
            status=CloudLifecycleStatus.CLEANUP_REQUIRED,
            last_event_at=event.occurred_at,
            failure_stage=event.step_type,
            evidence_ids=_merge_evidence(run.evidence_ids, event.evidence_ids),
        )
    if event.step_type is CloudLifecycleStepType.REVERT:
        _require_status(run, {CloudLifecycleStatus.DETONATED})
        return _replace_run(run, status=CloudLifecycleStatus.CLEANUP_REQUIRED, last_event_at=event.occurred_at, failure_stage=event.step_type)
    if event.step_type is CloudLifecycleStepType.CLEANUP:
        _require_status(run, {CloudLifecycleStatus.CLEANUP_REQUIRED, CloudLifecycleStatus.CLEANUP_RETRY_READY})
        attempts = run.cleanup_attempts + 1
        status = CloudLifecycleStatus.CLEANUP_RETRY_READY if attempts < definition.max_cleanup_attempts else CloudLifecycleStatus.FAILED
        return _replace_run(run, status=status, cleanup_attempts=attempts, last_event_at=event.occurred_at, failure_stage=event.step_type)
    raise ValueError("unsupported_failed_cloud_lifecycle_event")


def _handle_success_event(run: CloudLifecycleRun, event: CloudLifecycleEvent) -> CloudLifecycleRun:
    if event.step_type is CloudLifecycleStepType.WARM_UP:
        _require_status(run, {CloudLifecycleStatus.PLANNED})
        return _replace_run(run, status=CloudLifecycleStatus.WARMED_UP, last_event_at=event.occurred_at)
    if event.step_type is CloudLifecycleStepType.DETONATE:
        _require_status(run, {CloudLifecycleStatus.WARMED_UP})
        return _replace_run(
            run,
            status=CloudLifecycleStatus.DETONATED,
            last_event_at=event.occurred_at,
            evidence_ids=_merge_evidence(run.evidence_ids, event.evidence_ids),
        )
    if event.step_type is CloudLifecycleStepType.REVERT:
        _require_status(run, {CloudLifecycleStatus.DETONATED})
        return _replace_run(run, status=CloudLifecycleStatus.REVERTED, last_event_at=event.occurred_at)
    if event.step_type is CloudLifecycleStepType.CLEANUP:
        _require_status(run, {CloudLifecycleStatus.REVERTED, CloudLifecycleStatus.CLEANUP_REQUIRED, CloudLifecycleStatus.CLEANUP_RETRY_READY})
        return _replace_run(
            run,
            status=CloudLifecycleStatus.CLEANUP_COMPLETED,
            cleanup_attempts=run.cleanup_attempts + 1,
            last_event_at=event.occurred_at,
        )
    if event.step_type is CloudLifecycleStepType.VERIFY_CLEANUP:
        _require_status(run, {CloudLifecycleStatus.CLEANUP_COMPLETED})
        return _replace_run(run, status=CloudLifecycleStatus.CLEANUP_VERIFIED, cleanup_verified=True, last_event_at=event.occurred_at)
    raise ValueError("unsupported_cloud_lifecycle_event")


def _validate_step(step: CloudLifecycleStep, expected: CloudLifecycleStepType) -> None:
    if step.step_type is not expected:
        raise ValueError(f"cloud_{expected.value}_step_required")
    for field_name, value in (("step_name", step.name), ("operator_intent", step.operator_intent)):
        _require_non_empty(field_name, value)
    if not step.idempotent:
        raise ValueError(f"cloud_{expected.value}_must_be_idempotent")
    if not step.expected_log_sources:
        raise ValueError(f"cloud_{expected.value}_expected_logs_required")


def _validate_run(run: CloudLifecycleRun) -> None:
    for field_name, value in (("run_id", run.run_id), ("technique_id", run.technique_id)):
        _require_non_empty(field_name, value)
    _require_timezone(run.started_at)
    _require_timezone(run.last_event_at)
    if run.cleanup_attempts < 0:
        raise ValueError("cloud_cleanup_attempts_invalid")


def _validate_event(event: CloudLifecycleEvent) -> None:
    _require_timezone(event.occurred_at)
    for evidence_id in event.evidence_ids:
        _require_non_empty("evidence_id", evidence_id)


def _require_status(run: CloudLifecycleRun, allowed: set[CloudLifecycleStatus]) -> None:
    if run.status not in allowed:
        raise ValueError("invalid_cloud_lifecycle_transition")


def _replace_run(
    run: CloudLifecycleRun,
    *,
    status: CloudLifecycleStatus,
    cleanup_attempts: int | None = None,
    cleanup_verified: bool | None = None,
    last_event_at: datetime,
    failure_stage: CloudLifecycleStepType | None = None,
    evidence_ids: tuple[str, ...] | None = None,
) -> CloudLifecycleRun:
    return CloudLifecycleRun(
        run_id=run.run_id,
        technique_id=run.technique_id,
        status=status,
        cleanup_attempts=run.cleanup_attempts if cleanup_attempts is None else cleanup_attempts,
        cleanup_verified=run.cleanup_verified if cleanup_verified is None else cleanup_verified,
        started_at=run.started_at,
        last_event_at=last_event_at,
        failure_stage=failure_stage,
        evidence_ids=evidence_ids if evidence_ids is not None else run.evidence_ids,
    )


def _merge_evidence(existing: tuple[str, ...], additional: tuple[str, ...]) -> tuple[str, ...]:
    merged = list(existing)
    for evidence_id in additional:
        _require_non_empty("evidence_id", evidence_id)
        if evidence_id not in merged:
            merged.append(evidence_id)
    return tuple(merged)


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
