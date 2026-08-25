"""Fail-closed active testing policy gate contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.domain import JobStatus, PolicyDecisionOutcome, TestMode
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.job_queue import JobRecord, PolicyGrant
from redagent_platform.scope_authorization import EngagementScope, JobScopeRequest, ScopeTarget, decide_scope


class PayloadClass(str, Enum):
    SAFE_METADATA = "safe_metadata"
    STANDARD_ACTIVE = "standard_active"
    AUTHENTICATED_ACTIVE = "authenticated_active"
    INTRUSIVE = "intrusive"
    DESTRUCTIVE = "destructive"


@dataclass(frozen=True, kw_only=True)
class StopConditionPolicy:
    stop_on_scope_violation: bool
    stop_on_error_rate: bool
    max_error_count: int
    emergency_contact_required: bool


@dataclass(frozen=True, kw_only=True)
class ActiveModulePolicy:
    module_id: str
    allowed_modes: tuple[TestMode, ...]
    allowed_payload_classes: tuple[PayloadClass, ...]
    max_rate_per_second: float
    max_requests: int
    max_duration_seconds: int
    max_concurrent_per_engagement: int
    max_concurrent_per_target: int
    stop_conditions: StopConditionPolicy


@dataclass(frozen=True, kw_only=True)
class OperatorConfirmation:
    confirmed_by_user_id: str
    confirmed_at: datetime
    scope_acknowledged: bool
    risk_acknowledged: bool
    stop_conditions_acknowledged: bool


@dataclass(frozen=True, kw_only=True)
class ActiveJobRequest:
    job_id: str
    organization_id: str
    engagement_id: str
    target: ScopeTarget
    mode: TestMode
    module_id: str
    payload_class: PayloadClass
    requested_at: datetime
    projected_requests: int
    projected_duration_seconds: int
    requested_rate_per_second: float
    operator_confirmation: OperatorConfirmation | None


@dataclass(frozen=True, kw_only=True)
class ActivePolicyDecision:
    outcome: PolicyDecisionOutcome
    reason: str
    policy_grant: PolicyGrant | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome is PolicyDecisionOutcome.ALLOW


@dataclass(frozen=True, kw_only=True)
class ActivePolicyResult:
    decision: ActivePolicyDecision
    audit_chain: EvidenceChain


@dataclass(frozen=True, kw_only=True)
class KillSwitchPlan:
    cancelled_jobs: tuple[JobRecord, ...]
    unaffected_jobs: tuple[JobRecord, ...]
    audit_chain: EvidenceChain


ACTIVE_GATE_MODES = frozenset({TestMode.ACTIVE_SCAN, TestMode.ADVERSARY_EMULATION, TestMode.CLOUD_TECHNIQUE})
KILL_SWITCH_STATUSES = frozenset({JobStatus.QUEUED, JobStatus.DISPATCHED, JobStatus.RUNNING})


def evaluate_active_policy(
    *,
    request: ActiveJobRequest,
    scope: EngagementScope,
    module_policy: ActiveModulePolicy,
    existing_jobs: tuple[JobRecord, ...],
    audit_chain: EvidenceChain,
    decision_id: str,
    policy_expires_at: datetime,
) -> ActivePolicyResult:
    _validate_request(request)
    _validate_module_policy(module_policy)
    _require_non_empty("decision_id", decision_id)
    _require_timezone(policy_expires_at)
    denial = _first_denial(request, scope, module_policy, existing_jobs, policy_expires_at)
    if denial is None:
        grant = PolicyGrant(
            decision_id=decision_id.strip(),
            organization_id=request.organization_id,
            outcome=PolicyDecisionOutcome.ALLOW,
            decided_at=request.requested_at,
            expires_at=policy_expires_at,
            reason="active_policy_authorized",
        )
        decision = ActivePolicyDecision(outcome=PolicyDecisionOutcome.ALLOW, reason="active_policy_authorized", policy_grant=grant)
    else:
        decision = ActivePolicyDecision(outcome=PolicyDecisionOutcome.DENY, reason=denial)
    next_chain = audit_chain.append_audit_event(
        event_id=decision_id,
        organization_id=request.organization_id,
        actor_user_id=request.operator_confirmation.confirmed_by_user_id if request.operator_confirmation else None,
        action=AuditAction.POLICY_DECISION,
        subject_type="active_job_request",
        subject_id=request.job_id,
        occurred_at=request.requested_at,
        details={
            "outcome": decision.outcome.value,
            "reason": decision.reason,
            "mode": request.mode.value,
            "module_id": request.module_id,
            "payload_class": request.payload_class.value,
            "projected_requests": request.projected_requests,
        },
    )
    return ActivePolicyResult(decision=decision, audit_chain=next_chain)


def build_kill_switch_plan(
    *,
    jobs: tuple[JobRecord, ...],
    reason: str,
    actor_user_id: str,
    event_id: str,
    occurred_at: datetime,
    audit_chain: EvidenceChain,
) -> KillSwitchPlan:
    _require_non_empty("kill_switch_reason", reason)
    _require_non_empty("actor_user_id", actor_user_id)
    _require_non_empty("event_id", event_id)
    _require_timezone(occurred_at)
    cancelled: list[JobRecord] = []
    unaffected: list[JobRecord] = []
    for job in jobs:
        if job.mode in ACTIVE_GATE_MODES and job.status in KILL_SWITCH_STATUSES:
            cancelled.append(_replace_job_cancelled(job, reason))
        else:
            unaffected.append(job)
    next_chain = audit_chain.append_audit_event(
        event_id=event_id,
        organization_id="active_policy",
        actor_user_id=actor_user_id,
        action=AuditAction.SCHEDULER_CONTROL,
        subject_type="active_kill_switch",
        subject_id="active-policy",
        occurred_at=occurred_at,
        details={
            "control": "kill_switch",
            "reason": reason,
            "cancelled_job_count": len(cancelled),
        },
    )
    return KillSwitchPlan(cancelled_jobs=tuple(cancelled), unaffected_jobs=tuple(unaffected), audit_chain=next_chain)


def _first_denial(
    request: ActiveJobRequest,
    scope: EngagementScope,
    module_policy: ActiveModulePolicy,
    existing_jobs: tuple[JobRecord, ...],
    policy_expires_at: datetime,
) -> str | None:
    if request.organization_id != scope.organization_id:
        return "organization_mismatch"
    if request.engagement_id != scope.engagement_id:
        return "engagement_mismatch"
    if request.mode not in ACTIVE_GATE_MODES:
        return "active_mode_required"
    scope_decision = decide_scope(
        scope,
        JobScopeRequest(
            target=request.target,
            mode=request.mode,
            requested_at=request.requested_at,
            projected_interactions=request.projected_requests,
        ),
    )
    if not scope_decision.allowed:
        return f"scope_{scope_decision.reason}"
    if request.module_id != module_policy.module_id:
        return "module_policy_mismatch"
    if request.mode not in module_policy.allowed_modes:
        return "active_module_permission_required"
    if request.payload_class is PayloadClass.DESTRUCTIVE:
        return "destructive_payload_forbidden"
    if request.payload_class not in module_policy.allowed_payload_classes:
        return "payload_class_not_allowed"
    if request.requested_rate_per_second > min(scope.max_rate_per_second, module_policy.max_rate_per_second):
        return "rate_limit_exceeded"
    if request.projected_requests > min(scope.max_interactions, module_policy.max_requests):
        return "request_count_exceeded"
    if request.projected_duration_seconds > module_policy.max_duration_seconds:
        return "duration_limit_exceeded"
    if policy_expires_at <= request.requested_at:
        return "policy_expiry_invalid"
    if not _stop_conditions_valid(module_policy.stop_conditions, scope):
        return "stop_conditions_required"
    if _engagement_active_count(existing_jobs, request.engagement_id) >= module_policy.max_concurrent_per_engagement:
        return "engagement_concurrency_exceeded"
    if _target_active_count(existing_jobs, request.target) >= module_policy.max_concurrent_per_target:
        return "target_concurrency_exceeded"
    confirmation_denial = _confirmation_denial(request)
    if confirmation_denial:
        return confirmation_denial
    return None


def _confirmation_denial(request: ActiveJobRequest) -> str | None:
    confirmation = request.operator_confirmation
    if confirmation is None:
        return "operator_confirmation_required"
    _require_timezone(confirmation.confirmed_at)
    if confirmation.confirmed_at > request.requested_at:
        return "operator_confirmation_after_request"
    if not confirmation.confirmed_by_user_id.strip():
        return "operator_confirmation_user_required"
    if not confirmation.scope_acknowledged:
        return "operator_scope_acknowledgement_required"
    if not confirmation.risk_acknowledged:
        return "operator_risk_acknowledgement_required"
    if not confirmation.stop_conditions_acknowledged:
        return "operator_stop_condition_acknowledgement_required"
    return None


def _stop_conditions_valid(stop_conditions: StopConditionPolicy, scope: EngagementScope) -> bool:
    if stop_conditions.max_error_count <= 0:
        return False
    if not stop_conditions.stop_on_scope_violation:
        return False
    if not stop_conditions.stop_on_error_rate:
        return False
    if stop_conditions.emergency_contact_required and not scope.emergency_contact_method:
        return False
    return True


def _engagement_active_count(jobs: tuple[JobRecord, ...], engagement_id: str) -> int:
    return sum(
        1
        for job in jobs
        if job.engagement_id == engagement_id and job.mode in ACTIVE_GATE_MODES and job.status in KILL_SWITCH_STATUSES
    )


def _target_active_count(jobs: tuple[JobRecord, ...], target: ScopeTarget) -> int:
    normalized = target.normalized()
    return sum(
        1
        for job in jobs
        if job.target.normalized() == normalized and job.mode in ACTIVE_GATE_MODES and job.status in KILL_SWITCH_STATUSES
    )


def _replace_job_cancelled(job: JobRecord, reason: str) -> JobRecord:
    return JobRecord(
        job_id=job.job_id,
        organization_id=job.organization_id,
        engagement_id=job.engagement_id,
        test_definition_id=job.test_definition_id,
        target=job.target,
        mode=job.mode,
        status=JobStatus.CANCELLED,
        projected_interactions=job.projected_interactions,
        timeout_seconds=job.timeout_seconds,
        cleanup_required=job.cleanup_required,
        max_attempts=job.max_attempts,
        attempts=job.attempts,
        runner_id=job.runner_id,
        policy_decision_id=job.policy_decision_id,
        policy_expires_at=job.policy_expires_at,
        last_transition_at=job.last_transition_at,
        last_heartbeat_at=job.last_heartbeat_at,
        evidence_ids=job.evidence_ids,
        failure_reason=reason,
    )


def _validate_request(request: ActiveJobRequest) -> None:
    for field_name, value in (
        ("job_id", request.job_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("module_id", request.module_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    if request.projected_requests <= 0:
        raise ValueError("invalid_projected_requests")
    if request.projected_duration_seconds <= 0:
        raise ValueError("invalid_projected_duration")
    if request.requested_rate_per_second <= 0:
        raise ValueError("invalid_requested_rate")


def _validate_module_policy(module_policy: ActiveModulePolicy) -> None:
    _require_non_empty("module_id", module_policy.module_id)
    if not module_policy.allowed_modes:
        raise ValueError("missing_module_allowed_modes")
    if not module_policy.allowed_payload_classes:
        raise ValueError("missing_payload_class_allowlist")
    for field_name, value in (
        ("max_rate_per_second", module_policy.max_rate_per_second),
        ("max_requests", module_policy.max_requests),
        ("max_duration_seconds", module_policy.max_duration_seconds),
        ("max_concurrent_per_engagement", module_policy.max_concurrent_per_engagement),
        ("max_concurrent_per_target", module_policy.max_concurrent_per_target),
    ):
        if value <= 0:
            raise ValueError(f"invalid_{field_name}")


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
