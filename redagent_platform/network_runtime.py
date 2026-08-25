"""Controlled network runtime adapter contracts.

This module does not send packets, scan ports, capture traffic, run tools, or
contact targets. It binds approved network ROE decisions to runner lifecycle
and imports supplied sanitized network observations.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.credentials import CredentialBroker, CredentialLease
from redagent_platform.domain import JobStatus, TestMode
from redagent_platform.evidence_chain import EvidenceChain, RedactionStatus
from redagent_platform.job_queue import JobQueueState, JobRecord, RunnerCallback, RunnerCallbackKind, RunnerContract
from redagent_platform.kill_switch import (
    CancellationEvidence,
    KillSwitchScope,
    RunnerCancellationResponse,
    RunnerCancellationStatus,
    enforce_kill_switch,
    kill_switch_blocks_dispatch,
)
from redagent_platform.lab_validation import LabValidationRecord, ScannerPolicyProfile, validate_enterprise_job_lab_gate
from redagent_platform.network_assessment import (
    NetworkAssessmentMode,
    NetworkAssessmentRequest,
    NetworkEvidenceObservation,
    NetworkROE,
    append_network_evidence,
    evaluate_network_assessment,
)
from redagent_platform.target_inventory import InventoryTarget


class NetworkRuntimeResultKind(str, Enum):
    INVENTORY = "inventory"
    PASSIVE_METADATA = "passive_metadata"
    SERVICE_EXPOSURE = "service_exposure"
    TLS_CONFIGURATION = "tls_configuration"
    MANUAL_REVIEW_NOTE = "manual_review_note"


@dataclass(frozen=True, kw_only=True)
class NetworkRuntimeProfile:
    profile_id: str
    module_id: str
    allowed_modes: tuple[NetworkAssessmentMode, ...]
    max_rate_per_second: float
    max_connection_count: int
    timeout_seconds: int
    lab_profile: ScannerPolicyProfile


@dataclass(frozen=True, kw_only=True)
class NetworkRuntimeRequest:
    runtime_id: str
    profile: NetworkRuntimeProfile
    roe: NetworkROE
    assessment_request: NetworkAssessmentRequest
    runner: RunnerContract
    inventory_target: InventoryTarget
    requested_at: datetime
    operator_user_id: str
    lab_validation_records: tuple[LabValidationRecord, ...]


@dataclass(frozen=True, kw_only=True)
class NetworkRuntimePlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    normalized_target: str
    mode: NetworkAssessmentMode
    rate_limit_per_second: float
    max_connection_count: int
    timeout_seconds: int
    lab_validation_id: str | None
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class NetworkRuntimeResultItem:
    item_id: str
    kind: NetworkRuntimeResultKind
    summary: str
    connection_count: int
    request_count: int
    redaction_status: RedactionStatus
    notes: str


@dataclass(frozen=True, kw_only=True)
class NetworkRuntimeExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    imported_evidence_ids: tuple[str, ...]
    result_items: tuple[NetworkRuntimeResultItem, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()
    credential_broker: CredentialBroker = CredentialBroker()


def build_network_runtime_plan(request: NetworkRuntimeRequest) -> NetworkRuntimePlan:
    _validate_request(request)
    decision = evaluate_network_assessment(request.roe, request.assessment_request)
    if not decision.allowed:
        raise ValueError(f"network_assessment_denied:{decision.reason}")
    if decision.normalized_target is None:
        raise ValueError("network_target_normalization_required")
    if request.runner.target_scope.normalized().value != decision.normalized_target:
        raise ValueError("runner_target_scope_mismatch")
    lab_gate = validate_enterprise_job_lab_gate(
        target=request.inventory_target,
        profile=request.profile.lab_profile,
        validation_records=request.lab_validation_records,
        requested_at=request.requested_at,
    )
    if not lab_gate.allowed:
        raise ValueError(lab_gate.reason)
    job = JobRecord(
        job_id=request.assessment_request.job_id,
        organization_id=request.assessment_request.organization_id,
        engagement_id=request.assessment_request.engagement_id,
        test_definition_id=request.profile.profile_id,
        target=request.runner.target_scope.normalized(),
        mode=_test_mode_for(request.assessment_request.mode),
        status=JobStatus.QUEUED,
        projected_interactions=request.assessment_request.projected_connection_count,
        timeout_seconds=request.profile.timeout_seconds,
        cleanup_required=True,
        max_attempts=1,
        policy_decision_id=f"{request.runtime_id}:network-policy",
        policy_expires_at=request.roe.window_end,
        last_transition_at=request.requested_at,
    )
    return NetworkRuntimePlan(
        runtime_id=request.runtime_id.strip(),
        job=job,
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        normalized_target=decision.normalized_target,
        mode=request.assessment_request.mode,
        rate_limit_per_second=request.assessment_request.requested_rate_per_second,
        max_connection_count=request.profile.max_connection_count,
        timeout_seconds=request.profile.timeout_seconds,
        lab_validation_id=lab_gate.validation_id,
        cancellation_supported=True,
    )


def execute_network_runtime_plan(
    *,
    plan: NetworkRuntimePlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    result_items: tuple[NetworkRuntimeResultItem, ...] = (),
    cancel_requested: bool = False,
    credential_broker: CredentialBroker = CredentialBroker(),
    credential_leases_by_job_id: dict[str, CredentialLease] | None = None,
    kill_switch_scope: KillSwitchScope | None = None,
) -> NetworkRuntimeExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return NetworkRuntimeExecutionResult(
                allowed=False,
                reason=decision.reason,
                state=state,
                evidence_chain=evidence_chain,
                imported_evidence_ids=(),
                result_items=(),
                credential_broker=credential_broker,
            )
    dispatched, dispatch_decision = state.dispatch_job(
        plan.job.job_id,
        runner,
        actor_user_id=operator_user_id,
        event_id=f"{plan.runtime_id}:dispatch",
        occurred_at=occurred_at,
    )
    if not dispatch_decision.allowed:
        return NetworkRuntimeExecutionResult(
            allowed=False,
            reason=dispatch_decision.reason,
            state=state,
            evidence_chain=evidence_chain,
            imported_evidence_ids=(),
            result_items=(),
            credential_broker=credential_broker,
        )
    if cancel_requested:
        cancellation = enforce_kill_switch(
            scope=KillSwitchScope(engagement_id=plan.job.engagement_id, target=plan.job.target, modes=(plan.job.mode,)),
            state=dispatched,
            credential_broker=credential_broker,
            leases_by_job_id=credential_leases_by_job_id or {},
            runner_responses={
                plan.job.job_id: RunnerCancellationResponse(
                    job_id=plan.job.job_id,
                    runner_id=plan.runner_id,
                    status=RunnerCancellationStatus.TERMINATED,
                    cleanup_attempted=True,
                    cleanup_succeeded=True,
                    responded_at=occurred_at,
                )
            },
            reason="network_runtime_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return NetworkRuntimeExecutionResult(
            allowed=True,
            reason="cancelled",
            state=cancellation.state,
            evidence_chain=evidence_chain,
            imported_evidence_ids=(),
            result_items=(),
            cancellation_evidence=cancellation.evidence,
            credential_broker=cancellation.credential_broker,
        )
    running = _callback(dispatched, plan, RunnerCallbackKind.STARTED, "started", occurred_at)
    chain, evidence_ids = _append_result_evidence(plan, evidence_chain, occurred_at, operator_user_id, result_items)
    with_result = _callback(running, plan, RunnerCallbackKind.RESULT, "result", occurred_at, evidence_ids=evidence_ids)
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return NetworkRuntimeExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        imported_evidence_ids=evidence_ids,
        result_items=result_items,
        credential_broker=credential_broker,
    )


def _validate_request(request: NetworkRuntimeRequest) -> None:
    for field_name, value in (
        ("runtime_id", request.runtime_id),
        ("operator_user_id", request.operator_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    if request.assessment_request.requested_at != request.requested_at:
        raise ValueError("network_runtime_time_mismatch")
    if request.assessment_request.mode not in request.profile.allowed_modes:
        raise ValueError("network_runtime_mode_not_allowed")
    if request.assessment_request.requested_rate_per_second > request.profile.max_rate_per_second:
        raise ValueError("network_runtime_rate_cap_exceeded")
    if request.assessment_request.projected_connection_count > request.profile.max_connection_count:
        raise ValueError("network_runtime_connection_cap_exceeded")
    if request.runner.organization_id != request.assessment_request.organization_id:
        raise ValueError("runner_organization_mismatch")
    expected_mode = _test_mode_for(request.assessment_request.mode)
    if expected_mode not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")
    if request.inventory_target.organization_id != request.assessment_request.organization_id:
        raise ValueError("inventory_organization_mismatch")
    if request.inventory_target.engagement_id != request.assessment_request.engagement_id:
        raise ValueError("inventory_engagement_mismatch")


def _validate_profile(profile: NetworkRuntimeProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_modes:
        raise ValueError("network_runtime_modes_required")
    if profile.max_rate_per_second <= 0:
        raise ValueError("invalid_network_runtime_rate")
    if profile.max_connection_count <= 0:
        raise ValueError("invalid_network_runtime_connection_cap")
    if profile.timeout_seconds <= 0:
        raise ValueError("invalid_network_runtime_timeout")


def _validate_execution_inputs(
    plan: NetworkRuntimePlan,
    runner: RunnerContract,
    occurred_at: datetime,
    operator_user_id: str,
) -> None:
    _require_non_empty("operator_user_id", operator_user_id)
    _require_timezone(occurred_at)
    if runner.runner_id != plan.runner_id:
        raise ValueError("runner_mismatch")
    if plan.job.mode not in runner.capabilities:
        raise ValueError("runner_capability_missing")
    if runner.target_scope.normalized() != plan.job.target.normalized():
        raise ValueError("runner_target_scope_mismatch")


def _append_result_evidence(
    plan: NetworkRuntimePlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    result_items: tuple[NetworkRuntimeResultItem, ...],
) -> tuple[EvidenceChain, tuple[str, ...]]:
    chain = evidence_chain
    evidence_ids: list[str] = []
    for item in result_items:
        _validate_result_item(item)
        evidence_id = f"{plan.runtime_id}:{item.kind.value}:{item.item_id}"
        result = append_network_evidence(
            chain=chain,
            evidence_id=evidence_id,
            observation=NetworkEvidenceObservation(
                job_id=plan.job.job_id,
                organization_id=plan.job.organization_id,
                scope_summary=f"{plan.normalized_target} {item.kind.value}",
                method=plan.mode,
                request_count=item.request_count,
                connection_count=item.connection_count,
                started_at=occurred_at,
                ended_at=occurred_at,
                operator_user_id=operator_user_id,
                runner_id=plan.runner_id,
                redaction_status=item.redaction_status,
                notes=f"{item.summary}: {item.notes}",
            ),
        )
        chain = result.chain
        evidence_ids.append(evidence_id)
    return chain, tuple(evidence_ids)


def _validate_result_item(item: NetworkRuntimeResultItem) -> None:
    for field_name, value in (("item_id", item.item_id), ("summary", item.summary), ("notes", item.notes)):
        _require_non_empty(field_name, value)
    if item.connection_count < 0 or item.request_count < 0:
        raise ValueError("invalid_network_runtime_counts")


def _callback(
    state: JobQueueState,
    plan: NetworkRuntimePlan,
    kind: RunnerCallbackKind,
    label: str,
    occurred_at: datetime,
    *,
    evidence_ids: tuple[str, ...] = (),
) -> JobQueueState:
    next_state, decision = state.handle_callback(
        RunnerCallback(
            callback_id=f"{plan.runtime_id}:{label}",
            runner_id=plan.runner_id,
            job_id=plan.job.job_id,
            kind=kind,
            occurred_at=occurred_at,
            evidence_ids=evidence_ids,
        ),
        actor_user_id=plan.runner_id,
        event_id=f"{plan.runtime_id}:callback:{label}",
    )
    if not decision.allowed:
        raise ValueError(decision.reason)
    return next_state


def _test_mode_for(mode: NetworkAssessmentMode) -> TestMode:
    if mode is NetworkAssessmentMode.ACTIVE_PROBE:
        return TestMode.ACTIVE_SCAN
    return TestMode.PASSIVE_SCAN


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
