"""Controlled DLP canary validation workflow runtime contracts.

This module does not transfer data, execute protocols, move files, call DLP or
telemetry connectors, retrieve credentials, or start subprocesses. It builds a
review-queue plan and imports supplied sanitized detection evidence.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import dlp_validation
from redagent_platform.credentials import CredentialBroker
from redagent_platform.domain import EvidenceKind, JobStatus, TargetType, TestMode
from redagent_platform.evidence_chain import (
    EvidenceAccessPolicy,
    EvidenceChain,
    RedactionStatus,
    RetentionClass,
)
from redagent_platform.job_queue import JobQueueState, JobRecord, RunnerCallback, RunnerCallbackKind, RunnerContract
from redagent_platform.kill_switch import (
    CancellationEvidence,
    KillSwitchScope,
    RunnerCancellationResponse,
    RunnerCancellationStatus,
    enforce_kill_switch,
    kill_switch_blocks_dispatch,
)
from redagent_platform.redaction import RedactionArtifactClass, RedactionConfig, sanitize_mapping
from redagent_platform.scope_authorization import ScopeTarget


class DlpWorkflowAction(str, Enum):
    IMPORT_DETECTION_EVIDENCE = "import_detection_evidence"
    PREPARE_REVIEW_QUEUE = "prepare_review_queue"
    TRANSFER_DATA = "transfer_data"
    EXECUTE_PROTOCOL = "execute_protocol"
    QUERY_DLP_CONNECTOR = "query_dlp_connector"
    MOVE_FILE = "move_file"


@dataclass(frozen=True, kw_only=True)
class DlpWorkflowProfile:
    profile_id: str
    module_id: str
    allowed_source_systems: tuple[str, ...]
    allowed_destination_systems: tuple[str, ...]
    allowed_protocols: tuple[dlp_validation.DlpProtocol, ...]
    max_volume_bytes: int
    max_record_count: int
    timeout_seconds: int
    kill_switch_enabled: bool
    actions: tuple[DlpWorkflowAction, ...]


@dataclass(frozen=True, kw_only=True)
class DlpWorkflowRequest:
    runtime_id: str
    validation_request: dlp_validation.DlpValidationRequest
    profile: DlpWorkflowProfile
    runner: RunnerContract
    requested_at: datetime
    operator_user_id: str


@dataclass(frozen=True, kw_only=True)
class DlpWorkflowPlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    validation_id: str
    roe_id: str
    source_system_id: str
    destination_system_id: str
    protocol: dlp_validation.DlpProtocol
    volume_bytes: int
    record_count: int
    data_labels: tuple[str, ...]
    canary_markers: tuple[str, ...]
    monitoring_sources: tuple[str, ...]
    execution_enabled: bool
    actions: tuple[DlpWorkflowAction, ...]
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class DlpWorkflowReportRow:
    evidence_id: str
    validation_id: str
    detection_outcome: str
    telemetry_source: str
    alert_latency_seconds: int | None
    control_owner_user_id: str
    remediation_follow_up: str
    redaction_status: RedactionStatus


@dataclass(frozen=True, kw_only=True)
class DlpWorkflowExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    report_rows: tuple[DlpWorkflowReportRow, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()


_FORBIDDEN_ACTIONS = frozenset(
    {
        DlpWorkflowAction.TRANSFER_DATA,
        DlpWorkflowAction.EXECUTE_PROTOCOL,
        DlpWorkflowAction.QUERY_DLP_CONNECTOR,
        DlpWorkflowAction.MOVE_FILE,
    }
)


def build_dlp_workflow_plan(request: DlpWorkflowRequest) -> DlpWorkflowPlan:
    _validate_request(request)
    validation_request = request.validation_request
    roe = validation_request.roe
    target_scope = validation_request.target_scope
    dataset = validation_request.dataset
    monitoring = validation_request.monitoring
    if roe is None or target_scope is None or dataset is None or monitoring is None or target_scope.protocol is None:
        raise ValueError("dlp_workflow_request_incomplete")
    target = _scope_target(target_scope)
    if request.runner.target_scope.normalized() != target:
        raise ValueError("runner_target_scope_mismatch")
    return DlpWorkflowPlan(
        runtime_id=request.runtime_id.strip(),
        job=JobRecord(
            job_id=f"{request.runtime_id}:job",
            organization_id=validation_request.organization_id,
            engagement_id=validation_request.engagement_id,
            test_definition_id=request.profile.profile_id,
            target=target,
            mode=TestMode.DLP_CANARY_VALIDATION,
            status=JobStatus.QUEUED,
            projected_interactions=max(1, target_scope.record_count),
            timeout_seconds=request.profile.timeout_seconds,
            cleanup_required=True,
            max_attempts=1,
            policy_decision_id=f"{request.runtime_id}:dlp-policy",
            policy_expires_at=request.requested_at.replace(year=request.requested_at.year + 1),
            last_transition_at=request.requested_at,
        ),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        validation_id=validation_request.validation_id.strip(),
        roe_id=roe.roe_id.strip(),
        source_system_id=target_scope.source_system_id.strip(),
        destination_system_id=target_scope.destination_system_id.strip(),
        protocol=target_scope.protocol,
        volume_bytes=target_scope.volume_bytes,
        record_count=target_scope.record_count,
        data_labels=tuple(roe.data_labels),
        canary_markers=tuple(dataset.canary_markers),
        monitoring_sources=tuple(source.value for source in monitoring.telemetry_sources),
        execution_enabled=False,
        actions=tuple(request.profile.actions),
        cancellation_supported=True,
    )


def execute_dlp_workflow_plan(
    *,
    plan: DlpWorkflowPlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    detection_evidence: tuple[dlp_validation.DlpDetectionEvidence, ...] = (),
    cancel_requested: bool = False,
    kill_switch_scope: KillSwitchScope | None = None,
) -> DlpWorkflowExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return DlpWorkflowExecutionResult(
                allowed=False,
                reason=decision.reason,
                state=state,
                evidence_chain=evidence_chain,
                report_rows=(),
                imported_evidence_ids=(),
            )
    dispatched, dispatch_decision = state.dispatch_job(
        plan.job.job_id,
        runner,
        actor_user_id=operator_user_id,
        event_id=f"{plan.runtime_id}:dispatch",
        occurred_at=occurred_at,
    )
    if not dispatch_decision.allowed:
        return DlpWorkflowExecutionResult(
            allowed=False,
            reason=dispatch_decision.reason,
            state=state,
            evidence_chain=evidence_chain,
            report_rows=(),
            imported_evidence_ids=(),
        )
    if cancel_requested:
        cancellation = enforce_kill_switch(
            scope=KillSwitchScope(engagement_id=plan.job.engagement_id, target=plan.job.target, modes=(plan.job.mode,)),
            state=dispatched,
            credential_broker=CredentialBroker(),
            leases_by_job_id={},
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
            reason="dlp_workflow_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return DlpWorkflowExecutionResult(
            allowed=True,
            reason="cancelled",
            state=cancellation.state,
            evidence_chain=evidence_chain,
            report_rows=(),
            imported_evidence_ids=(),
            cancellation_evidence=cancellation.evidence,
        )
    running = _callback(dispatched, plan, RunnerCallbackKind.STARTED, "started", occurred_at)
    chain, evidence_ids, rows = _append_detection_evidence(plan, evidence_chain, occurred_at, detection_evidence)
    with_result = _callback(running, plan, RunnerCallbackKind.RESULT, "result", occurred_at, evidence_ids=evidence_ids)
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return DlpWorkflowExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        report_rows=rows,
        imported_evidence_ids=evidence_ids,
    )


def _validate_request(request: DlpWorkflowRequest) -> None:
    _require_non_empty("runtime_id", request.runtime_id)
    _require_non_empty("operator_user_id", request.operator_user_id)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    decision = dlp_validation.evaluate_dlp_validation_request(request.validation_request)
    if not decision.allowed:
        raise ValueError(f"dlp_workflow_denied:{decision.reason.value}")
    if decision.execution_enabled:
        raise ValueError("dlp_execution_must_remain_disabled")
    target_scope = request.validation_request.target_scope
    if target_scope is None or target_scope.protocol is None:
        raise ValueError("dlp_target_scope_required")
    if target_scope.source_system_id not in _normalized_set(request.profile.allowed_source_systems):
        raise ValueError("source_system_not_allowlisted")
    if target_scope.destination_system_id not in _normalized_set(request.profile.allowed_destination_systems):
        raise ValueError("destination_system_not_allowlisted")
    if target_scope.protocol not in request.profile.allowed_protocols:
        raise ValueError("protocol_not_allowlisted")
    if target_scope.volume_bytes > request.profile.max_volume_bytes:
        raise ValueError("workflow_volume_cap_exceeded")
    if target_scope.record_count > request.profile.max_record_count:
        raise ValueError("workflow_record_count_cap_exceeded")
    if request.runner.organization_id != request.validation_request.organization_id:
        raise ValueError("runner_organization_mismatch")
    if TestMode.DLP_CANARY_VALIDATION not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")


def _validate_profile(profile: DlpWorkflowProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_source_systems:
        raise ValueError("source_system_allowlist_required")
    if not profile.allowed_destination_systems:
        raise ValueError("destination_system_allowlist_required")
    if not profile.allowed_protocols:
        raise ValueError("protocol_allowlist_required")
    if DlpWorkflowAction.IMPORT_DETECTION_EVIDENCE not in profile.actions:
        raise ValueError("detection_import_action_required")
    if DlpWorkflowAction.PREPARE_REVIEW_QUEUE not in profile.actions:
        raise ValueError("review_queue_action_required")
    if _FORBIDDEN_ACTIONS.intersection(profile.actions):
        raise ValueError("dlp_transfer_or_connector_action_not_allowed")
    if profile.max_volume_bytes <= 0:
        raise ValueError("workflow_volume_cap_required")
    if profile.max_record_count <= 0:
        raise ValueError("workflow_record_count_cap_required")
    if profile.timeout_seconds <= 0:
        raise ValueError("workflow_timeout_invalid")
    if not profile.kill_switch_enabled:
        raise ValueError("kill_switch_required")


def _validate_execution_inputs(
    plan: DlpWorkflowPlan,
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


def _append_detection_evidence(
    plan: DlpWorkflowPlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    detection_evidence: tuple[dlp_validation.DlpDetectionEvidence, ...],
) -> tuple[EvidenceChain, tuple[str, ...], tuple[DlpWorkflowReportRow, ...]]:
    chain = evidence_chain
    evidence_ids: list[str] = []
    rows: list[DlpWorkflowReportRow] = []
    for item in detection_evidence:
        exported = dlp_validation.export_dlp_detection_evidence(item)
        sanitized, redaction_result = sanitize_mapping(
            exported,
            RedactionArtifactClass.EVIDENCE_ARTIFACT,
            RedactionConfig(canary_markers=plan.canary_markers),
        )
        evidence_id = f"{plan.runtime_id}:dlp-detection:{item.evidence_id}"
        redaction_status = redaction_result.redaction_status
        content = json.dumps(sanitized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
        chain = chain.append_evidence_record(
            evidence_id=evidence_id,
            organization_id=plan.job.organization_id,
            source_job_id=plan.job.job_id,
            kind=EvidenceKind.TELEMETRY,
            created_at=occurred_at,
            redaction_status=redaction_status,
            retention_class=RetentionClass.STANDARD,
            access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=content,
            contains_sensitive_capture=redaction_result.redacted,
            metadata={
                "validation_id": plan.validation_id,
                "source_system_id": plan.source_system_id,
                "destination_system_id": plan.destination_system_id,
                "protocol": plan.protocol.value,
                "detection_outcome": exported["detection_outcome"],
                "telemetry_source": exported["telemetry_source"],
            },
        )
        evidence_ids.append(evidence_id)
        rows.append(
            DlpWorkflowReportRow(
                evidence_id=evidence_id,
                validation_id=str(exported["validation_id"]),
                detection_outcome=str(exported["detection_outcome"]),
                telemetry_source=str(exported["telemetry_source"]),
                alert_latency_seconds=exported["alert_latency_seconds"],  # type: ignore[arg-type]
                control_owner_user_id=str(exported["control_owner_user_id"]),
                remediation_follow_up=str(sanitized["remediation_follow_up"]),
                redaction_status=redaction_status,
            )
        )
    return chain, tuple(evidence_ids), tuple(rows)


def _scope_target(scope: dlp_validation.DlpTargetScope) -> ScopeTarget:
    if scope.source_system_id is None or scope.destination_system_id is None:
        raise ValueError("dlp_target_scope_required")
    return ScopeTarget(
        target_type=TargetType.LAB_TARGET,
        value=f"{scope.source_system_id.strip()}->{scope.destination_system_id.strip()}",
    ).normalized()


def _callback(
    state: JobQueueState,
    plan: DlpWorkflowPlan,
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


def _normalized_set(values: tuple[str, ...]) -> frozenset[str]:
    return frozenset(value.strip() for value in values if value.strip())


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
