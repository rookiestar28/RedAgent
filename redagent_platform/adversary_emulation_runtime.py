"""Lab-only adversary-emulation orchestration contracts.

This module does not execute campaigns, atomic commands, payloads, processes,
cloud actions, endpoint agents, or subprocesses. It composes reviewed campaign
metadata, atomic metadata, manual checkpoints, and telemetry evidence imports.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import attack_campaigns, atomic_runner, telemetry_feedback
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
from redagent_platform.scope_authorization import ScopeTarget


class EmulationRunMode(str, Enum):
    DRY_RUN = "dry_run"
    MANUAL_CHECKPOINT = "manual_checkpoint"
    AUTOMATED_LAB_RUN = "automated_lab_run"


class EmulationAction(str, Enum):
    IMPORT_TELEMETRY = "import_telemetry"
    PREPARE_DRY_RUN = "prepare_dry_run"
    RECORD_MANUAL_CHECKPOINT = "record_manual_checkpoint"
    START_AUTOMATED_LAB_RUN = "start_automated_lab_run"
    EXECUTE_ATOMIC_COMMAND = "execute_atomic_command"
    IMPORT_PAYLOAD_BODY = "import_payload_body"


@dataclass(frozen=True, kw_only=True)
class EmulationProfile:
    profile_id: str
    module_id: str
    allowed_campaign_ids: tuple[str, ...]
    allowed_atomic_test_ids: tuple[str, ...]
    supported_platforms: tuple[str, ...]
    allowed_modes: tuple[EmulationRunMode, ...]
    max_techniques: int
    timeout_seconds: int
    kill_switch_enabled: bool
    actions: tuple[EmulationAction, ...]


@dataclass(frozen=True, kw_only=True)
class ReviewedTechnique:
    technique_id: str
    reviewed_by_user_id: str
    reviewed_at: datetime
    approved: bool


@dataclass(frozen=True, kw_only=True)
class OperatorConfirmation:
    confirmed: bool
    confirmed_by_user_id: str
    confirmed_at: datetime
    cleanup_plan: str
    manual_checkpoint_acknowledged: bool


@dataclass(frozen=True, kw_only=True)
class EmulationOrchestrationRequest:
    runtime_id: str
    organization_id: str
    engagement_id: str
    campaign: attack_campaigns.AttackCampaign
    atomic_tests: tuple[atomic_runner.AtomicTestMetadata, ...]
    target: atomic_runner.LabTargetContext
    reviewed_techniques: tuple[ReviewedTechnique, ...]
    telemetry_definition: telemetry_feedback.TelemetryEnabledTestDefinition
    operator_confirmation: OperatorConfirmation
    profile: EmulationProfile
    runner: RunnerContract
    requested_mode: EmulationRunMode
    requested_at: datetime
    operator_user_id: str


@dataclass(frozen=True, kw_only=True)
class EmulationOrchestrationPlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    campaign_id: str
    mode: EmulationRunMode
    target_id: str
    platform: str
    technique_ids: tuple[str, ...]
    atomic_test_ids: tuple[str, ...]
    telemetry_expectation_ids: tuple[str, ...]
    cleanup_plan: str
    manual_checkpoint_required: bool
    actions: tuple[EmulationAction, ...]
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class EmulationReportRow:
    campaign_id: str
    expectation_id: str
    source: attack_campaigns.TelemetrySource
    event_name: str
    detection_owner: str
    status: telemetry_feedback.TelemetryObservationStatus
    evidence_id: str | None
    gap_reason: str | None


@dataclass(frozen=True, kw_only=True)
class EmulationExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    report_rows: tuple[EmulationReportRow, ...]
    telemetry_evidence: telemetry_feedback.TelemetryEvidence | None
    detection_report: telemetry_feedback.CampaignDetectionReport | None
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()


_FORBIDDEN_ACTIONS = frozenset(
    {
        EmulationAction.START_AUTOMATED_LAB_RUN,
        EmulationAction.EXECUTE_ATOMIC_COMMAND,
        EmulationAction.IMPORT_PAYLOAD_BODY,
    }
)


def build_emulation_orchestration_plan(request: EmulationOrchestrationRequest) -> EmulationOrchestrationPlan:
    _validate_request(request)
    target = ScopeTarget(target_type=TargetType.LAB_TARGET, value=request.target.target_id).normalized()
    if request.runner.target_scope.normalized() != target:
        raise ValueError("runner_target_scope_mismatch")
    expectation_ids = tuple(item.expectation_id for item in telemetry_feedback.all_expectations(request.telemetry_definition))
    technique_ids = _required_technique_ids(request)
    return EmulationOrchestrationPlan(
        runtime_id=request.runtime_id.strip(),
        job=JobRecord(
            job_id=f"{request.runtime_id}:job",
            organization_id=request.organization_id,
            engagement_id=request.engagement_id,
            test_definition_id=request.profile.profile_id,
            target=target,
            mode=TestMode.ADVERSARY_EMULATION,
            status=JobStatus.QUEUED,
            projected_interactions=max(1, len(request.atomic_tests) + len(expectation_ids)),
            timeout_seconds=request.profile.timeout_seconds,
            cleanup_required=True,
            max_attempts=1,
            policy_decision_id=f"{request.runtime_id}:emulation-policy",
            policy_expires_at=request.requested_at.replace(year=request.requested_at.year + 1),
            last_transition_at=request.requested_at,
        ),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        campaign_id=request.campaign.campaign_id.strip(),
        mode=request.requested_mode,
        target_id=request.target.target_id.strip(),
        platform=request.target.platform.strip().lower(),
        technique_ids=technique_ids,
        atomic_test_ids=tuple(item.test_id for item in request.atomic_tests),
        telemetry_expectation_ids=expectation_ids,
        cleanup_plan=request.operator_confirmation.cleanup_plan.strip(),
        manual_checkpoint_required=True,
        actions=tuple(request.profile.actions),
        cancellation_supported=True,
    )


def execute_emulation_orchestration_plan(
    *,
    plan: EmulationOrchestrationPlan,
    telemetry_definition: telemetry_feedback.TelemetryEnabledTestDefinition,
    observed_events: tuple[telemetry_feedback.ObservedTelemetryEvent, ...],
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    cancel_requested: bool = False,
    kill_switch_scope: KillSwitchScope | None = None,
) -> EmulationExecutionResult:
    _validate_execution_inputs(plan, telemetry_definition, runner, occurred_at, operator_user_id)
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return EmulationExecutionResult(
                allowed=False,
                reason=decision.reason,
                state=state,
                evidence_chain=evidence_chain,
                report_rows=(),
                telemetry_evidence=None,
                detection_report=None,
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
        return EmulationExecutionResult(
            allowed=False,
            reason=dispatch_decision.reason,
            state=state,
            evidence_chain=evidence_chain,
            report_rows=(),
            telemetry_evidence=None,
            detection_report=None,
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
            reason="emulation_orchestration_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return EmulationExecutionResult(
            allowed=True,
            reason="cancelled",
            state=cancellation.state,
            evidence_chain=evidence_chain,
            report_rows=(),
            telemetry_evidence=None,
            detection_report=None,
            imported_evidence_ids=(),
            cancellation_evidence=cancellation.evidence,
        )
    running = _callback(dispatched, plan, RunnerCallbackKind.STARTED, "started", occurred_at)
    chain, evidence_id, telemetry_evidence, detection_report, rows = _append_telemetry_evidence(
        plan,
        telemetry_definition,
        observed_events,
        evidence_chain,
        occurred_at,
    )
    with_result = _callback(running, plan, RunnerCallbackKind.RESULT, "result", occurred_at, evidence_ids=(evidence_id,))
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return EmulationExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        report_rows=rows,
        telemetry_evidence=telemetry_evidence,
        detection_report=detection_report,
        imported_evidence_ids=(evidence_id,),
    )


def _validate_request(request: EmulationOrchestrationRequest) -> None:
    for field_name, value in (
        ("runtime_id", request.runtime_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("operator_user_id", request.operator_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    attack_campaigns.validate_campaign(request.campaign)
    telemetry_feedback.validate_telemetry_test_definition(request.telemetry_definition)
    _validate_target(request.target)
    _validate_operator_confirmation(request.operator_confirmation, request.requested_at)
    if request.requested_mode not in request.profile.allowed_modes:
        raise ValueError("emulation_mode_not_allowed")
    if request.requested_mode is EmulationRunMode.AUTOMATED_LAB_RUN:
        raise ValueError("automated_lab_run_not_enabled")
    if request.campaign.campaign_id not in _normalized_set(request.profile.allowed_campaign_ids):
        raise ValueError("campaign_not_allowlisted")
    if len(request.campaign.techniques) > request.profile.max_techniques:
        raise ValueError("technique_cap_exceeded")
    if not request.atomic_tests:
        raise ValueError("atomic_metadata_required")
    for metadata in request.atomic_tests:
        atomic_runner.validate_atomic_metadata(metadata)
        if metadata.test_id not in _normalized_set(request.profile.allowed_atomic_test_ids):
            raise ValueError("atomic_test_not_allowlisted")
        if request.target.platform.strip().lower() not in metadata.supported_platforms:
            raise ValueError("unsupported_platform")
        if not metadata.cleanup_summary:
            raise ValueError("missing_cleanup")
    _validate_reviewed_techniques(request)
    if request.runner.organization_id != request.organization_id:
        raise ValueError("runner_organization_mismatch")
    if TestMode.ADVERSARY_EMULATION not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")


def _validate_profile(profile: EmulationProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_campaign_ids:
        raise ValueError("campaign_allowlist_required")
    if not profile.allowed_atomic_test_ids:
        raise ValueError("atomic_allowlist_required")
    if not profile.supported_platforms:
        raise ValueError("platform_allowlist_required")
    if not profile.allowed_modes:
        raise ValueError("emulation_modes_required")
    if EmulationAction.IMPORT_TELEMETRY not in profile.actions:
        raise ValueError("telemetry_import_action_required")
    if EmulationAction.PREPARE_DRY_RUN not in profile.actions:
        raise ValueError("dry_run_action_required")
    if _FORBIDDEN_ACTIONS.intersection(profile.actions):
        raise ValueError("payload_or_automated_execution_action_not_allowed")
    if profile.max_techniques <= 0:
        raise ValueError("technique_cap_required")
    if profile.timeout_seconds <= 0:
        raise ValueError("emulation_timeout_invalid")
    if not profile.kill_switch_enabled:
        raise ValueError("kill_switch_required")


def _validate_target(target: atomic_runner.LabTargetContext) -> None:
    for field_name, value in (
        ("target_id", target.target_id),
        ("environment", target.environment),
        ("platform", target.platform),
    ):
        _require_non_empty(field_name, value)
    if target.target_type is not TargetType.LAB_TARGET or not target.is_lab_target:
        raise ValueError("lab_target_required")
    if not target.approved_by_user_id or not target.approved_by_user_id.strip():
        raise ValueError("lab_target_approval_required")


def _validate_operator_confirmation(confirmation: OperatorConfirmation, requested_at: datetime) -> None:
    _require_timezone(confirmation.confirmed_at)
    _require_non_empty("confirmed_by_user_id", confirmation.confirmed_by_user_id)
    _require_non_empty("cleanup_plan", confirmation.cleanup_plan)
    if not confirmation.confirmed:
        raise ValueError("operator_confirmation_required")
    if confirmation.confirmed_at > requested_at:
        raise ValueError("operator_confirmation_after_request")
    if not confirmation.manual_checkpoint_acknowledged:
        raise ValueError("manual_checkpoint_required")


def _validate_reviewed_techniques(request: EmulationOrchestrationRequest) -> None:
    reviewed = {item.technique_id.strip(): item for item in request.reviewed_techniques}
    for item in reviewed.values():
        _require_non_empty("reviewed_by_user_id", item.reviewed_by_user_id)
        _require_timezone(item.reviewed_at)
    for technique_id in _required_technique_ids(request):
        review = reviewed.get(technique_id)
        if review is None or not review.approved:
            raise ValueError("unreviewed_technique_denied")


def _required_technique_ids(request: EmulationOrchestrationRequest) -> tuple[str, ...]:
    technique_ids: list[str] = []
    for technique in request.campaign.techniques:
        technique_ids.append(technique.technique_id)
    for metadata in request.atomic_tests:
        for technique in metadata.attack_mapping:
            technique_ids.append(technique.technique_id)
    return tuple(sorted(set(technique_ids)))


def _validate_execution_inputs(
    plan: EmulationOrchestrationPlan,
    telemetry_definition: telemetry_feedback.TelemetryEnabledTestDefinition,
    runner: RunnerContract,
    occurred_at: datetime,
    operator_user_id: str,
) -> None:
    _require_non_empty("operator_user_id", operator_user_id)
    _require_timezone(occurred_at)
    telemetry_feedback.validate_telemetry_test_definition(telemetry_definition)
    if runner.runner_id != plan.runner_id:
        raise ValueError("runner_mismatch")
    if plan.job.mode not in runner.capabilities:
        raise ValueError("runner_capability_missing")
    if runner.target_scope.normalized() != plan.job.target.normalized():
        raise ValueError("runner_target_scope_mismatch")


def _append_telemetry_evidence(
    plan: EmulationOrchestrationPlan,
    telemetry_definition: telemetry_feedback.TelemetryEnabledTestDefinition,
    observed_events: tuple[telemetry_feedback.ObservedTelemetryEvent, ...],
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
) -> tuple[
    EvidenceChain,
    str,
    telemetry_feedback.TelemetryEvidence,
    telemetry_feedback.CampaignDetectionReport,
    tuple[EmulationReportRow, ...],
]:
    evidence_id = f"{plan.runtime_id}:telemetry-comparison"
    telemetry_evidence = telemetry_feedback.compare_telemetry(
        telemetry_definition,
        observed_events,
        evidence_id=evidence_id,
    )
    detection_report = telemetry_feedback.build_campaign_detection_report(plan.campaign_id, telemetry_evidence)
    rows = tuple(
        EmulationReportRow(
            campaign_id=plan.campaign_id,
            expectation_id=comparison.expectation_id,
            source=comparison.source,
            event_name=comparison.event_name,
            detection_owner=comparison.detection_owner,
            status=comparison.status,
            evidence_id=comparison.evidence_id,
            gap_reason=comparison.gap_reason,
        )
        for comparison in telemetry_evidence.comparisons
    )
    content = json.dumps(
        {
            "campaign_id": plan.campaign_id,
            "mode": plan.mode.value,
            "manual_checkpoint_required": plan.manual_checkpoint_required,
            "telemetry_evidence_id": telemetry_evidence.evidence_id,
            "observed": detection_report.observed,
            "gaps": detection_report.gaps,
            "not_evaluated": detection_report.not_evaluated,
            "overstates_unobserved_controls": detection_report.overstates_unobserved_controls,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    chain = evidence_chain.append_evidence_record(
        evidence_id=evidence_id,
        organization_id=plan.job.organization_id,
        source_job_id=plan.job.job_id,
        kind=EvidenceKind.TELEMETRY,
        created_at=occurred_at,
        redaction_status=RedactionStatus.NOT_APPLICABLE,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=content,
        contains_sensitive_capture=False,
        metadata={
            "campaign_id": plan.campaign_id,
            "mode": plan.mode.value,
            "target_id": plan.target_id,
            "technique_ids": plan.technique_ids,
            "atomic_test_ids": plan.atomic_test_ids,
        },
    )
    return chain, evidence_id, telemetry_evidence, detection_report, rows


def _callback(
    state: JobQueueState,
    plan: EmulationOrchestrationPlan,
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
