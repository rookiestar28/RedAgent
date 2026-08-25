"""Controlled mobile static and lab-dynamic assessment pipeline contracts.

This module does not start emulators, control devices, run instrumentation,
intercept traffic, extract packages, run scanners, or invoke subprocesses. It
builds local plans and imports supplied sanitized mobile assessment results.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import mobile_assessment
from redagent_platform.credentials import CredentialBroker
from redagent_platform.domain import EvidenceKind, FindingStatus, JobStatus, TargetType, TestMode
from redagent_platform.evidence_chain import (
    EvidenceAccessPolicy,
    EvidenceChain,
    RedactionStatus,
    RetentionClass,
)
from redagent_platform.findings import (
    AssetCriticality,
    BusinessImpact,
    Confidence,
    EvidenceLink,
    ExploitLikelihood,
    FindingRecord,
    RiskFactors,
    Severity,
    VulnerabilityIntelligence,
    validate_finding,
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


class MobileRuntimeAction(str, Enum):
    IMPORT_RESULTS = "import_results"
    PREPARE_LAB_DYNAMIC_PLAN = "prepare_lab_dynamic_plan"
    START_INSTRUMENTATION = "start_instrumentation"
    START_TRAFFIC_INTERCEPTION = "start_traffic_interception"
    DEVICE_CONTROL = "device_control"


@dataclass(frozen=True, kw_only=True)
class MobileRuntimeProfile:
    profile_id: str
    module_id: str
    allowed_package_ids: tuple[str, ...]
    allowed_modes: tuple[mobile_assessment.MobileAssessmentMode, ...]
    lab_dynamic_allowed: bool
    max_results: int
    timeout_seconds: int
    actions: tuple[MobileRuntimeAction, ...]


@dataclass(frozen=True, kw_only=True)
class MobileRuntimeRequest:
    runtime_id: str
    profile: MobileRuntimeProfile
    scope: mobile_assessment.MobileAssessmentScope
    assessment_request: mobile_assessment.MobileAssessmentRequest
    runner: RunnerContract
    requested_at: datetime
    operator_user_id: str


@dataclass(frozen=True, kw_only=True)
class MobileRuntimePlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    package_id: str
    mode: mobile_assessment.MobileAssessmentMode
    platform: mobile_assessment.MobilePlatform
    lab_id: str
    device_label: str
    lab_only: bool
    max_results: int
    timeout_seconds: int
    actions: tuple[MobileRuntimeAction, ...]
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class MobileRuntimeResultItem:
    item_id: str
    category: mobile_assessment.MobileEvidenceCategory
    package_id: str
    masvs_control: str
    mastg_test: str
    severity: Severity
    remediation_guidance: str
    lab_reproduction_steps: tuple[str, ...]
    evidence_redaction_class: RedactionStatus
    summary: str
    lab_only: bool
    contains_sensitive_material: bool = False
    component_label: str | None = None


@dataclass(frozen=True, kw_only=True)
class MobileRuntimeReportRow:
    finding_id: str
    evidence_id: str
    category: mobile_assessment.MobileEvidenceCategory
    package_id: str
    masvs_control: str
    mastg_test: str
    severity: Severity
    evidence_redaction_class: RedactionStatus
    remediation_guidance: str
    lab_only: bool


@dataclass(frozen=True, kw_only=True)
class MobileRuntimeExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    report_rows: tuple[MobileRuntimeReportRow, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()


_FORBIDDEN_ACTIONS = frozenset(
    {
        MobileRuntimeAction.START_INSTRUMENTATION,
        MobileRuntimeAction.START_TRAFFIC_INTERCEPTION,
        MobileRuntimeAction.DEVICE_CONTROL,
    }
)
_LAB_DYNAMIC_MODES = frozenset(
    {
        mobile_assessment.MobileAssessmentMode.DYNAMIC_INSTRUMENTATION,
        mobile_assessment.MobileAssessmentMode.TRAFFIC_INTERCEPTION,
    }
)


def build_mobile_runtime_plan(request: MobileRuntimeRequest) -> MobileRuntimePlan:
    _validate_request(request)
    package = _package_by_id(request.scope, request.assessment_request.package_id)
    if package is None:
        raise ValueError("mobile_package_not_allowlisted")
    if not package.approved:
        raise ValueError("mobile_package_owner_approval_required")
    mode = request.assessment_request.mode
    if mode in mobile_assessment.STATIC_MOBILE_MODES:
        review_plan = mobile_assessment.build_mobile_static_review_plan(
            scope=request.scope,
            request=request.assessment_request,
        )
        projected = len(review_plan.steps)
        lab_only = False
    elif mode in _LAB_DYNAMIC_MODES:
        _validate_lab_dynamic_request(request)
        projected = 1
        lab_only = True
    else:
        raise ValueError("mobile_mode_not_supported")
    target = ScopeTarget(target_type=TargetType.MOBILE_PACKAGE, value=package.package_id)
    if request.runner.target_scope.normalized() != target.normalized():
        raise ValueError("runner_target_scope_mismatch")
    return MobileRuntimePlan(
        runtime_id=request.runtime_id.strip(),
        job=JobRecord(
            job_id=request.assessment_request.job_id,
            organization_id=request.assessment_request.organization_id,
            engagement_id=request.assessment_request.engagement_id,
            test_definition_id=request.profile.profile_id,
            target=target.normalized(),
            mode=TestMode.MOBILE_ASSESSMENT,
            status=JobStatus.QUEUED,
            projected_interactions=max(1, projected),
            timeout_seconds=request.profile.timeout_seconds,
            cleanup_required=True,
            max_attempts=1,
            policy_decision_id=f"{request.runtime_id}:mobile-policy",
            policy_expires_at=request.requested_at.replace(year=request.requested_at.year + 1),
            last_transition_at=request.requested_at,
        ),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        package_id=package.package_id,
        mode=mode,
        platform=package.platform,
        lab_id=request.scope.lab_boundary.lab_id,
        device_label=request.scope.lab_boundary.device_label,
        lab_only=lab_only,
        max_results=request.profile.max_results,
        timeout_seconds=request.profile.timeout_seconds,
        actions=tuple(request.profile.actions),
        cancellation_supported=True,
    )


def execute_mobile_runtime_plan(
    *,
    plan: MobileRuntimePlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    result_items: tuple[MobileRuntimeResultItem, ...] = (),
    cancel_requested: bool = False,
    kill_switch_scope: KillSwitchScope | None = None,
) -> MobileRuntimeExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if len(result_items) > plan.max_results:
        raise ValueError("mobile_runtime_result_cap_exceeded")
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return MobileRuntimeExecutionResult(
                allowed=False,
                reason=decision.reason,
                state=state,
                evidence_chain=evidence_chain,
                findings=(),
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
        return MobileRuntimeExecutionResult(
            allowed=False,
            reason=dispatch_decision.reason,
            state=state,
            evidence_chain=evidence_chain,
            findings=(),
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
            reason="mobile_runtime_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return MobileRuntimeExecutionResult(
            allowed=True,
            reason="cancelled",
            state=cancellation.state,
            evidence_chain=evidence_chain,
            findings=(),
            report_rows=(),
            imported_evidence_ids=(),
            cancellation_evidence=cancellation.evidence,
        )
    running = _callback(dispatched, plan, RunnerCallbackKind.STARTED, "started", occurred_at)
    chain, evidence_ids, findings, rows = _append_result_evidence(plan, evidence_chain, occurred_at, result_items)
    with_result = _callback(running, plan, RunnerCallbackKind.RESULT, "result", occurred_at, evidence_ids=evidence_ids)
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return MobileRuntimeExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        report_rows=rows,
        imported_evidence_ids=evidence_ids,
    )


def _validate_request(request: MobileRuntimeRequest) -> None:
    for field_name, value in (("runtime_id", request.runtime_id), ("operator_user_id", request.operator_user_id)):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    mobile_assessment.validate_mobile_scope(request.scope)
    if request.assessment_request.package_id not in _normalized_set(request.profile.allowed_package_ids):
        raise ValueError("mobile_runtime_package_not_allowlisted")
    if request.assessment_request.mode not in request.profile.allowed_modes:
        raise ValueError("mobile_runtime_mode_not_allowed")
    if request.runner.organization_id != request.assessment_request.organization_id:
        raise ValueError("runner_organization_mismatch")
    if TestMode.MOBILE_ASSESSMENT not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")


def _validate_profile(profile: MobileRuntimeProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_package_ids:
        raise ValueError("mobile_runtime_package_allowlist_required")
    if not profile.allowed_modes:
        raise ValueError("mobile_runtime_modes_required")
    if MobileRuntimeAction.IMPORT_RESULTS not in profile.actions:
        raise ValueError("mobile_runtime_import_action_required")
    if _FORBIDDEN_ACTIONS.intersection(profile.actions):
        raise ValueError("mobile_runtime_live_action_not_allowed")
    if profile.max_results <= 0:
        raise ValueError("mobile_runtime_result_cap_invalid")
    if profile.timeout_seconds <= 0:
        raise ValueError("mobile_runtime_timeout_invalid")


def _validate_lab_dynamic_request(request: MobileRuntimeRequest) -> None:
    if not request.profile.lab_dynamic_allowed:
        raise ValueError("mobile_lab_dynamic_not_allowed")
    if MobileRuntimeAction.PREPARE_LAB_DYNAMIC_PLAN not in request.profile.actions:
        raise ValueError("mobile_lab_dynamic_action_required")
    if request.assessment_request.requested_activities:
        raise ValueError("mobile_forbidden_activity_requested")
    mobile_assessment.validate_mobile_scope(request.scope)


def _validate_execution_inputs(
    plan: MobileRuntimePlan,
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
    plan: MobileRuntimePlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    result_items: tuple[MobileRuntimeResultItem, ...],
) -> tuple[EvidenceChain, tuple[str, ...], tuple[FindingRecord, ...], tuple[MobileRuntimeReportRow, ...]]:
    chain = evidence_chain
    evidence_ids: list[str] = []
    findings: list[FindingRecord] = []
    rows: list[MobileRuntimeReportRow] = []
    for item in result_items:
        _validate_result_item(plan, item)
        evidence_id = f"{plan.runtime_id}:{item.category.value}:{item.item_id}"
        content = None if item.evidence_redaction_class is RedactionStatus.BLOCKED else _result_content(item)
        chain = chain.append_evidence_record(
            evidence_id=evidence_id,
            organization_id=plan.job.organization_id,
            source_job_id=plan.job.job_id,
            kind=EvidenceKind.SCANNER_OUTPUT,
            created_at=occurred_at,
            redaction_status=item.evidence_redaction_class,
            retention_class=RetentionClass.STANDARD,
            access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=content,
            contains_sensitive_capture=item.contains_sensitive_material,
            metadata={
                "package_id": item.package_id,
                "category": item.category.value,
                "masvs_control": item.masvs_control,
                "mastg_test": item.mastg_test,
                "lab_only": item.lab_only,
                "severity": item.severity.value,
            },
        )
        record = chain.evidence_records[-1]
        evidence = EvidenceLink(
            evidence_id=evidence_id,
            integrity_hash=record.integrity_hash,
            redaction_status=item.evidence_redaction_class,
            contains_sensitive_payload=item.contains_sensitive_material,
        )
        finding = _finding_for(plan, item, evidence)
        validate_finding(finding)
        findings.append(finding)
        evidence_ids.append(evidence_id)
        rows.append(
            MobileRuntimeReportRow(
                finding_id=finding.id,
                evidence_id=evidence_id,
                category=item.category,
                package_id=item.package_id.strip(),
                masvs_control=item.masvs_control.strip(),
                mastg_test=item.mastg_test.strip(),
                severity=item.severity,
                evidence_redaction_class=item.evidence_redaction_class,
                remediation_guidance=item.remediation_guidance.strip(),
                lab_only=item.lab_only,
            )
        )
    return chain, tuple(evidence_ids), tuple(findings), tuple(rows)


def _validate_result_item(plan: MobileRuntimePlan, item: MobileRuntimeResultItem) -> None:
    if item.package_id != plan.package_id:
        raise ValueError("mobile_result_package_mismatch")
    if item.contains_sensitive_material and item.evidence_redaction_class not in {
        RedactionStatus.REDACTED,
        RedactionStatus.BLOCKED,
    }:
        raise ValueError("mobile_sensitive_result_requires_redaction")
    mobile_assessment.classify_mobile_evidence(
        mobile_assessment.MobileEvidenceClassification(
            evidence_id=f"{plan.runtime_id}:{item.item_id}",
            category=item.category,
            redaction_status=item.evidence_redaction_class,
            lab_only=item.lab_only,
        )
    )
    mobile_assessment.build_mobile_finding_mapping(
        finding_id=item.item_id,
        masvs_control=item.masvs_control,
        mastg_test=item.mastg_test,
        package_id=item.package_id,
        severity=item.severity,
        lab_reproduction_steps=item.lab_reproduction_steps,
        remediation_guidance=item.remediation_guidance,
    )


def _finding_for(plan: MobileRuntimePlan, item: MobileRuntimeResultItem, evidence: EvidenceLink) -> FindingRecord:
    return FindingRecord(
        id=f"{plan.runtime_id}:finding:{item.item_id.strip()}",
        title=f"Mobile finding: {item.masvs_control.strip()} for {item.package_id.strip()}",
        status=FindingStatus.RAW_ALERT,
        affected_asset_id=item.package_id.strip(),
        affected_asset_value=item.package_id.strip(),
        confidence=Confidence.MEDIUM,
        risk=RiskFactors(
            severity=item.severity,
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.UNKNOWN,
            vulnerability_intelligence=VulnerabilityIntelligence(cve_ids=(), cwe_ids=()),
        ),
        reproduction_summary=(
            f"Sanitized mobile {item.category.value} import for package {plan.package_id}; "
            "no emulator, device control, instrumentation, or traffic interception was executed."
        ),
        evidence_links=(evidence,),
        remediation=item.remediation_guidance.strip(),
        owner_user_id=None,
        source="mobile_runtime",
        source_rule_id=f"{item.masvs_control.strip()}:{item.mastg_test.strip()}",
    )


def _result_content(item: MobileRuntimeResultItem) -> bytes:
    return json.dumps(
        {
            "category": item.category.value,
            "package_id": item.package_id.strip(),
            "masvs_control": item.masvs_control.strip(),
            "mastg_test": item.mastg_test.strip(),
            "severity": item.severity.value,
            "summary": item.summary.strip(),
            "remediation": item.remediation_guidance.strip(),
            "lab_only": item.lab_only,
            "component_label": item.component_label,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _package_by_id(
    scope: mobile_assessment.MobileAssessmentScope,
    package_id: str,
) -> mobile_assessment.MobilePackageAllowlistEntry | None:
    for package in scope.package_allowlist:
        if package.package_id == package_id:
            return package
    return None


def _callback(
    state: JobQueueState,
    plan: MobileRuntimePlan,
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
