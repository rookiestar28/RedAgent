"""Controlled AI/LLM and agentic application harness contracts.

This module does not call AI providers, execute prompts, run retrieval queries,
invoke tools, automate browsers, or start subprocesses. It builds local dry-run
plans and imports supplied sanitized AI/agentic assessment results.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import ai_agentic
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
from redagent_platform.redaction import RedactionArtifactClass, sanitize_mapping
from redagent_platform.scope_authorization import ScopeTarget
from redagent_platform.skill_command_contract import AssessmentType, ContractDecision, evaluate_skill_assessment_request


class AiHarnessAction(str, Enum):
    IMPORT_RESULTS = "import_results"
    PREPARE_PROMPT_CASE = "prepare_prompt_case"
    PREPARE_DRY_RUN_TOOL_PLAN = "prepare_dry_run_tool_plan"
    CALL_LIVE_PROVIDER = "call_live_provider"
    EXECUTE_TOOL_SIDE_EFFECT = "execute_tool_side_effect"
    EXTRACT_THIRD_PARTY_PROMPT = "extract_third_party_prompt"


@dataclass(frozen=True, kw_only=True)
class AiHarnessProfile:
    profile_id: str
    module_id: str
    allowed_test_ids: tuple[str, ...]
    allowed_provider_account_ids: tuple[str, ...]
    allowed_model_ids: tuple[str, ...]
    allowed_tool_ids: tuple[str, ...]
    max_cost_usd: float
    max_requests: int
    timeout_seconds: int
    dry_run_default: bool
    actions: tuple[AiHarnessAction, ...]


@dataclass(frozen=True, kw_only=True)
class AiHarnessRequest:
    runtime_id: str
    organization_id: str
    engagement_id: str
    target: ScopeTarget
    profile: AiHarnessProfile
    assessment_request: ai_agentic.AiAssessmentRequest
    runner: RunnerContract
    requested_at: datetime
    operator_user_id: str
    approved_by_user_id: str


@dataclass(frozen=True, kw_only=True)
class AiHarnessPlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    test_id: str
    category: ai_agentic.AiRiskCategory
    provider_account_id: str
    model_id: str
    max_cost_usd: float
    max_requests: int
    timeout_seconds: int
    dry_run_only: bool
    tool_ids: tuple[str, ...]
    actions: tuple[AiHarnessAction, ...]
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class AiHarnessResultItem:
    item_id: str
    category: ai_agentic.AiRiskCategory
    affected_workflow: str
    data_boundary: str
    tool_action_boundary: str
    severity: Severity
    remediation_guidance: str
    evidence_redaction_class: RedactionStatus
    summary: str
    dry_run_only: bool
    cost_usd: float = 0.0
    request_count: int = 0
    tool_ids: tuple[str, ...] = ()
    contains_sensitive_material: bool = False


@dataclass(frozen=True, kw_only=True)
class AiHarnessReportRow:
    finding_id: str
    evidence_id: str
    category: ai_agentic.AiRiskCategory
    affected_workflow: str
    data_boundary: str
    tool_action_boundary: str
    severity: Severity
    evidence_redaction_class: RedactionStatus
    dry_run_only: bool
    cost_usd: float
    request_count: int
    remediation_guidance: str


@dataclass(frozen=True, kw_only=True)
class AiHarnessExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    report_rows: tuple[AiHarnessReportRow, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()


@dataclass(frozen=True, kw_only=True)
class AiSkillWorkflowSpec:
    request_id: str
    skill_client: str
    skill_version: str
    owner_label: str
    approver_label: str
    operator_label: str
    authorization_label: str
    requested_at: datetime
    window_start: datetime
    window_end: datetime
    command_log_path: str
    evidence_dir: str
    report_path: str
    emergency_stop_method: str


_FORBIDDEN_ACTIONS = frozenset(
    {
        AiHarnessAction.CALL_LIVE_PROVIDER,
        AiHarnessAction.EXECUTE_TOOL_SIDE_EFFECT,
        AiHarnessAction.EXTRACT_THIRD_PARTY_PROMPT,
    }
)


def build_ai_harness_plan(request: AiHarnessRequest) -> AiHarnessPlan:
    _validate_request(request)
    provider_scope = request.assessment_request.provider_scope
    if provider_scope is None or request.assessment_request.requested_model_id is None:
        raise ValueError("ai_provider_scope_required")
    target = request.target.normalized()
    if target.target_type is not TargetType.AI_APPLICATION:
        raise ValueError("ai_application_target_required")
    if request.runner.target_scope.normalized() != target:
        raise ValueError("runner_target_scope_mismatch")
    return AiHarnessPlan(
        runtime_id=request.runtime_id.strip(),
        job=JobRecord(
            job_id=request.assessment_request.job_id,
            organization_id=request.organization_id,
            engagement_id=request.engagement_id,
            test_definition_id=request.profile.profile_id,
            target=target,
            mode=TestMode.AI_AGENTIC_ASSESSMENT,
            status=JobStatus.QUEUED,
            projected_interactions=max(1, min(provider_scope.max_requests, request.profile.max_requests)),
            timeout_seconds=request.profile.timeout_seconds,
            cleanup_required=True,
            max_attempts=1,
            policy_decision_id=f"{request.runtime_id}:ai-policy",
            policy_expires_at=request.requested_at.replace(year=request.requested_at.year + 1),
            last_transition_at=request.requested_at,
        ),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        test_id=request.assessment_request.test_case.test_id.strip(),
        category=request.assessment_request.test_case.category,
        provider_account_id=provider_scope.provider_account_id.strip(),
        model_id=request.assessment_request.requested_model_id.strip(),
        max_cost_usd=min(provider_scope.max_cost_usd, request.profile.max_cost_usd),
        max_requests=min(provider_scope.max_requests, request.profile.max_requests),
        timeout_seconds=request.profile.timeout_seconds,
        dry_run_only=True,
        tool_ids=tuple(request.assessment_request.requested_tool_ids),
        actions=tuple(request.profile.actions),
        cancellation_supported=True,
    )


def build_ai_skill_workflow_decision(plan: AiHarnessPlan, spec: AiSkillWorkflowSpec) -> ContractDecision:
    _validate_skill_spec(spec)
    target = {"target_type": TargetType.AI_APPLICATION.value, "value": plan.job.target.value}
    request = {
        "request_id": spec.request_id,
        "skill_client": spec.skill_client,
        "skill_version": spec.skill_version,
        "mode": "dry_run",
        "assessment_type": AssessmentType.AI_AGENTIC.value,
        "requested_at": spec.requested_at.isoformat(),
        "organization_id": plan.job.organization_id,
        "engagement_id": plan.job.engagement_id,
        "owner_label": spec.owner_label,
        "approver_label": spec.approver_label,
        "operator_label": spec.operator_label,
        "authorization_label": spec.authorization_label,
        "roe_status": "approved",
        "authorization_confirmed": True,
        "authorized_targets": [target],
        "requested_targets": [target],
        "excluded_targets": [],
        "environment": "lab",
        "sensitivity": "synthetic_ai_fixture_only",
        "allowed_categories": [AssessmentType.AI_AGENTIC.value],
        "forbidden_actions": [
            "live_provider_call",
            "real_sensitive_data_exfiltration",
            "third_party_prompt_extraction",
            "side_effecting_tool_call",
        ],
        "window": {"start": spec.window_start.isoformat(), "end": spec.window_end.isoformat()},
        "limits": {
            "rate_limit_per_second": 1,
            "max_concurrency": 1,
            "max_interactions": plan.max_requests,
            "timeout_seconds": plan.timeout_seconds,
        },
        "credential_requirement": "not_required",
        "output_paths": {
            "command_log_path": spec.command_log_path,
            "evidence_dir": spec.evidence_dir,
            "report_path": spec.report_path,
        },
        "emergency_stop_method": spec.emergency_stop_method,
        "data_handling": {
            "redaction_required": True,
            "retention_class": "standard",
            "export_allowed": False,
        },
        "user_confirmation": {"confirmed": False},
    }
    return evaluate_skill_assessment_request(request)


def execute_ai_harness_plan(
    *,
    plan: AiHarnessPlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    result_items: tuple[AiHarnessResultItem, ...] = (),
    cancel_requested: bool = False,
    kill_switch_scope: KillSwitchScope | None = None,
) -> AiHarnessExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    _validate_result_budget(plan, result_items)
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return AiHarnessExecutionResult(
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
        return AiHarnessExecutionResult(
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
            reason="ai_harness_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return AiHarnessExecutionResult(
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
    return AiHarnessExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        report_rows=rows,
        imported_evidence_ids=evidence_ids,
    )


def _validate_request(request: AiHarnessRequest) -> None:
    for field_name, value in (
        ("runtime_id", request.runtime_id),
        ("organization_id", request.organization_id),
        ("engagement_id", request.engagement_id),
        ("operator_user_id", request.operator_user_id),
        ("approved_by_user_id", request.approved_by_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    decision = ai_agentic.evaluate_ai_assessment(request.assessment_request)
    if not decision.allowed:
        raise ValueError(f"ai_assessment_denied:{decision.reason}")
    provider_scope = request.assessment_request.provider_scope
    if provider_scope is None:
        raise ValueError("ai_provider_scope_required")
    if request.assessment_request.test_case.test_id not in _normalized_set(request.profile.allowed_test_ids):
        raise ValueError("ai_test_case_not_allowlisted")
    if provider_scope.provider_account_id not in _normalized_set(request.profile.allowed_provider_account_ids):
        raise ValueError("ai_provider_account_not_allowlisted")
    if request.assessment_request.requested_model_id not in _normalized_set(request.profile.allowed_model_ids):
        raise ValueError("ai_model_not_allowlisted")
    if provider_scope.max_cost_usd > request.profile.max_cost_usd:
        raise ValueError("ai_cost_cap_exceeded")
    if provider_scope.max_requests > request.profile.max_requests:
        raise ValueError("ai_request_cap_exceeded")
    boundary = request.assessment_request.tool_boundary
    if boundary is None:
        raise ValueError("ai_tool_boundary_required")
    if not set(request.assessment_request.requested_tool_ids) <= set(request.profile.allowed_tool_ids):
        raise ValueError("ai_tool_not_allowlisted")
    if not boundary.dry_run:
        raise ValueError("ai_tool_dry_run_required")
    if not boundary.side_effect_controls_enabled:
        raise ValueError("ai_side_effect_controls_required")
    if not boundary.kill_switch_enabled:
        raise ValueError("ai_kill_switch_required")
    if request.runner.organization_id != request.organization_id:
        raise ValueError("runner_organization_mismatch")
    if TestMode.AI_AGENTIC_ASSESSMENT not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")


def _validate_profile(profile: AiHarnessProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_test_ids:
        raise ValueError("ai_test_allowlist_required")
    if not profile.allowed_provider_account_ids:
        raise ValueError("ai_provider_allowlist_required")
    if not profile.allowed_model_ids:
        raise ValueError("ai_model_allowlist_required")
    if not profile.allowed_tool_ids:
        raise ValueError("ai_tool_allowlist_required")
    if not profile.dry_run_default:
        raise ValueError("ai_harness_dry_run_default_required")
    if AiHarnessAction.IMPORT_RESULTS not in profile.actions:
        raise ValueError("ai_harness_import_action_required")
    if _FORBIDDEN_ACTIONS.intersection(profile.actions):
        raise ValueError("ai_harness_live_or_side_effect_action_not_allowed")
    if profile.max_cost_usd <= 0:
        raise ValueError("ai_harness_cost_cap_required")
    if profile.max_requests <= 0:
        raise ValueError("ai_harness_request_cap_required")
    if profile.timeout_seconds <= 0:
        raise ValueError("ai_harness_timeout_invalid")


def _validate_skill_spec(spec: AiSkillWorkflowSpec) -> None:
    for field_name, value in (
        ("request_id", spec.request_id),
        ("skill_client", spec.skill_client),
        ("skill_version", spec.skill_version),
        ("owner_label", spec.owner_label),
        ("approver_label", spec.approver_label),
        ("operator_label", spec.operator_label),
        ("authorization_label", spec.authorization_label),
        ("command_log_path", spec.command_log_path),
        ("evidence_dir", spec.evidence_dir),
        ("report_path", spec.report_path),
        ("emergency_stop_method", spec.emergency_stop_method),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(spec.requested_at)
    _require_timezone(spec.window_start)
    _require_timezone(spec.window_end)


def _validate_execution_inputs(
    plan: AiHarnessPlan,
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


def _validate_result_budget(plan: AiHarnessPlan, result_items: tuple[AiHarnessResultItem, ...]) -> None:
    total_cost = sum(item.cost_usd for item in result_items)
    total_requests = sum(item.request_count for item in result_items)
    if total_cost > plan.max_cost_usd:
        raise ValueError("ai_result_cost_cap_exceeded")
    if total_requests > plan.max_requests:
        raise ValueError("ai_result_request_cap_exceeded")


def _append_result_evidence(
    plan: AiHarnessPlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    result_items: tuple[AiHarnessResultItem, ...],
) -> tuple[EvidenceChain, tuple[str, ...], tuple[FindingRecord, ...], tuple[AiHarnessReportRow, ...]]:
    chain = evidence_chain
    evidence_ids: list[str] = []
    findings: list[FindingRecord] = []
    rows: list[AiHarnessReportRow] = []
    for item in result_items:
        content = _validate_result_item(plan, item)
        evidence_id = f"{plan.runtime_id}:{item.category.value}:{item.item_id}"
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
                "category": item.category.value,
                "affected_workflow": item.affected_workflow,
                "data_boundary": item.data_boundary,
                "tool_action_boundary": item.tool_action_boundary,
                "dry_run_only": item.dry_run_only,
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
        finding = _finding_for(item, evidence)
        validate_finding(finding)
        findings.append(finding)
        evidence_ids.append(evidence_id)
        rows.append(
            AiHarnessReportRow(
                finding_id=finding.id,
                evidence_id=evidence_id,
                category=item.category,
                affected_workflow=item.affected_workflow.strip(),
                data_boundary=item.data_boundary.strip(),
                tool_action_boundary=item.tool_action_boundary.strip(),
                severity=item.severity,
                evidence_redaction_class=item.evidence_redaction_class,
                dry_run_only=item.dry_run_only,
                cost_usd=item.cost_usd,
                request_count=item.request_count,
                remediation_guidance=item.remediation_guidance.strip(),
            )
        )
    return chain, tuple(evidence_ids), tuple(findings), tuple(rows)


def _validate_result_item(plan: AiHarnessPlan, item: AiHarnessResultItem) -> bytes | None:
    if item.cost_usd < 0 or item.request_count < 0:
        raise ValueError("ai_result_budget_invalid")
    if item.tool_ids and not item.dry_run_only:
        raise ValueError("ai_tool_result_must_be_dry_run")
    if not set(item.tool_ids) <= set(plan.tool_ids):
        raise ValueError("ai_result_tool_not_planned")
    if item.contains_sensitive_material and item.evidence_redaction_class not in {
        RedactionStatus.REDACTED,
        RedactionStatus.BLOCKED,
    }:
        raise ValueError("ai_sensitive_result_requires_redaction")
    ai_agentic.build_ai_finding_mapping(
        finding_id=item.item_id,
        category=item.category,
        affected_workflow=item.affected_workflow,
        data_boundary=item.data_boundary,
        tool_action_boundary=item.tool_action_boundary,
        severity=item.severity,
        remediation_guidance=item.remediation_guidance,
    )
    if item.evidence_redaction_class is RedactionStatus.BLOCKED:
        return None
    sanitized, redaction_result = sanitize_mapping(_result_payload(item), RedactionArtifactClass.SCANNER_OUTPUT)
    if redaction_result.redacted and item.evidence_redaction_class is RedactionStatus.NOT_APPLICABLE:
        raise ValueError("ai_result_requires_redaction")
    return json.dumps(sanitized, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _finding_for(item: AiHarnessResultItem, evidence: EvidenceLink) -> FindingRecord:
    return FindingRecord(
        id=f"ai-agentic:finding:{item.item_id.strip()}",
        title=f"AI/agentic finding: {item.category.value} in {item.affected_workflow.strip()}",
        status=FindingStatus.RAW_ALERT,
        affected_asset_id=item.affected_workflow.strip(),
        affected_asset_value=item.affected_workflow.strip(),
        confidence=Confidence.MEDIUM,
        risk=RiskFactors(
            severity=item.severity,
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.UNKNOWN,
            vulnerability_intelligence=VulnerabilityIntelligence(cve_ids=(), cwe_ids=()),
        ),
        reproduction_summary=(
            f"Sanitized dry-run AI/agentic {item.category.value} import for workflow "
            f"{item.affected_workflow.strip()}; no provider, model, prompt, retrieval, or tool execution occurred."
        ),
        evidence_links=(evidence,),
        remediation=item.remediation_guidance.strip(),
        owner_user_id=None,
        source="ai_agentic_runtime",
        source_rule_id=item.category.value,
    )


def _result_payload(item: AiHarnessResultItem) -> dict[str, object]:
    return {
        "category": item.category.value,
        "affected_workflow": item.affected_workflow.strip(),
        "data_boundary": item.data_boundary.strip(),
        "tool_action_boundary": item.tool_action_boundary.strip(),
        "severity": item.severity.value,
        "summary": item.summary.strip(),
        "remediation": item.remediation_guidance.strip(),
        "dry_run_only": item.dry_run_only,
        "cost_usd": item.cost_usd,
        "request_count": item.request_count,
        "tool_ids": tuple(item.tool_ids),
    }


def _callback(
    state: JobQueueState,
    plan: AiHarnessPlan,
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
