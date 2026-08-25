"""Controlled web active DAST workflow orchestration contracts.

This module does not crawl, send HTTP requests, start scanners, validate
vulnerabilities, or contact targets. It coordinates already-approved local
runtime contracts and supplied sanitized component results.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from redagent_platform.active_policy import ActiveJobRequest, ActivePolicyResult
from redagent_platform.auth_sessions import AuthenticatedSessionContext
from redagent_platform.credentials import CredentialBroker, CredentialLease
from redagent_platform.domain import EvidenceKind, JobStatus, PolicyDecisionOutcome
from redagent_platform.evidence_chain import EvidenceAccessPolicy, EvidenceChain, RedactionStatus, RetentionClass
from redagent_platform.findings import FindingRecord, duplicate_correlation_key, validate_finding
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
from redagent_platform.nuclei_runtime import NucleiRuntimeExecutionResult
from redagent_platform.openapi_harness import OpenApiHarnessExecutionResult
from redagent_platform.scope_authorization import ScopeTarget
from redagent_platform.target_inventory import InventoryTarget
from redagent_platform.zap_runtime import ZapRuntimeExecutionResult


@dataclass(frozen=True, kw_only=True)
class DastCrawlerPolicy:
    max_depth: int
    max_pages: int
    form_submission_allowed: bool
    parameter_mutation_allowed: bool
    authentication_allowed: bool
    destructive_tests_allowed: bool


@dataclass(frozen=True, kw_only=True)
class DastWorkflowPolicy:
    policy_id: str
    module_id: str
    max_rate_per_second: float
    max_requests: int
    timeout_seconds: int
    crawler: DastCrawlerPolicy
    lab_profile: ScannerPolicyProfile


@dataclass(frozen=True, kw_only=True)
class DastWorkflowRequest:
    workflow_id: str
    roe_id: str
    active_request: ActiveJobRequest
    active_policy: ActivePolicyResult
    runner: RunnerContract
    inventory_target: InventoryTarget
    workflow_policy: DastWorkflowPolicy
    target_allowlist: tuple[ScopeTarget, ...]
    emergency_stop_method: str
    lab_validation_records: tuple[LabValidationRecord, ...]
    requested_at: datetime
    operator_user_id: str
    crawler_depth: int
    planned_crawl_pages: int
    form_submission_requested: bool = False
    parameter_mutation_requested: bool = False
    authentication_requested: bool = False
    destructive_tests_requested: bool = False
    auth_contexts: tuple[AuthenticatedSessionContext, ...] = ()


@dataclass(frozen=True, kw_only=True)
class DastWorkflowPlan:
    workflow_id: str
    roe_id: str
    job: JobRecord
    runner_id: str
    policy_id: str
    crawler_depth: int
    planned_crawl_pages: int
    form_submission_enabled: bool
    parameter_mutation_enabled: bool
    authentication_enabled: bool
    destructive_tests_enabled: bool
    rate_limit_per_second: float
    max_requests: int
    timeout_seconds: int
    auth_context_ids: tuple[str, ...]
    lab_validation_id: str | None
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class DastWorkflowReportSummary:
    report_id: str
    workflow_id: str
    finding_count: int
    deduplicated_finding_count: int
    evidence_count: int
    redacted_evidence_link_count: int
    component_count: int
    unsupported_exploitability_claims: bool
    claim_boundary: str


@dataclass(frozen=True, kw_only=True)
class DastWorkflowExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    evidence_ids: tuple[str, ...]
    report_summary: DastWorkflowReportSummary | None
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()
    credential_broker: CredentialBroker = CredentialBroker()


ComponentResult = ZapRuntimeExecutionResult | NucleiRuntimeExecutionResult | OpenApiHarnessExecutionResult


def build_dast_workflow_plan(request: DastWorkflowRequest) -> DastWorkflowPlan:
    _validate_request(request)
    lab_gate = validate_enterprise_job_lab_gate(
        target=request.inventory_target,
        profile=request.workflow_policy.lab_profile,
        validation_records=request.lab_validation_records,
        requested_at=request.requested_at,
    )
    if not lab_gate.allowed:
        raise ValueError(lab_gate.reason)
    grant = request.active_policy.decision.policy_grant
    if grant is None:
        raise ValueError("active_policy_grant_required")
    job = JobRecord(
        job_id=request.active_request.job_id,
        organization_id=request.active_request.organization_id,
        engagement_id=request.active_request.engagement_id,
        test_definition_id=request.workflow_policy.policy_id,
        target=request.active_request.target.normalized(),
        mode=request.active_request.mode,
        status=JobStatus.QUEUED,
        projected_interactions=request.active_request.projected_requests,
        timeout_seconds=request.active_request.projected_duration_seconds,
        cleanup_required=True,
        max_attempts=1,
        policy_decision_id=grant.decision_id,
        policy_expires_at=grant.expires_at,
        last_transition_at=request.requested_at,
    )
    return DastWorkflowPlan(
        workflow_id=request.workflow_id.strip(),
        roe_id=request.roe_id.strip(),
        job=job,
        runner_id=request.runner.runner_id,
        policy_id=request.workflow_policy.policy_id,
        crawler_depth=request.crawler_depth,
        planned_crawl_pages=request.planned_crawl_pages,
        form_submission_enabled=request.form_submission_requested,
        parameter_mutation_enabled=request.parameter_mutation_requested,
        authentication_enabled=request.authentication_requested,
        destructive_tests_enabled=request.destructive_tests_requested,
        rate_limit_per_second=request.active_request.requested_rate_per_second,
        max_requests=request.workflow_policy.max_requests,
        timeout_seconds=request.workflow_policy.timeout_seconds,
        auth_context_ids=tuple(context.session_id for context in request.auth_contexts),
        lab_validation_id=lab_gate.validation_id,
        cancellation_supported=True,
    )


def execute_dast_workflow_plan(
    *,
    plan: DastWorkflowPlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    component_results: tuple[ComponentResult, ...] = (),
    cancel_requested: bool = False,
    credential_broker: CredentialBroker = CredentialBroker(),
    credential_leases_by_job_id: dict[str, CredentialLease] | None = None,
    kill_switch_scope: KillSwitchScope | None = None,
) -> DastWorkflowExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return DastWorkflowExecutionResult(
                allowed=False,
                reason=decision.reason,
                state=state,
                evidence_chain=evidence_chain,
                findings=(),
                evidence_ids=(),
                report_summary=None,
                credential_broker=credential_broker,
            )
    dispatched, dispatch_decision = state.dispatch_job(
        plan.job.job_id,
        runner,
        actor_user_id=operator_user_id,
        event_id=f"{plan.workflow_id}:dispatch",
        occurred_at=occurred_at,
    )
    if not dispatch_decision.allowed:
        return DastWorkflowExecutionResult(
            allowed=False,
            reason=dispatch_decision.reason,
            state=state,
            evidence_chain=evidence_chain,
            findings=(),
            evidence_ids=(),
            report_summary=None,
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
            reason="dast_workflow_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.workflow_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return DastWorkflowExecutionResult(
            allowed=True,
            reason="cancelled",
            state=cancellation.state,
            evidence_chain=evidence_chain,
            findings=(),
            evidence_ids=(),
            report_summary=None,
            cancellation_evidence=cancellation.evidence,
            credential_broker=cancellation.credential_broker,
        )
    component_denial = _component_denial(component_results)
    if component_denial:
        return DastWorkflowExecutionResult(
            allowed=False,
            reason=component_denial,
            state=dispatched,
            evidence_chain=evidence_chain,
            findings=(),
            evidence_ids=(),
            report_summary=None,
            credential_broker=credential_broker,
        )
    running = _callback(dispatched, plan, RunnerCallbackKind.STARTED, "started", occurred_at)
    findings = _dedupe_findings(component_results)
    evidence_ids = _merge_evidence_ids(component_results)
    summary = _build_report_summary(plan, findings, evidence_ids, component_results)
    chain = _append_report_summary(evidence_chain, plan, summary, occurred_at)
    evidence_ids = evidence_ids + (summary.report_id,)
    with_result = _callback(running, plan, RunnerCallbackKind.RESULT, "result", occurred_at, evidence_ids=evidence_ids)
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return DastWorkflowExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        evidence_ids=evidence_ids,
        report_summary=summary,
        credential_broker=credential_broker,
    )


def _validate_request(request: DastWorkflowRequest) -> None:
    for field_name, value in (
        ("workflow_id", request.workflow_id),
        ("roe_id", request.roe_id),
        ("operator_user_id", request.operator_user_id),
        ("emergency_stop_method", request.emergency_stop_method),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    _validate_policy(request.workflow_policy)
    _validate_crawler_request(request)
    if request.active_request.requested_at != request.requested_at:
        raise ValueError("workflow_request_time_mismatch")
    if request.active_request.module_id != request.workflow_policy.module_id:
        raise ValueError("dast_policy_mismatch")
    if request.active_request.operator_confirmation is None:
        raise ValueError("operator_confirmation_required")
    if not request.active_policy.decision.allowed:
        raise ValueError(f"active_policy_denied:{request.active_policy.decision.reason}")
    if request.active_policy.decision.outcome is not PolicyDecisionOutcome.ALLOW:
        raise ValueError("active_policy_must_allow")
    grant = request.active_policy.decision.policy_grant
    if grant is None:
        raise ValueError("active_policy_grant_required")
    if request.requested_at >= grant.expires_at:
        raise ValueError("current_policy_decision_required")
    if request.active_request.requested_rate_per_second > request.workflow_policy.max_rate_per_second:
        raise ValueError("dast_rate_cap_exceeded")
    if request.active_request.projected_requests > request.workflow_policy.max_requests:
        raise ValueError("dast_request_cap_exceeded")
    if request.active_request.projected_duration_seconds > request.workflow_policy.timeout_seconds:
        raise ValueError("dast_timeout_exceeded")
    if not _target_allowed(request.active_request.target, request.target_allowlist):
        raise ValueError("target_not_in_allowlist")
    if request.inventory_target.to_scope_target().normalized() != request.active_request.target.normalized():
        raise ValueError("inventory_target_mismatch")
    if request.runner.organization_id != request.active_request.organization_id:
        raise ValueError("runner_organization_mismatch")
    if request.active_request.mode not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")
    if request.runner.target_scope.normalized() != request.active_request.target.normalized():
        raise ValueError("runner_target_scope_mismatch")
    _validate_auth_contexts(request)


def _validate_policy(policy: DastWorkflowPolicy) -> None:
    _require_non_empty("policy_id", policy.policy_id)
    _require_non_empty("module_id", policy.module_id)
    if policy.max_rate_per_second <= 0:
        raise ValueError("invalid_dast_rate")
    if policy.max_requests <= 0:
        raise ValueError("invalid_dast_request_cap")
    if policy.timeout_seconds <= 0:
        raise ValueError("invalid_dast_timeout")
    if policy.crawler.max_depth < 0:
        raise ValueError("invalid_crawler_depth_cap")
    if policy.crawler.max_pages <= 0:
        raise ValueError("invalid_crawler_page_cap")


def _validate_crawler_request(request: DastWorkflowRequest) -> None:
    crawler = request.workflow_policy.crawler
    if request.crawler_depth < 0:
        raise ValueError("invalid_crawler_depth")
    if request.planned_crawl_pages <= 0:
        raise ValueError("invalid_crawler_page_count")
    if request.crawler_depth > crawler.max_depth:
        raise ValueError("crawler_depth_cap_exceeded")
    if request.planned_crawl_pages > crawler.max_pages:
        raise ValueError("crawler_page_cap_exceeded")
    if request.form_submission_requested and not crawler.form_submission_allowed:
        raise ValueError("form_submission_not_allowed")
    if request.parameter_mutation_requested and not crawler.parameter_mutation_allowed:
        raise ValueError("parameter_mutation_not_allowed")
    if request.authentication_requested and not crawler.authentication_allowed:
        raise ValueError("authentication_not_allowed")
    if request.destructive_tests_requested:
        raise ValueError("destructive_tests_forbidden")
    if crawler.destructive_tests_allowed and request.workflow_policy.lab_profile.profile_id:
        # The first compat_065 workflow remains non-destructive even if a future policy
        # object accidentally advertises destructive support.
        raise ValueError("destructive_tests_policy_forbidden")


def _validate_auth_contexts(request: DastWorkflowRequest) -> None:
    if request.authentication_requested and not request.auth_contexts:
        raise ValueError("auth_context_required")
    for context in request.auth_contexts:
        if context.target.normalized() != request.active_request.target.normalized():
            raise ValueError("auth_context_target_mismatch")
        if context.mode is not request.active_request.mode:
            raise ValueError("auth_context_mode_mismatch")
        if request.requested_at >= context.expires_at:
            raise ValueError("auth_context_expired")


def _validate_execution_inputs(plan: DastWorkflowPlan, runner: RunnerContract, occurred_at: datetime, operator_user_id: str) -> None:
    _require_non_empty("operator_user_id", operator_user_id)
    _require_timezone(occurred_at)
    if runner.runner_id != plan.runner_id:
        raise ValueError("runner_mismatch")
    if plan.job.mode not in runner.capabilities:
        raise ValueError("runner_capability_missing")
    if runner.target_scope.normalized() != plan.job.target.normalized():
        raise ValueError("runner_target_scope_mismatch")


def _component_denial(component_results: tuple[ComponentResult, ...]) -> str | None:
    for result in component_results:
        if not result.allowed:
            return f"component_result_denied:{result.reason}"
    return None


def _dedupe_findings(component_results: tuple[ComponentResult, ...]) -> tuple[FindingRecord, ...]:
    findings: list[FindingRecord] = []
    seen: set[str] = set()
    for result in component_results:
        for finding in result.findings:
            validate_finding(finding)
            key = duplicate_correlation_key(finding)
            if key in seen:
                continue
            seen.add(key)
            findings.append(finding)
    return tuple(findings)


def _merge_evidence_ids(component_results: tuple[ComponentResult, ...]) -> tuple[str, ...]:
    merged: list[str] = []
    for result in component_results:
        for evidence_id in result.imported_evidence_ids:
            _require_non_empty("evidence_id", evidence_id)
            if evidence_id not in merged:
                merged.append(evidence_id)
    return tuple(merged)


def _build_report_summary(
    plan: DastWorkflowPlan,
    findings: tuple[FindingRecord, ...],
    evidence_ids: tuple[str, ...],
    component_results: tuple[ComponentResult, ...],
) -> DastWorkflowReportSummary:
    redacted_links = sum(
        1
        for finding in findings
        for link in finding.evidence_links
        if link.redaction_status is RedactionStatus.REDACTED or link.contains_sensitive_payload
    )
    return DastWorkflowReportSummary(
        report_id=f"{plan.workflow_id}:report-summary",
        workflow_id=plan.workflow_id,
        finding_count=sum(len(result.findings) for result in component_results),
        deduplicated_finding_count=len(findings),
        evidence_count=len(evidence_ids),
        redacted_evidence_link_count=redacted_links,
        component_count=len(component_results),
        unsupported_exploitability_claims=False,
        claim_boundary="Supplied scanner/API observations are reviewable findings; no exploitability is claimed without separate evidence.",
    )


def _append_report_summary(
    evidence_chain: EvidenceChain,
    plan: DastWorkflowPlan,
    summary: DastWorkflowReportSummary,
    occurred_at: datetime,
) -> EvidenceChain:
    return evidence_chain.append_evidence_record(
        evidence_id=summary.report_id,
        organization_id=plan.job.organization_id,
        source_job_id=plan.job.job_id,
        kind=EvidenceKind.REPORT_SOURCE,
        created_at=occurred_at,
        redaction_status=RedactionStatus.NOT_APPLICABLE,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=json.dumps(
            {
                "workflow_id": summary.workflow_id,
                "finding_count": summary.finding_count,
                "deduplicated_finding_count": summary.deduplicated_finding_count,
                "evidence_count": summary.evidence_count,
                "redacted_evidence_link_count": summary.redacted_evidence_link_count,
                "component_count": summary.component_count,
                "unsupported_exploitability_claims": summary.unsupported_exploitability_claims,
                "claim_boundary": summary.claim_boundary,
            },
            sort_keys=True,
        ).encode("utf-8"),
        contains_sensitive_capture=False,
        metadata={"module": "active_dast_workflow", "workflow_id": plan.workflow_id},
    )


def _callback(
    state: JobQueueState,
    plan: DastWorkflowPlan,
    kind: RunnerCallbackKind,
    label: str,
    occurred_at: datetime,
    *,
    evidence_ids: tuple[str, ...] = (),
) -> JobQueueState:
    next_state, decision = state.handle_callback(
        RunnerCallback(
            callback_id=f"{plan.workflow_id}:{label}",
            runner_id=plan.runner_id,
            job_id=plan.job.job_id,
            kind=kind,
            occurred_at=occurred_at,
            evidence_ids=evidence_ids,
        ),
        actor_user_id=plan.runner_id,
        event_id=f"{plan.workflow_id}:callback:{label}",
    )
    if not decision.allowed:
        raise ValueError(decision.reason)
    return next_state


def _target_allowed(target: ScopeTarget, allowlist: tuple[ScopeTarget, ...]) -> bool:
    normalized = target.normalized()
    return any(candidate.normalized() == normalized for candidate in allowlist)


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
