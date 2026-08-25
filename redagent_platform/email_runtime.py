"""Controlled email/domain resilience workflow runtime contracts.

This module does not perform DNS lookups, HTTP requests, SMTP actions, email
sending, credential collection, mailbox access, campaign execution, or
subprocess execution. It imports supplied read-only observations and aggregate
campaign metrics.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import email_resilience
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


class EmailWorkflowAction(str, Enum):
    IMPORT_DOMAIN_CONTROL = "import_domain_control"
    IMPORT_AGGREGATE_EVIDENCE = "import_aggregate_evidence"
    PREPARE_REVIEW_QUEUE = "prepare_review_queue"
    SEND_EMAIL = "send_email"
    COLLECT_CREDENTIALS = "collect_credentials"
    ACCESS_MAILBOX_CONTENT = "access_mailbox_content"
    ATTACH_PAYLOAD = "attach_payload"


@dataclass(frozen=True, kw_only=True)
class EmailWorkflowProfile:
    profile_id: str
    module_id: str
    allowed_domains: tuple[str, ...]
    max_delivered_count: int
    timeout_seconds: int
    kill_switch_enabled: bool
    actions: tuple[EmailWorkflowAction, ...]


@dataclass(frozen=True, kw_only=True)
class EmailWorkflowRequest:
    runtime_id: str
    domain_assessment: email_resilience.DomainControlAssessment
    simulation_request: email_resilience.PhishingSimulationRequest
    profile: EmailWorkflowProfile
    runner: RunnerContract
    requested_at: datetime
    operator_user_id: str


@dataclass(frozen=True, kw_only=True)
class EmailWorkflowPlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    simulation_id: str
    domain: str
    recipient_domains: tuple[str, ...]
    domain_control_summary: dict[email_resilience.DomainControlCheckType, email_resilience.DomainControlStatus]
    max_delivered_count: int
    execution_enabled: bool
    actions: tuple[EmailWorkflowAction, ...]
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class EmailWorkflowReportRow:
    evidence_id: str
    domain: str
    section: str
    key: str
    value: str | int


@dataclass(frozen=True, kw_only=True)
class EmailWorkflowExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    report_rows: tuple[EmailWorkflowReportRow, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()


_FORBIDDEN_ACTIONS = frozenset(
    {
        EmailWorkflowAction.SEND_EMAIL,
        EmailWorkflowAction.COLLECT_CREDENTIALS,
        EmailWorkflowAction.ACCESS_MAILBOX_CONTENT,
        EmailWorkflowAction.ATTACH_PAYLOAD,
    }
)


def build_email_workflow_plan(request: EmailWorkflowRequest) -> EmailWorkflowPlan:
    _validate_request(request)
    domain = _normalize_domain(request.domain_assessment.domain)
    target = ScopeTarget(target_type=TargetType.DOMAIN, value=domain).normalized()
    if request.runner.target_scope.normalized() != target:
        raise ValueError("runner_target_scope_mismatch")
    summary = email_resilience.summarize_domain_control(request.domain_assessment)
    return EmailWorkflowPlan(
        runtime_id=request.runtime_id.strip(),
        job=JobRecord(
            job_id=f"{request.runtime_id}:job",
            organization_id=request.simulation_request.organization_id,
            engagement_id=request.simulation_request.engagement_id,
            test_definition_id=request.profile.profile_id,
            target=target,
            mode=TestMode.EMAIL_RESILIENCE,
            status=JobStatus.QUEUED,
            projected_interactions=1,
            timeout_seconds=request.profile.timeout_seconds,
            cleanup_required=True,
            max_attempts=1,
            policy_decision_id=f"{request.runtime_id}:email-policy",
            policy_expires_at=request.requested_at.replace(year=request.requested_at.year + 1),
            last_transition_at=request.requested_at,
        ),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        simulation_id=request.simulation_request.simulation_id.strip(),
        domain=domain,
        recipient_domains=tuple(_normalize_domain(domain) for domain in request.simulation_request.recipient_scope.requested_recipient_domains),
        domain_control_summary=summary,
        max_delivered_count=request.profile.max_delivered_count,
        execution_enabled=False,
        actions=tuple(request.profile.actions),
        cancellation_supported=True,
    )


def execute_email_workflow_plan(
    *,
    plan: EmailWorkflowPlan,
    domain_assessment: email_resilience.DomainControlAssessment,
    evidence: email_resilience.EmailResilienceEvidence,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    cancel_requested: bool = False,
    kill_switch_scope: KillSwitchScope | None = None,
) -> EmailWorkflowExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return EmailWorkflowExecutionResult(
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
        return EmailWorkflowExecutionResult(
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
            reason="email_workflow_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return EmailWorkflowExecutionResult(
            allowed=True,
            reason="cancelled",
            state=cancellation.state,
            evidence_chain=evidence_chain,
            report_rows=(),
            imported_evidence_ids=(),
            cancellation_evidence=cancellation.evidence,
        )
    running = _callback(dispatched, plan, RunnerCallbackKind.STARTED, "started", occurred_at)
    chain, evidence_id, rows = _append_email_evidence(plan, domain_assessment, evidence, evidence_chain, occurred_at)
    with_result = _callback(running, plan, RunnerCallbackKind.RESULT, "result", occurred_at, evidence_ids=(evidence_id,))
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return EmailWorkflowExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        report_rows=rows,
        imported_evidence_ids=(evidence_id,),
    )


def _validate_request(request: EmailWorkflowRequest) -> None:
    _require_non_empty("runtime_id", request.runtime_id)
    _require_non_empty("operator_user_id", request.operator_user_id)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    domain = _normalize_domain(request.domain_assessment.domain)
    if domain not in _normalized_domains(request.profile.allowed_domains):
        raise ValueError("domain_not_allowlisted")
    email_resilience.validate_domain_control_assessment(request.domain_assessment)
    decision = email_resilience.evaluate_phishing_simulation_request(request.simulation_request)
    if not decision.allowed:
        raise ValueError(f"email_workflow_denied:{decision.reason.value}")
    if any(_normalize_domain(domain) not in _normalized_domains(request.profile.allowed_domains) for domain in request.simulation_request.recipient_scope.requested_recipient_domains):
        raise ValueError("recipient_domain_not_allowlisted")
    if request.runner.organization_id != request.simulation_request.organization_id:
        raise ValueError("runner_organization_mismatch")
    if TestMode.EMAIL_RESILIENCE not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")


def _validate_profile(profile: EmailWorkflowProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_domains:
        raise ValueError("domain_allowlist_required")
    if EmailWorkflowAction.IMPORT_DOMAIN_CONTROL not in profile.actions:
        raise ValueError("domain_control_import_action_required")
    if EmailWorkflowAction.IMPORT_AGGREGATE_EVIDENCE not in profile.actions:
        raise ValueError("aggregate_evidence_import_action_required")
    if EmailWorkflowAction.PREPARE_REVIEW_QUEUE not in profile.actions:
        raise ValueError("review_queue_action_required")
    if _FORBIDDEN_ACTIONS.intersection(profile.actions):
        raise ValueError("email_sending_or_collection_action_not_allowed")
    if profile.max_delivered_count <= 0:
        raise ValueError("delivered_count_cap_required")
    if profile.timeout_seconds <= 0:
        raise ValueError("workflow_timeout_invalid")
    if not profile.kill_switch_enabled:
        raise ValueError("kill_switch_required")


def _validate_execution_inputs(
    plan: EmailWorkflowPlan,
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


def _append_email_evidence(
    plan: EmailWorkflowPlan,
    domain_assessment: email_resilience.DomainControlAssessment,
    evidence: email_resilience.EmailResilienceEvidence,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
) -> tuple[EvidenceChain, str, tuple[EmailWorkflowReportRow, ...]]:
    exported = email_resilience.export_aggregate_evidence(evidence)
    metrics = exported.get("aggregate_metrics")
    if isinstance(metrics, dict) and int(metrics.get("delivered_count", 0)) > plan.max_delivered_count:
        raise ValueError("delivered_count_cap_exceeded")
    report = email_resilience.build_email_resilience_report(
        report_id=f"{plan.runtime_id}:report",
        domain_assessment=domain_assessment,
        evidence=evidence,
    )
    evidence_id = f"{plan.runtime_id}:email-aggregate:{evidence.evidence_id}"
    content = json.dumps(
        {
            "aggregate_evidence": exported,
            "domain_control_findings": report.domain_control_findings,
            "campaign_outcomes": report.campaign_outcomes,
            "execution_enabled": plan.execution_enabled,
        },
        sort_keys=True,
        separators=(",", ":"),
        default=str,
    ).encode("utf-8")
    chain = evidence_chain.append_evidence_record(
        evidence_id=evidence_id,
        organization_id=plan.job.organization_id,
        source_job_id=plan.job.job_id,
        kind=EvidenceKind.REPORT_SOURCE,
        created_at=occurred_at,
        redaction_status=RedactionStatus.NOT_APPLICABLE,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=content,
        contains_sensitive_capture=False,
        metadata={"domain": plan.domain, "simulation_id": plan.simulation_id},
    )
    rows: list[EmailWorkflowReportRow] = []
    for finding in report.domain_control_findings:
        rows.append(
            EmailWorkflowReportRow(
                evidence_id=evidence_id,
                domain=str(finding["domain"]),
                section="domain_control",
                key=str(finding["check_type"]),
                value=str(finding["status"]),
            )
        )
    for outcome in report.campaign_outcomes:
        for key, value in outcome.items():
            if key == "domain":
                continue
            rows.append(
                EmailWorkflowReportRow(
                    evidence_id=evidence_id,
                    domain=str(outcome["domain"]),
                    section="campaign_outcome",
                    key=str(key),
                    value=value,
                )
            )
    return chain, evidence_id, tuple(rows)


def _callback(
    state: JobQueueState,
    plan: EmailWorkflowPlan,
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


def _normalize_domain(value: str) -> str:
    _require_non_empty("domain", value)
    return value.strip().lower().rstrip(".")


def _normalized_domains(values: tuple[str, ...]) -> frozenset[str]:
    return frozenset(_normalize_domain(value) for value in values)


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
