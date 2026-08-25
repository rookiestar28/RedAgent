"""Controlled Nuclei runtime adapter and template trust contracts.

This module does not start Nuclei, load external template bodies, execute
templates, create OAST callbacks, or contact targets. It binds reviewed
metadata and supplied results to local runner/evidence contracts.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from redagent_platform.credentials import CredentialBroker, CredentialLease
from redagent_platform.domain import JobStatus, TestRiskClass
from redagent_platform.evidence_chain import EvidenceChain
from redagent_platform.findings import FindingRecord
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
from redagent_platform.nuclei_execution import (
    NucleiExecutionPlan,
    NucleiResult,
    append_nuclei_result_evidence,
    normalize_nuclei_result_to_finding,
)
from redagent_platform.nuclei_metadata import NucleiReviewStatus, NucleiSeverity, NucleiTemplateReview
from redagent_platform.target_inventory import InventoryTarget


class NucleiTemplateTrustStatus(str, Enum):
    SIGNED_VERIFIED = "signed_verified"
    TRUSTED_INTERNAL = "trusted_internal"
    UNTRUSTED = "untrusted"


class NucleiRuntimeAction(str, Enum):
    LOAD_TRUSTED_TEMPLATE = "load_trusted_template"
    START_SCAN = "start_scan"
    POLL_SCAN = "poll_scan"
    STOP_SCAN = "stop_scan"
    IMPORT_RESULTS = "import_results"


@dataclass(frozen=True, kw_only=True)
class NucleiTemplateTrustRecord:
    template_id: str
    template_digest: str
    status: NucleiTemplateTrustStatus
    reviewer_user_id: str
    reviewed_at: datetime
    source_label: str


@dataclass(frozen=True, kw_only=True)
class NucleiRuntimeProfile:
    profile_id: str
    module_id: str
    allowed_template_ids: tuple[str, ...]
    allowed_severities: tuple[NucleiSeverity, ...]
    allowed_risk_classes: tuple[TestRiskClass, ...]
    allowed_protocols: tuple[str, ...]
    max_rate_per_second: float
    timeout_seconds: int
    max_results: int
    lab_profile: ScannerPolicyProfile
    actions: tuple[NucleiRuntimeAction, ...]
    require_verified_trust: bool = True


@dataclass(frozen=True, kw_only=True)
class NucleiRuntimeRequest:
    runtime_id: str
    profile: NucleiRuntimeProfile
    runner: RunnerContract
    inventory_target: InventoryTarget
    requested_at: datetime
    operator_user_id: str
    execution_plan: NucleiExecutionPlan
    template_review: NucleiTemplateReview
    template_trust: NucleiTemplateTrustRecord
    lab_validation_records: tuple[LabValidationRecord, ...]
    credential_lease: CredentialLease | None = None


@dataclass(frozen=True, kw_only=True)
class NucleiRuntimePlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    template_id: str
    template_digest: str
    protocols: tuple[str, ...]
    severity: NucleiSeverity
    risk_class: TestRiskClass
    rate_limit_per_second: float
    timeout_seconds: int
    max_results: int
    lab_validation_id: str | None
    credential_lease_id: str | None
    actions: tuple[NucleiRuntimeAction, ...]
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class NucleiRuntimeExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()
    credential_broker: CredentialBroker = CredentialBroker()


FORBIDDEN_NUCLEI_RUNTIME_PAYLOAD_FIELDS = frozenset(
    {
        "args",
        "binary",
        "command",
        "docker_image",
        "headless",
        "interactsh",
        "oast",
        "script",
        "shell",
        "template_body",
        "template_path",
        "url",
    }
)

_DENIED_HIGH_RISK_MARKERS = frozenset(
    {
        "code",
        "credential",
        "credentials",
        "destructive",
        "headless",
        "interactsh",
        "intrusive",
        "oast",
        "self_contained",
        "unclear_behavior",
    }
)


def assert_no_arbitrary_nuclei_controls(payload: Mapping[str, object]) -> None:
    forbidden = FORBIDDEN_NUCLEI_RUNTIME_PAYLOAD_FIELDS.intersection(payload)
    if forbidden:
        raise ValueError("arbitrary_nuclei_control_forbidden")


def build_nuclei_runtime_plan(request: NucleiRuntimeRequest) -> NucleiRuntimePlan:
    _validate_request(request)
    lab_gate = validate_enterprise_job_lab_gate(
        target=request.inventory_target,
        profile=request.profile.lab_profile,
        validation_records=request.lab_validation_records,
        requested_at=request.requested_at,
    )
    if not lab_gate.allowed:
        raise ValueError(lab_gate.reason)
    plan = request.execution_plan
    return NucleiRuntimePlan(
        runtime_id=request.runtime_id.strip(),
        job=_queued_job(plan.job),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        template_id=plan.template_id,
        template_digest=request.template_trust.template_digest,
        protocols=plan.protocols,
        severity=plan.severity,
        risk_class=plan.risk_class,
        rate_limit_per_second=plan.rate_limit_per_second,
        timeout_seconds=plan.timeout_seconds,
        max_results=plan.max_results,
        lab_validation_id=lab_gate.validation_id,
        credential_lease_id=request.credential_lease.id if request.credential_lease else None,
        actions=request.profile.actions,
        cancellation_supported=plan.cancellation_supported and NucleiRuntimeAction.STOP_SCAN in request.profile.actions,
    )


def execute_nuclei_runtime_plan(
    *,
    plan: NucleiRuntimePlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    execution_plan: NucleiExecutionPlan,
    results: tuple[NucleiResult, ...] = (),
    cancel_requested: bool = False,
    credential_broker: CredentialBroker = CredentialBroker(),
    credential_leases_by_job_id: Mapping[str, CredentialLease] | None = None,
    kill_switch_scope: KillSwitchScope | None = None,
) -> NucleiRuntimeExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return NucleiRuntimeExecutionResult(
                allowed=False,
                reason=decision.reason,
                state=state,
                evidence_chain=evidence_chain,
                findings=(),
                imported_evidence_ids=(),
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
        return NucleiRuntimeExecutionResult(
            allowed=False,
            reason=dispatch_decision.reason,
            state=state,
            evidence_chain=evidence_chain,
            findings=(),
            imported_evidence_ids=(),
            credential_broker=credential_broker,
        )
    if cancel_requested:
        cancellation_scope = KillSwitchScope(
            engagement_id=plan.job.engagement_id,
            target=plan.job.target,
            modes=(plan.job.mode,),
        )
        cancellation = enforce_kill_switch(
            scope=cancellation_scope,
            state=dispatched,
            credential_broker=credential_broker,
            leases_by_job_id=dict(credential_leases_by_job_id or {}),
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
            reason="nuclei_runtime_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return NucleiRuntimeExecutionResult(
            allowed=True,
            reason="cancelled",
            state=cancellation.state,
            evidence_chain=evidence_chain,
            findings=(),
            imported_evidence_ids=(),
            cancellation_evidence=cancellation.evidence,
            credential_broker=cancellation.credential_broker,
        )
    running = _callback(dispatched, plan, RunnerCallbackKind.STARTED, "started", occurred_at)
    chain, findings, evidence_ids = _import_results(plan, evidence_chain, occurred_at, execution_plan, results)
    with_result = _callback(
        running,
        plan,
        RunnerCallbackKind.RESULT,
        "result",
        occurred_at,
        evidence_ids=evidence_ids,
    )
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return NucleiRuntimeExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        imported_evidence_ids=evidence_ids,
        credential_broker=credential_broker,
    )


def _validate_request(request: NucleiRuntimeRequest) -> None:
    _require_non_empty("runtime_id", request.runtime_id)
    _require_non_empty("operator_user_id", request.operator_user_id)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    _validate_trust(request.template_trust, request.template_review, request.profile)
    plan = request.execution_plan
    review = request.template_review
    if review.status is not NucleiReviewStatus.APPROVED:
        raise ValueError("template_review_must_be_approved")
    if not review.reviewer_user_id.strip():
        raise ValueError("template_reviewer_required")
    if review.template.template_id != plan.template_id:
        raise ValueError("template_review_plan_mismatch")
    if review.template.high_risk_reasons:
        raise ValueError("high_risk_template_denied")
    if _contains_denied_marker(review.template.protocol_types + review.template.tags + review.template.high_risk_reasons):
        raise ValueError("high_risk_template_denied")
    if plan.template_id not in request.profile.allowed_template_ids:
        raise ValueError("template_id_not_approved")
    if plan.severity not in request.profile.allowed_severities:
        raise ValueError("severity_not_allowed")
    if plan.risk_class not in request.profile.allowed_risk_classes:
        raise ValueError("risk_class_not_allowed")
    if not set(plan.protocols).issubset(set(request.profile.allowed_protocols)):
        raise ValueError("protocol_not_allowed")
    if plan.rate_limit_per_second > request.profile.max_rate_per_second:
        raise ValueError("nuclei_rate_cap_exceeded")
    if plan.timeout_seconds > request.profile.timeout_seconds:
        raise ValueError("nuclei_timeout_exceeded")
    if plan.max_results > request.profile.max_results:
        raise ValueError("nuclei_result_cap_exceeded")
    if request.runner.organization_id != plan.job.organization_id:
        raise ValueError("runner_organization_mismatch")
    if plan.job.mode not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")
    if request.runner.target_scope.normalized() != plan.job.target.normalized():
        raise ValueError("runner_target_scope_mismatch")


def _validate_profile(profile: NucleiRuntimeProfile) -> None:
    for field_name, value in (
        ("profile_id", profile.profile_id),
        ("module_id", profile.module_id),
    ):
        _require_non_empty(field_name, value)
    if not profile.allowed_template_ids:
        raise ValueError("runtime_template_allowlist_required")
    if not profile.allowed_severities:
        raise ValueError("runtime_severity_allowlist_required")
    if not profile.allowed_risk_classes:
        raise ValueError("runtime_risk_allowlist_required")
    if not profile.allowed_protocols:
        raise ValueError("runtime_protocol_allowlist_required")
    if profile.max_rate_per_second <= 0:
        raise ValueError("invalid_runtime_rate")
    if profile.timeout_seconds <= 0:
        raise ValueError("invalid_runtime_timeout")
    if profile.max_results <= 0:
        raise ValueError("invalid_runtime_max_results")
    if not profile.actions:
        raise ValueError("runtime_actions_required")


def _validate_trust(
    trust: NucleiTemplateTrustRecord,
    review: NucleiTemplateReview,
    profile: NucleiRuntimeProfile,
) -> None:
    for field_name, value in (
        ("template_id", trust.template_id),
        ("template_digest", trust.template_digest),
        ("reviewer_user_id", trust.reviewer_user_id),
        ("source_label", trust.source_label),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(trust.reviewed_at)
    if trust.template_id != review.template.template_id:
        raise ValueError("template_trust_mismatch")
    if trust.reviewer_user_id != review.reviewer_user_id:
        raise ValueError("template_trust_reviewer_mismatch")
    if profile.require_verified_trust and trust.status not in {
        NucleiTemplateTrustStatus.SIGNED_VERIFIED,
        NucleiTemplateTrustStatus.TRUSTED_INTERNAL,
    }:
        raise ValueError("template_trust_required")


def _validate_execution_inputs(
    plan: NucleiRuntimePlan,
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


def _import_results(
    plan: NucleiRuntimePlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    execution_plan: NucleiExecutionPlan,
    results: tuple[NucleiResult, ...],
) -> tuple[EvidenceChain, tuple[FindingRecord, ...], tuple[str, ...]]:
    if execution_plan.template_id != plan.template_id:
        raise ValueError("execution_plan_template_mismatch")
    if len(results) > plan.max_results:
        raise ValueError("nuclei_result_cap_exceeded")
    chain = evidence_chain
    findings: list[FindingRecord] = []
    evidence_ids: list[str] = []
    for index, result in enumerate(results, start=1):
        evidence_id = f"{plan.runtime_id}:nuclei-result:{index}"
        evidence = append_nuclei_result_evidence(
            chain=chain,
            plan=execution_plan,
            result=result,
            evidence_id=evidence_id,
            observed_at=occurred_at,
        )
        chain = evidence.chain
        evidence_ids.append(evidence_id)
        findings.append(
            normalize_nuclei_result_to_finding(
                finding_id=f"{plan.runtime_id}:finding:{index}",
                plan=execution_plan,
                result=result,
                evidence_record=evidence.record,
            )
        )
    return chain, tuple(findings), tuple(evidence_ids)


def _contains_denied_marker(values: tuple[str, ...]) -> bool:
    for value in values:
        normalized = value.strip().lower()
        if normalized in _DENIED_HIGH_RISK_MARKERS:
            return True
        if normalized.startswith("protocol:") and normalized.removeprefix("protocol:") in _DENIED_HIGH_RISK_MARKERS:
            return True
        if normalized.startswith("tag:") and normalized.removeprefix("tag:") in _DENIED_HIGH_RISK_MARKERS:
            return True
    return False


def _queued_job(job: JobRecord) -> JobRecord:
    return JobRecord(
        job_id=job.job_id,
        organization_id=job.organization_id,
        engagement_id=job.engagement_id,
        test_definition_id=job.test_definition_id,
        target=job.target,
        mode=job.mode,
        status=JobStatus.QUEUED,
        projected_interactions=job.projected_interactions,
        timeout_seconds=job.timeout_seconds,
        cleanup_required=job.cleanup_required,
        max_attempts=job.max_attempts,
        policy_decision_id=job.policy_decision_id,
        policy_expires_at=job.policy_expires_at,
        last_transition_at=job.last_transition_at,
    )


def _callback(
    state: JobQueueState,
    plan: NucleiRuntimePlan,
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


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
