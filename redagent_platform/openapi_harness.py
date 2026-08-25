"""Controlled OpenAPI differential API harness contracts.

This module generates reviewed request specifications and imports supplied
observations. It never sends HTTP requests, mutates API resources, fuzzes
parameters, or performs live authorization checks.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from redagent_platform.active_policy import ActiveJobRequest, ActivePolicyResult
from redagent_platform.api_lab import ApiLabCase, ApiLabCaseType, HttpMethod
from redagent_platform.auth_sessions import AuthenticatedSessionContext
from redagent_platform.credentials import CredentialBroker, CredentialLease
from redagent_platform.domain import EvidenceKind, FindingStatus, JobStatus, PolicyDecisionOutcome, TestMode
from redagent_platform.evidence_chain import EvidenceAccessPolicy, EvidenceChain, RedactionStatus, RetentionClass
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
from redagent_platform.lab_validation import LabValidationRecord, ScannerPolicyProfile, validate_enterprise_job_lab_gate
from redagent_platform.redaction import RedactionArtifactClass, sanitize_text
from redagent_platform.target_inventory import InventoryTarget


@dataclass(frozen=True, kw_only=True)
class OpenApiHarnessProfile:
    profile_id: str
    module_id: str
    allowed_case_types: tuple[ApiLabCaseType, ...]
    max_rate_per_second: float
    max_requests: int
    timeout_seconds: int
    max_resource_probe_requests: int
    lab_profile: ScannerPolicyProfile
    mutation_allowed: bool = False


@dataclass(frozen=True, kw_only=True)
class ReviewedApiCase:
    case: ApiLabCase
    reviewer_user_id: str
    reviewed_at: datetime
    approved: bool
    mutation_requested: bool = False
    resource_probe_requests: int = 1


@dataclass(frozen=True, kw_only=True)
class ApiRequestSpec:
    spec_id: str
    case_id: str
    case_type: ApiLabCaseType
    method: HttpMethod
    path_template: str
    mode: TestMode
    auth_context_ids: tuple[str, ...]
    credential_lease_ids: tuple[str, ...]
    mutation_enabled: bool
    non_destructive: bool
    planned_requests: int


@dataclass(frozen=True, kw_only=True)
class OpenApiHarnessRequest:
    runtime_id: str
    profile: OpenApiHarnessProfile
    active_request: ActiveJobRequest
    active_policy: ActivePolicyResult
    runner: RunnerContract
    inventory_target: InventoryTarget
    reviewed_cases: tuple[ReviewedApiCase, ...]
    auth_contexts: tuple[AuthenticatedSessionContext, ...]
    credential_leases: tuple[CredentialLease, ...]
    lab_validation_records: tuple[LabValidationRecord, ...]
    requested_at: datetime
    operator_user_id: str


@dataclass(frozen=True, kw_only=True)
class OpenApiHarnessPlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    request_specs: tuple[ApiRequestSpec, ...]
    rate_limit_per_second: float
    timeout_seconds: int
    max_requests: int
    lab_validation_id: str | None
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class ApiObservation:
    case_id: str
    observed_at: datetime
    lower_status: int | None = None
    higher_status: int | None = None
    unauthenticated_status: int | None = None
    notes: str = ""
    request_excerpt: str | None = None
    response_excerpt: str | None = None


@dataclass(frozen=True, kw_only=True)
class OpenApiHarnessExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()
    credential_broker: CredentialBroker = CredentialBroker()


def build_openapi_harness_plan(request: OpenApiHarnessRequest) -> OpenApiHarnessPlan:
    _validate_request_basics(request)
    lab_gate = validate_enterprise_job_lab_gate(
        target=request.inventory_target,
        profile=request.profile.lab_profile,
        validation_records=request.lab_validation_records,
        requested_at=request.requested_at,
    )
    if not lab_gate.allowed:
        raise ValueError(lab_gate.reason)
    specs = tuple(_build_request_spec(request, reviewed_case, index) for index, reviewed_case in enumerate(request.reviewed_cases, start=1))
    planned_requests = sum(spec.planned_requests for spec in specs)
    if planned_requests > request.profile.max_requests:
        raise ValueError("api_request_cap_exceeded")
    job = JobRecord(
        job_id=request.active_request.job_id,
        organization_id=request.active_request.organization_id,
        engagement_id=request.active_request.engagement_id,
        test_definition_id=request.profile.profile_id,
        target=request.active_request.target.normalized(),
        mode=request.active_request.mode,
        status=JobStatus.QUEUED,
        projected_interactions=planned_requests,
        timeout_seconds=request.active_request.projected_duration_seconds,
        cleanup_required=True,
        max_attempts=1,
        policy_decision_id=request.active_policy.decision.policy_grant.decision_id
        if request.active_policy.decision.policy_grant
        else None,
        policy_expires_at=request.active_policy.decision.policy_grant.expires_at
        if request.active_policy.decision.policy_grant
        else None,
        last_transition_at=request.requested_at,
    )
    return OpenApiHarnessPlan(
        runtime_id=request.runtime_id.strip(),
        job=job,
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        request_specs=specs,
        rate_limit_per_second=request.active_request.requested_rate_per_second,
        timeout_seconds=request.active_request.projected_duration_seconds,
        max_requests=request.profile.max_requests,
        lab_validation_id=lab_gate.validation_id,
        cancellation_supported=True,
    )


def execute_openapi_harness_plan(
    *,
    plan: OpenApiHarnessPlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    observations: tuple[ApiObservation, ...] = (),
    cancel_requested: bool = False,
    credential_broker: CredentialBroker = CredentialBroker(),
    credential_leases_by_job_id: dict[str, CredentialLease] | None = None,
    kill_switch_scope: KillSwitchScope | None = None,
) -> OpenApiHarnessExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return OpenApiHarnessExecutionResult(
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
        return OpenApiHarnessExecutionResult(
            allowed=False,
            reason=dispatch_decision.reason,
            state=state,
            evidence_chain=evidence_chain,
            findings=(),
            imported_evidence_ids=(),
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
            reason="openapi_harness_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return OpenApiHarnessExecutionResult(
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
    chain, findings, evidence_ids = _import_observations(plan, evidence_chain, observations)
    with_result = _callback(running, plan, RunnerCallbackKind.RESULT, "result", occurred_at, evidence_ids=evidence_ids)
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return OpenApiHarnessExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        imported_evidence_ids=evidence_ids,
        credential_broker=credential_broker,
    )


def _validate_request_basics(request: OpenApiHarnessRequest) -> None:
    _require_non_empty("runtime_id", request.runtime_id)
    _require_non_empty("operator_user_id", request.operator_user_id)
    _validate_profile(request.profile)
    _require_timezone(request.requested_at)
    if not request.active_policy.decision.allowed:
        raise ValueError(f"active_policy_denied:{request.active_policy.decision.reason}")
    if request.active_policy.decision.outcome is not PolicyDecisionOutcome.ALLOW:
        raise ValueError("active_policy_must_allow")
    if request.active_policy.decision.policy_grant is None:
        raise ValueError("active_policy_grant_required")
    if request.active_request.requested_rate_per_second > request.profile.max_rate_per_second:
        raise ValueError("api_rate_cap_exceeded")
    if request.active_request.projected_duration_seconds > request.profile.timeout_seconds:
        raise ValueError("api_timeout_exceeded")
    if request.runner.organization_id != request.active_request.organization_id:
        raise ValueError("runner_organization_mismatch")
    if request.active_request.mode not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")
    if request.runner.target_scope.normalized() != request.active_request.target.normalized():
        raise ValueError("runner_target_scope_mismatch")
    if not request.reviewed_cases:
        raise ValueError("reviewed_api_cases_required")


def _validate_profile(profile: OpenApiHarnessProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_case_types:
        raise ValueError("api_case_type_allowlist_required")
    if profile.max_rate_per_second <= 0:
        raise ValueError("invalid_api_rate")
    if profile.max_requests <= 0:
        raise ValueError("invalid_api_request_cap")
    if profile.timeout_seconds <= 0:
        raise ValueError("invalid_api_timeout")
    if profile.max_resource_probe_requests <= 0:
        raise ValueError("invalid_resource_probe_cap")


def _build_request_spec(request: OpenApiHarnessRequest, reviewed: ReviewedApiCase, index: int) -> ApiRequestSpec:
    case = reviewed.case
    _validate_reviewed_case(request, reviewed)
    auth_contexts = _auth_contexts_for_case(request, case)
    leases = _leases_for_contexts(request.credential_leases, auth_contexts)
    planned_requests = reviewed.resource_probe_requests if case.case_type is ApiLabCaseType.RESOURCE_CONSUMPTION_REVIEW else 1
    if planned_requests > request.profile.max_resource_probe_requests:
        raise ValueError("resource_consumption_cap_exceeded")
    return ApiRequestSpec(
        spec_id=f"{request.runtime_id}:case:{index}",
        case_id=case.case_id,
        case_type=case.case_type,
        method=case.method,
        path_template=case.path,
        mode=request.active_request.mode,
        auth_context_ids=tuple(context.session_id for context in auth_contexts),
        credential_lease_ids=tuple(lease.id for lease in leases),
        mutation_enabled=False,
        non_destructive=True,
        planned_requests=planned_requests,
    )


def _validate_reviewed_case(request: OpenApiHarnessRequest, reviewed: ReviewedApiCase) -> None:
    _require_non_empty("reviewer_user_id", reviewed.reviewer_user_id)
    _require_timezone(reviewed.reviewed_at)
    if not reviewed.approved:
        raise ValueError("api_case_review_not_approved")
    case = reviewed.case
    if case.case_type not in request.profile.allowed_case_types:
        raise ValueError("api_case_type_not_allowed")
    if case.mode not in {TestMode.LAB_ONLY_RUN, TestMode.ACTIVE_SCAN}:
        raise ValueError("api_case_mode_not_allowed")
    if reviewed.mutation_requested and not request.profile.mutation_allowed:
        raise ValueError("api_mutation_forbidden")


def _auth_contexts_for_case(request: OpenApiHarnessRequest, case: ApiLabCase) -> tuple[AuthenticatedSessionContext, ...]:
    if case.case_type is ApiLabCaseType.AUTHORIZATION_DIFFERENTIAL:
        if len(request.auth_contexts) < 2:
            raise ValueError("auth_context_pair_required")
        contexts = request.auth_contexts[:2]
    elif case.case_type is ApiLabCaseType.UNAUTHENTICATED_ACCESS:
        contexts = ()
    else:
        if not request.auth_contexts:
            raise ValueError("auth_context_required")
        contexts = request.auth_contexts[:1]
    for context in contexts:
        if context.target.normalized() != request.active_request.target.normalized():
            raise ValueError("auth_context_target_mismatch")
        if context.mode is not request.active_request.mode:
            raise ValueError("auth_context_mode_mismatch")
        if request.requested_at >= context.expires_at:
            raise ValueError("auth_context_expired")
    return contexts


def _leases_for_contexts(
    leases: tuple[CredentialLease, ...],
    contexts: tuple[AuthenticatedSessionContext, ...],
) -> tuple[CredentialLease, ...]:
    lease_by_id = {lease.id: lease for lease in leases}
    selected: list[CredentialLease] = []
    for context in contexts:
        lease = lease_by_id.get(context.credential_lease_id)
        if lease is None:
            raise ValueError("credential_lease_required")
        selected.append(lease)
    return tuple(selected)


def _import_observations(
    plan: OpenApiHarnessPlan,
    evidence_chain: EvidenceChain,
    observations: tuple[ApiObservation, ...],
) -> tuple[EvidenceChain, tuple[FindingRecord, ...], tuple[str, ...]]:
    spec_by_case = {spec.case_id: spec for spec in plan.request_specs}
    chain = evidence_chain
    findings: list[FindingRecord] = []
    evidence_ids: list[str] = []
    for index, observation in enumerate(observations, start=1):
        spec = spec_by_case.get(observation.case_id)
        if spec is None:
            raise ValueError("observation_case_not_planned")
        evidence_id = f"{plan.runtime_id}:api-observation:{index}"
        content, redacted = _sanitize_observation(observation, spec)
        chain = chain.append_evidence_record(
            evidence_id=evidence_id,
            organization_id=plan.job.organization_id,
            source_job_id=plan.job.job_id,
            kind=EvidenceKind.OPENAPI_METADATA,
            created_at=observation.observed_at,
            redaction_status=RedactionStatus.REDACTED if redacted else RedactionStatus.NOT_APPLICABLE,
            retention_class=RetentionClass.STANDARD,
            access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=json.dumps(content, sort_keys=True).encode("utf-8"),
            contains_sensitive_capture=redacted,
            metadata={"adapter": "openapi_harness", "case_type": spec.case_type.value},
        )
        record = chain.evidence_records[-1]
        evidence_ids.append(evidence_id)
        findings.append(_finding_from_observation(plan, spec, observation, record.id, record.integrity_hash, record.redaction_status))
    return chain, tuple(findings), tuple(evidence_ids)


def _sanitize_observation(observation: ApiObservation, spec: ApiRequestSpec) -> tuple[dict[str, object], bool]:
    request_excerpt, request_redacted = _sanitize_optional(observation.request_excerpt)
    response_excerpt, response_redacted = _sanitize_optional(observation.response_excerpt)
    notes, notes_redacted = _sanitize_optional(observation.notes)
    return (
        {
            "case_id": observation.case_id,
            "case_type": spec.case_type.value,
            "method": spec.method.value,
            "path_template": spec.path_template,
            "observed_at": observation.observed_at.isoformat(),
            "lower_status": observation.lower_status,
            "higher_status": observation.higher_status,
            "unauthenticated_status": observation.unauthenticated_status,
            "notes": notes,
            "request_excerpt": request_excerpt,
            "response_excerpt": response_excerpt,
        },
        request_redacted or response_redacted or notes_redacted,
    )


def _finding_from_observation(
    plan: OpenApiHarnessPlan,
    spec: ApiRequestSpec,
    observation: ApiObservation,
    evidence_id: str,
    integrity_hash: str,
    redaction_status: RedactionStatus,
) -> FindingRecord:
    evidence_link = EvidenceLink(
        evidence_id=evidence_id,
        integrity_hash=integrity_hash,
        redaction_status=redaction_status,
        contains_sensitive_payload=redaction_status is RedactionStatus.REDACTED,
    )
    finding = FindingRecord(
        id=f"{plan.runtime_id}:finding:{spec.case_id}",
        title=f"OpenAPI {spec.case_type.value} observation",
        status=FindingStatus.NEEDS_REVIEW,
        affected_asset_id=plan.job.target.normalized().value,
        affected_asset_value=f"{spec.method.value} {spec.path_template}",
        confidence=Confidence.MEDIUM,
        risk=RiskFactors(
            severity=_severity_for(spec, observation),
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.UNKNOWN,
            vulnerability_intelligence=VulnerabilityIntelligence(cve_ids=(), cwe_ids=()),
        ),
        reproduction_summary=f"Reviewed supplied OpenAPI observation for {spec.case_type.value} on {spec.method.value} {spec.path_template}.",
        evidence_links=(evidence_link,),
        remediation="Review authorization and schema controls for the affected API operation.",
        owner_user_id=None,
        source="openapi_harness",
        source_rule_id=spec.case_type.value,
    )
    validate_finding(finding)
    return finding


def _severity_for(spec: ApiRequestSpec, observation: ApiObservation) -> Severity:
    if spec.case_type is ApiLabCaseType.AUTHORIZATION_DIFFERENTIAL and observation.lower_status and observation.higher_status:
        if 200 <= observation.lower_status < 300 and 200 <= observation.higher_status < 300:
            return Severity.HIGH
    if spec.case_type is ApiLabCaseType.UNAUTHENTICATED_ACCESS and observation.unauthenticated_status:
        if 200 <= observation.unauthenticated_status < 300:
            return Severity.HIGH
    if spec.case_type is ApiLabCaseType.RESOURCE_CONSUMPTION_REVIEW:
        return Severity.LOW
    return Severity.MEDIUM


def _validate_execution_inputs(
    plan: OpenApiHarnessPlan,
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


def _callback(
    state: JobQueueState,
    plan: OpenApiHarnessPlan,
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


def _sanitize_optional(value: str | None) -> tuple[str | None, bool]:
    if value is None:
        return None, False
    result = sanitize_text(value, RedactionArtifactClass.HTTP_METADATA)
    return result.sanitized_text, result.redacted


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
