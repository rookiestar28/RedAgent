"""Controlled enterprise identity and SaaS posture runtime contracts.

This module does not call identity providers, SaaS APIs, browser flows, or
external tools. It binds compat_038 read-only identity posture policy to runner,
credential, evidence, finding, report, and kill-switch contracts.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import identity_assessment
from redagent_platform.credentials import CredentialBroker, CredentialLease, build_runtime_binding
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


class IdentityRuntimeAction(str, Enum):
    IMPORT_BASELINE_RESULTS = "import_baseline_results"
    IMPORT_SSO_RESULTS = "import_sso_results"
    IMPORT_OAUTH_RESULTS = "import_oauth_results"
    IMPORT_ACCESS_RESULTS = "import_access_results"
    LIVE_AUTH_TEST = "live_auth_test"
    LIVE_PRIVILEGE_TEST = "live_privilege_test"


class IdentityRuntimeResultKind(str, Enum):
    SCUBA_BASELINE = "scuba_baseline"
    SSO_CONFIGURATION = "sso_configuration"
    OAUTH_APPLICATION = "oauth_application"
    MFA_POLICY = "mfa_policy"
    PRIVILEGED_ACCESS = "privileged_access"
    CONDITIONAL_ACCESS = "conditional_access"


@dataclass(frozen=True, kw_only=True)
class IdentityRuntimeProfile:
    profile_id: str
    module_id: str
    allowed_tenant_ids: tuple[str, ...]
    allowed_resource_ids: tuple[str, ...]
    allowed_modes: tuple[identity_assessment.IdentityAssessmentMode, ...]
    max_results: int
    timeout_seconds: int
    actions: tuple[IdentityRuntimeAction, ...]


@dataclass(frozen=True, kw_only=True)
class IdentityRuntimeRequest:
    runtime_id: str
    profile: IdentityRuntimeProfile
    scope: identity_assessment.IdentityTenantScope
    assessment_request: identity_assessment.IdentityAssessmentRequest
    runner: RunnerContract
    credential_lease: CredentialLease
    requested_at: datetime
    operator_user_id: str


@dataclass(frozen=True, kw_only=True)
class IdentityRuntimePlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    tenant_id: str
    target: ScopeTarget
    allowed_principal_ids: tuple[str, ...]
    allowed_resource_ids: tuple[str, ...]
    credential_lease_id: str
    requested_permissions: tuple[str, ...]
    max_results: int
    timeout_seconds: int
    actions: tuple[IdentityRuntimeAction, ...]
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class IdentityRuntimeResultItem:
    item_id: str
    kind: IdentityRuntimeResultKind
    control_area: identity_assessment.IdentityControlArea
    tenant_id: str
    affected_principal_ids: tuple[str, ...]
    affected_resource_ids: tuple[str, ...]
    severity: Severity
    remediation_guidance: str
    evidence_redaction_class: RedactionStatus
    summary: str
    contains_sensitive_material: bool = False
    source_policy_id: str | None = None


@dataclass(frozen=True, kw_only=True)
class IdentityRuntimeReportRow:
    finding_id: str
    evidence_id: str
    kind: IdentityRuntimeResultKind
    control_area: identity_assessment.IdentityControlArea
    tenant_id: str
    affected_principal_ids: tuple[str, ...]
    affected_resource_ids: tuple[str, ...]
    severity: Severity
    evidence_redaction_class: RedactionStatus
    remediation_guidance: str


@dataclass(frozen=True, kw_only=True)
class IdentityRuntimeExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    report_rows: tuple[IdentityRuntimeReportRow, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()
    credential_broker: CredentialBroker = CredentialBroker()


_FORBIDDEN_ACTIONS = frozenset(
    {IdentityRuntimeAction.LIVE_AUTH_TEST, IdentityRuntimeAction.LIVE_PRIVILEGE_TEST}
)
_READ_ONLY_MODES = frozenset({identity_assessment.IdentityAssessmentMode.READ_ONLY_CONFIGURATION})
_ACTION_BY_KIND = {
    IdentityRuntimeResultKind.SCUBA_BASELINE: IdentityRuntimeAction.IMPORT_BASELINE_RESULTS,
    IdentityRuntimeResultKind.SSO_CONFIGURATION: IdentityRuntimeAction.IMPORT_SSO_RESULTS,
    IdentityRuntimeResultKind.OAUTH_APPLICATION: IdentityRuntimeAction.IMPORT_OAUTH_RESULTS,
    IdentityRuntimeResultKind.MFA_POLICY: IdentityRuntimeAction.IMPORT_ACCESS_RESULTS,
    IdentityRuntimeResultKind.PRIVILEGED_ACCESS: IdentityRuntimeAction.IMPORT_ACCESS_RESULTS,
    IdentityRuntimeResultKind.CONDITIONAL_ACCESS: IdentityRuntimeAction.IMPORT_ACCESS_RESULTS,
}
_WRITE_PERMISSION_MARKERS = frozenset(
    {
        "*",
        "admin",
        "administrator",
        "delete",
        "manage",
        "owner",
        "privileged",
        "readwrite",
        "update",
        "write",
    }
)


def build_identity_runtime_plan(request: IdentityRuntimeRequest) -> IdentityRuntimePlan:
    _validate_request(request)
    target = ScopeTarget(target_type=TargetType.SAAS_TENANT, value=request.scope.tenant_id)
    if request.runner.target_scope.normalized() != target.normalized():
        raise ValueError("runner_target_scope_mismatch")
    if request.runner.credential_lease_id != request.credential_lease.id:
        raise ValueError("runner_credential_lease_mismatch")
    if not _lease_permissions_are_read_only(request.credential_lease.scoped_permissions):
        raise ValueError("identity_runtime_read_only_credential_required")
    build_runtime_binding(
        request.credential_lease,
        job_id=request.assessment_request.job_id,
        runner_id=request.runner.runner_id,
        target=target,
        mode=TestMode.IDENTITY_POSTURE,
        requested_permissions=request.assessment_request.requested_permissions,
        now=request.requested_at,
    )
    assessment_request = _assessment_request_with_lease_boundary(request)
    decision = identity_assessment.evaluate_identity_assessment(scope=request.scope, request=assessment_request)
    if not decision.allowed:
        raise ValueError(f"identity_assessment_denied:{decision.reason}")
    collection = identity_assessment.build_read_only_collection_plan(scope=request.scope, request=assessment_request)
    return IdentityRuntimePlan(
        runtime_id=request.runtime_id.strip(),
        job=JobRecord(
            job_id=assessment_request.job_id,
            organization_id=assessment_request.organization_id,
            engagement_id=assessment_request.engagement_id,
            test_definition_id=request.profile.profile_id,
            target=target.normalized(),
            mode=TestMode.IDENTITY_POSTURE,
            status=JobStatus.QUEUED,
            projected_interactions=max(1, len(collection.steps)),
            timeout_seconds=request.profile.timeout_seconds,
            cleanup_required=True,
            max_attempts=1,
            policy_decision_id=f"{request.runtime_id}:identity-policy",
            policy_expires_at=request.credential_lease.expires_at,
            last_transition_at=request.requested_at,
        ),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        tenant_id=request.scope.tenant_id,
        target=target.normalized(),
        allowed_principal_ids=tuple(request.scope.allowed_principal_ids),
        allowed_resource_ids=tuple(request.scope.allowed_resource_ids),
        credential_lease_id=request.credential_lease.id,
        requested_permissions=tuple(assessment_request.requested_permissions),
        max_results=request.profile.max_results,
        timeout_seconds=request.profile.timeout_seconds,
        actions=tuple(request.profile.actions),
        cancellation_supported=True,
    )


def execute_identity_runtime_plan(
    *,
    plan: IdentityRuntimePlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    result_items: tuple[IdentityRuntimeResultItem, ...] = (),
    cancel_requested: bool = False,
    credential_broker: CredentialBroker = CredentialBroker(),
    credential_lease: CredentialLease | None = None,
    kill_switch_scope: KillSwitchScope | None = None,
) -> IdentityRuntimeExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if len(result_items) > plan.max_results:
        raise ValueError("identity_runtime_result_cap_exceeded")
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return IdentityRuntimeExecutionResult(
                allowed=False,
                reason=decision.reason,
                state=state,
                evidence_chain=evidence_chain,
                findings=(),
                report_rows=(),
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
        return IdentityRuntimeExecutionResult(
            allowed=False,
            reason=dispatch_decision.reason,
            state=state,
            evidence_chain=evidence_chain,
            findings=(),
            report_rows=(),
            imported_evidence_ids=(),
            credential_broker=credential_broker,
        )
    if cancel_requested:
        cancellation = enforce_kill_switch(
            scope=KillSwitchScope(engagement_id=plan.job.engagement_id, target=plan.job.target, modes=(plan.job.mode,)),
            state=dispatched,
            credential_broker=credential_broker,
            leases_by_job_id={plan.job.job_id: credential_lease} if credential_lease else {},
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
            reason="identity_runtime_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return IdentityRuntimeExecutionResult(
            allowed=True,
            reason="cancelled",
            state=cancellation.state,
            evidence_chain=evidence_chain,
            findings=(),
            report_rows=(),
            imported_evidence_ids=(),
            cancellation_evidence=cancellation.evidence,
            credential_broker=cancellation.credential_broker,
        )
    running = _callback(dispatched, plan, RunnerCallbackKind.STARTED, "started", occurred_at)
    chain, evidence_ids, findings, rows = _append_result_evidence(plan, evidence_chain, occurred_at, result_items)
    with_result = _callback(running, plan, RunnerCallbackKind.RESULT, "result", occurred_at, evidence_ids=evidence_ids)
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return IdentityRuntimeExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        report_rows=rows,
        imported_evidence_ids=evidence_ids,
        credential_broker=credential_broker,
    )


def _validate_request(request: IdentityRuntimeRequest) -> None:
    for field_name, value in (("runtime_id", request.runtime_id), ("operator_user_id", request.operator_user_id)):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    if request.assessment_request.requested_at != request.requested_at:
        raise ValueError("identity_runtime_time_mismatch")
    if request.assessment_request.tenant_id not in _normalized_set(request.profile.allowed_tenant_ids):
        raise ValueError("identity_runtime_tenant_not_allowlisted")
    if request.assessment_request.mode not in request.profile.allowed_modes:
        raise ValueError("identity_runtime_mode_not_allowed")
    if request.runner.organization_id != request.scope.organization_id:
        raise ValueError("runner_organization_mismatch")
    if TestMode.IDENTITY_POSTURE not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")


def _validate_profile(profile: IdentityRuntimeProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_tenant_ids:
        raise ValueError("identity_runtime_tenant_allowlist_required")
    if not profile.allowed_resource_ids:
        raise ValueError("identity_runtime_resource_allowlist_required")
    if not profile.allowed_modes:
        raise ValueError("identity_runtime_modes_required")
    if any(mode not in _READ_ONLY_MODES for mode in profile.allowed_modes):
        raise ValueError("identity_runtime_active_mode_not_allowed")
    if _FORBIDDEN_ACTIONS.intersection(profile.actions):
        raise ValueError("identity_runtime_live_action_not_allowed")
    if not set(_ACTION_BY_KIND.values()).intersection(profile.actions):
        raise ValueError("identity_runtime_import_action_required")
    if profile.max_results <= 0:
        raise ValueError("identity_runtime_result_cap_invalid")
    if profile.timeout_seconds <= 0:
        raise ValueError("identity_runtime_timeout_invalid")


def _validate_execution_inputs(
    plan: IdentityRuntimePlan,
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
    if runner.credential_lease_id != plan.credential_lease_id:
        raise ValueError("runner_credential_lease_mismatch")


def _assessment_request_with_lease_boundary(
    request: IdentityRuntimeRequest,
) -> identity_assessment.IdentityAssessmentRequest:
    lease = request.credential_lease
    return identity_assessment.IdentityAssessmentRequest(
        job_id=request.assessment_request.job_id,
        organization_id=request.assessment_request.organization_id,
        engagement_id=request.assessment_request.engagement_id,
        tenant_id=request.assessment_request.tenant_id,
        mode=request.assessment_request.mode,
        requested_at=request.assessment_request.requested_at,
        requested_permissions=tuple(request.assessment_request.requested_permissions),
        requested_activities=tuple(request.assessment_request.requested_activities),
        operator_user_id=request.assessment_request.operator_user_id,
        credential_boundary=identity_assessment.IdentityCredentialBoundary(
            credential_reference_id=lease.credential_reference_id,
            lease_id=lease.id,
            permissions=tuple(lease.scoped_permissions),
            read_only=_lease_permissions_are_read_only(lease.scoped_permissions),
            expires_at=lease.expires_at,
            redaction_label=lease.redaction_label,
        ),
    )


def _append_result_evidence(
    plan: IdentityRuntimePlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    result_items: tuple[IdentityRuntimeResultItem, ...],
) -> tuple[EvidenceChain, tuple[str, ...], tuple[FindingRecord, ...], tuple[IdentityRuntimeReportRow, ...]]:
    chain = evidence_chain
    evidence_ids: list[str] = []
    findings: list[FindingRecord] = []
    rows: list[IdentityRuntimeReportRow] = []
    for item in result_items:
        _validate_result_item(plan, item)
        evidence_id = f"{plan.runtime_id}:{item.kind.value}:{item.item_id}"
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
                "tenant_id": item.tenant_id,
                "kind": item.kind.value,
                "control_area": item.control_area.value,
                "principal_count": len(item.affected_principal_ids),
                "resource_count": len(item.affected_resource_ids),
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
            IdentityRuntimeReportRow(
                finding_id=finding.id,
                evidence_id=evidence_id,
                kind=item.kind,
                control_area=item.control_area,
                tenant_id=item.tenant_id.strip(),
                affected_principal_ids=tuple(item.affected_principal_ids),
                affected_resource_ids=tuple(item.affected_resource_ids),
                severity=item.severity,
                evidence_redaction_class=item.evidence_redaction_class,
                remediation_guidance=item.remediation_guidance.strip(),
            )
        )
    return chain, tuple(evidence_ids), tuple(findings), tuple(rows)


def _validate_result_item(plan: IdentityRuntimePlan, item: IdentityRuntimeResultItem) -> None:
    for field_name, value in (
        ("item_id", item.item_id),
        ("tenant_id", item.tenant_id),
        ("summary", item.summary),
        ("remediation_guidance", item.remediation_guidance),
    ):
        _require_non_empty(field_name, value)
    if item.tenant_id.strip() != plan.tenant_id:
        raise ValueError("identity_result_tenant_mismatch")
    if _ACTION_BY_KIND[item.kind] not in plan.actions:
        raise ValueError("identity_result_kind_not_allowed")
    if item.contains_sensitive_material and item.evidence_redaction_class not in {
        RedactionStatus.REDACTED,
        RedactionStatus.BLOCKED,
    }:
        raise ValueError("identity_sensitive_result_requires_redaction")
    if not item.affected_principal_ids and not item.affected_resource_ids:
        raise ValueError("identity_result_requires_affected_entity")
    allowed_principals = _normalized_set(plan.allowed_principal_ids)
    allowed_resources = _normalized_set(plan.allowed_resource_ids)
    if any(principal.strip() not in allowed_principals for principal in item.affected_principal_ids):
        raise ValueError("identity_principal_not_allowlisted")
    if any(resource.strip() not in allowed_resources for resource in item.affected_resource_ids):
        raise ValueError("identity_resource_not_allowlisted")


def _finding_for(plan: IdentityRuntimePlan, item: IdentityRuntimeResultItem, evidence: EvidenceLink) -> FindingRecord:
    affected_id = (
        item.affected_resource_ids[0].strip()
        if item.affected_resource_ids
        else item.affected_principal_ids[0].strip()
    )
    return FindingRecord(
        id=f"{plan.runtime_id}:finding:{item.item_id.strip()}",
        title=f"Identity posture finding: {item.control_area.value} in {item.tenant_id.strip()}",
        status=FindingStatus.RAW_ALERT,
        affected_asset_id=affected_id,
        affected_asset_value=affected_id,
        confidence=Confidence.MEDIUM,
        risk=RiskFactors(
            severity=item.severity,
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.UNKNOWN,
            vulnerability_intelligence=VulnerabilityIntelligence(cve_ids=(), cwe_ids=()),
        ),
        reproduction_summary=(
            f"Sanitized identity/SaaS posture import for tenant {item.tenant_id.strip()}; "
            "no live identity-provider or SaaS execution was performed."
        ),
        evidence_links=(evidence,),
        remediation=item.remediation_guidance.strip(),
        owner_user_id=None,
        source="identity_runtime",
        source_rule_id=f"{item.kind.value}:{item.control_area.value}",
    )


def _result_content(item: IdentityRuntimeResultItem) -> bytes:
    return json.dumps(
        {
            "kind": item.kind.value,
            "control_area": item.control_area.value,
            "tenant_id": item.tenant_id.strip(),
            "principal_count": len(item.affected_principal_ids),
            "resource_count": len(item.affected_resource_ids),
            "severity": item.severity.value,
            "summary": item.summary.strip(),
            "remediation": item.remediation_guidance.strip(),
            "source_policy_id": item.source_policy_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _lease_permissions_are_read_only(permissions: tuple[str, ...]) -> bool:
    if not permissions:
        return False
    for permission in permissions:
        normalized = permission.strip().lower().replace("_", "").replace("-", "")
        if not normalized:
            return False
        if normalized == "*":
            return False
        if any(marker in normalized for marker in _WRITE_PERMISSION_MARKERS if marker != "*"):
            return False
    return True


def _normalized_set(values: tuple[str, ...]) -> frozenset[str]:
    return frozenset(value.strip() for value in values if value.strip())


def _callback(
    state: JobQueueState,
    plan: IdentityRuntimePlan,
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
