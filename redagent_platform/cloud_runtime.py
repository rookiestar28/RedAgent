"""Controlled cloud posture runtime connector contracts.

This module does not call cloud APIs, start scanners, load kubeconfig files, run
subprocesses, or mutate resources. It binds read-only posture policy decisions
to local runner/evidence/finding contracts and imports supplied sanitized
posture results.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import cloud_posture
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


class CloudRuntimeAction(str, Enum):
    READ_POSTURE = "read_posture"
    IMPORT_RESULTS = "import_results"
    MUTATE_RESOURCE = "mutate_resource"
    DETONATE_CLOUD_TECHNIQUE = "detonate_cloud_technique"


@dataclass(frozen=True, kw_only=True)
class CloudRuntimeProfile:
    profile_id: str
    module_id: str
    allowed_providers: tuple[cloud_posture.CloudProvider, ...]
    allowed_modes: tuple[cloud_posture.CloudPostureMode, ...]
    max_monthly_cost_usd: float
    max_api_calls: int
    max_results: int
    timeout_seconds: int
    actions: tuple[CloudRuntimeAction, ...]


@dataclass(frozen=True, kw_only=True)
class CloudRuntimeRequest:
    runtime_id: str
    profile: CloudRuntimeProfile
    scope: cloud_posture.CloudScope
    posture_request: cloud_posture.CloudPostureRequest
    runner: RunnerContract
    credential_lease: CredentialLease
    requested_at: datetime
    operator_user_id: str


@dataclass(frozen=True, kw_only=True)
class CloudRuntimePlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    provider: cloud_posture.CloudProvider
    target_id: str
    target: ScopeTarget
    regions: tuple[str, ...]
    credential_lease_id: str
    requested_permissions: tuple[str, ...]
    max_api_calls: int
    max_results: int
    timeout_seconds: int
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class CloudRuntimeResultItem:
    item_id: str
    control_domain: cloud_posture.CloudControlDomain
    resource_id: str
    region: str | None
    cluster_id: str | None
    severity: Severity
    remediation_guidance: str
    evidence_redaction_class: RedactionStatus
    summary: str
    contains_sensitive_material: bool = False


@dataclass(frozen=True, kw_only=True)
class CloudRuntimeReportRow:
    finding_id: str
    evidence_id: str
    control_domain: cloud_posture.CloudControlDomain
    resource_id: str
    region: str | None
    cluster_id: str | None
    severity: Severity
    evidence_redaction_class: RedactionStatus
    remediation_guidance: str


@dataclass(frozen=True, kw_only=True)
class CloudRuntimeExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    report_rows: tuple[CloudRuntimeReportRow, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()
    credential_broker: CredentialBroker = CredentialBroker()


_MUTATING_ACTIONS = frozenset(
    {CloudRuntimeAction.MUTATE_RESOURCE, CloudRuntimeAction.DETONATE_CLOUD_TECHNIQUE}
)
_READ_ONLY_MODES = frozenset({cloud_posture.CloudPostureMode.READ_ONLY_POSTURE})
_WRITE_PERMISSION_MARKERS = frozenset(
    {
        "*",
        "admin",
        "administrator",
        "attach",
        "create",
        "delete",
        "detach",
        "edit",
        "fullaccess",
        "modify",
        "owner",
        "put",
        "update",
        "write",
    }
)


def build_cloud_runtime_plan(request: CloudRuntimeRequest) -> CloudRuntimePlan:
    _validate_request(request)
    target = _target_for(request.scope, request.posture_request.target_id)
    if request.runner.target_scope.normalized() != target.normalized():
        raise ValueError("runner_target_scope_mismatch")
    if request.runner.credential_lease_id != request.credential_lease.id:
        raise ValueError("runner_credential_lease_mismatch")
    if request.credential_lease.credential_reference_id != request.scope.credential_reference_id:
        raise ValueError("cloud_runtime_credential_reference_mismatch")
    if not _lease_permissions_are_read_only(request.credential_lease.scoped_permissions):
        raise ValueError("cloud_runtime_read_only_credential_required")
    build_runtime_binding(
        request.credential_lease,
        job_id=request.posture_request.job_id,
        runner_id=request.runner.runner_id,
        target=target,
        mode=TestMode.CLOUD_TECHNIQUE,
        requested_permissions=request.posture_request.requested_permissions,
        now=request.requested_at,
    )
    posture_request = _posture_request_with_lease_boundary(request)
    decision = cloud_posture.evaluate_cloud_posture(request.scope, posture_request)
    if not decision.allowed:
        raise ValueError(f"cloud_posture_denied:{decision.reason}")
    collection = cloud_posture.build_cloud_collection_plan(request.scope, posture_request)
    if len(collection.steps) > request.profile.max_api_calls:
        raise ValueError("cloud_runtime_api_call_cap_exceeded")
    return CloudRuntimePlan(
        runtime_id=request.runtime_id.strip(),
        job=JobRecord(
            job_id=posture_request.job_id,
            organization_id=posture_request.organization_id,
            engagement_id=posture_request.engagement_id,
            test_definition_id=request.profile.profile_id,
            target=target.normalized(),
            mode=TestMode.CLOUD_TECHNIQUE,
            status=JobStatus.QUEUED,
            projected_interactions=max(1, len(collection.steps)),
            timeout_seconds=request.profile.timeout_seconds,
            cleanup_required=True,
            max_attempts=1,
            policy_decision_id=f"{request.runtime_id}:cloud-policy",
            policy_expires_at=request.credential_lease.expires_at,
            last_transition_at=request.requested_at,
        ),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        provider=request.scope.provider,
        target_id=posture_request.target_id.strip(),
        target=target.normalized(),
        regions=tuple(region.strip() for region in request.scope.regions if region.strip()),
        credential_lease_id=request.credential_lease.id,
        requested_permissions=tuple(posture_request.requested_permissions),
        max_api_calls=request.profile.max_api_calls,
        max_results=request.profile.max_results,
        timeout_seconds=request.profile.timeout_seconds,
        cancellation_supported=True,
    )


def execute_cloud_runtime_plan(
    *,
    plan: CloudRuntimePlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    result_items: tuple[CloudRuntimeResultItem, ...] = (),
    cancel_requested: bool = False,
    credential_broker: CredentialBroker = CredentialBroker(),
    credential_lease: CredentialLease | None = None,
    kill_switch_scope: KillSwitchScope | None = None,
) -> CloudRuntimeExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if len(result_items) > plan.max_results:
        raise ValueError("cloud_runtime_result_cap_exceeded")
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return CloudRuntimeExecutionResult(
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
        return CloudRuntimeExecutionResult(
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
            reason="cloud_runtime_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return CloudRuntimeExecutionResult(
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
    chain, evidence_ids, findings, report_rows = _append_result_evidence(
        plan,
        evidence_chain,
        occurred_at,
        result_items,
    )
    with_result = _callback(running, plan, RunnerCallbackKind.RESULT, "result", occurred_at, evidence_ids=evidence_ids)
    cleanup_started = _callback(with_result, plan, RunnerCallbackKind.CLEANUP_STARTED, "cleanup-started", occurred_at)
    final_state = _callback(cleanup_started, plan, RunnerCallbackKind.CLEANUP_COMPLETED, "cleanup-completed", occurred_at)
    return CloudRuntimeExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        report_rows=report_rows,
        imported_evidence_ids=evidence_ids,
        credential_broker=credential_broker,
    )


def _validate_request(request: CloudRuntimeRequest) -> None:
    for field_name, value in (("runtime_id", request.runtime_id), ("operator_user_id", request.operator_user_id)):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    if request.posture_request.requested_at != request.requested_at:
        raise ValueError("cloud_runtime_time_mismatch")
    if request.scope.provider not in request.profile.allowed_providers:
        raise ValueError("cloud_runtime_provider_not_allowed")
    if request.posture_request.mode not in request.profile.allowed_modes:
        raise ValueError("cloud_runtime_mode_not_allowed")
    if request.scope.monthly_cost_estimate_usd > request.profile.max_monthly_cost_usd:
        raise ValueError("cloud_runtime_cost_cap_exceeded")
    if request.runner.organization_id != request.scope.organization_id:
        raise ValueError("runner_organization_mismatch")
    if TestMode.CLOUD_TECHNIQUE not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")


def _validate_profile(profile: CloudRuntimeProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_providers:
        raise ValueError("cloud_runtime_providers_required")
    if not profile.allowed_modes:
        raise ValueError("cloud_runtime_modes_required")
    if any(mode not in _READ_ONLY_MODES for mode in profile.allowed_modes):
        raise ValueError("cloud_runtime_mutating_mode_not_allowed")
    if _MUTATING_ACTIONS.intersection(profile.actions):
        raise ValueError("cloud_runtime_mutating_action_not_allowed")
    if CloudRuntimeAction.IMPORT_RESULTS not in profile.actions:
        raise ValueError("cloud_runtime_import_action_required")
    if profile.max_monthly_cost_usd < 0:
        raise ValueError("cloud_runtime_cost_cap_invalid")
    if profile.max_api_calls <= 0:
        raise ValueError("cloud_runtime_api_call_cap_invalid")
    if profile.max_results <= 0:
        raise ValueError("cloud_runtime_result_cap_invalid")
    if profile.timeout_seconds <= 0:
        raise ValueError("cloud_runtime_timeout_invalid")


def _validate_execution_inputs(
    plan: CloudRuntimePlan,
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


def _posture_request_with_lease_boundary(request: CloudRuntimeRequest) -> cloud_posture.CloudPostureRequest:
    lease = request.credential_lease
    return cloud_posture.CloudPostureRequest(
        job_id=request.posture_request.job_id,
        organization_id=request.posture_request.organization_id,
        engagement_id=request.posture_request.engagement_id,
        provider=request.posture_request.provider,
        mode=request.posture_request.mode,
        requested_at=request.posture_request.requested_at,
        target_id=request.posture_request.target_id,
        requested_permissions=tuple(request.posture_request.requested_permissions),
        credential_boundary=cloud_posture.CloudCredentialBoundary(
            credential_reference_id=lease.credential_reference_id,
            lease_id=lease.id,
            permissions=tuple(lease.scoped_permissions),
            read_only=_lease_permissions_are_read_only(lease.scoped_permissions),
            expires_at=lease.expires_at,
            redaction_label=lease.redaction_label,
        ),
    )


def _append_result_evidence(
    plan: CloudRuntimePlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    result_items: tuple[CloudRuntimeResultItem, ...],
) -> tuple[EvidenceChain, tuple[str, ...], tuple[FindingRecord, ...], tuple[CloudRuntimeReportRow, ...]]:
    chain = evidence_chain
    evidence_ids: list[str] = []
    findings: list[FindingRecord] = []
    rows: list[CloudRuntimeReportRow] = []
    for item in result_items:
        _validate_result_item(item)
        evidence_id = f"{plan.runtime_id}:cloud:{item.item_id}"
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
                "provider": plan.provider.value,
                "control_domain": item.control_domain.value,
                "resource_id": item.resource_id,
                "region": item.region,
                "cluster_id": item.cluster_id,
                "severity": item.severity.value,
            },
        )
        record = chain.evidence_records[-1]
        finding = _finding_for(plan, item, EvidenceLink(evidence_id=evidence_id, integrity_hash=record.integrity_hash, redaction_status=item.evidence_redaction_class, contains_sensitive_payload=item.contains_sensitive_material))
        validate_finding(finding)
        findings.append(finding)
        evidence_ids.append(evidence_id)
        rows.append(
            CloudRuntimeReportRow(
                finding_id=finding.id,
                evidence_id=evidence_id,
                control_domain=item.control_domain,
                resource_id=item.resource_id.strip(),
                region=item.region.strip() if item.region else None,
                cluster_id=item.cluster_id.strip() if item.cluster_id else None,
                severity=item.severity,
                evidence_redaction_class=item.evidence_redaction_class,
                remediation_guidance=item.remediation_guidance.strip(),
            )
        )
    return chain, tuple(evidence_ids), tuple(findings), tuple(rows)


def _finding_for(plan: CloudRuntimePlan, item: CloudRuntimeResultItem, evidence: EvidenceLink) -> FindingRecord:
    return FindingRecord(
        id=f"{plan.runtime_id}:finding:{item.item_id.strip()}",
        title=f"Cloud posture finding: {item.control_domain.value} on {item.resource_id.strip()}",
        status=FindingStatus.RAW_ALERT,
        affected_asset_id=item.resource_id.strip(),
        affected_asset_value=item.resource_id.strip(),
        confidence=Confidence.MEDIUM,
        risk=RiskFactors(
            severity=item.severity,
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.UNKNOWN,
            vulnerability_intelligence=VulnerabilityIntelligence(cve_ids=(), cwe_ids=()),
        ),
        reproduction_summary=(
            f"Read-only cloud posture import for {plan.provider.value} "
            f"{item.control_domain.value}; no live validation was performed."
        ),
        evidence_links=(evidence,),
        remediation=item.remediation_guidance.strip(),
        owner_user_id=None,
        source="cloud_runtime",
        source_rule_id=item.control_domain.value,
    )


def _result_content(item: CloudRuntimeResultItem) -> bytes:
    return json.dumps(
        {
            "control_domain": item.control_domain.value,
            "resource_id": item.resource_id.strip(),
            "region": item.region.strip() if item.region else None,
            "cluster_id": item.cluster_id.strip() if item.cluster_id else None,
            "severity": item.severity.value,
            "summary": item.summary.strip(),
            "remediation": item.remediation_guidance.strip(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _validate_result_item(item: CloudRuntimeResultItem) -> None:
    for field_name, value in (
        ("item_id", item.item_id),
        ("resource_id", item.resource_id),
        ("remediation_guidance", item.remediation_guidance),
        ("summary", item.summary),
    ):
        _require_non_empty(field_name, value)
    if item.contains_sensitive_material and item.evidence_redaction_class not in {
        RedactionStatus.REDACTED,
        RedactionStatus.BLOCKED,
    }:
        raise ValueError("cloud_runtime_sensitive_result_requires_redaction")


def _target_for(scope: cloud_posture.CloudScope, target_id: str) -> ScopeTarget:
    _require_non_empty("target_id", target_id)
    normalized = target_id.strip()
    if normalized not in _allowed_target_ids(scope):
        raise ValueError("cloud_runtime_target_not_allowlisted")
    if scope.provider is cloud_posture.CloudProvider.AWS:
        return ScopeTarget(target_type=TargetType.CLOUD_ACCOUNT, value=normalized)
    if scope.provider is cloud_posture.CloudProvider.AZURE:
        return ScopeTarget(target_type=TargetType.CLOUD_SUBSCRIPTION, value=normalized)
    if scope.provider is cloud_posture.CloudProvider.GCP:
        return ScopeTarget(target_type=TargetType.CLOUD_PROJECT, value=normalized)
    return ScopeTarget(target_type=TargetType.KUBERNETES_CLUSTER, value=normalized)


def _allowed_target_ids(scope: cloud_posture.CloudScope) -> frozenset[str]:
    return frozenset(
        item.strip()
        for item in scope.account_ids + scope.project_ids + scope.subscription_ids + scope.cluster_ids
        if item.strip()
    )


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


def _callback(
    state: JobQueueState,
    plan: CloudRuntimePlan,
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
