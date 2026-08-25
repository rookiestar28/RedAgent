"""Controlled Kubernetes, container, and IaC runtime import contracts.

This module does not load kubeconfig files, call Kubernetes APIs, pull
container images, run kube-bench, run IaC scanners, start subprocesses, or
mutate cluster resources. It builds on the compat_068 cloud runtime gate and imports
supplied sanitized results into evidence, findings, and report rows.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import cloud_posture, cloud_runtime, supply_chain
from redagent_platform.credentials import CredentialBroker, CredentialLease
from redagent_platform.domain import EvidenceKind, FindingStatus, JobStatus
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
from redagent_platform.job_queue import JobQueueState, RunnerCallback, RunnerCallbackKind, RunnerContract
from redagent_platform.kill_switch import (
    CancellationEvidence,
    KillSwitchScope,
    RunnerCancellationResponse,
    RunnerCancellationStatus,
    enforce_kill_switch,
    kill_switch_blocks_dispatch,
)


class KubernetesRuntimeAction(str, Enum):
    IMPORT_BENCHMARK_RESULTS = "import_benchmark_results"
    IMPORT_CONTAINER_METADATA = "import_container_metadata"
    IMPORT_IAC_RESULTS = "import_iac_results"
    RUN_KUBE_BENCH = "run_kube_bench"
    PULL_CONTAINER_IMAGE = "pull_container_image"
    APPLY_IAC = "apply_iac"


class KubernetesRuntimeResultKind(str, Enum):
    BENCHMARK = "benchmark"
    CONTAINER_IMAGE = "container_image"
    IAC_FILE = "iac_file"


class KubernetesBenchmarkStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    WARN = "warn"
    INFO = "info"


@dataclass(frozen=True, kw_only=True)
class KubernetesRuntimeProfile:
    profile_id: str
    module_id: str
    allowed_cluster_ids: tuple[str, ...]
    allowed_namespaces: tuple[str, ...]
    allow_all_namespaces: bool
    max_results: int
    timeout_seconds: int
    actions: tuple[KubernetesRuntimeAction, ...]


@dataclass(frozen=True, kw_only=True)
class KubernetesRuntimeRequest:
    runtime_id: str
    profile: KubernetesRuntimeProfile
    cloud_request: cloud_runtime.CloudRuntimeRequest
    namespaces: tuple[str, ...]
    requested_at: datetime
    operator_user_id: str
    iac_scope: supply_chain.SupplyChainScope | None = None
    iac_request: supply_chain.SupplyChainAssessmentRequest | None = None


@dataclass(frozen=True, kw_only=True)
class KubernetesRuntimePlan:
    runtime_id: str
    cloud_plan: cloud_runtime.CloudRuntimePlan
    runner_id: str
    profile_id: str
    cluster_id: str
    namespaces: tuple[str, ...]
    max_results: int
    timeout_seconds: int
    actions: tuple[KubernetesRuntimeAction, ...]
    iac_repository_id: str | None
    iac_local_only: bool
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class KubernetesRuntimeResultItem:
    item_id: str
    kind: KubernetesRuntimeResultKind
    resource_id: str
    namespace: str | None
    summary: str
    remediation_guidance: str
    evidence_redaction_class: RedactionStatus
    contains_sensitive_material: bool = False
    benchmark_status: KubernetesBenchmarkStatus | None = None
    kubernetes_area: cloud_posture.KubernetesFindingArea | None = None
    severity: Severity | None = None
    iac_file_path: str | None = None
    repository_id: str | None = None
    image_ref: str | None = None


@dataclass(frozen=True, kw_only=True)
class KubernetesRuntimeReportRow:
    finding_id: str
    evidence_id: str
    kind: KubernetesRuntimeResultKind
    resource_id: str
    namespace: str | None
    control_domain: cloud_posture.CloudControlDomain
    severity: Severity
    evidence_redaction_class: RedactionStatus
    remediation_guidance: str
    benchmark_status: KubernetesBenchmarkStatus | None = None
    iac_file_path: str | None = None
    image_ref: str | None = None


@dataclass(frozen=True, kw_only=True)
class KubernetesRuntimeExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    report_rows: tuple[KubernetesRuntimeReportRow, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()
    credential_broker: CredentialBroker = CredentialBroker()


_FORBIDDEN_ACTIONS = frozenset(
    {
        KubernetesRuntimeAction.RUN_KUBE_BENCH,
        KubernetesRuntimeAction.PULL_CONTAINER_IMAGE,
        KubernetesRuntimeAction.APPLY_IAC,
    }
)
_ACTION_BY_KIND = {
    KubernetesRuntimeResultKind.BENCHMARK: KubernetesRuntimeAction.IMPORT_BENCHMARK_RESULTS,
    KubernetesRuntimeResultKind.CONTAINER_IMAGE: KubernetesRuntimeAction.IMPORT_CONTAINER_METADATA,
    KubernetesRuntimeResultKind.IAC_FILE: KubernetesRuntimeAction.IMPORT_IAC_RESULTS,
}


def build_kubernetes_runtime_plan(request: KubernetesRuntimeRequest) -> KubernetesRuntimePlan:
    _validate_request(request)
    cloud_plan = cloud_runtime.build_cloud_runtime_plan(request.cloud_request)
    cluster_id = cloud_plan.target_id
    if cluster_id not in _normalized_set(request.profile.allowed_cluster_ids):
        raise ValueError("kubernetes_cluster_not_allowlisted")
    namespaces = _validate_namespaces(request.profile, request.namespaces)
    iac_repository_id = None
    iac_local_only = True
    if request.iac_scope is not None or request.iac_request is not None:
        if request.iac_scope is None or request.iac_request is None:
            raise ValueError("iac_scope_and_request_required")
        decision = supply_chain.evaluate_supply_chain_assessment(scope=request.iac_scope, request=request.iac_request)
        if not decision.allowed:
            raise ValueError(f"iac_assessment_denied:{decision.reason}")
        iac_plan = supply_chain.build_supply_chain_check_plan(scope=request.iac_scope, request=request.iac_request)
        iac_repository_id = iac_plan.repository_id
        iac_local_only = iac_plan.local_only
    return KubernetesRuntimePlan(
        runtime_id=request.runtime_id.strip(),
        cloud_plan=cloud_plan,
        runner_id=cloud_plan.runner_id,
        profile_id=request.profile.profile_id,
        cluster_id=cluster_id,
        namespaces=namespaces,
        max_results=request.profile.max_results,
        timeout_seconds=request.profile.timeout_seconds,
        actions=tuple(request.profile.actions),
        iac_repository_id=iac_repository_id,
        iac_local_only=iac_local_only,
        cancellation_supported=True,
    )


def execute_kubernetes_runtime_plan(
    *,
    plan: KubernetesRuntimePlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    result_items: tuple[KubernetesRuntimeResultItem, ...] = (),
    cancel_requested: bool = False,
    credential_broker: CredentialBroker = CredentialBroker(),
    credential_lease: CredentialLease | None = None,
    kill_switch_scope: KillSwitchScope | None = None,
) -> KubernetesRuntimeExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if len(result_items) > plan.max_results:
        raise ValueError("kubernetes_runtime_result_cap_exceeded")
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.cloud_plan.job)
        if not decision.allowed:
            return KubernetesRuntimeExecutionResult(
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
        plan.cloud_plan.job.job_id,
        runner,
        actor_user_id=operator_user_id,
        event_id=f"{plan.runtime_id}:dispatch",
        occurred_at=occurred_at,
    )
    if not dispatch_decision.allowed:
        return KubernetesRuntimeExecutionResult(
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
            scope=KillSwitchScope(
                engagement_id=plan.cloud_plan.job.engagement_id,
                target=plan.cloud_plan.job.target,
                modes=(plan.cloud_plan.job.mode,),
            ),
            state=dispatched,
            credential_broker=credential_broker,
            leases_by_job_id={plan.cloud_plan.job.job_id: credential_lease} if credential_lease else {},
            runner_responses={
                plan.cloud_plan.job.job_id: RunnerCancellationResponse(
                    job_id=plan.cloud_plan.job.job_id,
                    runner_id=plan.runner_id,
                    status=RunnerCancellationStatus.TERMINATED,
                    cleanup_attempted=True,
                    cleanup_succeeded=True,
                    responded_at=occurred_at,
                )
            },
            reason="kubernetes_runtime_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return KubernetesRuntimeExecutionResult(
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
    return KubernetesRuntimeExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        report_rows=rows,
        imported_evidence_ids=evidence_ids,
        credential_broker=credential_broker,
    )


def _validate_request(request: KubernetesRuntimeRequest) -> None:
    for field_name, value in (("runtime_id", request.runtime_id), ("operator_user_id", request.operator_user_id)):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    if request.cloud_request.scope.provider is not cloud_posture.CloudProvider.KUBERNETES:
        raise ValueError("kubernetes_provider_required")
    if request.cloud_request.requested_at != request.requested_at:
        raise ValueError("kubernetes_runtime_time_mismatch")
    if request.cloud_request.operator_user_id != request.operator_user_id:
        raise ValueError("kubernetes_runtime_operator_mismatch")
    _validate_profile(request.profile)


def _validate_profile(profile: KubernetesRuntimeProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_cluster_ids:
        raise ValueError("kubernetes_cluster_allowlist_required")
    if not profile.allowed_namespaces and not profile.allow_all_namespaces:
        raise ValueError("kubernetes_namespace_allowlist_required")
    if _FORBIDDEN_ACTIONS.intersection(profile.actions):
        raise ValueError("kubernetes_mutating_or_live_action_not_allowed")
    if not set(_ACTION_BY_KIND.values()).intersection(profile.actions):
        raise ValueError("kubernetes_import_action_required")
    if profile.max_results <= 0:
        raise ValueError("kubernetes_runtime_result_cap_invalid")
    if profile.timeout_seconds <= 0:
        raise ValueError("kubernetes_runtime_timeout_invalid")


def _validate_execution_inputs(
    plan: KubernetesRuntimePlan,
    runner: RunnerContract,
    occurred_at: datetime,
    operator_user_id: str,
) -> None:
    _require_non_empty("operator_user_id", operator_user_id)
    _require_timezone(occurred_at)
    if runner.runner_id != plan.runner_id:
        raise ValueError("runner_mismatch")
    if plan.cloud_plan.job.mode not in runner.capabilities:
        raise ValueError("runner_capability_missing")
    if runner.target_scope.normalized() != plan.cloud_plan.job.target.normalized():
        raise ValueError("runner_target_scope_mismatch")
    if runner.credential_lease_id != plan.cloud_plan.credential_lease_id:
        raise ValueError("runner_credential_lease_mismatch")


def _append_result_evidence(
    plan: KubernetesRuntimePlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    result_items: tuple[KubernetesRuntimeResultItem, ...],
) -> tuple[EvidenceChain, tuple[str, ...], tuple[FindingRecord, ...], tuple[KubernetesRuntimeReportRow, ...]]:
    chain = evidence_chain
    evidence_ids: list[str] = []
    findings: list[FindingRecord] = []
    rows: list[KubernetesRuntimeReportRow] = []
    for item in result_items:
        _validate_result_item(plan, item)
        control_domain = _control_domain_for(item)
        severity = _severity_for(item)
        evidence_id = f"{plan.runtime_id}:{item.kind.value}:{item.item_id}"
        content = None if item.evidence_redaction_class is RedactionStatus.BLOCKED else _result_content(item, control_domain, severity)
        chain = chain.append_evidence_record(
            evidence_id=evidence_id,
            organization_id=plan.cloud_plan.job.organization_id,
            source_job_id=plan.cloud_plan.job.job_id,
            kind=EvidenceKind.SCANNER_OUTPUT,
            created_at=occurred_at,
            redaction_status=item.evidence_redaction_class,
            retention_class=RetentionClass.STANDARD,
            access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=content,
            contains_sensitive_capture=item.contains_sensitive_material,
            metadata={
                "cluster_id": plan.cluster_id,
                "namespace": item.namespace,
                "kind": item.kind.value,
                "control_domain": control_domain.value,
                "benchmark_status": item.benchmark_status.value if item.benchmark_status else None,
                "iac_file_path": item.iac_file_path,
                "image_ref": item.image_ref,
                "severity": severity.value,
            },
        )
        record = chain.evidence_records[-1]
        evidence = EvidenceLink(
            evidence_id=evidence_id,
            integrity_hash=record.integrity_hash,
            redaction_status=item.evidence_redaction_class,
            contains_sensitive_payload=item.contains_sensitive_material,
        )
        finding = _finding_for(plan, item, control_domain, severity, evidence)
        validate_finding(finding)
        findings.append(finding)
        evidence_ids.append(evidence_id)
        rows.append(
            KubernetesRuntimeReportRow(
                finding_id=finding.id,
                evidence_id=evidence_id,
                kind=item.kind,
                resource_id=item.resource_id.strip(),
                namespace=item.namespace.strip() if item.namespace else None,
                control_domain=control_domain,
                severity=severity,
                evidence_redaction_class=item.evidence_redaction_class,
                remediation_guidance=item.remediation_guidance.strip(),
                benchmark_status=item.benchmark_status,
                iac_file_path=item.iac_file_path.strip() if item.iac_file_path else None,
                image_ref=item.image_ref.strip() if item.image_ref else None,
            )
        )
    return chain, tuple(evidence_ids), tuple(findings), tuple(rows)


def _validate_result_item(plan: KubernetesRuntimePlan, item: KubernetesRuntimeResultItem) -> None:
    for field_name, value in (
        ("item_id", item.item_id),
        ("resource_id", item.resource_id),
        ("summary", item.summary),
        ("remediation_guidance", item.remediation_guidance),
    ):
        _require_non_empty(field_name, value)
    required_action = _ACTION_BY_KIND[item.kind]
    if required_action not in plan.actions:
        raise ValueError("kubernetes_result_kind_not_allowed")
    if item.contains_sensitive_material and item.evidence_redaction_class not in {
        RedactionStatus.REDACTED,
        RedactionStatus.BLOCKED,
    }:
        raise ValueError("kubernetes_sensitive_result_requires_redaction")
    if item.namespace is not None and item.namespace.strip() not in plan.namespaces and "*" not in plan.namespaces:
        raise ValueError("kubernetes_result_namespace_out_of_scope")
    if item.kind is KubernetesRuntimeResultKind.BENCHMARK:
        if item.benchmark_status is None or item.kubernetes_area is None:
            raise ValueError("kubernetes_benchmark_status_and_area_required")
    if item.kind is KubernetesRuntimeResultKind.CONTAINER_IMAGE and not item.image_ref:
        raise ValueError("container_image_ref_required")
    if item.kind is KubernetesRuntimeResultKind.IAC_FILE:
        if plan.iac_repository_id is None:
            raise ValueError("iac_plan_required_for_iac_results")
        if item.repository_id != plan.iac_repository_id:
            raise ValueError("iac_repository_mismatch")
        _require_non_empty("iac_file_path", item.iac_file_path or "")


def _finding_for(
    plan: KubernetesRuntimePlan,
    item: KubernetesRuntimeResultItem,
    control_domain: cloud_posture.CloudControlDomain,
    severity: Severity,
    evidence: EvidenceLink,
) -> FindingRecord:
    source_rule_id = item.benchmark_status.value if item.benchmark_status else item.kind.value
    return FindingRecord(
        id=f"{plan.runtime_id}:finding:{item.item_id.strip()}",
        title=f"Kubernetes {item.kind.value} finding: {item.resource_id.strip()}",
        status=FindingStatus.RAW_ALERT,
        affected_asset_id=item.resource_id.strip(),
        affected_asset_value=item.resource_id.strip(),
        confidence=Confidence.MEDIUM,
        risk=RiskFactors(
            severity=severity,
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.UNKNOWN,
            vulnerability_intelligence=VulnerabilityIntelligence(cve_ids=(), cwe_ids=()),
        ),
        reproduction_summary=(
            f"Sanitized {item.kind.value} import for cluster {plan.cluster_id}; "
            "no live Kubernetes, registry, or IaC scanner execution was performed."
        ),
        evidence_links=(evidence,),
        remediation=item.remediation_guidance.strip(),
        owner_user_id=None,
        source="kubernetes_runtime",
        source_rule_id=f"{control_domain.value}:{source_rule_id}",
    )


def _result_content(
    item: KubernetesRuntimeResultItem,
    control_domain: cloud_posture.CloudControlDomain,
    severity: Severity,
) -> bytes:
    return json.dumps(
        {
            "kind": item.kind.value,
            "resource_id": item.resource_id.strip(),
            "namespace": item.namespace.strip() if item.namespace else None,
            "control_domain": control_domain.value,
            "benchmark_status": item.benchmark_status.value if item.benchmark_status else None,
            "iac_file_path": item.iac_file_path.strip() if item.iac_file_path else None,
            "image_ref": item.image_ref.strip() if item.image_ref else None,
            "severity": severity.value,
            "summary": item.summary.strip(),
            "remediation": item.remediation_guidance.strip(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _control_domain_for(item: KubernetesRuntimeResultItem) -> cloud_posture.CloudControlDomain:
    if item.kind is KubernetesRuntimeResultKind.CONTAINER_IMAGE:
        return cloud_posture.CloudControlDomain.CONTAINER_IMAGE
    if item.kind is KubernetesRuntimeResultKind.IAC_FILE:
        return cloud_posture.CloudControlDomain.IAC_CONFIGURATION
    for mapping in cloud_posture.kubernetes_check_mappings():
        if mapping.area is item.kubernetes_area:
            return mapping.control_domain
    raise ValueError("kubernetes_area_not_mapped")


def _severity_for(item: KubernetesRuntimeResultItem) -> Severity:
    if item.kind is KubernetesRuntimeResultKind.BENCHMARK:
        if item.benchmark_status is KubernetesBenchmarkStatus.FAIL:
            return Severity.HIGH
        if item.benchmark_status is KubernetesBenchmarkStatus.WARN:
            return Severity.MEDIUM
        return Severity.INFO
    if item.severity is None:
        raise ValueError("kubernetes_result_severity_required")
    return item.severity


def _validate_namespaces(profile: KubernetesRuntimeProfile, namespaces: tuple[str, ...]) -> tuple[str, ...]:
    if not namespaces:
        raise ValueError("kubernetes_namespace_scope_required")
    normalized = tuple(namespace.strip() for namespace in namespaces if namespace.strip())
    if not normalized:
        raise ValueError("kubernetes_namespace_scope_required")
    if "*" in normalized:
        if not profile.allow_all_namespaces:
            raise ValueError("kubernetes_all_namespaces_not_allowed")
        return ("*",)
    allowed = _normalized_set(profile.allowed_namespaces)
    for namespace in normalized:
        if namespace not in allowed:
            raise ValueError("kubernetes_namespace_not_allowlisted")
    return normalized


def _normalized_set(values: tuple[str, ...]) -> frozenset[str]:
    return frozenset(value.strip() for value in values if value.strip())


def _callback(
    state: JobQueueState,
    plan: KubernetesRuntimePlan,
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
            job_id=plan.cloud_plan.job.job_id,
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
