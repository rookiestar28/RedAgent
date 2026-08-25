"""Controlled supply-chain and CI/CD posture runtime contracts.

This module does not run scanners, clone repositories, contact external
verification services, execute package hooks, or perform network validation. It
binds compat_040 trusted-repository decisions to local runner/evidence/finding/report
contracts and imports supplied sanitized results.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import redaction, supply_chain
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


class SupplyChainRuntimeAction(str, Enum):
    IMPORT_RESULTS = "import_results"
    EXTERNAL_VERIFY = "external_verify"
    NETWORK_VALIDATE = "network_validate"
    RUN_SCANNER = "run_scanner"


class SupplyChainRuntimeResultKind(str, Enum):
    SAST = "sast"
    DEPENDENCY_INVENTORY = "dependency_inventory"
    SBOM = "sbom"
    SCORECARD = "scorecard"
    SENSITIVE_VALUE = "sensitive_value"
    PROVENANCE = "provenance"
    PIPELINE_REVIEW = "pipeline_review"
    ARTIFACT_INTEGRITY = "artifact_integrity"


@dataclass(frozen=True, kw_only=True)
class SupplyChainRuntimeProfile:
    profile_id: str
    module_id: str
    allowed_repository_ids: tuple[str, ...]
    allowed_pipeline_ids: tuple[str, ...]
    allowed_check_kinds: tuple[supply_chain.SupplyChainCheckKind, ...]
    max_results: int
    timeout_seconds: int
    actions: tuple[SupplyChainRuntimeAction, ...]


@dataclass(frozen=True, kw_only=True)
class SupplyChainRuntimeRequest:
    runtime_id: str
    profile: SupplyChainRuntimeProfile
    scope: supply_chain.SupplyChainScope
    assessment_request: supply_chain.SupplyChainAssessmentRequest
    runner: RunnerContract
    requested_at: datetime
    operator_user_id: str


@dataclass(frozen=True, kw_only=True)
class SupplyChainRuntimePlan:
    runtime_id: str
    job: JobRecord
    runner_id: str
    profile_id: str
    repository_id: str
    pipeline_id: str | None
    local_only: bool
    check_kinds: tuple[supply_chain.SupplyChainCheckKind, ...]
    max_results: int
    timeout_seconds: int
    actions: tuple[SupplyChainRuntimeAction, ...]
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class SupplyChainRuntimeResultItem:
    item_id: str
    kind: SupplyChainRuntimeResultKind
    location_type: supply_chain.SupplyChainLocationType
    location: str
    control_category: supply_chain.SupplyChainControlCategory
    severity: Severity
    remediation_guidance: str
    false_positive_workflow: str
    evidence_redaction_class: RedactionStatus
    summary: str
    detector_name: str
    repository_id: str
    pipeline_id: str | None = None
    redacted_locations: tuple[str, ...] = ()
    raw_value_recorded: bool = False
    canary_markers: tuple[str, ...] = ()
    contains_sensitive_material: bool = False


@dataclass(frozen=True, kw_only=True)
class SupplyChainRuntimeReportRow:
    finding_id: str
    evidence_id: str
    kind: SupplyChainRuntimeResultKind
    location_type: supply_chain.SupplyChainLocationType
    location: str
    control_category: supply_chain.SupplyChainControlCategory
    severity: Severity
    remediation_guidance: str
    false_positive_workflow: str
    evidence_redaction_class: RedactionStatus
    detector_name: str


@dataclass(frozen=True, kw_only=True)
class SupplyChainRuntimeExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    report_rows: tuple[SupplyChainRuntimeReportRow, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()


_FORBIDDEN_ACTIONS = frozenset(
    {
        SupplyChainRuntimeAction.EXTERNAL_VERIFY,
        SupplyChainRuntimeAction.NETWORK_VALIDATE,
        SupplyChainRuntimeAction.RUN_SCANNER,
    }
)


def build_supply_chain_runtime_plan(request: SupplyChainRuntimeRequest) -> SupplyChainRuntimePlan:
    _validate_request(request)
    decision = supply_chain.evaluate_supply_chain_assessment(scope=request.scope, request=request.assessment_request)
    if not decision.allowed:
        raise ValueError(f"supply_chain_assessment_denied:{decision.reason}")
    check_plan = supply_chain.build_supply_chain_check_plan(scope=request.scope, request=request.assessment_request)
    target = ScopeTarget(target_type=TargetType.REPOSITORY, value=check_plan.repository_id)
    if request.runner.target_scope.normalized() != target.normalized():
        raise ValueError("runner_target_scope_mismatch")
    return SupplyChainRuntimePlan(
        runtime_id=request.runtime_id.strip(),
        job=JobRecord(
            job_id=request.assessment_request.job_id,
            organization_id=request.assessment_request.organization_id,
            engagement_id=request.assessment_request.engagement_id,
            test_definition_id=request.profile.profile_id,
            target=target.normalized(),
            mode=TestMode.SUPPLY_CHAIN_POSTURE,
            status=JobStatus.QUEUED,
            projected_interactions=max(1, len(check_plan.check_kinds)),
            timeout_seconds=request.profile.timeout_seconds,
            cleanup_required=True,
            max_attempts=1,
            policy_decision_id=f"{request.runtime_id}:supply-chain-policy",
            policy_expires_at=request.requested_at.replace(year=request.requested_at.year + 1),
            last_transition_at=request.requested_at,
        ),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        repository_id=check_plan.repository_id,
        pipeline_id=check_plan.pipeline_id,
        local_only=check_plan.local_only,
        check_kinds=tuple(check_plan.check_kinds),
        max_results=request.profile.max_results,
        timeout_seconds=request.profile.timeout_seconds,
        actions=tuple(request.profile.actions),
        cancellation_supported=True,
    )


def execute_supply_chain_runtime_plan(
    *,
    plan: SupplyChainRuntimePlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    result_items: tuple[SupplyChainRuntimeResultItem, ...] = (),
    cancel_requested: bool = False,
    kill_switch_scope: KillSwitchScope | None = None,
) -> SupplyChainRuntimeExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if len(result_items) > plan.max_results:
        raise ValueError("supply_chain_runtime_result_cap_exceeded")
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return SupplyChainRuntimeExecutionResult(
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
        return SupplyChainRuntimeExecutionResult(
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
            reason="supply_chain_runtime_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return SupplyChainRuntimeExecutionResult(
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
    return SupplyChainRuntimeExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        report_rows=rows,
        imported_evidence_ids=evidence_ids,
    )


def _validate_request(request: SupplyChainRuntimeRequest) -> None:
    for field_name, value in (("runtime_id", request.runtime_id), ("operator_user_id", request.operator_user_id)):
        _require_non_empty(field_name, value)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    if request.assessment_request.requested_at != request.requested_at:
        raise ValueError("supply_chain_runtime_time_mismatch")
    if request.assessment_request.repository_id not in _normalized_set(request.profile.allowed_repository_ids):
        raise ValueError("supply_chain_runtime_repository_not_allowlisted")
    if request.assessment_request.pipeline_id and request.assessment_request.pipeline_id not in _normalized_set(
        request.profile.allowed_pipeline_ids
    ):
        raise ValueError("supply_chain_runtime_pipeline_not_allowlisted")
    if not set(request.assessment_request.check_kinds).issubset(set(request.profile.allowed_check_kinds)):
        raise ValueError("supply_chain_runtime_check_kind_not_allowed")
    if request.runner.organization_id != request.assessment_request.organization_id:
        raise ValueError("runner_organization_mismatch")
    if TestMode.SUPPLY_CHAIN_POSTURE not in request.runner.capabilities:
        raise ValueError("runner_capability_missing")


def _validate_profile(profile: SupplyChainRuntimeProfile) -> None:
    for field_name, value in (("profile_id", profile.profile_id), ("module_id", profile.module_id)):
        _require_non_empty(field_name, value)
    if not profile.allowed_repository_ids:
        raise ValueError("supply_chain_runtime_repository_allowlist_required")
    if not profile.allowed_check_kinds:
        raise ValueError("supply_chain_runtime_check_kinds_required")
    if SupplyChainRuntimeAction.IMPORT_RESULTS not in profile.actions:
        raise ValueError("supply_chain_runtime_import_action_required")
    if _FORBIDDEN_ACTIONS.intersection(profile.actions):
        raise ValueError("supply_chain_runtime_external_or_scanner_action_not_allowed")
    if profile.max_results <= 0:
        raise ValueError("supply_chain_runtime_result_cap_invalid")
    if profile.timeout_seconds <= 0:
        raise ValueError("supply_chain_runtime_timeout_invalid")


def _validate_execution_inputs(
    plan: SupplyChainRuntimePlan,
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
    plan: SupplyChainRuntimePlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    result_items: tuple[SupplyChainRuntimeResultItem, ...],
) -> tuple[EvidenceChain, tuple[str, ...], tuple[FindingRecord, ...], tuple[SupplyChainRuntimeReportRow, ...]]:
    chain = evidence_chain
    evidence_ids: list[str] = []
    findings: list[FindingRecord] = []
    rows: list[SupplyChainRuntimeReportRow] = []
    for item in result_items:
        _validate_result_item(plan, item)
        evidence_id = f"{plan.runtime_id}:{item.kind.value}:{item.item_id}"
        content_payload, redaction_result = _sanitized_content_payload(item)
        content = None if redaction_result.redaction_status is RedactionStatus.BLOCKED else json.dumps(
            content_payload,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        chain = chain.append_evidence_record(
            evidence_id=evidence_id,
            organization_id=plan.job.organization_id,
            source_job_id=plan.job.job_id,
            kind=EvidenceKind.SCANNER_OUTPUT,
            created_at=occurred_at,
            redaction_status=redaction_result.redaction_status
            if redaction_result.redacted
            else item.evidence_redaction_class,
            retention_class=RetentionClass.STANDARD,
            access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=content,
            contains_sensitive_capture=item.contains_sensitive_material,
            metadata={
                "repository_id": item.repository_id,
                "pipeline_id": item.pipeline_id,
                "kind": item.kind.value,
                "control_category": item.control_category.value,
                "detector_name": item.detector_name,
                "location_type": item.location_type.value,
                "severity": item.severity.value,
            },
        )
        record = chain.evidence_records[-1]
        evidence = EvidenceLink(
            evidence_id=evidence_id,
            integrity_hash=record.integrity_hash,
            redaction_status=record.redaction_status,
            contains_sensitive_payload=item.contains_sensitive_material,
        )
        finding = _finding_for(plan, item, evidence)
        validate_finding(finding)
        findings.append(finding)
        evidence_ids.append(evidence_id)
        rows.append(
            SupplyChainRuntimeReportRow(
                finding_id=finding.id,
                evidence_id=evidence_id,
                kind=item.kind,
                location_type=item.location_type,
                location=item.location.strip(),
                control_category=item.control_category,
                severity=item.severity,
                remediation_guidance=item.remediation_guidance.strip(),
                false_positive_workflow=item.false_positive_workflow.strip(),
                evidence_redaction_class=record.redaction_status,
                detector_name=item.detector_name.strip(),
            )
        )
    return chain, tuple(evidence_ids), tuple(findings), tuple(rows)


def _validate_result_item(plan: SupplyChainRuntimePlan, item: SupplyChainRuntimeResultItem) -> None:
    for field_name, value in (
        ("item_id", item.item_id),
        ("location", item.location),
        ("remediation_guidance", item.remediation_guidance),
        ("false_positive_workflow", item.false_positive_workflow),
        ("summary", item.summary),
        ("detector_name", item.detector_name),
        ("repository_id", item.repository_id),
    ):
        _require_non_empty(field_name, value)
    if item.repository_id != plan.repository_id:
        raise ValueError("supply_chain_result_repository_mismatch")
    if item.pipeline_id and item.pipeline_id != plan.pipeline_id:
        raise ValueError("supply_chain_result_pipeline_mismatch")
    if item.contains_sensitive_material and item.evidence_redaction_class not in {
        RedactionStatus.REDACTED,
        RedactionStatus.BLOCKED,
    }:
        raise ValueError("supply_chain_sensitive_result_requires_redaction")
    if item.kind is SupplyChainRuntimeResultKind.SENSITIVE_VALUE:
        supply_chain.validate_redacted_sensitive_evidence(
            supply_chain.RedactedSensitiveEvidence(
                evidence_id=f"{plan.runtime_id}:{item.item_id}",
                redaction_status=item.evidence_redaction_class,
                redacted_locations=tuple(item.redacted_locations),
                raw_value_recorded=item.raw_value_recorded,
                canary_markers=tuple(item.canary_markers),
            )
        )
    mapping = supply_chain.build_supply_chain_finding_mapping(
        finding_id=item.item_id,
        location_type=item.location_type,
        location=item.location,
        control_category=item.control_category,
        severity=item.severity,
        remediation_guidance=item.remediation_guidance,
        false_positive_workflow=item.false_positive_workflow,
    )
    if mapping.location != item.location.strip():
        raise ValueError("supply_chain_mapping_location_mismatch")


def _sanitized_content_payload(item: SupplyChainRuntimeResultItem) -> tuple[dict[str, object], redaction.RedactionResult]:
    payload = {
        "kind": item.kind.value,
        "location_type": item.location_type.value,
        "location": item.location.strip(),
        "control_category": item.control_category.value,
        "severity": item.severity.value,
        "remediation": item.remediation_guidance.strip(),
        "false_positive_workflow": item.false_positive_workflow.strip(),
        "summary": item.summary.strip(),
        "detector_name": item.detector_name.strip(),
        "repository_id": item.repository_id.strip(),
        "pipeline_id": item.pipeline_id.strip() if item.pipeline_id else None,
        "redacted_locations": tuple(item.redacted_locations),
    }
    sanitized, result = redaction.sanitize_mapping(
        payload,
        redaction.RedactionArtifactClass.SCANNER_OUTPUT,
        redaction.RedactionConfig(canary_markers=tuple(item.canary_markers)),
    )
    return sanitized, result


def _finding_for(plan: SupplyChainRuntimePlan, item: SupplyChainRuntimeResultItem, evidence: EvidenceLink) -> FindingRecord:
    return FindingRecord(
        id=f"{plan.runtime_id}:finding:{item.item_id.strip()}",
        title=f"Supply-chain finding: {item.control_category.value} at {item.location.strip()}",
        status=FindingStatus.RAW_ALERT,
        affected_asset_id=item.location.strip(),
        affected_asset_value=item.location.strip(),
        confidence=Confidence.MEDIUM,
        risk=RiskFactors(
            severity=item.severity,
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.UNKNOWN,
            vulnerability_intelligence=VulnerabilityIntelligence(cve_ids=(), cwe_ids=()),
        ),
        reproduction_summary=(
            f"Sanitized supply-chain result import for repository {plan.repository_id}; "
            "no scanner, network validation, or external verification was executed."
        ),
        evidence_links=(evidence,),
        remediation=item.remediation_guidance.strip(),
        owner_user_id=None,
        source="supply_chain_runtime",
        source_rule_id=f"{item.kind.value}:{item.control_category.value}",
    )


def _callback(
    state: JobQueueState,
    plan: SupplyChainRuntimePlan,
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
