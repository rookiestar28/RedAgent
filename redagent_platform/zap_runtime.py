"""Controlled ZAP runtime adapter contracts.

This module does not start ZAP, call ZAP APIs, spider, proxy, or contact
targets. It binds approved ZAP plans to the local runner/evidence state
machine and imports supplied, untrusted alert metadata through the existing
sanitizers.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from redagent_platform.credentials import CredentialBroker, CredentialLease
from redagent_platform.domain import JobStatus, TargetType, TestMode
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
from redagent_platform.lab_validation import (
    LabValidationRecord,
    ScannerPolicyProfile,
    validate_enterprise_job_lab_gate,
)
from redagent_platform.scope_authorization import ScopeTarget
from redagent_platform.target_inventory import InventoryTarget
from redagent_platform.zap_active import (
    ZapActiveAlert,
    ZapActiveScanPlan,
    append_zap_active_evidence,
    normalize_zap_active_alert_to_finding,
)
from redagent_platform.zap_passive import (
    ZapPassiveAlert,
    ZapPassiveAuthorization,
    ZapPassiveCaptureContext,
    append_zap_passive_evidence,
    normalize_zap_alert_to_finding,
)


class ZapRuntimeKind(str, Enum):
    PASSIVE_ALERT_IMPORT = "passive_alert_import"
    ACTIVE_SCAN = "active_scan"


class ZapRuntimeApiAction(str, Enum):
    IMPORT_PASSIVE_ALERTS = "import_passive_alerts"
    LOAD_AUTH_CONTEXT = "load_auth_context"
    START_ACTIVE_SCAN = "start_active_scan"
    POLL_ACTIVE_SCAN = "poll_active_scan"
    STOP_ACTIVE_SCAN = "stop_active_scan"
    IMPORT_ACTIVE_ALERTS = "import_active_alerts"


@dataclass(frozen=True, kw_only=True)
class ZapRuntimeProfile:
    profile_id: str
    module_id: str
    scan_policy_id: str
    allowed_modes: tuple[TestMode, ...]
    max_rate_per_second: float
    max_requests: int
    max_duration_seconds: int
    lab_profile: ScannerPolicyProfile
    api_actions: tuple[ZapRuntimeApiAction, ...]
    allow_authenticated_context: bool


@dataclass(frozen=True, kw_only=True)
class ZapRuntimeRequest:
    runtime_id: str
    profile: ZapRuntimeProfile
    runner: RunnerContract
    inventory_target: InventoryTarget
    requested_at: datetime
    operator_user_id: str
    lab_validation_records: tuple[LabValidationRecord, ...]
    credential_lease: CredentialLease | None = None
    active_plan: ZapActiveScanPlan | None = None
    passive_capture: ZapPassiveCaptureContext | None = None
    passive_authorization: ZapPassiveAuthorization | None = None
    passive_policy_decision_id: str | None = None
    passive_policy_expires_at: datetime | None = None


@dataclass(frozen=True, kw_only=True)
class ZapRuntimePlan:
    runtime_id: str
    kind: ZapRuntimeKind
    job: JobRecord
    runner_id: str
    profile_id: str
    scan_policy_id: str
    api_actions: tuple[ZapRuntimeApiAction, ...]
    rate_limit_per_second: float
    max_requests: int
    timeout_seconds: int
    credential_lease_id: str | None
    lab_validation_id: str | None
    cancellation_supported: bool


@dataclass(frozen=True, kw_only=True)
class ZapRuntimeExecutionResult:
    allowed: bool
    reason: str
    state: JobQueueState
    evidence_chain: EvidenceChain
    findings: tuple[FindingRecord, ...]
    imported_evidence_ids: tuple[str, ...]
    cancellation_evidence: tuple[CancellationEvidence, ...] = ()
    credential_broker: CredentialBroker = CredentialBroker()


FORBIDDEN_ZAP_RUNTIME_PAYLOAD_FIELDS = frozenset(
    {
        "args",
        "binary",
        "command",
        "docker_image",
        "scan_url",
        "script",
        "shell",
        "spider_url",
        "target_url",
        "url",
        "zap_api_url",
    }
)


def assert_no_arbitrary_zap_controls(payload: Mapping[str, object]) -> None:
    forbidden = FORBIDDEN_ZAP_RUNTIME_PAYLOAD_FIELDS.intersection(payload)
    if forbidden:
        raise ValueError("arbitrary_zap_control_forbidden")


def build_zap_runtime_plan(request: ZapRuntimeRequest) -> ZapRuntimePlan:
    _validate_request_basics(request)
    kind = _request_kind(request)
    if kind is ZapRuntimeKind.ACTIVE_SCAN:
        return _build_active_plan(request)
    return _build_passive_plan(request)


def execute_zap_runtime_plan(
    *,
    plan: ZapRuntimePlan,
    state: JobQueueState,
    runner: RunnerContract,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    operator_user_id: str,
    active_alerts: tuple[ZapActiveAlert, ...] = (),
    passive_alerts: tuple[ZapPassiveAlert, ...] = (),
    active_scan_plan: ZapActiveScanPlan | None = None,
    passive_capture: ZapPassiveCaptureContext | None = None,
    passive_authorization: ZapPassiveAuthorization | None = None,
    cancel_requested: bool = False,
    credential_broker: CredentialBroker = CredentialBroker(),
    credential_leases_by_job_id: Mapping[str, CredentialLease] | None = None,
    kill_switch_scope: KillSwitchScope | None = None,
) -> ZapRuntimeExecutionResult:
    _validate_execution_inputs(plan, runner, occurred_at, operator_user_id)
    if kill_switch_scope is not None:
        decision = kill_switch_blocks_dispatch(kill_switch_scope, plan.job)
        if not decision.allowed:
            return ZapRuntimeExecutionResult(
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
        return ZapRuntimeExecutionResult(
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
            reason="zap_runtime_cancel_requested",
            actor_user_id=operator_user_id,
            event_id=f"{plan.runtime_id}:kill-switch",
            occurred_at=occurred_at,
        )
        return ZapRuntimeExecutionResult(
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
    chain, findings, evidence_ids = _import_alerts(
        plan=plan,
        evidence_chain=evidence_chain,
        occurred_at=occurred_at,
        active_alerts=active_alerts,
        passive_alerts=passive_alerts,
        active_scan_plan=active_scan_plan,
        passive_capture=passive_capture,
        passive_authorization=passive_authorization,
    )
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
    return ZapRuntimeExecutionResult(
        allowed=True,
        reason="succeeded",
        state=final_state,
        evidence_chain=chain,
        findings=findings,
        imported_evidence_ids=evidence_ids,
        credential_broker=credential_broker,
    )


def _build_active_plan(request: ZapRuntimeRequest) -> ZapRuntimePlan:
    active_plan = request.active_plan
    if active_plan is None:
        raise ValueError("active_plan_required")
    _validate_profile_for_job(request.profile, active_plan.job)
    if active_plan.scan_policy_id != request.profile.scan_policy_id:
        raise ValueError("scan_policy_not_approved")
    if active_plan.rate_limit_per_second > request.profile.max_rate_per_second:
        raise ValueError("zap_rate_cap_exceeded")
    if active_plan.max_requests > request.profile.max_requests:
        raise ValueError("zap_request_cap_exceeded")
    if active_plan.timeout_seconds > request.profile.max_duration_seconds:
        raise ValueError("zap_duration_cap_exceeded")
    if active_plan.authenticated_context_id and not request.profile.allow_authenticated_context:
        raise ValueError("authenticated_context_not_allowed")
    if active_plan.authenticated_context_id and request.credential_lease is None:
        raise ValueError("credential_lease_required_for_authenticated_zap")
    lab_gate = validate_enterprise_job_lab_gate(
        target=request.inventory_target,
        profile=request.profile.lab_profile,
        validation_records=request.lab_validation_records,
        requested_at=request.requested_at,
    )
    if not lab_gate.allowed:
        raise ValueError(lab_gate.reason)
    return ZapRuntimePlan(
        runtime_id=request.runtime_id.strip(),
        kind=ZapRuntimeKind.ACTIVE_SCAN,
        job=_queued_job(active_plan.job),
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        scan_policy_id=active_plan.scan_policy_id,
        api_actions=request.profile.api_actions,
        rate_limit_per_second=active_plan.rate_limit_per_second,
        max_requests=active_plan.max_requests,
        timeout_seconds=active_plan.timeout_seconds,
        credential_lease_id=request.credential_lease.id if request.credential_lease else None,
        lab_validation_id=lab_gate.validation_id,
        cancellation_supported=active_plan.cancellation_supported and ZapRuntimeApiAction.STOP_ACTIVE_SCAN in request.profile.api_actions,
    )


def _build_passive_plan(request: ZapRuntimeRequest) -> ZapRuntimePlan:
    capture = request.passive_capture
    authorization = request.passive_authorization
    if capture is None:
        raise ValueError("passive_capture_required")
    if authorization is None or not authorization.allowed:
        reason = authorization.reason if authorization else "missing_passive_authorization"
        raise ValueError(f"zap_passive_capture_denied:{reason}")
    if request.passive_policy_decision_id is None or request.passive_policy_expires_at is None:
        raise ValueError("passive_policy_grant_required")
    _require_timezone(request.passive_policy_expires_at)
    if request.requested_at >= request.passive_policy_expires_at:
        raise ValueError("current_policy_decision_required")
    job = JobRecord(
        job_id=capture.capture_id,
        organization_id=capture.organization_id,
        engagement_id=capture.engagement_id,
        test_definition_id=request.profile.scan_policy_id,
        target=capture.target.normalized(),
        mode=capture.mode,
        status=JobStatus.QUEUED,
        projected_interactions=capture.projected_interactions,
        timeout_seconds=request.profile.max_duration_seconds,
        cleanup_required=True,
        max_attempts=1,
        policy_decision_id=request.passive_policy_decision_id,
        policy_expires_at=request.passive_policy_expires_at,
        last_transition_at=request.requested_at,
    )
    _validate_profile_for_job(request.profile, job)
    lab_gate = validate_enterprise_job_lab_gate(
        target=request.inventory_target,
        profile=request.profile.lab_profile,
        validation_records=request.lab_validation_records,
        requested_at=request.requested_at,
    )
    if not lab_gate.allowed:
        raise ValueError(lab_gate.reason)
    return ZapRuntimePlan(
        runtime_id=request.runtime_id.strip(),
        kind=ZapRuntimeKind.PASSIVE_ALERT_IMPORT,
        job=job,
        runner_id=request.runner.runner_id,
        profile_id=request.profile.profile_id,
        scan_policy_id=request.profile.scan_policy_id,
        api_actions=request.profile.api_actions,
        rate_limit_per_second=request.profile.max_rate_per_second,
        max_requests=request.profile.max_requests,
        timeout_seconds=request.profile.max_duration_seconds,
        credential_lease_id=None,
        lab_validation_id=lab_gate.validation_id,
        cancellation_supported=False,
    )


def _import_alerts(
    *,
    plan: ZapRuntimePlan,
    evidence_chain: EvidenceChain,
    occurred_at: datetime,
    active_alerts: tuple[ZapActiveAlert, ...],
    passive_alerts: tuple[ZapPassiveAlert, ...],
    active_scan_plan: ZapActiveScanPlan | None,
    passive_capture: ZapPassiveCaptureContext | None,
    passive_authorization: ZapPassiveAuthorization | None,
) -> tuple[EvidenceChain, tuple[FindingRecord, ...], tuple[str, ...]]:
    chain = evidence_chain
    findings: list[FindingRecord] = []
    evidence_ids: list[str] = []
    if plan.kind is ZapRuntimeKind.ACTIVE_SCAN:
        if active_scan_plan is None:
            raise ValueError("active_scan_plan_required_for_alert_import")
        for index, alert in enumerate(active_alerts, start=1):
            evidence_id = f"{plan.runtime_id}:zap-active-alert:{index}"
            evidence = append_zap_active_evidence(
                chain=chain,
                plan=active_scan_plan,
                alert=alert,
                evidence_id=evidence_id,
                observed_at=occurred_at,
            )
            chain = evidence.chain
            evidence_ids.append(evidence_id)
            findings.append(
                normalize_zap_active_alert_to_finding(
                    finding_id=f"{plan.runtime_id}:finding:{index}",
                    plan=active_scan_plan,
                    alert=alert,
                    evidence_record=evidence.record,
                )
            )
    else:
        if passive_capture is None or passive_authorization is None:
            raise ValueError("passive_capture_required_for_alert_import")
        for index, alert in enumerate(passive_alerts, start=1):
            evidence_id = f"{plan.runtime_id}:zap-passive-alert:{index}"
            evidence = append_zap_passive_evidence(
                chain=chain,
                capture=passive_capture,
                alert=alert,
                evidence_id=evidence_id,
                authorization=passive_authorization,
            )
            chain = evidence.chain
            evidence_ids.append(evidence_id)
            findings.append(
                normalize_zap_alert_to_finding(
                    finding_id=f"{plan.runtime_id}:finding:{index}",
                    capture=passive_capture,
                    alert=alert,
                    evidence_record=evidence.record,
                    authorization=passive_authorization,
                )
            )
    return chain, tuple(findings), tuple(evidence_ids)


def _validate_request_basics(request: ZapRuntimeRequest) -> None:
    _require_non_empty("runtime_id", request.runtime_id)
    _require_non_empty("operator_user_id", request.operator_user_id)
    _require_timezone(request.requested_at)
    _validate_profile(request.profile)
    _validate_runner(request.runner)
    if (request.active_plan is None) == (request.passive_capture is None):
        raise ValueError("exactly_one_zap_workflow_required")


def _validate_profile(profile: ZapRuntimeProfile) -> None:
    for field_name, value in (
        ("profile_id", profile.profile_id),
        ("module_id", profile.module_id),
        ("scan_policy_id", profile.scan_policy_id),
    ):
        _require_non_empty(field_name, value)
    if not profile.allowed_modes:
        raise ValueError("zap_profile_modes_required")
    if profile.max_rate_per_second <= 0:
        raise ValueError("zap_profile_rate_invalid")
    if profile.max_requests <= 0:
        raise ValueError("zap_profile_requests_invalid")
    if profile.max_duration_seconds <= 0:
        raise ValueError("zap_profile_duration_invalid")
    if not profile.api_actions:
        raise ValueError("zap_profile_actions_required")


def _validate_runner(runner: RunnerContract) -> None:
    for field_name, value in (
        ("runner_id", runner.runner_id),
        ("organization_id", runner.organization_id),
        ("policy_token_reference", runner.policy_token_reference),
        ("cleanup_callback", runner.cleanup_callback),
    ):
        _require_non_empty(field_name, value)
    if not runner.capabilities:
        raise ValueError("runner_capabilities_required")


def _validate_profile_for_job(profile: ZapRuntimeProfile, job: JobRecord) -> None:
    if job.mode not in profile.allowed_modes:
        raise ValueError("zap_mode_not_approved")
    if job.projected_interactions > profile.max_requests:
        raise ValueError("zap_request_cap_exceeded")
    if job.timeout_seconds > profile.max_duration_seconds:
        raise ValueError("zap_duration_cap_exceeded")


def _validate_execution_inputs(plan: ZapRuntimePlan, runner: RunnerContract, occurred_at: datetime, operator_user_id: str) -> None:
    _require_non_empty("operator_user_id", operator_user_id)
    _require_timezone(occurred_at)
    if runner.runner_id != plan.runner_id:
        raise ValueError("runner_mismatch")
    if plan.job.mode not in runner.capabilities:
        raise ValueError("runner_capability_missing")
    if runner.target_scope.normalized() != plan.job.target.normalized():
        raise ValueError("runner_target_scope_mismatch")


def _request_kind(request: ZapRuntimeRequest) -> ZapRuntimeKind:
    if request.active_plan is not None:
        return ZapRuntimeKind.ACTIVE_SCAN
    return ZapRuntimeKind.PASSIVE_ALERT_IMPORT


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
    plan: ZapRuntimePlan,
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
