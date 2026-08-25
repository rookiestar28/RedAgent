"""Controlled runner execution-plane MVP.

This module intentionally does not start subprocesses or invoke external tools.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from enum import Enum
from typing import Mapping

from redagent_platform.domain import EvidenceKind, JobStatus, TargetType, TestMode
from redagent_platform.evidence_chain import EvidenceAccessPolicy, EvidenceChain, RedactionStatus, RetentionClass
from redagent_platform.evidence_store import EvidenceArtifactManifest, EvidenceArtifactWriteRequest, LocalEvidenceArtifactStore
from redagent_platform.job_queue import JobQueueState, JobRecord, RunnerCallback, RunnerCallbackKind, RunnerContract
from redagent_platform.redaction import RedactionArtifactClass, sanitize_text
from redagent_platform.scope_authorization import ScopeTarget


class RunnerAdapterKind(str, Enum):
    DRY_RUN = "dry_run"
    LAB_ECHO = "lab_echo"


class RunnerExitClassification(str, Enum):
    SUCCEEDED = "succeeded"
    DENIED = "denied"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    CLEANUP_FAILED = "cleanup_failed"


@dataclass(frozen=True, kw_only=True)
class RunnerCleanupResult:
    required: bool
    attempted: bool
    succeeded: bool
    reason: str


@dataclass(frozen=True, kw_only=True)
class RunnerJobSpec:
    spec_id: str
    job_id: str
    organization_id: str
    runner_id: str
    adapter: RunnerAdapterKind
    mode: TestMode
    target: ScopeTarget
    policy_decision_id: str
    policy_expires_at: datetime
    requested_at: datetime
    timeout_seconds: int
    cleanup_required: bool
    evidence_id: str
    operator_user_id: str
    credential_lease_id: str | None
    adapter_parameters: Mapping[str, object]
    spec_hash: str


@dataclass(frozen=True, kw_only=True)
class RunnerExecutionResult:
    allowed: bool
    reason: str
    exit_classification: RunnerExitClassification
    state: JobQueueState
    sanitized_stdout: str
    sanitized_stderr: str
    evidence_manifest: EvidenceArtifactManifest | None
    cleanup: RunnerCleanupResult


FORBIDDEN_PAYLOAD_FIELDS = frozenset({"command", "shell", "args", "url", "binary", "docker_image"})
ALLOWLISTED_ADAPTERS = frozenset(RunnerAdapterKind)


def build_runner_job_spec(
    *,
    spec_id: str,
    job: JobRecord,
    runner: RunnerContract,
    adapter: RunnerAdapterKind,
    requested_at: datetime,
    evidence_id: str,
    operator_user_id: str,
    adapter_parameters: Mapping[str, object] | None = None,
) -> RunnerJobSpec:
    if job.policy_decision_id is None or job.policy_expires_at is None:
        raise ValueError("policy_decision_required")
    spec = RunnerJobSpec(
        spec_id=spec_id.strip(),
        job_id=job.job_id,
        organization_id=job.organization_id,
        runner_id=runner.runner_id,
        adapter=adapter,
        mode=job.mode,
        target=job.target.normalized(),
        policy_decision_id=job.policy_decision_id,
        policy_expires_at=job.policy_expires_at,
        requested_at=requested_at,
        timeout_seconds=job.timeout_seconds,
        cleanup_required=job.cleanup_required,
        evidence_id=evidence_id.strip(),
        operator_user_id=operator_user_id.strip(),
        credential_lease_id=runner.credential_lease_id,
        adapter_parameters=dict(adapter_parameters or {}),
        spec_hash="",
    )
    return replace(spec, spec_hash=_spec_hash(spec))


def build_runner_job_spec_from_payload(payload: Mapping[str, object]) -> RunnerJobSpec:
    forbidden = FORBIDDEN_PAYLOAD_FIELDS.intersection(payload)
    if forbidden:
        raise ValueError("arbitrary_shell_or_url_forbidden")
    target_payload = _mapping(payload.get("target"), "target")
    spec = RunnerJobSpec(
        spec_id=str(payload["spec_id"]),
        job_id=str(payload["job_id"]),
        organization_id=str(payload["organization_id"]),
        runner_id=str(payload["runner_id"]),
        adapter=RunnerAdapterKind(str(payload["adapter"])),
        mode=TestMode(str(payload["mode"])),
        target=ScopeTarget(target_type=TargetType(str(target_payload["target_type"])), value=str(target_payload["value"])).normalized(),
        policy_decision_id=str(payload["policy_decision_id"]),
        policy_expires_at=datetime.fromisoformat(str(payload["policy_expires_at"])),
        requested_at=datetime.fromisoformat(str(payload["requested_at"])),
        timeout_seconds=int(payload["timeout_seconds"]),
        cleanup_required=bool(payload["cleanup_required"]),
        evidence_id=str(payload["evidence_id"]),
        operator_user_id=str(payload["operator_user_id"]),
        credential_lease_id=str(payload["credential_lease_id"]) if payload.get("credential_lease_id") else None,
        adapter_parameters=dict(_mapping(payload.get("adapter_parameters", {}), "adapter_parameters")),
        spec_hash=str(payload["spec_hash"]),
    )
    verify_runner_job_spec(spec)
    return spec


def verify_runner_job_spec(spec: RunnerJobSpec) -> None:
    _validate_spec_basics(spec)
    if _spec_hash(spec) != spec.spec_hash:
        raise ValueError("runner_job_spec_hash_mismatch")


def dispatch_runner_job(
    *,
    state: JobQueueState,
    runner: RunnerContract,
    spec: RunnerJobSpec,
    evidence_store: LocalEvidenceArtifactStore,
    occurred_at: datetime,
) -> RunnerExecutionResult:
    denial = _deny_reason(spec, runner, occurred_at)
    if denial:
        return _denied(state, denial)

    dispatched, decision = state.dispatch_job(
        spec.job_id,
        runner,
        actor_user_id=spec.operator_user_id,
        event_id=f"{spec.spec_id}:dispatch",
        occurred_at=occurred_at,
    )
    if not decision.allowed:
        return _denied(state, decision.reason)

    if bool(spec.adapter_parameters.get("cancel_requested")):
        cancelled, cancel_decision = dispatched.cancel_job(
            spec.job_id,
            reason="runner_cancel_requested",
            actor_user_id=spec.operator_user_id,
            event_id=f"{spec.spec_id}:cancel",
            occurred_at=occurred_at,
        )
        return RunnerExecutionResult(
            allowed=cancel_decision.allowed,
            reason=cancel_decision.reason,
            exit_classification=RunnerExitClassification.CANCELLED,
            state=cancelled,
            sanitized_stdout="",
            sanitized_stderr="",
            evidence_manifest=None,
            cleanup=RunnerCleanupResult(required=spec.cleanup_required, attempted=False, succeeded=False, reason="cancelled"),
        )

    running = _callback(dispatched, spec, RunnerCallbackKind.STARTED, "started", occurred_at)
    running = _callback(running, spec, RunnerCallbackKind.HEARTBEAT, "heartbeat", occurred_at + timedelta(seconds=1))

    if bool(spec.adapter_parameters.get("simulate_timeout")):
        timed_out = running.fail_timed_out_jobs(
            now=occurred_at + timedelta(seconds=spec.timeout_seconds + 2),
            actor_user_id=spec.runner_id,
            event_id_prefix=f"{spec.spec_id}:timeout",
        )
        return RunnerExecutionResult(
            allowed=True,
            reason="timeout",
            exit_classification=RunnerExitClassification.TIMED_OUT,
            state=timed_out,
            sanitized_stdout="",
            sanitized_stderr="",
            evidence_manifest=None,
            cleanup=RunnerCleanupResult(required=spec.cleanup_required, attempted=False, succeeded=False, reason="timeout"),
        )

    stdout, stderr = _run_synthetic_adapter(spec)
    stdout_result = sanitize_text(stdout, RedactionArtifactClass.COMMAND_LOG)
    stderr_result = sanitize_text(stderr, RedactionArtifactClass.COMMAND_LOG)
    content = json.dumps(
        {
            "adapter": spec.adapter.value,
            "stdout": stdout_result.sanitized_text,
            "stderr": stderr_result.sanitized_text,
            "redacted": stdout_result.redacted or stderr_result.redacted,
            "credential_lease_id": spec.credential_lease_id,
        },
        sort_keys=True,
    ).encode("utf-8")
    write = evidence_store.write_artifact(
        EvidenceArtifactWriteRequest(
            evidence_id=spec.evidence_id,
            organization_id=spec.organization_id,
            source_job_id=spec.job_id,
            kind=EvidenceKind.COMMAND_LOG,
            created_at=occurred_at,
            redaction_status=RedactionStatus.REDACTED
            if stdout_result.redacted or stderr_result.redacted
            else RedactionStatus.NOT_APPLICABLE,
            retention_class=RetentionClass.STANDARD,
            access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
            content=content,
            contains_sensitive_capture=stdout_result.redacted or stderr_result.redacted,
            artifact_metadata={
                "runner_id": spec.runner_id,
                "adapter": spec.adapter.value,
                "spec_hash": spec.spec_hash,
                "credential_lease_id": spec.credential_lease_id,
            },
            operator_user_id=spec.operator_user_id,
            runner_id=spec.runner_id,
        ),
        EvidenceChain(),
    )
    with_result = _callback(
        running,
        spec,
        RunnerCallbackKind.RESULT,
        "result",
        occurred_at + timedelta(seconds=2),
        evidence_ids=(spec.evidence_id,),
    )
    cleanup_started = _callback(
        with_result,
        spec,
        RunnerCallbackKind.CLEANUP_STARTED,
        "cleanup-started",
        occurred_at + timedelta(seconds=3),
    )
    cleanup_success = bool(spec.adapter_parameters.get("cleanup_success", True))
    if not cleanup_success:
        return RunnerExecutionResult(
            allowed=True,
            reason="cleanup_failed",
            exit_classification=RunnerExitClassification.CLEANUP_FAILED,
            state=cleanup_started,
            sanitized_stdout=stdout_result.sanitized_text,
            sanitized_stderr=stderr_result.sanitized_text,
            evidence_manifest=write.manifest,
            cleanup=RunnerCleanupResult(required=True, attempted=True, succeeded=False, reason="cleanup_failed"),
        )
    final_state = _callback(
        cleanup_started,
        spec,
        RunnerCallbackKind.CLEANUP_COMPLETED,
        "cleanup-completed",
        occurred_at + timedelta(seconds=4),
    )
    return RunnerExecutionResult(
        allowed=True,
        reason="succeeded",
        exit_classification=RunnerExitClassification.SUCCEEDED,
        state=final_state,
        sanitized_stdout=stdout_result.sanitized_text,
        sanitized_stderr=stderr_result.sanitized_text,
        evidence_manifest=write.manifest,
        cleanup=RunnerCleanupResult(required=True, attempted=True, succeeded=True, reason="cleanup_completed"),
    )


def _deny_reason(spec: RunnerJobSpec, runner: RunnerContract, occurred_at: datetime) -> str | None:
    try:
        verify_runner_job_spec(spec)
    except ValueError as exc:
        return str(exc)
    if spec.adapter not in ALLOWLISTED_ADAPTERS:
        return "adapter_not_approved"
    if spec.adapter is RunnerAdapterKind.LAB_ECHO and spec.target.target_type is not TargetType.LAB_TARGET:
        return "lab_target_required"
    if spec.target.normalized() != runner.target_scope.normalized():
        return "unscoped_target"
    if spec.mode not in runner.capabilities:
        return "runner_capability_missing"
    if spec.policy_expires_at <= occurred_at:
        return "current_policy_decision_required"
    return None


def _run_synthetic_adapter(spec: RunnerJobSpec) -> tuple[str, str]:
    if spec.adapter is RunnerAdapterKind.DRY_RUN:
        return (f"dry-run completed for {spec.job_id}", "")
    if spec.adapter is RunnerAdapterKind.LAB_ECHO:
        return (str(spec.adapter_parameters.get("stdout", "lab echo completed")), str(spec.adapter_parameters.get("stderr", "")))
    raise ValueError("adapter_not_approved")


def _callback(
    state: JobQueueState,
    spec: RunnerJobSpec,
    kind: RunnerCallbackKind,
    label: str,
    occurred_at: datetime,
    *,
    evidence_ids: tuple[str, ...] = (),
) -> JobQueueState:
    next_state, decision = state.handle_callback(
        RunnerCallback(
            callback_id=f"{spec.spec_id}:{label}",
            runner_id=spec.runner_id,
            job_id=spec.job_id,
            kind=kind,
            occurred_at=occurred_at,
            evidence_ids=evidence_ids,
        ),
        actor_user_id=spec.runner_id,
        event_id=f"{spec.spec_id}:callback:{label}",
    )
    if not decision.allowed:
        raise ValueError(decision.reason)
    return next_state


def _denied(state: JobQueueState, reason: str) -> RunnerExecutionResult:
    return RunnerExecutionResult(
        allowed=False,
        reason=reason,
        exit_classification=RunnerExitClassification.DENIED,
        state=state,
        sanitized_stdout="",
        sanitized_stderr="",
        evidence_manifest=None,
        cleanup=RunnerCleanupResult(required=False, attempted=False, succeeded=False, reason="denied"),
    )


def _validate_spec_basics(spec: RunnerJobSpec) -> None:
    for field_name, value in (
        ("spec_id", spec.spec_id),
        ("job_id", spec.job_id),
        ("organization_id", spec.organization_id),
        ("runner_id", spec.runner_id),
        ("policy_decision_id", spec.policy_decision_id),
        ("evidence_id", spec.evidence_id),
        ("operator_user_id", spec.operator_user_id),
    ):
        _require_non_empty(field_name, value)
    if spec.timeout_seconds <= 0:
        raise ValueError("missing_timeout")
    if not spec.cleanup_required:
        raise ValueError("missing_cleanup_policy")
    _require_timezone(spec.requested_at)
    _require_timezone(spec.policy_expires_at)


def _spec_hash(spec: RunnerJobSpec) -> str:
    payload = {
        "spec_id": spec.spec_id,
        "job_id": spec.job_id,
        "organization_id": spec.organization_id,
        "runner_id": spec.runner_id,
        "adapter": spec.adapter.value,
        "mode": spec.mode.value,
        "target": {"target_type": spec.target.target_type.value, "value": spec.target.normalized().value},
        "policy_decision_id": spec.policy_decision_id,
        "policy_expires_at": spec.policy_expires_at.isoformat(),
        "requested_at": spec.requested_at.isoformat(),
        "timeout_seconds": spec.timeout_seconds,
        "cleanup_required": spec.cleanup_required,
        "evidence_id": spec.evidence_id,
        "operator_user_id": spec.operator_user_id,
        "credential_lease_id": spec.credential_lease_id,
        "adapter_parameters": spec.adapter_parameters,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _mapping(value: object, field_name: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"invalid_{field_name}")
    return value


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
