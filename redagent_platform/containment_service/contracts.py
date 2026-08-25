"""Closed compat_101 control, phase-receipt, incident, and quota contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


SCHEMA_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_EXTENSION = re.compile(r"^[a-z][a-z0-9_.-]{2,63}$")


class ControlScopeKind(str, Enum):
    JOB = "job"
    CAMPAIGN = "campaign"
    CAPABILITY = "capability"
    TENANT = "tenant"
    GLOBAL = "global"


class ContainmentPhase(str, Enum):
    DISPATCH_BLOCK = "dispatch_block"
    WORKFLOW_ACK = "workflow_ack"
    RUNNER_ACK = "runner_ack"
    WORKLOAD_STOP = "workload_stop"
    NETWORK_CONTAINMENT = "network_containment"
    LEASE_REVOCATION = "lease_revocation"
    CLEANUP = "cleanup"
    EVIDENCE_LOCK = "evidence_lock"


REQUIRED_CONTAINMENT_PHASES = tuple(ContainmentPhase)


class ContainmentOutcome(str, Enum):
    CONTAINED = "contained"
    CONTAINED_WITH_RESIDUAL_RISK = "contained_with_residual_risk"
    CONTAINMENT_FAILED = "containment_failed"


class QuotaDimension(str, Enum):
    TIME_SECONDS = "time_seconds"
    OPERATIONS = "operations"
    CONCURRENCY = "concurrency"
    TARGETS = "targets"
    DATA_BYTES = "data_bytes"
    EVIDENCE_BYTES = "evidence_bytes"
    EXTENSION = "extension"


@dataclass(frozen=True)
class ControlScope:
    kind: ControlScopeKind
    scope_id: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.kind, ControlScopeKind):
            raise ValueError("control_scope_kind_invalid")
        if self.kind is ControlScopeKind.GLOBAL:
            if self.scope_id is not None:
                raise ValueError("control_global_scope_id_forbidden")
        elif self.scope_id is None or not _IDENTIFIER.fullmatch(self.scope_id):
            raise ValueError("control_scope_id_required")

    @property
    def canonical_key(self) -> str:
        return f"{self.kind.value}:{self.scope_id or '*'}"


@dataclass(frozen=True, kw_only=True)
class StopRequest:
    schema_version: str
    stop_id: str
    tenant_id: str
    scope: ControlScope
    initiated_by: str
    reason: str
    requested_at: datetime
    expected_version: int
    idempotency_key: str

    def __post_init__(self) -> None:
        if self.schema_version != SCHEMA_VERSION:
            raise ValueError("stop_schema_version_invalid")
        for name, value in (
            ("stop_id", self.stop_id), ("tenant_id", self.tenant_id),
            ("initiated_by", self.initiated_by), ("idempotency_key", self.idempotency_key),
        ):
            _identifier(name, value)
        if not self.reason.strip() or len(self.reason) > 500:
            raise ValueError("stop_reason_invalid")
        _time(self.requested_at)
        if self.expected_version < 1:
            raise ValueError("stop_expected_version_invalid")


@dataclass(frozen=True, kw_only=True)
class StopApproval:
    approval_id: str
    stop_id: str
    tenant_id: str
    approver_user_id: str
    request_hash: str
    approved_at: datetime
    expected_version: int

    def __post_init__(self) -> None:
        for name, value in (
            ("approval_id", self.approval_id), ("stop_id", self.stop_id),
            ("tenant_id", self.tenant_id), ("approver_user_id", self.approver_user_id),
        ):
            _identifier(name, value)
        if not re.fullmatch(r"[0-9a-f]{64}", self.request_hash):
            raise ValueError("stop_request_hash_invalid")
        _time(self.approved_at)
        if self.expected_version < 1:
            raise ValueError("stop_approval_version_invalid")

    def authorize(self, request: StopRequest) -> bool:
        # CRITICAL: broad stop activation must preserve distinct-person approval.
        if self.approver_user_id == request.initiated_by:
            raise ValueError("stop_approval_separation_required")
        if self.tenant_id != request.tenant_id or self.stop_id != request.stop_id:
            raise ValueError("stop_approval_scope_mismatch")
        if self.request_hash != canonical_stop_hash(request):
            raise ValueError("stop_approval_request_hash_mismatch")
        return True


@dataclass(frozen=True, kw_only=True)
class PhaseReceipt:
    phase: ContainmentPhase
    state: str
    reason_code: str
    occurred_at: datetime
    duration_ms: int

    def __post_init__(self) -> None:
        if not isinstance(self.phase, ContainmentPhase):
            raise ValueError("containment_phase_invalid")
        if self.state not in {"verified", "failed"}:
            raise ValueError("containment_phase_state_invalid")
        _identifier("reason_code", self.reason_code)
        _time(self.occurred_at)
        if isinstance(self.duration_ms, bool) or self.duration_ms < 0 or self.duration_ms > 3_600_000:
            raise ValueError("containment_duration_invalid")


@dataclass(frozen=True)
class ContainmentAssessment:
    outcome: ContainmentOutcome
    residual_risks: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class QuotaPolicy:
    policy_id: str
    tenant_id: str
    revision: int
    dimension: QuotaDimension
    scope: ControlScope
    hard_limit: int
    window_seconds: int
    active_from: datetime
    active_until: datetime
    extension_name: str | None

    def __post_init__(self) -> None:
        _identifier("policy_id", self.policy_id)
        _identifier("tenant_id", self.tenant_id)
        if isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("quota_revision_invalid")
        if not isinstance(self.dimension, QuotaDimension):
            raise ValueError("quota_dimension_invalid")
        if isinstance(self.hard_limit, bool) or not isinstance(self.hard_limit, int) or self.hard_limit <= 0:
            raise ValueError("quota_limit_invalid")
        if isinstance(self.window_seconds, bool) or not 1 <= self.window_seconds <= 31_536_000:
            raise ValueError("quota_window_invalid")
        _time(self.active_from)
        _time(self.active_until)
        if self.active_until <= self.active_from:
            raise ValueError("quota_activation_window_invalid")
        if self.dimension is QuotaDimension.EXTENSION:
            if self.extension_name is None or not _EXTENSION.fullmatch(self.extension_name):
                raise ValueError("quota_extension_name_required")
        elif self.extension_name is not None:
            raise ValueError("quota_extension_name_forbidden")


def canonical_stop_hash(request: StopRequest) -> str:
    payload = {
        "schema_version": request.schema_version, "stop_id": request.stop_id,
        "tenant_id": request.tenant_id, "scope": request.scope.canonical_key,
        "initiated_by": request.initiated_by, "reason": request.reason.strip(),
        "requested_at": request.requested_at.isoformat(),
        "expected_version": request.expected_version,
        "idempotency_key": request.idempotency_key,
    }
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def aggregate_containment(receipts: tuple[PhaseReceipt, ...]) -> ContainmentAssessment:
    by_phase: dict[ContainmentPhase, PhaseReceipt] = {}
    for receipt in receipts:
        if receipt.phase in by_phase:
            raise ValueError("containment_phase_duplicate")
        by_phase[receipt.phase] = receipt
    missing = tuple(phase for phase in REQUIRED_CONTAINMENT_PHASES if phase not in by_phase)
    if missing:
        return ContainmentAssessment(
            ContainmentOutcome.CONTAINMENT_FAILED,
            tuple(f"missing_phase:{phase.value}" for phase in missing),
        )
    failures = tuple(
        f"{phase.value}:{by_phase[phase].reason_code}"
        for phase in REQUIRED_CONTAINMENT_PHASES if by_phase[phase].state != "verified"
    )
    if not failures:
        return ContainmentAssessment(ContainmentOutcome.CONTAINED, ())
    critical = {
        ContainmentPhase.DISPATCH_BLOCK, ContainmentPhase.WORKFLOW_ACK,
        ContainmentPhase.RUNNER_ACK, ContainmentPhase.WORKLOAD_STOP,
        ContainmentPhase.NETWORK_CONTAINMENT, ContainmentPhase.LEASE_REVOCATION,
        ContainmentPhase.EVIDENCE_LOCK,
    }
    outcome = (
        ContainmentOutcome.CONTAINMENT_FAILED
        if any(by_phase[phase].state != "verified" for phase in critical)
        else ContainmentOutcome.CONTAINED_WITH_RESIDUAL_RISK
    )
    return ContainmentAssessment(outcome, failures)


def _identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _time(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
