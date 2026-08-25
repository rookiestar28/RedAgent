"""Persistent control-plane and ROE workflow contracts.

compat_055 provides a repo-local durable control-plane baseline. It does not expose a
web server, dispatch runners, execute scanners, or contact targets.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Mapping

from redagent_platform import active_policy, domain, target_inventory
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.job_queue import PolicyGrant
from redagent_platform.scope_authorization import EngagementScope, JobScopeRequest, ScopeDecision, ScopeTarget, decide_scope


class RoeStatus(str, Enum):
    DRAFT = "draft"
    APPROVED = "approved"
    SUSPENDED = "suspended"
    REVOKED = "revoked"
    SUPERSEDED = "superseded"


class ControlPlaneRecordType(str, Enum):
    ENGAGEMENT = "engagement"
    TARGET = "target"
    ROE_VERSION = "roe_version"
    APPROVAL = "approval"
    REVOCATION = "revocation"
    POLICY_DECISION = "policy_decision"
    OPERATOR_CONFIRMATION = "operator_confirmation"


@dataclass(frozen=True, kw_only=True)
class EngagementRecord:
    engagement_id: str
    organization_id: str
    name: str
    owner_user_id: str
    created_at: datetime


@dataclass(frozen=True, kw_only=True)
class ControlPlaneTargetRecord:
    target: target_inventory.InventoryTarget
    registered_at: datetime
    registered_by_user_id: str


@dataclass(frozen=True, kw_only=True)
class RoeVersionRecord:
    roe_version_id: str
    engagement_id: str
    organization_id: str
    version: int
    status: RoeStatus
    allowed_targets: tuple[ScopeTarget, ...]
    forbidden_targets: tuple[ScopeTarget, ...]
    allowed_modes: tuple[domain.TestMode, ...]
    window_start: datetime
    window_end: datetime
    max_interactions: int
    max_rate_per_second: float
    emergency_contact_method: str | None
    created_by_user_id: str
    created_at: datetime
    approved_by_user_id: str | None = None
    approved_at: datetime | None = None
    superseded_by_version_id: str | None = None
    status_reason: str | None = None


@dataclass(frozen=True, kw_only=True)
class ApprovalRecord:
    approval_id: str
    roe_version_id: str
    approved_by_user_id: str
    approved_at: datetime
    approval_label: str


@dataclass(frozen=True, kw_only=True)
class RevocationRecord:
    revocation_id: str
    roe_version_id: str
    revoked_by_user_id: str
    revoked_at: datetime
    reason: str


@dataclass(frozen=True, kw_only=True)
class PolicyDecisionRecord:
    decision_id: str
    roe_version_id: str
    organization_id: str
    engagement_id: str
    outcome: domain.PolicyDecisionOutcome
    reason: str
    decided_at: datetime
    expires_at: datetime
    target: ScopeTarget
    mode: domain.TestMode
    projected_interactions: int
    operator_user_id: str | None

    @property
    def allowed(self) -> bool:
        return self.outcome is domain.PolicyDecisionOutcome.ALLOW


@dataclass(frozen=True, kw_only=True)
class OperatorConfirmationRecord:
    confirmation_id: str
    roe_version_id: str
    operator_user_id: str
    confirmed_at: datetime
    scope_acknowledged: bool
    risk_acknowledged: bool
    stop_conditions_acknowledged: bool
    policy_decision_id: str | None = None

    def to_active_confirmation(self) -> active_policy.OperatorConfirmation:
        return active_policy.OperatorConfirmation(
            confirmed_by_user_id=self.operator_user_id,
            confirmed_at=self.confirmed_at,
            scope_acknowledged=self.scope_acknowledged,
            risk_acknowledged=self.risk_acknowledged,
            stop_conditions_acknowledged=self.stop_conditions_acknowledged,
        )


@dataclass(frozen=True, kw_only=True)
class PersistentControlRecord:
    record_type: ControlPlaneRecordType
    record_id: str
    payload: Mapping[str, object]
    record_hash: str


@dataclass(frozen=True, kw_only=True)
class PolicyDecisionCheck:
    allowed: bool
    reason: str


@dataclass(frozen=True)
class ControlPlaneState:
    engagements: tuple[EngagementRecord, ...] = ()
    targets: tuple[ControlPlaneTargetRecord, ...] = ()
    roe_versions: tuple[RoeVersionRecord, ...] = ()
    approvals: tuple[ApprovalRecord, ...] = ()
    revocations: tuple[RevocationRecord, ...] = ()
    policy_decisions: tuple[PolicyDecisionRecord, ...] = ()
    operator_confirmations: tuple[OperatorConfirmationRecord, ...] = ()
    audit_chain: EvidenceChain = EvidenceChain()

    def create_engagement(
        self,
        engagement: EngagementRecord,
        *,
        actor_user_id: str,
        event_id: str,
    ) -> "ControlPlaneState":
        validate_engagement(engagement)
        if any(existing.engagement_id == engagement.engagement_id for existing in self.engagements):
            raise ValueError("engagement_already_exists")
        return ControlPlaneState(
            engagements=self.engagements + (engagement,),
            targets=self.targets,
            roe_versions=self.roe_versions,
            approvals=self.approvals,
            revocations=self.revocations,
            policy_decisions=self.policy_decisions,
            operator_confirmations=self.operator_confirmations,
            audit_chain=_append_transition(
                self.audit_chain,
                event_id=event_id,
                organization_id=engagement.organization_id,
                actor_user_id=actor_user_id,
                subject_type="engagement",
                subject_id=engagement.engagement_id,
                occurred_at=engagement.created_at,
                transition="engagement_created",
            ),
        )

    def register_target(
        self,
        target: ControlPlaneTargetRecord,
        *,
        actor_user_id: str,
        event_id: str,
    ) -> "ControlPlaneState":
        validate_target_record(target)
        _require_engagement(self, target.target.engagement_id)
        if any(existing.target.id == target.target.id for existing in self.targets):
            raise ValueError("target_already_exists")
        return _replace_state(
            self,
            targets=self.targets + (target,),
            audit_chain=_append_transition(
                self.audit_chain,
                event_id=event_id,
                organization_id=target.target.organization_id,
                actor_user_id=actor_user_id,
                subject_type="target",
                subject_id=target.target.id,
                occurred_at=target.registered_at,
                transition="target_registered",
            ),
        )

    def create_roe_draft(
        self,
        roe: RoeVersionRecord,
        *,
        actor_user_id: str,
        event_id: str,
    ) -> "ControlPlaneState":
        validate_roe_shape(roe)
        if roe.status is not RoeStatus.DRAFT:
            raise ValueError("roe_draft_status_required")
        _require_engagement(self, roe.engagement_id)
        if any(existing.roe_version_id == roe.roe_version_id for existing in self.roe_versions):
            raise ValueError("roe_version_already_exists")
        if any(existing.engagement_id == roe.engagement_id and existing.version == roe.version for existing in self.roe_versions):
            raise ValueError("roe_version_number_already_exists")
        return _replace_state(
            self,
            roe_versions=self.roe_versions + (roe,),
            audit_chain=_append_transition(
                self.audit_chain,
                event_id=event_id,
                organization_id=roe.organization_id,
                actor_user_id=actor_user_id,
                subject_type="roe_version",
                subject_id=roe.roe_version_id,
                occurred_at=roe.created_at,
                transition="roe_draft_created",
            ),
        )

    def approve_roe(self, approval: ApprovalRecord, *, event_id: str) -> "ControlPlaneState":
        validate_approval(approval)
        roe = _require_roe(self, approval.roe_version_id)
        if roe.status is not RoeStatus.DRAFT:
            raise ValueError("roe_must_be_draft_to_approve")
        if not _roe_targets_are_registered(self, roe):
            raise ValueError("roe_target_allowlist_not_registered")
        approved = _replace_roe(
            roe,
            status=RoeStatus.APPROVED,
            approved_by_user_id=approval.approved_by_user_id,
            approved_at=approval.approved_at,
            status_reason=approval.approval_label,
        )
        return _replace_state(
            self,
            roe_versions=_upsert_roe(self.roe_versions, approved),
            approvals=self.approvals + (approval,),
            audit_chain=_append_transition(
                self.audit_chain,
                event_id=event_id,
                organization_id=roe.organization_id,
                actor_user_id=approval.approved_by_user_id,
                subject_type="roe_version",
                subject_id=roe.roe_version_id,
                occurred_at=approval.approved_at,
                transition="roe_approved",
            ),
        )

    def suspend_roe(
        self,
        *,
        roe_version_id: str,
        suspended_by_user_id: str,
        suspended_at: datetime,
        reason: str,
        event_id: str,
    ) -> "ControlPlaneState":
        return self._set_roe_status(
            roe_version_id=roe_version_id,
            status=RoeStatus.SUSPENDED,
            actor_user_id=suspended_by_user_id,
            occurred_at=suspended_at,
            reason=reason,
            event_id=event_id,
            transition="roe_suspended",
        )

    def revoke_roe(self, revocation: RevocationRecord, *, event_id: str) -> "ControlPlaneState":
        validate_revocation(revocation)
        state = self._set_roe_status(
            roe_version_id=revocation.roe_version_id,
            status=RoeStatus.REVOKED,
            actor_user_id=revocation.revoked_by_user_id,
            occurred_at=revocation.revoked_at,
            reason=revocation.reason,
            event_id=event_id,
            transition="roe_revoked",
        )
        return _replace_state(state, revocations=state.revocations + (revocation,))

    def supersede_roe(
        self,
        *,
        current_roe_version_id: str,
        replacement: RoeVersionRecord,
        actor_user_id: str,
        event_id: str,
    ) -> "ControlPlaneState":
        current = _require_roe(self, current_roe_version_id)
        if current.status is not RoeStatus.APPROVED:
            raise ValueError("only_approved_roe_can_be_superseded")
        state = self.create_roe_draft(replacement, actor_user_id=actor_user_id, event_id=f"{event_id}:draft")
        superseded = _replace_roe(
            current,
            status=RoeStatus.SUPERSEDED,
            superseded_by_version_id=replacement.roe_version_id,
            status_reason="superseded",
        )
        return _replace_state(
            state,
            roe_versions=_upsert_roe(state.roe_versions, superseded),
            audit_chain=_append_transition(
                state.audit_chain,
                event_id=event_id,
                organization_id=current.organization_id,
                actor_user_id=actor_user_id,
                subject_type="roe_version",
                subject_id=current.roe_version_id,
                occurred_at=replacement.created_at,
                transition="roe_superseded",
            ),
        )

    def evaluate_policy(
        self,
        *,
        decision_id: str,
        roe_version_id: str,
        request: JobScopeRequest,
        decided_at: datetime,
        expires_at: datetime,
        operator_user_id: str | None,
        event_id: str,
    ) -> tuple["ControlPlaneState", PolicyDecisionRecord]:
        _require_non_empty("decision_id", decision_id)
        _require_timezone(decided_at)
        _require_timezone(expires_at)
        if expires_at <= decided_at:
            raise ValueError("policy_decision_expiry_invalid")
        scope_result = build_scope_from_current_roe(self, roe_version_id)
        if isinstance(scope_result, ScopeDecision):
            roe = _require_roe(self, roe_version_id)
            decision = PolicyDecisionRecord(
                decision_id=decision_id.strip(),
                roe_version_id=roe_version_id,
                organization_id=roe.organization_id,
                engagement_id=roe.engagement_id,
                outcome=scope_result.outcome,
                reason=scope_result.reason,
                decided_at=decided_at,
                expires_at=expires_at,
                target=request.target.normalized(),
                mode=request.mode,
                projected_interactions=request.projected_interactions,
                operator_user_id=operator_user_id,
            )
        else:
            scope = scope_result
            scope_decision = decide_scope(scope, request)
            decision = PolicyDecisionRecord(
                decision_id=decision_id.strip(),
                roe_version_id=roe_version_id,
                organization_id=scope.organization_id,
                engagement_id=scope.engagement_id,
                outcome=scope_decision.outcome,
                reason=scope_decision.reason,
                decided_at=decided_at,
                expires_at=expires_at,
                target=request.target.normalized(),
                mode=request.mode,
                projected_interactions=request.projected_interactions,
                operator_user_id=operator_user_id,
            )
        next_state = _replace_state(
            self,
            policy_decisions=self.policy_decisions + (decision,),
            audit_chain=_append_policy_decision(self.audit_chain, decision, event_id),
        )
        return next_state, decision

    def record_operator_confirmation(
        self,
        confirmation: OperatorConfirmationRecord,
        *,
        event_id: str,
    ) -> "ControlPlaneState":
        validate_operator_confirmation(confirmation)
        _require_roe(self, confirmation.roe_version_id)
        if confirmation.policy_decision_id:
            current = assert_policy_decision_current(self, confirmation.policy_decision_id, confirmation.confirmed_at)
            if not current.allowed:
                raise ValueError(current.reason)
        return _replace_state(
            self,
            operator_confirmations=self.operator_confirmations + (confirmation,),
            audit_chain=_append_transition(
                self.audit_chain,
                event_id=event_id,
                organization_id=_require_roe(self, confirmation.roe_version_id).organization_id,
                actor_user_id=confirmation.operator_user_id,
                subject_type="operator_confirmation",
                subject_id=confirmation.confirmation_id,
                occurred_at=confirmation.confirmed_at,
                transition="operator_confirmed",
            ),
        )

    def _set_roe_status(
        self,
        *,
        roe_version_id: str,
        status: RoeStatus,
        actor_user_id: str,
        occurred_at: datetime,
        reason: str,
        event_id: str,
        transition: str,
    ) -> "ControlPlaneState":
        _require_non_empty("reason", reason)
        _require_timezone(occurred_at)
        roe = _require_roe(self, roe_version_id)
        if roe.status in {RoeStatus.REVOKED, RoeStatus.SUPERSEDED}:
            raise ValueError("terminal_roe_status")
        changed = _replace_roe(roe, status=status, status_reason=reason)
        return _replace_state(
            self,
            roe_versions=_upsert_roe(self.roe_versions, changed),
            audit_chain=_append_transition(
                self.audit_chain,
                event_id=event_id,
                organization_id=roe.organization_id,
                actor_user_id=actor_user_id,
                subject_type="roe_version",
                subject_id=roe.roe_version_id,
                occurred_at=occurred_at,
                transition=transition,
            ),
        )


class JsonlControlPlaneStore:
    """Tiny JSONL persistence adapter used until compat_055 is backed by a service DB."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def append(self, record_type: ControlPlaneRecordType, record_id: str, payload: Mapping[str, object]) -> PersistentControlRecord:
        _require_non_empty("record_id", record_id)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        record_hash = _canonical_sha256({"record_type": record_type.value, "record_id": record_id, "payload": payload})
        row = {
            "record_type": record_type.value,
            "record_id": record_id,
            "payload": payload,
            "record_hash": record_hash,
        }
        with self.path.open("a", encoding="utf-8", newline="\n") as handle:
            handle.write(json.dumps(row, sort_keys=True, separators=(",", ":"), default=str) + "\n")
        return PersistentControlRecord(record_type=record_type, record_id=record_id, payload=payload, record_hash=record_hash)

    def read_all(self) -> tuple[PersistentControlRecord, ...]:
        if not self.path.exists():
            return ()
        records: list[PersistentControlRecord] = []
        with self.path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                row = json.loads(line)
                try:
                    record_type = ControlPlaneRecordType(row["record_type"])
                    record_id = str(row["record_id"])
                    payload = row["payload"]
                    record_hash = str(row["record_hash"])
                except (KeyError, ValueError, TypeError) as exc:
                    raise ValueError(f"invalid_control_plane_record:{line_number}") from exc
                expected = _canonical_sha256({"record_type": record_type.value, "record_id": record_id, "payload": payload})
                if expected != record_hash:
                    raise ValueError(f"control_plane_record_hash_mismatch:{line_number}")
                records.append(
                    PersistentControlRecord(
                        record_type=record_type,
                        record_id=record_id,
                        payload=payload,
                        record_hash=record_hash,
                    )
                )
        return tuple(records)


def build_roe_draft(
    *,
    roe_version_id: str,
    engagement: EngagementRecord,
    version: int,
    targets: tuple[target_inventory.InventoryTarget, ...],
    forbidden_targets: tuple[ScopeTarget, ...],
    allowed_modes: tuple[domain.TestMode, ...],
    window_start: datetime,
    window_end: datetime,
    max_interactions: int,
    max_rate_per_second: float,
    emergency_contact_method: str | None,
    created_by_user_id: str,
    created_at: datetime,
) -> RoeVersionRecord:
    return RoeVersionRecord(
        roe_version_id=roe_version_id,
        engagement_id=engagement.engagement_id,
        organization_id=engagement.organization_id,
        version=version,
        status=RoeStatus.DRAFT,
        allowed_targets=tuple(target.to_scope_target() for target in targets),
        forbidden_targets=tuple(target.normalized() for target in forbidden_targets),
        allowed_modes=tuple(allowed_modes),
        window_start=window_start,
        window_end=window_end,
        max_interactions=max_interactions,
        max_rate_per_second=max_rate_per_second,
        emergency_contact_method=emergency_contact_method,
        created_by_user_id=created_by_user_id,
        created_at=created_at,
    )


def build_scope_from_current_roe(state: ControlPlaneState, roe_version_id: str) -> EngagementScope | ScopeDecision:
    roe = _require_roe(state, roe_version_id)
    denial = _roe_current_denial(roe)
    if denial:
        return ScopeDecision(outcome=domain.PolicyDecisionOutcome.DENY, reason=denial)
    return EngagementScope(
        engagement_id=roe.engagement_id,
        organization_id=roe.organization_id,
        authorization_status=domain.AuthorizationStatus.APPROVED,
        approved_by_user_id=roe.approved_by_user_id,
        allowed_targets=tuple(target.normalized() for target in roe.allowed_targets),
        forbidden_targets=tuple(target.normalized() for target in roe.forbidden_targets),
        allowed_modes=roe.allowed_modes,
        window_start=roe.window_start,
        window_end=roe.window_end,
        max_interactions=roe.max_interactions,
        max_rate_per_second=roe.max_rate_per_second,
        emergency_contact_method=roe.emergency_contact_method,
    )


def assert_policy_decision_current(state: ControlPlaneState, decision_id: str, now: datetime) -> PolicyDecisionCheck:
    _require_timezone(now)
    decision = _require_policy_decision(state, decision_id)
    if not decision.allowed:
        return PolicyDecisionCheck(allowed=False, reason=f"policy_decision_not_allowed:{decision.reason}")
    if not (decision.decided_at <= now < decision.expires_at):
        return PolicyDecisionCheck(allowed=False, reason="stale_policy_decision")
    roe = _require_roe(state, decision.roe_version_id)
    denial = _roe_current_denial(roe)
    if denial:
        return PolicyDecisionCheck(allowed=False, reason=f"stale_policy_decision:{denial}")
    return PolicyDecisionCheck(allowed=True, reason="policy_decision_current")


def policy_grant_from_decision(decision: PolicyDecisionRecord) -> PolicyGrant:
    if not decision.allowed:
        raise ValueError("policy_decision_must_allow")
    return PolicyGrant(
        decision_id=decision.decision_id,
        organization_id=decision.organization_id,
        outcome=decision.outcome,
        decided_at=decision.decided_at,
        expires_at=decision.expires_at,
        reason=decision.reason,
    )


def engagement_payload(record: EngagementRecord) -> dict[str, object]:
    validate_engagement(record)
    return {
        "engagement_id": record.engagement_id,
        "organization_id": record.organization_id,
        "name": record.name,
        "owner_user_id": record.owner_user_id,
        "created_at": record.created_at.isoformat(),
    }


def target_payload(record: ControlPlaneTargetRecord) -> dict[str, object]:
    validate_target_record(record)
    target = record.target
    return {
        "target_id": target.id,
        "organization_id": target.organization_id,
        "engagement_id": target.engagement_id,
        "owner_label": target.owner_label,
        "target_type": target.target_type.value,
        "value": target.value,
        "environment": target.environment.value,
        "data_sensitivity": target.data_sensitivity.value,
        "authorization_status": target.authorization_status.value,
        "allowed_modes": tuple(mode.value for mode in target.allowed_modes),
        "registered_at": record.registered_at.isoformat(),
        "registered_by_user_id": record.registered_by_user_id,
    }


def roe_payload(record: RoeVersionRecord) -> dict[str, object]:
    validate_roe_shape(record)
    return {
        "roe_version_id": record.roe_version_id,
        "engagement_id": record.engagement_id,
        "organization_id": record.organization_id,
        "version": record.version,
        "status": record.status.value,
        "allowed_targets": tuple(_scope_target_payload(target) for target in record.allowed_targets),
        "forbidden_targets": tuple(_scope_target_payload(target) for target in record.forbidden_targets),
        "allowed_modes": tuple(mode.value for mode in record.allowed_modes),
        "window_start": record.window_start.isoformat(),
        "window_end": record.window_end.isoformat(),
        "max_interactions": record.max_interactions,
        "max_rate_per_second": record.max_rate_per_second,
        "emergency_contact_method": record.emergency_contact_method,
        "created_by_user_id": record.created_by_user_id,
        "created_at": record.created_at.isoformat(),
        "approved_by_user_id": record.approved_by_user_id,
        "approved_at": record.approved_at.isoformat() if record.approved_at else None,
        "superseded_by_version_id": record.superseded_by_version_id,
        "status_reason": record.status_reason,
    }


def policy_decision_payload(record: PolicyDecisionRecord) -> dict[str, object]:
    return {
        "decision_id": record.decision_id,
        "roe_version_id": record.roe_version_id,
        "organization_id": record.organization_id,
        "engagement_id": record.engagement_id,
        "outcome": record.outcome.value,
        "reason": record.reason,
        "decided_at": record.decided_at.isoformat(),
        "expires_at": record.expires_at.isoformat(),
        "target": _scope_target_payload(record.target),
        "mode": record.mode.value,
        "projected_interactions": record.projected_interactions,
        "operator_user_id": record.operator_user_id,
    }


def validate_engagement(record: EngagementRecord) -> None:
    for field_name, value in (
        ("engagement_id", record.engagement_id),
        ("organization_id", record.organization_id),
        ("name", record.name),
        ("owner_user_id", record.owner_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(record.created_at)


def validate_target_record(record: ControlPlaneTargetRecord) -> None:
    _require_non_empty("registered_by_user_id", record.registered_by_user_id)
    _require_timezone(record.registered_at)


def validate_roe_shape(record: RoeVersionRecord) -> None:
    for field_name, value in (
        ("roe_version_id", record.roe_version_id),
        ("engagement_id", record.engagement_id),
        ("organization_id", record.organization_id),
        ("created_by_user_id", record.created_by_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(record.created_at)
    _require_timezone(record.window_start)
    _require_timezone(record.window_end)
    if record.approved_at is not None:
        _require_timezone(record.approved_at)
    if record.version <= 0:
        raise ValueError("invalid_roe_version")
    if not record.allowed_targets:
        raise ValueError("missing_target_allowlist")
    if not record.allowed_modes:
        raise ValueError("missing_allowed_modes")
    if record.window_start >= record.window_end:
        raise ValueError("invalid_time_window")
    if record.max_interactions <= 0:
        raise ValueError("invalid_interaction_cap")
    if record.max_rate_per_second <= 0:
        raise ValueError("invalid_rate_limit")
    if not record.emergency_contact_method or not record.emergency_contact_method.strip():
        raise ValueError("missing_emergency_contact")


def validate_approval(record: ApprovalRecord) -> None:
    for field_name, value in (
        ("approval_id", record.approval_id),
        ("roe_version_id", record.roe_version_id),
        ("approved_by_user_id", record.approved_by_user_id),
        ("approval_label", record.approval_label),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(record.approved_at)


def validate_revocation(record: RevocationRecord) -> None:
    for field_name, value in (
        ("revocation_id", record.revocation_id),
        ("roe_version_id", record.roe_version_id),
        ("revoked_by_user_id", record.revoked_by_user_id),
        ("reason", record.reason),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(record.revoked_at)


def validate_operator_confirmation(record: OperatorConfirmationRecord) -> None:
    for field_name, value in (
        ("confirmation_id", record.confirmation_id),
        ("roe_version_id", record.roe_version_id),
        ("operator_user_id", record.operator_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(record.confirmed_at)
    if not record.scope_acknowledged:
        raise ValueError("operator_scope_acknowledgement_required")
    if not record.risk_acknowledged:
        raise ValueError("operator_risk_acknowledgement_required")
    if not record.stop_conditions_acknowledged:
        raise ValueError("operator_stop_condition_acknowledgement_required")


def _roe_current_denial(roe: RoeVersionRecord) -> str | None:
    if roe.status is not RoeStatus.APPROVED:
        return f"roe_not_current:{roe.status.value}"
    if not roe.approved_by_user_id:
        return "missing_approver"
    return None


def _append_policy_decision(chain: EvidenceChain, decision: PolicyDecisionRecord, event_id: str) -> EvidenceChain:
    return chain.append_audit_event(
        event_id=event_id,
        organization_id=decision.organization_id,
        actor_user_id=decision.operator_user_id,
        action=AuditAction.POLICY_DECISION,
        subject_type="control_plane_policy_decision",
        subject_id=decision.decision_id,
        occurred_at=decision.decided_at,
        details={
            "roe_version_id": decision.roe_version_id,
            "outcome": decision.outcome.value,
            "reason": decision.reason,
            "target": decision.target.normalized().value,
            "mode": decision.mode.value,
        },
    )


def _append_transition(
    chain: EvidenceChain,
    *,
    event_id: str,
    organization_id: str,
    actor_user_id: str,
    subject_type: str,
    subject_id: str,
    occurred_at: datetime,
    transition: str,
) -> EvidenceChain:
    _require_non_empty("transition", transition)
    return chain.append_audit_event(
        event_id=event_id,
        organization_id=organization_id,
        actor_user_id=actor_user_id,
        action=AuditAction.TARGET_CHANGE,
        subject_type=subject_type,
        subject_id=subject_id,
        occurred_at=occurred_at,
        details={"transition": transition},
    )


def _roe_targets_are_registered(state: ControlPlaneState, roe: RoeVersionRecord) -> bool:
    registered = {target.target.to_scope_target().normalized() for target in state.targets if target.target.engagement_id == roe.engagement_id}
    return all(target.normalized() in registered for target in roe.allowed_targets)


def _require_engagement(state: ControlPlaneState, engagement_id: str) -> EngagementRecord:
    for engagement in state.engagements:
        if engagement.engagement_id == engagement_id:
            return engagement
    raise ValueError("engagement_not_found")


def _require_roe(state: ControlPlaneState, roe_version_id: str) -> RoeVersionRecord:
    for roe in state.roe_versions:
        if roe.roe_version_id == roe_version_id:
            return roe
    raise ValueError("roe_version_not_found")


def _require_policy_decision(state: ControlPlaneState, decision_id: str) -> PolicyDecisionRecord:
    for decision in state.policy_decisions:
        if decision.decision_id == decision_id:
            return decision
    raise ValueError("policy_decision_not_found")


def _replace_state(
    state: ControlPlaneState,
    *,
    engagements: tuple[EngagementRecord, ...] | None = None,
    targets: tuple[ControlPlaneTargetRecord, ...] | None = None,
    roe_versions: tuple[RoeVersionRecord, ...] | None = None,
    approvals: tuple[ApprovalRecord, ...] | None = None,
    revocations: tuple[RevocationRecord, ...] | None = None,
    policy_decisions: tuple[PolicyDecisionRecord, ...] | None = None,
    operator_confirmations: tuple[OperatorConfirmationRecord, ...] | None = None,
    audit_chain: EvidenceChain | None = None,
) -> ControlPlaneState:
    return ControlPlaneState(
        engagements=engagements if engagements is not None else state.engagements,
        targets=targets if targets is not None else state.targets,
        roe_versions=roe_versions if roe_versions is not None else state.roe_versions,
        approvals=approvals if approvals is not None else state.approvals,
        revocations=revocations if revocations is not None else state.revocations,
        policy_decisions=policy_decisions if policy_decisions is not None else state.policy_decisions,
        operator_confirmations=operator_confirmations if operator_confirmations is not None else state.operator_confirmations,
        audit_chain=audit_chain if audit_chain is not None else state.audit_chain,
    )


def _upsert_roe(records: tuple[RoeVersionRecord, ...], changed: RoeVersionRecord) -> tuple[RoeVersionRecord, ...]:
    return tuple(record for record in records if record.roe_version_id != changed.roe_version_id) + (changed,)


def _replace_roe(
    roe: RoeVersionRecord,
    *,
    status: RoeStatus | None = None,
    approved_by_user_id: str | None = None,
    approved_at: datetime | None = None,
    superseded_by_version_id: str | None = None,
    status_reason: str | None = None,
) -> RoeVersionRecord:
    return RoeVersionRecord(
        roe_version_id=roe.roe_version_id,
        engagement_id=roe.engagement_id,
        organization_id=roe.organization_id,
        version=roe.version,
        status=status or roe.status,
        allowed_targets=roe.allowed_targets,
        forbidden_targets=roe.forbidden_targets,
        allowed_modes=roe.allowed_modes,
        window_start=roe.window_start,
        window_end=roe.window_end,
        max_interactions=roe.max_interactions,
        max_rate_per_second=roe.max_rate_per_second,
        emergency_contact_method=roe.emergency_contact_method,
        created_by_user_id=roe.created_by_user_id,
        created_at=roe.created_at,
        approved_by_user_id=approved_by_user_id if approved_by_user_id is not None else roe.approved_by_user_id,
        approved_at=approved_at if approved_at is not None else roe.approved_at,
        superseded_by_version_id=superseded_by_version_id
        if superseded_by_version_id is not None
        else roe.superseded_by_version_id,
        status_reason=status_reason if status_reason is not None else roe.status_reason,
    )


def _scope_target_payload(target: ScopeTarget) -> dict[str, str]:
    normalized = target.normalized()
    return {"target_type": normalized.target_type.value, "value": normalized.value}


def _canonical_sha256(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
