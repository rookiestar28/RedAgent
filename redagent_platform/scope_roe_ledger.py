"""Scope and ROE version ledger assurance contracts.

compat_078 adds replayable authorization and scope-change evidence around the compat_055
control plane. It does not dispatch jobs, publish reports, contact targets, or
call external systems.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from redagent_platform import control_plane, domain
from redagent_platform.scope_authorization import ScopeTarget


class ScopeDiffKind(str, Enum):
    INITIAL_SCOPE = "initial_scope"
    TARGET_ADDED = "target_added"
    TARGET_REMOVED = "target_removed"
    MODE_ADDED = "mode_added"
    MODE_REMOVED = "mode_removed"
    TIME_WINDOW_CHANGED = "time_window_changed"
    INTERACTION_CAP_CHANGED = "interaction_cap_changed"
    RATE_LIMIT_CHANGED = "rate_limit_changed"
    EMERGENCY_CONTACT_CHANGED = "emergency_contact_changed"


@dataclass(frozen=True, kw_only=True)
class RoeScopeSnapshot:
    allowed_targets: tuple[ScopeTarget, ...]
    forbidden_targets: tuple[ScopeTarget, ...]
    allowed_modes: tuple[domain.TestMode, ...]
    window_start: datetime
    window_end: datetime
    max_interactions: int
    max_rate_per_second: float
    emergency_contact_method: str


@dataclass(frozen=True, kw_only=True)
class TargetOwnershipEvidence:
    evidence_id: str
    target: ScopeTarget
    owner_label: str
    verified_by_user_id: str
    verified_at: datetime
    expires_at: datetime
    proof_hash: str


@dataclass(frozen=True, kw_only=True)
class ScopeDiffEntry:
    kind: ScopeDiffKind
    field: str
    before: str | None
    after: str | None


@dataclass(frozen=True, kw_only=True)
class RoeLedgerVersion:
    ledger_version_id: str
    parent_ledger_version_id: str | None
    roe_version_id: str
    engagement_id: str
    organization_id: str
    version: int
    snapshot: RoeScopeSnapshot
    diff: tuple[ScopeDiffEntry, ...]
    approver_user_id: str
    approved_at: datetime
    reason: str
    expires_at: datetime
    affected_targets: tuple[ScopeTarget, ...]
    affected_modes: tuple[domain.TestMode, ...]
    ownership_evidence_ids: tuple[str, ...]
    immutable_hash: str


@dataclass(frozen=True, kw_only=True)
class RoeDeviationApproval:
    deviation_id: str
    ledger_version_id: str
    approved_by_user_id: str
    approved_at: datetime
    effective_from: datetime
    expires_at: datetime
    reason: str
    affected_targets: tuple[ScopeTarget, ...]
    affected_modes: tuple[domain.TestMode, ...]
    justification: str
    approval_hash: str


@dataclass(frozen=True, kw_only=True)
class RoeRevocationEntry:
    revocation_id: str
    ledger_version_id: str
    revoked_by_user_id: str
    revoked_at: datetime
    reason: str
    affected_targets: tuple[ScopeTarget, ...]
    affected_modes: tuple[domain.TestMode, ...]
    revocation_hash: str


@dataclass(frozen=True, kw_only=True)
class ScopeGateDecision:
    allowed: bool
    reason: str


@dataclass(frozen=True, kw_only=True)
class AuthorizationReplayProof:
    proof_id: str
    ledger_version_id: str
    policy_decision_id: str
    generated_at: datetime
    scope_version_hash: str
    policy_decision_hash: str
    deviation_hashes: tuple[str, ...]
    revocation_hashes: tuple[str, ...]
    proof_hash: str


def snapshot_from_roe(roe: control_plane.RoeVersionRecord) -> RoeScopeSnapshot:
    control_plane.validate_roe_shape(roe)
    if not roe.emergency_contact_method:
        raise ValueError("missing_emergency_contact")
    return RoeScopeSnapshot(
        allowed_targets=tuple(_normalize_target(target) for target in roe.allowed_targets),
        forbidden_targets=tuple(_normalize_target(target) for target in roe.forbidden_targets),
        allowed_modes=tuple(roe.allowed_modes),
        window_start=roe.window_start,
        window_end=roe.window_end,
        max_interactions=roe.max_interactions,
        max_rate_per_second=roe.max_rate_per_second,
        emergency_contact_method=roe.emergency_contact_method.strip(),
    )


def build_target_ownership_evidence(
    *,
    evidence_id: str,
    target: ScopeTarget,
    owner_label: str,
    verified_by_user_id: str,
    verified_at: datetime,
    expires_at: datetime,
    proof_reference: str,
) -> TargetOwnershipEvidence:
    for field_name, value in (
        ("evidence_id", evidence_id),
        ("owner_label", owner_label),
        ("verified_by_user_id", verified_by_user_id),
        ("proof_reference", proof_reference),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(verified_at)
    _require_timezone(expires_at)
    if expires_at <= verified_at:
        raise ValueError("ownership_evidence_expiry_invalid")
    normalized = _normalize_target(target)
    payload = {
        "evidence_id": evidence_id.strip(),
        "target": _target_payload(normalized),
        "owner_label": owner_label.strip(),
        "verified_by_user_id": verified_by_user_id.strip(),
        "verified_at": verified_at.isoformat(),
        "expires_at": expires_at.isoformat(),
        "proof_reference_hash": _sha256_text(proof_reference),
    }
    return TargetOwnershipEvidence(
        evidence_id=evidence_id.strip(),
        target=normalized,
        owner_label=owner_label.strip(),
        verified_by_user_id=verified_by_user_id.strip(),
        verified_at=verified_at,
        expires_at=expires_at,
        proof_hash=_canonical_sha256(payload),
    )


def build_ledger_version(
    *,
    ledger_version_id: str,
    roe: control_plane.RoeVersionRecord,
    parent: RoeLedgerVersion | None,
    ownership_evidence: tuple[TargetOwnershipEvidence, ...],
    approver_user_id: str,
    approved_at: datetime,
    reason: str,
) -> RoeLedgerVersion:
    _require_non_empty("ledger_version_id", ledger_version_id)
    _require_non_empty("approver_user_id", approver_user_id)
    _require_non_empty("reason", reason)
    _require_timezone(approved_at)
    if roe.status is not control_plane.RoeStatus.APPROVED:
        raise ValueError("approved_roe_required")
    if not roe.approved_by_user_id:
        raise ValueError("missing_roe_approver")
    snapshot = snapshot_from_roe(roe)
    if snapshot.window_end <= approved_at:
        raise ValueError("expired_roe_denied")
    _validate_target_ownership(snapshot.allowed_targets, ownership_evidence, approved_at)
    diff = diff_snapshots(parent.snapshot if parent else None, snapshot)
    affected_targets = _affected_targets_from_diff(diff, snapshot)
    affected_modes = _affected_modes_from_diff(diff, snapshot)
    payload = {
        "ledger_version_id": ledger_version_id.strip(),
        "parent_ledger_version_id": parent.ledger_version_id if parent else None,
        "roe_version_id": roe.roe_version_id,
        "engagement_id": roe.engagement_id,
        "organization_id": roe.organization_id,
        "version": roe.version,
        "snapshot": _snapshot_payload(snapshot),
        "diff": tuple(_diff_payload(entry) for entry in diff),
        "approver_user_id": approver_user_id.strip(),
        "approved_at": approved_at.isoformat(),
        "reason": reason.strip(),
        "expires_at": snapshot.window_end.isoformat(),
        "affected_targets": tuple(_target_payload(target) for target in affected_targets),
        "affected_modes": tuple(mode.value for mode in affected_modes),
        "ownership_evidence_ids": tuple(sorted(evidence.evidence_id for evidence in ownership_evidence)),
    }
    return RoeLedgerVersion(
        ledger_version_id=ledger_version_id.strip(),
        parent_ledger_version_id=parent.ledger_version_id if parent else None,
        roe_version_id=roe.roe_version_id,
        engagement_id=roe.engagement_id,
        organization_id=roe.organization_id,
        version=roe.version,
        snapshot=snapshot,
        diff=diff,
        approver_user_id=approver_user_id.strip(),
        approved_at=approved_at,
        reason=reason.strip(),
        expires_at=snapshot.window_end,
        affected_targets=affected_targets,
        affected_modes=affected_modes,
        ownership_evidence_ids=tuple(sorted(evidence.evidence_id for evidence in ownership_evidence)),
        immutable_hash=_canonical_sha256(payload),
    )


def diff_snapshots(
    before: RoeScopeSnapshot | None,
    after: RoeScopeSnapshot,
) -> tuple[ScopeDiffEntry, ...]:
    if before is None:
        return (
            ScopeDiffEntry(
                kind=ScopeDiffKind.INITIAL_SCOPE,
                field="scope",
                before=None,
                after=_canonical_sha256(_snapshot_payload(after)),
            ),
        )
    entries: list[ScopeDiffEntry] = []
    before_targets = {_target_key(target): target for target in before.allowed_targets}
    after_targets = {_target_key(target): target for target in after.allowed_targets}
    for key in sorted(after_targets.keys() - before_targets.keys()):
        entries.append(ScopeDiffEntry(kind=ScopeDiffKind.TARGET_ADDED, field="allowed_targets", before=None, after=key))
    for key in sorted(before_targets.keys() - after_targets.keys()):
        entries.append(ScopeDiffEntry(kind=ScopeDiffKind.TARGET_REMOVED, field="allowed_targets", before=key, after=None))
    before_modes = {mode.value for mode in before.allowed_modes}
    after_modes = {mode.value for mode in after.allowed_modes}
    for mode in sorted(after_modes - before_modes):
        entries.append(ScopeDiffEntry(kind=ScopeDiffKind.MODE_ADDED, field="allowed_modes", before=None, after=mode))
    for mode in sorted(before_modes - after_modes):
        entries.append(ScopeDiffEntry(kind=ScopeDiffKind.MODE_REMOVED, field="allowed_modes", before=mode, after=None))
    if before.window_start != after.window_start or before.window_end != after.window_end:
        entries.append(
            ScopeDiffEntry(
                kind=ScopeDiffKind.TIME_WINDOW_CHANGED,
                field="time_window",
                before=f"{before.window_start.isoformat()}..{before.window_end.isoformat()}",
                after=f"{after.window_start.isoformat()}..{after.window_end.isoformat()}",
            )
        )
    if before.max_interactions != after.max_interactions:
        entries.append(
            ScopeDiffEntry(
                kind=ScopeDiffKind.INTERACTION_CAP_CHANGED,
                field="max_interactions",
                before=str(before.max_interactions),
                after=str(after.max_interactions),
            )
        )
    if before.max_rate_per_second != after.max_rate_per_second:
        entries.append(
            ScopeDiffEntry(
                kind=ScopeDiffKind.RATE_LIMIT_CHANGED,
                field="max_rate_per_second",
                before=str(before.max_rate_per_second),
                after=str(after.max_rate_per_second),
            )
        )
    if before.emergency_contact_method != after.emergency_contact_method:
        entries.append(
            ScopeDiffEntry(
                kind=ScopeDiffKind.EMERGENCY_CONTACT_CHANGED,
                field="emergency_contact_method",
                before=before.emergency_contact_method,
                after=after.emergency_contact_method,
            )
        )
    return tuple(entries)


def approve_deviation(
    *,
    approval: RoeDeviationApproval,
    ledger_version: RoeLedgerVersion,
    policy_decisions: tuple[control_plane.PolicyDecisionRecord, ...],
) -> RoeDeviationApproval:
    _validate_deviation_shape(approval)
    if approval.ledger_version_id != ledger_version.ledger_version_id:
        raise ValueError("deviation_ledger_mismatch")
    if approval.effective_from < approval.approved_at:
        raise ValueError("deviation_retroactive_effective_time")
    for decision in policy_decisions:
        if decision.allowed:
            continue
        if decision.decided_at < approval.effective_from and _decision_affected_by_deviation(decision, approval):
            raise ValueError("deviation_retroactive_to_failed_policy_decision")
    payload = _deviation_payload_without_hash(approval)
    return RoeDeviationApproval(
        deviation_id=approval.deviation_id.strip(),
        ledger_version_id=approval.ledger_version_id.strip(),
        approved_by_user_id=approval.approved_by_user_id.strip(),
        approved_at=approval.approved_at,
        effective_from=approval.effective_from,
        expires_at=approval.expires_at,
        reason=approval.reason.strip(),
        affected_targets=tuple(_normalize_target(target) for target in approval.affected_targets),
        affected_modes=tuple(approval.affected_modes),
        justification=approval.justification.strip(),
        approval_hash=_canonical_sha256(payload),
    )


def build_revocation_entry(
    *,
    revocation_id: str,
    ledger_version_id: str,
    revoked_by_user_id: str,
    revoked_at: datetime,
    reason: str,
    affected_targets: tuple[ScopeTarget, ...],
    affected_modes: tuple[domain.TestMode, ...],
) -> RoeRevocationEntry:
    for field_name, value in (
        ("revocation_id", revocation_id),
        ("ledger_version_id", ledger_version_id),
        ("revoked_by_user_id", revoked_by_user_id),
        ("reason", reason),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(revoked_at)
    normalized_targets = tuple(_normalize_target(target) for target in affected_targets)
    if not normalized_targets:
        raise ValueError("revocation_targets_required")
    if not affected_modes:
        raise ValueError("revocation_modes_required")
    payload = {
        "revocation_id": revocation_id.strip(),
        "ledger_version_id": ledger_version_id.strip(),
        "revoked_by_user_id": revoked_by_user_id.strip(),
        "revoked_at": revoked_at.isoformat(),
        "reason": reason.strip(),
        "affected_targets": tuple(_target_payload(target) for target in normalized_targets),
        "affected_modes": tuple(mode.value for mode in affected_modes),
    }
    return RoeRevocationEntry(
        revocation_id=revocation_id.strip(),
        ledger_version_id=ledger_version_id.strip(),
        revoked_by_user_id=revoked_by_user_id.strip(),
        revoked_at=revoked_at,
        reason=reason.strip(),
        affected_targets=normalized_targets,
        affected_modes=tuple(affected_modes),
        revocation_hash=_canonical_sha256(payload),
    )


def evaluate_dispatch_gate(
    *,
    ledger_version: RoeLedgerVersion,
    revocations: tuple[RoeRevocationEntry, ...],
    target: ScopeTarget,
    mode: domain.TestMode,
    requested_at: datetime,
) -> ScopeGateDecision:
    _require_timezone(requested_at)
    normalized = _normalize_target(target)
    if requested_at >= ledger_version.expires_at:
        return ScopeGateDecision(allowed=False, reason="expired_roe_denied")
    if normalized not in ledger_version.snapshot.allowed_targets:
        return ScopeGateDecision(allowed=False, reason="target_not_in_scope")
    if mode not in ledger_version.snapshot.allowed_modes:
        return ScopeGateDecision(allowed=False, reason="mode_not_in_scope")
    for revocation in revocations:
        if _revocation_applies(revocation, ledger_version, normalized, mode, requested_at):
            return ScopeGateDecision(allowed=False, reason="scope_revoked_for_dispatch")
    return ScopeGateDecision(allowed=True, reason="scope_ledger_dispatch_allowed")


def evaluate_report_publication_gate(
    *,
    ledger_version: RoeLedgerVersion,
    revocations: tuple[RoeRevocationEntry, ...],
    report_id: str,
    requested_at: datetime,
) -> ScopeGateDecision:
    _require_non_empty("report_id", report_id)
    _require_timezone(requested_at)
    if requested_at >= ledger_version.expires_at:
        return ScopeGateDecision(allowed=False, reason="expired_roe_denied")
    for revocation in revocations:
        if revocation.ledger_version_id == ledger_version.ledger_version_id and revocation.revoked_at <= requested_at:
            return ScopeGateDecision(allowed=False, reason="scope_revoked_for_publication")
    return ScopeGateDecision(allowed=True, reason="scope_ledger_publication_allowed")


def export_replayable_authorization_proof(
    *,
    proof_id: str,
    ledger_version: RoeLedgerVersion,
    policy_decision: control_plane.PolicyDecisionRecord,
    deviations: tuple[RoeDeviationApproval, ...],
    revocations: tuple[RoeRevocationEntry, ...],
    generated_at: datetime,
) -> AuthorizationReplayProof:
    _require_non_empty("proof_id", proof_id)
    _require_timezone(generated_at)
    if policy_decision.roe_version_id != ledger_version.roe_version_id:
        raise ValueError("policy_decision_roe_mismatch")
    decision_hash = _canonical_sha256(control_plane.policy_decision_payload(policy_decision))
    deviation_hashes = tuple(sorted(deviation.approval_hash for deviation in deviations))
    revocation_hashes = tuple(sorted(revocation.revocation_hash for revocation in revocations))
    payload = {
        "proof_id": proof_id.strip(),
        "ledger_version_id": ledger_version.ledger_version_id,
        "policy_decision_id": policy_decision.decision_id,
        "generated_at": generated_at.isoformat(),
        "scope_version_hash": ledger_version.immutable_hash,
        "policy_decision_hash": decision_hash,
        "deviation_hashes": deviation_hashes,
        "revocation_hashes": revocation_hashes,
    }
    return AuthorizationReplayProof(
        proof_id=proof_id.strip(),
        ledger_version_id=ledger_version.ledger_version_id,
        policy_decision_id=policy_decision.decision_id,
        generated_at=generated_at,
        scope_version_hash=ledger_version.immutable_hash,
        policy_decision_hash=decision_hash,
        deviation_hashes=deviation_hashes,
        revocation_hashes=revocation_hashes,
        proof_hash=_canonical_sha256(payload),
    )


def _validate_target_ownership(
    allowed_targets: tuple[ScopeTarget, ...],
    ownership_evidence: tuple[TargetOwnershipEvidence, ...],
    approved_at: datetime,
) -> None:
    evidence_by_target = {evidence.target: evidence for evidence in ownership_evidence}
    for target in allowed_targets:
        evidence = evidence_by_target.get(target)
        if evidence is None:
            raise ValueError("target_ownership_evidence_missing")
        if evidence.expires_at <= approved_at:
            raise ValueError("target_ownership_evidence_expired")


def _validate_deviation_shape(approval: RoeDeviationApproval) -> None:
    for field_name, value in (
        ("deviation_id", approval.deviation_id),
        ("ledger_version_id", approval.ledger_version_id),
        ("approved_by_user_id", approval.approved_by_user_id),
        ("reason", approval.reason),
        ("justification", approval.justification),
    ):
        _require_non_empty(field_name, value)
    for value in (approval.approved_at, approval.effective_from, approval.expires_at):
        _require_timezone(value)
    if approval.expires_at <= approval.effective_from:
        raise ValueError("deviation_expiry_invalid")
    if not approval.affected_targets:
        raise ValueError("deviation_targets_required")
    if not approval.affected_modes:
        raise ValueError("deviation_modes_required")


def _decision_affected_by_deviation(
    decision: control_plane.PolicyDecisionRecord,
    approval: RoeDeviationApproval,
) -> bool:
    affected_targets = tuple(_normalize_target(target) for target in approval.affected_targets)
    return decision.target.normalized() in affected_targets and decision.mode in approval.affected_modes


def _revocation_applies(
    revocation: RoeRevocationEntry,
    ledger_version: RoeLedgerVersion,
    target: ScopeTarget,
    mode: domain.TestMode,
    requested_at: datetime,
) -> bool:
    return (
        revocation.ledger_version_id == ledger_version.ledger_version_id
        and revocation.revoked_at <= requested_at
        and target in revocation.affected_targets
        and mode in revocation.affected_modes
    )


def _affected_targets_from_diff(
    diff: tuple[ScopeDiffEntry, ...],
    snapshot: RoeScopeSnapshot,
) -> tuple[ScopeTarget, ...]:
    targets = []
    target_keys = {_target_key(target): target for target in snapshot.allowed_targets}
    for entry in diff:
        if entry.kind in {ScopeDiffKind.INITIAL_SCOPE, ScopeDiffKind.TIME_WINDOW_CHANGED}:
            return snapshot.allowed_targets
        if entry.kind in {ScopeDiffKind.TARGET_ADDED, ScopeDiffKind.TARGET_REMOVED}:
            key = entry.after or entry.before
            if key and key in target_keys:
                targets.append(target_keys[key])
    return tuple(targets) or snapshot.allowed_targets


def _affected_modes_from_diff(
    diff: tuple[ScopeDiffEntry, ...],
    snapshot: RoeScopeSnapshot,
) -> tuple[domain.TestMode, ...]:
    modes = []
    mode_by_value = {mode.value: mode for mode in snapshot.allowed_modes}
    for entry in diff:
        if entry.kind in {ScopeDiffKind.INITIAL_SCOPE, ScopeDiffKind.TIME_WINDOW_CHANGED}:
            return snapshot.allowed_modes
        if entry.kind in {ScopeDiffKind.MODE_ADDED, ScopeDiffKind.MODE_REMOVED}:
            value = entry.after or entry.before
            if value and value in mode_by_value:
                modes.append(mode_by_value[value])
    return tuple(modes) or snapshot.allowed_modes


def _deviation_payload_without_hash(approval: RoeDeviationApproval) -> dict[str, object]:
    return {
        "deviation_id": approval.deviation_id.strip(),
        "ledger_version_id": approval.ledger_version_id.strip(),
        "approved_by_user_id": approval.approved_by_user_id.strip(),
        "approved_at": approval.approved_at.isoformat(),
        "effective_from": approval.effective_from.isoformat(),
        "expires_at": approval.expires_at.isoformat(),
        "reason": approval.reason.strip(),
        "affected_targets": tuple(_target_payload(_normalize_target(target)) for target in approval.affected_targets),
        "affected_modes": tuple(mode.value for mode in approval.affected_modes),
        "justification": approval.justification.strip(),
    }


def _snapshot_payload(snapshot: RoeScopeSnapshot) -> dict[str, object]:
    return {
        "allowed_targets": tuple(_target_payload(target) for target in snapshot.allowed_targets),
        "forbidden_targets": tuple(_target_payload(target) for target in snapshot.forbidden_targets),
        "allowed_modes": tuple(mode.value for mode in snapshot.allowed_modes),
        "window_start": snapshot.window_start.isoformat(),
        "window_end": snapshot.window_end.isoformat(),
        "max_interactions": snapshot.max_interactions,
        "max_rate_per_second": snapshot.max_rate_per_second,
        "emergency_contact_method": snapshot.emergency_contact_method,
    }


def _diff_payload(entry: ScopeDiffEntry) -> dict[str, object]:
    return {
        "kind": entry.kind.value,
        "field": entry.field,
        "before": entry.before,
        "after": entry.after,
    }


def _target_payload(target: ScopeTarget) -> dict[str, str]:
    normalized = target.normalized()
    return {"target_type": normalized.target_type.value, "value": normalized.value}


def _target_key(target: ScopeTarget) -> str:
    normalized = target.normalized()
    return f"{normalized.target_type.value}:{normalized.value}"


def _normalize_target(target: ScopeTarget) -> ScopeTarget:
    return target.normalized()


def _canonical_sha256(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
