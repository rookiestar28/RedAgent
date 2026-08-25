"""Operator access governance, JIT grants, and break-glass controls.

This module is deterministic control-plane logic only. It never retrieves
credentials, dispatches runners, publishes reports, or contacts targets.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum

from redagent_platform import rbac
from redagent_platform.domain import PolicyDecisionOutcome, RoleName, TestMode
from redagent_platform.evidence_chain import AuditAction, EvidenceChain


class PrivilegedAction(str, Enum):
    HIGH_RISK_SCOPE_APPROVAL = "high_risk_scope_approval"
    POLICY_GRANT_APPROVAL = "policy_grant_approval"
    REPORT_PUBLICATION = "report_publication"
    REPORT_EXPORT = "report_export"
    BREAK_GLASS_ACCESS = "break_glass_access"
    CREDENTIAL_LEASE_USE = "credential_lease_use"


class BreakGlassReviewStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"


@dataclass(frozen=True, kw_only=True)
class OperatorIdentity:
    user_id: str
    organization_id: str
    roles: frozenset[RoleName]
    authenticated: bool = True


@dataclass(frozen=True, kw_only=True)
class OperatorAccessScope:
    organization_id: str
    engagement_id: str
    target_ids: tuple[str, ...]
    modes: tuple[TestMode, ...]
    resource_ids: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class JitGrantRequest:
    grant_id: str
    requester_user_id: str
    action: PrivilegedAction
    scope: OperatorAccessScope
    requested_at: datetime
    expires_at: datetime
    reason: str
    policy_result_hash: str
    policy_allowed: bool


@dataclass(frozen=True, kw_only=True)
class JitGrant:
    grant_id: str
    requester_user_id: str
    approver_user_id: str
    action: PrivilegedAction
    scope: OperatorAccessScope
    requested_at: datetime
    approved_at: datetime
    expires_at: datetime
    reason: str
    policy_result_hash: str
    audit_event_hash: str
    grant_hash: str


@dataclass(frozen=True, kw_only=True)
class BreakGlassAccessRequest:
    break_glass_id: str
    requester_user_id: str
    scope: OperatorAccessScope
    requested_at: datetime
    expires_at: datetime
    reason: str
    incident_id: str
    policy_result_hash: str
    policy_allowed: bool


@dataclass(frozen=True, kw_only=True)
class BreakGlassRecord:
    break_glass_id: str
    requester_user_id: str
    approver_user_id: str
    scope: OperatorAccessScope
    requested_at: datetime
    opened_at: datetime
    expires_at: datetime
    reason: str
    incident_id: str
    policy_result_hash: str
    mandatory_review_required: bool
    evidence_gate_required: bool
    redaction_gate_required: bool
    review_status: BreakGlassReviewStatus
    opened_audit_event_hash: str
    reviewed_by_user_id: str | None = None
    reviewed_at: datetime | None = None
    review_audit_event_hash: str | None = None


@dataclass(frozen=True, kw_only=True)
class ReportExportAccessRequest:
    request_id: str
    actor: OperatorIdentity
    action: PrivilegedAction
    scope: OperatorAccessScope
    report_id: str
    requested_at: datetime
    evidence_gate_passed: bool
    redaction_gate_passed: bool
    publication_approved_by_user_id: str | None
    jit_grant: JitGrant | None = None
    break_glass_record: BreakGlassRecord | None = None


@dataclass(frozen=True, kw_only=True)
class AccessDecision:
    outcome: PolicyDecisionOutcome
    reason: str
    actor_user_id: str
    action: PrivilegedAction
    grant_id: str | None = None
    break_glass_id: str | None = None
    audit_event_hash: str | None = None

    @property
    def allowed(self) -> bool:
        return self.outcome is PolicyDecisionOutcome.ALLOW


def approve_jit_grant(
    request: JitGrantRequest,
    *,
    requester: OperatorIdentity,
    approver: OperatorIdentity,
    approved_at: datetime,
    audit_event_id: str,
    audit_chain: EvidenceChain,
) -> tuple[EvidenceChain, JitGrant]:
    """Approve a scoped JIT grant and append immutable audit evidence."""
    _validate_jit_request(request)
    _validate_actor("requester", requester, request.scope)
    _validate_actor("approver", approver, request.scope)
    _require_timezone(approved_at)
    _require_non_empty("audit_event_id", audit_event_id)
    if requester.user_id != request.requester_user_id:
        raise PermissionError("requester_identity_mismatch")
    if requester.user_id == approver.user_id:
        raise PermissionError("self_approval_forbidden")
    if approved_at < request.requested_at:
        raise ValueError("approval_before_request")
    if approved_at >= request.expires_at:
        raise ValueError("jit_grant_expired_before_approval")
    if not request.policy_allowed:
        raise PermissionError("policy_gate_denied")
    _require_approver_permission(approver, request.action, request.scope)

    next_chain = audit_chain.append_audit_event(
        event_id=audit_event_id,
        organization_id=request.scope.organization_id,
        actor_user_id=approver.user_id,
        action=AuditAction.POLICY_DECISION,
        subject_type="operator_jit_grant",
        subject_id=request.grant_id,
        occurred_at=approved_at,
        details={
            "requester_user_id": requester.user_id,
            "approver_user_id": approver.user_id,
            "privileged_action": request.action.value,
            "engagement_id": request.scope.engagement_id,
            "target_count": len(request.scope.target_ids),
            "modes": tuple(mode.value for mode in request.scope.modes),
            "expires_at": request.expires_at.isoformat(),
            "policy_result_hash": request.policy_result_hash,
            "reason_hash": _sha256_text(request.reason),
        },
    )
    audit_hash = next_chain.audit_events[-1].event_hash
    grant = JitGrant(
        grant_id=request.grant_id.strip(),
        requester_user_id=request.requester_user_id.strip(),
        approver_user_id=approver.user_id.strip(),
        action=request.action,
        scope=request.scope,
        requested_at=request.requested_at,
        approved_at=approved_at,
        expires_at=request.expires_at,
        reason=request.reason.strip(),
        policy_result_hash=request.policy_result_hash.strip(),
        audit_event_hash=audit_hash,
        grant_hash=_grant_hash(request, approver.user_id, approved_at, audit_hash),
    )
    return next_chain, grant


def evaluate_jit_grant(
    grant: JitGrant,
    *,
    actor: OperatorIdentity,
    action: PrivilegedAction,
    scope: OperatorAccessScope,
    requested_at: datetime,
) -> AccessDecision:
    _validate_actor("actor", actor, scope)
    _validate_scope(scope)
    _require_timezone(requested_at)
    if actor.user_id != grant.requester_user_id:
        return _deny(actor, action, "jit_grant_actor_mismatch", grant_id=grant.grant_id)
    if action is not grant.action:
        return _deny(actor, action, "jit_grant_action_mismatch", grant_id=grant.grant_id)
    if requested_at >= grant.expires_at:
        return _deny(actor, action, "jit_grant_expired", grant_id=grant.grant_id)
    if not _scope_covers(grant.scope, scope):
        return _deny(actor, action, "jit_grant_scope_mismatch", grant_id=grant.grant_id)
    return AccessDecision(
        outcome=PolicyDecisionOutcome.ALLOW,
        reason="jit_grant_allowed",
        actor_user_id=actor.user_id,
        action=action,
        grant_id=grant.grant_id,
        audit_event_hash=grant.audit_event_hash,
    )


def open_break_glass_access(
    request: BreakGlassAccessRequest,
    *,
    requester: OperatorIdentity,
    approver: OperatorIdentity,
    opened_at: datetime,
    audit_event_id: str,
    audit_chain: EvidenceChain,
) -> tuple[EvidenceChain, BreakGlassRecord]:
    _validate_break_glass_request(request)
    _validate_actor("requester", requester, request.scope)
    _validate_actor("approver", approver, request.scope)
    _require_timezone(opened_at)
    _require_non_empty("audit_event_id", audit_event_id)
    if requester.user_id != request.requester_user_id:
        raise PermissionError("requester_identity_mismatch")
    if requester.user_id == approver.user_id:
        raise PermissionError("self_approval_forbidden")
    if opened_at < request.requested_at:
        raise ValueError("opening_before_request")
    if opened_at >= request.expires_at:
        raise ValueError("break_glass_expired_before_open")
    if not request.policy_allowed:
        raise PermissionError("policy_gate_denied")
    _require_approver_permission(approver, PrivilegedAction.BREAK_GLASS_ACCESS, request.scope)

    next_chain = audit_chain.append_audit_event(
        event_id=audit_event_id,
        organization_id=request.scope.organization_id,
        actor_user_id=approver.user_id,
        action=AuditAction.POLICY_DECISION,
        subject_type="operator_break_glass",
        subject_id=request.break_glass_id,
        occurred_at=opened_at,
        details={
            "requester_user_id": requester.user_id,
            "approver_user_id": approver.user_id,
            "incident_id": request.incident_id,
            "engagement_id": request.scope.engagement_id,
            "target_count": len(request.scope.target_ids),
            "expires_at": request.expires_at.isoformat(),
            "policy_result_hash": request.policy_result_hash,
            "mandatory_review_required": True,
            "evidence_gate_required": True,
            "redaction_gate_required": True,
            "reason_hash": _sha256_text(request.reason),
        },
    )
    return next_chain, BreakGlassRecord(
        break_glass_id=request.break_glass_id.strip(),
        requester_user_id=request.requester_user_id.strip(),
        approver_user_id=approver.user_id.strip(),
        scope=request.scope,
        requested_at=request.requested_at,
        opened_at=opened_at,
        expires_at=request.expires_at,
        reason=request.reason.strip(),
        incident_id=request.incident_id.strip(),
        policy_result_hash=request.policy_result_hash.strip(),
        mandatory_review_required=True,
        evidence_gate_required=True,
        redaction_gate_required=True,
        review_status=BreakGlassReviewStatus.PENDING,
        opened_audit_event_hash=next_chain.audit_events[-1].event_hash,
    )


def review_break_glass_access(
    record: BreakGlassRecord,
    *,
    reviewer: OperatorIdentity,
    reviewed_at: datetime,
    approved: bool,
    audit_event_id: str,
    audit_chain: EvidenceChain,
) -> tuple[EvidenceChain, BreakGlassRecord]:
    _validate_actor("reviewer", reviewer, record.scope)
    _require_timezone(reviewed_at)
    _require_non_empty("audit_event_id", audit_event_id)
    if reviewer.user_id in {record.requester_user_id, record.approver_user_id}:
        raise PermissionError("break_glass_independent_review_required")
    if not _has_any_role(reviewer, {RoleName.ADMINISTRATOR, RoleName.SECURITY_LEAD, RoleName.REVIEWER}):
        raise PermissionError("break_glass_reviewer_not_authorized")
    if reviewed_at < record.opened_at:
        raise ValueError("review_before_opening")

    status = BreakGlassReviewStatus.APPROVED if approved else BreakGlassReviewStatus.REJECTED
    next_chain = audit_chain.append_audit_event(
        event_id=audit_event_id,
        organization_id=record.scope.organization_id,
        actor_user_id=reviewer.user_id,
        action=AuditAction.POLICY_DECISION,
        subject_type="operator_break_glass_review",
        subject_id=record.break_glass_id,
        occurred_at=reviewed_at,
        details={
            "review_status": status.value,
            "requester_user_id": record.requester_user_id,
            "approver_user_id": record.approver_user_id,
            "incident_id": record.incident_id,
            "opened_audit_event_hash": record.opened_audit_event_hash,
        },
    )
    return next_chain, replace(
        record,
        review_status=status,
        reviewed_by_user_id=reviewer.user_id,
        reviewed_at=reviewed_at,
        review_audit_event_hash=next_chain.audit_events[-1].event_hash,
    )


def authorize_report_export(
    request: ReportExportAccessRequest,
    *,
    audit_chain: EvidenceChain,
    audit_event_id: str,
) -> tuple[EvidenceChain, AccessDecision]:
    _validate_actor("actor", request.actor, request.scope)
    _validate_scope(request.scope)
    _require_timezone(request.requested_at)
    _require_non_empty("request_id", request.request_id)
    _require_non_empty("report_id", request.report_id)
    _require_non_empty("audit_event_id", audit_event_id)
    if request.action not in {PrivilegedAction.REPORT_PUBLICATION, PrivilegedAction.REPORT_EXPORT}:
        decision = _deny(request.actor, request.action, "report_action_required")
    elif not request.evidence_gate_passed:
        decision = _deny(request.actor, request.action, "evidence_gate_required")
    elif not request.redaction_gate_passed:
        decision = _deny(request.actor, request.action, "redaction_gate_required")
    elif request.publication_approved_by_user_id == request.actor.user_id:
        decision = _deny(request.actor, request.action, "self_publication_approval_forbidden")
    else:
        decision = _authorize_report_access_path(request)

    next_chain = audit_chain.append_audit_event(
        event_id=audit_event_id,
        organization_id=request.scope.organization_id,
        actor_user_id=request.actor.user_id,
        action=AuditAction.EXPORT,
        subject_type="report_export_access",
        subject_id=request.report_id,
        occurred_at=request.requested_at,
        details={
            "request_id": request.request_id,
            "privileged_action": request.action.value,
            "decision_outcome": decision.outcome.value,
            "decision_reason": decision.reason,
            "evidence_gate_passed": request.evidence_gate_passed,
            "redaction_gate_passed": request.redaction_gate_passed,
            "jit_grant_id": request.jit_grant.grant_id if request.jit_grant else None,
            "break_glass_id": request.break_glass_record.break_glass_id if request.break_glass_record else None,
        },
    )
    return next_chain, replace(decision, audit_event_hash=next_chain.audit_events[-1].event_hash)


def _authorize_report_access_path(request: ReportExportAccessRequest) -> AccessDecision:
    if request.jit_grant is not None:
        return evaluate_jit_grant(
            request.jit_grant,
            actor=request.actor,
            action=request.action,
            scope=request.scope,
            requested_at=request.requested_at,
        )
    if request.break_glass_record is not None:
        return _evaluate_break_glass_record(
            request.break_glass_record,
            actor=request.actor,
            action=request.action,
            scope=request.scope,
            requested_at=request.requested_at,
        )
    return _deny(request.actor, request.action, "privileged_access_path_required")


def _evaluate_break_glass_record(
    record: BreakGlassRecord,
    *,
    actor: OperatorIdentity,
    action: PrivilegedAction,
    scope: OperatorAccessScope,
    requested_at: datetime,
) -> AccessDecision:
    if actor.user_id != record.requester_user_id:
        return _deny(actor, action, "break_glass_actor_mismatch", break_glass_id=record.break_glass_id)
    if requested_at >= record.expires_at:
        return _deny(actor, action, "break_glass_expired", break_glass_id=record.break_glass_id)
    if not _scope_covers(record.scope, scope):
        return _deny(actor, action, "break_glass_scope_mismatch", break_glass_id=record.break_glass_id)
    if record.review_status is not BreakGlassReviewStatus.APPROVED:
        return _deny(actor, action, "break_glass_review_required", break_glass_id=record.break_glass_id)
    return AccessDecision(
        outcome=PolicyDecisionOutcome.ALLOW,
        reason="break_glass_reviewed_access_allowed",
        actor_user_id=actor.user_id,
        action=action,
        break_glass_id=record.break_glass_id,
        audit_event_hash=record.review_audit_event_hash,
    )


def _require_approver_permission(
    approver: OperatorIdentity,
    action: PrivilegedAction,
    scope: OperatorAccessScope,
) -> None:
    resource_type, rbac_action = _required_rbac_permission(action)
    decision = rbac.decide(
        rbac.AuthorizationRequest(
            subject=rbac.Subject(
                user_id=approver.user_id,
                organization_id=approver.organization_id,
                roles=approver.roles,
                authenticated=approver.authenticated,
            ),
            action=rbac_action,
            resource=rbac.Resource(
                resource_type=resource_type,
                resource_id=scope.engagement_id,
                organization_id=scope.organization_id,
            ),
        )
    )
    if not decision.allowed:
        raise PermissionError(f"approver_not_authorized:{decision.reason}")


def _required_rbac_permission(action: PrivilegedAction) -> tuple[rbac.ResourceType, rbac.Action]:
    if action in {
        PrivilegedAction.HIGH_RISK_SCOPE_APPROVAL,
        PrivilegedAction.POLICY_GRANT_APPROVAL,
        PrivilegedAction.BREAK_GLASS_ACCESS,
        PrivilegedAction.CREDENTIAL_LEASE_USE,
    }:
        return rbac.ResourceType.AUTHORIZATION, rbac.Action.APPROVE
    if action in {PrivilegedAction.REPORT_PUBLICATION, PrivilegedAction.REPORT_EXPORT}:
        return rbac.ResourceType.REPORT, rbac.Action.EXPORT
    raise ValueError("unsupported_privileged_action")


def _scope_covers(granted: OperatorAccessScope, requested: OperatorAccessScope) -> bool:
    if granted.organization_id != requested.organization_id or granted.engagement_id != requested.engagement_id:
        return False
    return (
        set(requested.target_ids).issubset(set(granted.target_ids))
        and set(requested.modes).issubset(set(granted.modes))
        and set(requested.resource_ids).issubset(set(granted.resource_ids))
    )


def _validate_jit_request(request: JitGrantRequest) -> None:
    for field_name, value in (
        ("grant_id", request.grant_id),
        ("requester_user_id", request.requester_user_id),
        ("reason", request.reason),
        ("policy_result_hash", request.policy_result_hash),
    ):
        _require_non_empty(field_name, value)
    _validate_scope(request.scope)
    _require_timezone(request.requested_at)
    _require_timezone(request.expires_at)
    if request.expires_at <= request.requested_at:
        raise ValueError("jit_grant_expiry_invalid")


def _validate_break_glass_request(request: BreakGlassAccessRequest) -> None:
    for field_name, value in (
        ("break_glass_id", request.break_glass_id),
        ("requester_user_id", request.requester_user_id),
        ("reason", request.reason),
        ("incident_id", request.incident_id),
        ("policy_result_hash", request.policy_result_hash),
    ):
        _require_non_empty(field_name, value)
    _validate_scope(request.scope)
    _require_timezone(request.requested_at)
    _require_timezone(request.expires_at)
    if request.expires_at <= request.requested_at:
        raise ValueError("break_glass_expiry_invalid")


def _validate_actor(field_name: str, actor: OperatorIdentity, scope: OperatorAccessScope) -> None:
    _require_non_empty(f"{field_name}_user_id", actor.user_id)
    _require_non_empty(f"{field_name}_organization_id", actor.organization_id)
    if not actor.authenticated:
        raise PermissionError(f"{field_name}_unauthenticated")
    if not actor.roles:
        raise PermissionError(f"{field_name}_roles_required")
    if actor.organization_id != scope.organization_id:
        raise PermissionError(f"{field_name}_cross_tenant")


def _validate_scope(scope: OperatorAccessScope) -> None:
    for field_name, value in (
        ("organization_id", scope.organization_id),
        ("engagement_id", scope.engagement_id),
    ):
        _require_non_empty(field_name, value)
    if not scope.target_ids:
        raise ValueError("scope_targets_required")
    if not scope.modes:
        raise ValueError("scope_modes_required")
    for target_id in scope.target_ids:
        _require_non_empty("target_id", target_id)
    for resource_id in scope.resource_ids:
        _require_non_empty("resource_id", resource_id)


def _has_any_role(actor: OperatorIdentity, roles: set[RoleName]) -> bool:
    return bool(actor.roles.intersection(roles))


def _deny(
    actor: OperatorIdentity,
    action: PrivilegedAction,
    reason: str,
    *,
    grant_id: str | None = None,
    break_glass_id: str | None = None,
) -> AccessDecision:
    return AccessDecision(
        outcome=PolicyDecisionOutcome.DENY,
        reason=reason,
        actor_user_id=actor.user_id,
        action=action,
        grant_id=grant_id,
        break_glass_id=break_glass_id,
    )


def _grant_hash(
    request: JitGrantRequest,
    approver_user_id: str,
    approved_at: datetime,
    audit_event_hash: str,
) -> str:
    return _canonical_sha256(
        {
            "grant_id": request.grant_id.strip(),
            "requester_user_id": request.requester_user_id.strip(),
            "approver_user_id": approver_user_id.strip(),
            "action": request.action.value,
            "scope": _scope_payload(request.scope),
            "requested_at": request.requested_at.isoformat(),
            "approved_at": approved_at.isoformat(),
            "expires_at": request.expires_at.isoformat(),
            "reason_hash": _sha256_text(request.reason),
            "policy_result_hash": request.policy_result_hash.strip(),
            "audit_event_hash": audit_event_hash,
        }
    )


def _scope_payload(scope: OperatorAccessScope) -> dict[str, object]:
    return {
        "organization_id": scope.organization_id,
        "engagement_id": scope.engagement_id,
        "target_ids": scope.target_ids,
        "modes": tuple(mode.value for mode in scope.modes),
        "resource_ids": scope.resource_ids,
    }


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
