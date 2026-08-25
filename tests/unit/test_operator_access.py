from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import domain, evidence_chain, operator_access, policy_simulator


NOW = datetime(2026, 7, 9, 15, 30, tzinfo=timezone.utc)


def actor(
    user_id: str,
    *roles: domain.RoleName,
    organization_id: str = "org-1",
) -> operator_access.OperatorIdentity:
    return operator_access.OperatorIdentity(
        user_id=user_id,
        organization_id=organization_id,
        roles=frozenset(roles),
    )


def scope(**overrides: object) -> operator_access.OperatorAccessScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target_ids": ("target-1", "target-2"),
        "modes": (domain.TestMode.ACTIVE_SCAN,),
        "resource_ids": ("report-1",),
    }
    values.update(overrides)
    return operator_access.OperatorAccessScope(**values)  # type: ignore[arg-type]


def policy_hash() -> str:
    pack = policy_simulator.build_default_assurance_policy_pack(
        pack_id="assurance-pack",
        version="2026.07.09",
        status=policy_simulator.PolicyPackStatus.REVIEWED,
        created_at=NOW,
        reviewed_by_user_id="reviewer-1",
        reviewed_at=NOW,
    )
    result = policy_simulator.simulate_policy(
        policy_simulator.PolicySimulationRequest(
            simulation_id="simulation-1",
            policy_pack=pack,
            subjects=(
                policy_simulator.SimulationSubject(
                    subject_id="subject-authorization",
                    domain=policy_simulator.PolicyDomain.AUTHORIZATION,
                    context={"authorization_current": True},
                ),
            ),
            requested_at=NOW,
            actor_user_id="operator-1",
            dry_run=True,
        )
    )
    assert result.allowed
    return result.result_hash


def jit_request(**overrides: object) -> operator_access.JitGrantRequest:
    values = {
        "grant_id": "grant-1",
        "requester_user_id": "operator-1",
        "action": operator_access.PrivilegedAction.HIGH_RISK_SCOPE_APPROVAL,
        "scope": scope(),
        "requested_at": NOW,
        "expires_at": NOW + timedelta(minutes=30),
        "reason": "Approve high-risk scope for authorized engagement.",
        "policy_result_hash": policy_hash(),
        "policy_allowed": True,
    }
    values.update(overrides)
    return operator_access.JitGrantRequest(**values)  # type: ignore[arg-type]


def approve_grant(
    request: operator_access.JitGrantRequest | None = None,
) -> tuple[evidence_chain.EvidenceChain, operator_access.JitGrant]:
    return operator_access.approve_jit_grant(
        request or jit_request(),
        requester=actor("operator-1", domain.RoleName.OPERATOR),
        approver=actor("lead-1", domain.RoleName.SECURITY_LEAD),
        approved_at=NOW + timedelta(minutes=1),
        audit_event_id="audit-jit-1",
        audit_chain=evidence_chain.EvidenceChain(),
    )


def break_glass_request(**overrides: object) -> operator_access.BreakGlassAccessRequest:
    values = {
        "break_glass_id": "break-glass-1",
        "requester_user_id": "operator-1",
        "scope": scope(),
        "requested_at": NOW,
        "expires_at": NOW + timedelta(minutes=15),
        "reason": "Emergency stop validation requires privileged recovery review.",
        "incident_id": "incident-1",
        "policy_result_hash": policy_hash(),
        "policy_allowed": True,
    }
    values.update(overrides)
    return operator_access.BreakGlassAccessRequest(**values)  # type: ignore[arg-type]


def open_break_glass() -> tuple[evidence_chain.EvidenceChain, operator_access.BreakGlassRecord]:
    return operator_access.open_break_glass_access(
        break_glass_request(),
        requester=actor("operator-1", domain.RoleName.OPERATOR),
        approver=actor("lead-1", domain.RoleName.SECURITY_LEAD),
        opened_at=NOW + timedelta(minutes=1),
        audit_event_id="audit-bg-1",
        audit_chain=evidence_chain.EvidenceChain(),
    )


def test_self_approval_is_denied_for_high_risk_policy_report_and_break_glass() -> None:
    operator = actor("operator-1", domain.RoleName.OPERATOR, domain.RoleName.SECURITY_LEAD)
    for action in (
        operator_access.PrivilegedAction.HIGH_RISK_SCOPE_APPROVAL,
        operator_access.PrivilegedAction.POLICY_GRANT_APPROVAL,
        operator_access.PrivilegedAction.REPORT_PUBLICATION,
    ):
        with pytest.raises(PermissionError, match="self_approval_forbidden"):
            operator_access.approve_jit_grant(
                jit_request(action=action),
                requester=operator,
                approver=operator,
                approved_at=NOW + timedelta(minutes=1),
                audit_event_id=f"audit-{action.value}",
                audit_chain=evidence_chain.EvidenceChain(),
            )

    with pytest.raises(PermissionError, match="self_approval_forbidden"):
        operator_access.open_break_glass_access(
            break_glass_request(),
            requester=operator,
            approver=operator,
            opened_at=NOW + timedelta(minutes=1),
            audit_event_id="audit-bg-self",
            audit_chain=evidence_chain.EvidenceChain(),
        )


def test_jit_grant_records_explicit_scope_expiry_approver_reason_policy_and_audit() -> None:
    chain, grant = approve_grant()

    assert grant.grant_id == "grant-1"
    assert grant.scope.engagement_id == "eng-1"
    assert grant.expires_at == NOW + timedelta(minutes=30)
    assert grant.approver_user_id == "lead-1"
    assert grant.reason == "Approve high-risk scope for authorized engagement."
    assert grant.policy_result_hash
    assert grant.audit_event_hash == chain.audit_events[-1].event_hash
    assert grant.grant_hash
    assert chain.audit_events[-1].action is evidence_chain.AuditAction.POLICY_DECISION


def test_expired_wrong_action_and_scope_mismatched_grants_fail_closed() -> None:
    _, grant = approve_grant()
    operator = actor("operator-1", domain.RoleName.OPERATOR)

    expired = operator_access.evaluate_jit_grant(
        grant,
        actor=operator,
        action=operator_access.PrivilegedAction.HIGH_RISK_SCOPE_APPROVAL,
        scope=scope(),
        requested_at=grant.expires_at,
    )
    wrong_action = operator_access.evaluate_jit_grant(
        grant,
        actor=operator,
        action=operator_access.PrivilegedAction.POLICY_GRANT_APPROVAL,
        scope=scope(),
        requested_at=NOW + timedelta(minutes=2),
    )
    wrong_scope = operator_access.evaluate_jit_grant(
        grant,
        actor=operator,
        action=operator_access.PrivilegedAction.HIGH_RISK_SCOPE_APPROVAL,
        scope=scope(target_ids=("target-3",)),
        requested_at=NOW + timedelta(minutes=2),
    )

    assert expired.reason == "jit_grant_expired"
    assert wrong_action.reason == "jit_grant_action_mismatch"
    assert wrong_scope.reason == "jit_grant_scope_mismatch"
    assert not expired.allowed
    assert not wrong_action.allowed
    assert not wrong_scope.allowed


def test_break_glass_requires_independent_review_and_never_waives_gates() -> None:
    chain, record = open_break_glass()

    assert record.mandatory_review_required
    assert record.evidence_gate_required
    assert record.redaction_gate_required
    assert record.review_status is operator_access.BreakGlassReviewStatus.PENDING

    with pytest.raises(PermissionError, match="break_glass_independent_review_required"):
        operator_access.review_break_glass_access(
            record,
            reviewer=actor("lead-1", domain.RoleName.SECURITY_LEAD),
            reviewed_at=NOW + timedelta(minutes=3),
            approved=True,
            audit_event_id="audit-bg-review-self",
            audit_chain=chain,
        )

    reviewed_chain, reviewed = operator_access.review_break_glass_access(
        record,
        reviewer=actor("reviewer-1", domain.RoleName.REVIEWER),
        reviewed_at=NOW + timedelta(minutes=3),
        approved=True,
        audit_event_id="audit-bg-review-1",
        audit_chain=chain,
    )

    assert reviewed.review_status is operator_access.BreakGlassReviewStatus.APPROVED
    assert reviewed.reviewed_by_user_id == "reviewer-1"
    assert reviewed.review_audit_event_hash == reviewed_chain.audit_events[-1].event_hash


def test_report_export_requires_access_path_and_passed_evidence_redaction_gates() -> None:
    export_request = jit_request(
        grant_id="grant-export-1",
        action=operator_access.PrivilegedAction.REPORT_EXPORT,
        scope=scope(modes=(domain.TestMode.PASSIVE_SCAN,)),
    )
    _, grant = operator_access.approve_jit_grant(
        export_request,
        requester=actor("operator-1", domain.RoleName.OPERATOR),
        approver=actor("lead-1", domain.RoleName.SECURITY_LEAD),
        approved_at=NOW + timedelta(minutes=1),
        audit_event_id="audit-export-grant-1",
        audit_chain=evidence_chain.EvidenceChain(),
    )
    request = operator_access.ReportExportAccessRequest(
        request_id="report-export-1",
        actor=actor("operator-1", domain.RoleName.OPERATOR),
        action=operator_access.PrivilegedAction.REPORT_EXPORT,
        scope=scope(modes=(domain.TestMode.PASSIVE_SCAN,)),
        report_id="report-1",
        requested_at=NOW + timedelta(minutes=2),
        evidence_gate_passed=True,
        redaction_gate_passed=True,
        publication_approved_by_user_id="lead-1",
        jit_grant=grant,
    )

    chain, decision = operator_access.authorize_report_export(
        request,
        audit_chain=evidence_chain.EvidenceChain(),
        audit_event_id="audit-report-export-1",
    )
    _, redaction_denied = operator_access.authorize_report_export(
        operator_access.ReportExportAccessRequest(
            **{**request.__dict__, "redaction_gate_passed": False, "request_id": "report-export-2"}
        ),
        audit_chain=evidence_chain.EvidenceChain(),
        audit_event_id="audit-report-export-2",
    )
    _, self_denied = operator_access.authorize_report_export(
        operator_access.ReportExportAccessRequest(
            **{**request.__dict__, "publication_approved_by_user_id": "operator-1", "request_id": "report-export-3"}
        ),
        audit_chain=evidence_chain.EvidenceChain(),
        audit_event_id="audit-report-export-3",
    )

    assert decision.allowed
    assert decision.reason == "jit_grant_allowed"
    assert decision.audit_event_hash == chain.audit_events[-1].event_hash
    assert redaction_denied.reason == "redaction_gate_required"
    assert self_denied.reason == "self_publication_approval_forbidden"


def test_break_glass_cannot_authorize_report_export_until_reviewed_and_gates_pass() -> None:
    chain, record = open_break_glass()
    export_scope = scope()
    pending_request = operator_access.ReportExportAccessRequest(
        request_id="report-export-bg-1",
        actor=actor("operator-1", domain.RoleName.OPERATOR),
        action=operator_access.PrivilegedAction.REPORT_EXPORT,
        scope=export_scope,
        report_id="report-1",
        requested_at=NOW + timedelta(minutes=2),
        evidence_gate_passed=True,
        redaction_gate_passed=True,
        publication_approved_by_user_id="lead-1",
        break_glass_record=record,
    )

    _, pending_decision = operator_access.authorize_report_export(
        pending_request,
        audit_chain=chain,
        audit_event_id="audit-report-bg-pending",
    )
    reviewed_chain, reviewed = operator_access.review_break_glass_access(
        record,
        reviewer=actor("reviewer-1", domain.RoleName.REVIEWER),
        reviewed_at=NOW + timedelta(minutes=3),
        approved=True,
        audit_event_id="audit-bg-review-2",
        audit_chain=chain,
    )
    _, gate_denied = operator_access.authorize_report_export(
        operator_access.ReportExportAccessRequest(
            **{
                **pending_request.__dict__,
                "request_id": "report-export-bg-2",
                "redaction_gate_passed": False,
                "break_glass_record": reviewed,
            }
        ),
        audit_chain=reviewed_chain,
        audit_event_id="audit-report-bg-gate",
    )
    _, allowed = operator_access.authorize_report_export(
        operator_access.ReportExportAccessRequest(
            **{**pending_request.__dict__, "request_id": "report-export-bg-3", "break_glass_record": reviewed}
        ),
        audit_chain=reviewed_chain,
        audit_event_id="audit-report-bg-allowed",
    )

    assert pending_decision.reason == "break_glass_review_required"
    assert gate_denied.reason == "redaction_gate_required"
    assert allowed.allowed
    assert allowed.reason == "break_glass_reviewed_access_allowed"
