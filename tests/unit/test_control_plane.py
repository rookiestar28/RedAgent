from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import control_plane, domain, target_inventory
from redagent_platform.evidence_chain import AuditAction
from redagent_platform.scope_authorization import JobScopeRequest, ScopeTarget


NOW = datetime(2026, 7, 9, 8, 0, tzinfo=timezone.utc)
START = NOW - timedelta(minutes=5)
END = NOW + timedelta(hours=2)


def engagement(**overrides: object) -> control_plane.EngagementRecord:
    values = {
        "engagement_id": "eng-1",
        "organization_id": "org-1",
        "name": "Agentique authorized assessment",
        "owner_user_id": "owner-1",
        "created_at": NOW,
    }
    values.update(overrides)
    return control_plane.EngagementRecord(**values)  # type: ignore[arg-type]


def inventory_target(**overrides: object) -> target_inventory.InventoryTarget:
    values = {
        "id": "target-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "owner_label": "Ray Chiu",
        "target_type": domain.TargetType.WEB_ORIGIN,
        "value": "https://www.agentique.io",
        "environment": target_inventory.EnvironmentType.PRODUCTION,
        "data_sensitivity": target_inventory.DataSensitivity.PUBLIC,
        "authorization_status": domain.AuthorizationStatus.APPROVED,
        "allowed_modes": (domain.TestMode.PASSIVE_SCAN, domain.TestMode.ACTIVE_SCAN),
        "explicit_review": False,
        "review_reason": None,
    }
    values.update(overrides)
    return target_inventory.InventoryTarget(**values)  # type: ignore[arg-type]


def target_record(**overrides: object) -> control_plane.ControlPlaneTargetRecord:
    values = {
        "target": inventory_target(),
        "registered_at": NOW,
        "registered_by_user_id": "owner-1",
    }
    values.update(overrides)
    return control_plane.ControlPlaneTargetRecord(**values)  # type: ignore[arg-type]


def draft_roe(**overrides: object) -> control_plane.RoeVersionRecord:
    values = {
        "roe_version_id": "roe-1",
        "engagement_id": "eng-1",
        "organization_id": "org-1",
        "version": 1,
        "status": control_plane.RoeStatus.DRAFT,
        "allowed_targets": (ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io"),),
        "forbidden_targets": (ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://admin.agentique.io"),),
        "allowed_modes": (domain.TestMode.PASSIVE_SCAN,),
        "window_start": START,
        "window_end": END,
        "max_interactions": 50,
        "max_rate_per_second": 1.0,
        "emergency_contact_method": "email:security@example.test",
        "created_by_user_id": "operator-1",
        "created_at": NOW,
    }
    values.update(overrides)
    return control_plane.RoeVersionRecord(**values)  # type: ignore[arg-type]


def approval(**overrides: object) -> control_plane.ApprovalRecord:
    values = {
        "approval_id": "approval-1",
        "roe_version_id": "roe-1",
        "approved_by_user_id": "approver-1",
        "approved_at": NOW + timedelta(minutes=1),
        "approval_label": "Approved ROE v1",
    }
    values.update(overrides)
    return control_plane.ApprovalRecord(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> JobScopeRequest:
    values = {
        "target": ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io"),
        "mode": domain.TestMode.PASSIVE_SCAN,
        "requested_at": NOW + timedelta(minutes=2),
        "projected_interactions": 10,
    }
    values.update(overrides)
    return JobScopeRequest(**values)  # type: ignore[arg-type]


def approved_state() -> control_plane.ControlPlaneState:
    state = control_plane.ControlPlaneState()
    state = state.create_engagement(engagement(), actor_user_id="owner-1", event_id="event-eng")
    state = state.register_target(target_record(), actor_user_id="owner-1", event_id="event-target")
    state = state.create_roe_draft(draft_roe(), actor_user_id="operator-1", event_id="event-roe")
    return state.approve_roe(approval(), event_id="event-approval")


def test_workflow_creates_persistent_control_plane_records_and_audit() -> None:
    state = approved_state()

    assert len(state.engagements) == 1
    assert len(state.targets) == 1
    assert len(state.roe_versions) == 1
    assert len(state.approvals) == 1
    assert state.roe_versions[0].status is control_plane.RoeStatus.APPROVED
    assert state.roe_versions[0].approved_by_user_id == "approver-1"
    assert [event.action for event in state.audit_chain.audit_events] == [
        AuditAction.TARGET_CHANGE,
        AuditAction.TARGET_CHANGE,
        AuditAction.TARGET_CHANGE,
        AuditAction.TARGET_CHANGE,
    ]


def test_policy_decision_allows_current_approved_roe_and_records_audit() -> None:
    state, decision = approved_state().evaluate_policy(
        decision_id="decision-1",
        roe_version_id="roe-1",
        request=request(),
        decided_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=20),
        operator_user_id="operator-1",
        event_id="event-decision",
    )

    assert decision.allowed
    assert decision.reason == "scope_authorized"
    assert control_plane.policy_grant_from_decision(decision).decision_id == "decision-1"
    assert state.audit_chain.audit_events[-1].action is AuditAction.POLICY_DECISION
    assert state.policy_decisions == (decision,)


def test_missing_approval_fails_closed() -> None:
    state = control_plane.ControlPlaneState(
        engagements=(engagement(),),
        targets=(target_record(),),
        roe_versions=(
            draft_roe(
                status=control_plane.RoeStatus.APPROVED,
                approved_by_user_id=None,
            ),
        ),
    )
    state, decision = state.evaluate_policy(
        decision_id="decision-missing-approval",
        roe_version_id="roe-1",
        request=request(),
        decided_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=20),
        operator_user_id="operator-1",
        event_id="event-decision",
    )

    assert not decision.allowed
    assert decision.reason == "missing_approver"


def test_expired_window_fails_closed() -> None:
    state, decision = approved_state().evaluate_policy(
        decision_id="decision-expired",
        roe_version_id="roe-1",
        request=request(requested_at=END + timedelta(seconds=1)),
        decided_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=20),
        operator_user_id="operator-1",
        event_id="event-decision",
    )

    assert not decision.allowed
    assert decision.reason == "outside_time_window"


def test_forbidden_target_fails_closed() -> None:
    state, decision = approved_state().evaluate_policy(
        decision_id="decision-forbidden",
        roe_version_id="roe-1",
        request=request(target=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://admin.agentique.io")),
        decided_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=20),
        operator_user_id="operator-1",
        event_id="event-decision",
    )

    assert not decision.allowed
    assert decision.reason == "target_forbidden"


def test_revoked_scope_fails_closed_and_stales_prior_decision() -> None:
    state, decision = approved_state().evaluate_policy(
        decision_id="decision-1",
        roe_version_id="roe-1",
        request=request(),
        decided_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=20),
        operator_user_id="operator-1",
        event_id="event-decision",
    )
    assert decision.allowed

    state = state.revoke_roe(
        control_plane.RevocationRecord(
            revocation_id="revocation-1",
            roe_version_id="roe-1",
            revoked_by_user_id="approver-1",
            revoked_at=NOW + timedelta(minutes=3),
            reason="Emergency stop requested",
        ),
        event_id="event-revocation",
    )
    state, revoked_decision = state.evaluate_policy(
        decision_id="decision-revoked",
        roe_version_id="roe-1",
        request=request(requested_at=NOW + timedelta(minutes=4)),
        decided_at=NOW + timedelta(minutes=4),
        expires_at=NOW + timedelta(minutes=20),
        operator_user_id="operator-1",
        event_id="event-decision-revoked",
    )

    current = control_plane.assert_policy_decision_current(state, "decision-1", NOW + timedelta(minutes=4))
    assert state.roe_versions[-1].status is control_plane.RoeStatus.REVOKED
    assert not revoked_decision.allowed
    assert revoked_decision.reason == "roe_not_current:revoked"
    assert not current.allowed
    assert current.reason == "stale_policy_decision:roe_not_current:revoked"


def test_suspend_and_supersede_roe_workflows_are_audited() -> None:
    state = approved_state().suspend_roe(
        roe_version_id="roe-1",
        suspended_by_user_id="approver-1",
        suspended_at=NOW + timedelta(minutes=3),
        reason="Pause active testing",
        event_id="event-suspend",
    )
    assert state.roe_versions[-1].status is control_plane.RoeStatus.SUSPENDED

    state = approved_state()
    replacement = draft_roe(
        roe_version_id="roe-2",
        version=2,
        created_at=NOW + timedelta(minutes=5),
        window_end=END + timedelta(hours=1),
    )
    state = state.supersede_roe(
        current_roe_version_id="roe-1",
        replacement=replacement,
        actor_user_id="approver-1",
        event_id="event-supersede",
    )

    statuses = {roe.roe_version_id: roe.status for roe in state.roe_versions}
    assert statuses == {"roe-1": control_plane.RoeStatus.SUPERSEDED, "roe-2": control_plane.RoeStatus.DRAFT}
    assert state.audit_chain.audit_events[-1].subject_id == "roe-1"


def test_operator_confirmation_requires_current_policy_decision() -> None:
    state, decision = approved_state().evaluate_policy(
        decision_id="decision-1",
        roe_version_id="roe-1",
        request=request(),
        decided_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=20),
        operator_user_id="operator-1",
        event_id="event-decision",
    )
    assert decision.allowed

    state = state.record_operator_confirmation(
        control_plane.OperatorConfirmationRecord(
            confirmation_id="confirm-1",
            roe_version_id="roe-1",
            operator_user_id="operator-1",
            confirmed_at=NOW + timedelta(minutes=3),
            scope_acknowledged=True,
            risk_acknowledged=True,
            stop_conditions_acknowledged=True,
            policy_decision_id="decision-1",
        ),
        event_id="event-confirm",
    )

    assert state.operator_confirmations[0].to_active_confirmation().confirmed_by_user_id == "operator-1"

    with pytest.raises(ValueError, match="stale_policy_decision"):
        state.record_operator_confirmation(
            control_plane.OperatorConfirmationRecord(
                confirmation_id="confirm-2",
                roe_version_id="roe-1",
                operator_user_id="operator-1",
                confirmed_at=NOW + timedelta(hours=1),
                scope_acknowledged=True,
                risk_acknowledged=True,
                stop_conditions_acknowledged=True,
                policy_decision_id="decision-1",
            ),
            event_id="event-confirm-stale",
        )


def test_jsonl_store_persists_record_types_and_detects_tampering(tmp_path) -> None:
    path = tmp_path / "control-plane.jsonl"
    store = control_plane.JsonlControlPlaneStore(path)
    state, decision = approved_state().evaluate_policy(
        decision_id="decision-1",
        roe_version_id="roe-1",
        request=request(),
        decided_at=NOW + timedelta(minutes=2),
        expires_at=NOW + timedelta(minutes=20),
        operator_user_id="operator-1",
        event_id="event-decision",
    )

    store.append(
        control_plane.ControlPlaneRecordType.ENGAGEMENT,
        "eng-1",
        control_plane.engagement_payload(state.engagements[0]),
    )
    store.append(
        control_plane.ControlPlaneRecordType.TARGET,
        "target-1",
        control_plane.target_payload(state.targets[0]),
    )
    store.append(
        control_plane.ControlPlaneRecordType.ROE_VERSION,
        "roe-1",
        control_plane.roe_payload(state.roe_versions[0]),
    )
    store.append(
        control_plane.ControlPlaneRecordType.APPROVAL,
        "approval-1",
        {
            "approval_id": "approval-1",
            "roe_version_id": "roe-1",
            "approved_by_user_id": "approver-1",
            "approved_at": approval().approved_at.isoformat(),
            "approval_label": "Approved ROE v1",
        },
    )
    store.append(
        control_plane.ControlPlaneRecordType.REVOCATION,
        "revocation-placeholder",
        {
            "revocation_id": "revocation-placeholder",
            "roe_version_id": "roe-1",
            "revoked_by_user_id": "none",
            "revoked_at": NOW.isoformat(),
            "reason": "not revoked in active state; record type coverage only",
        },
    )
    store.append(
        control_plane.ControlPlaneRecordType.POLICY_DECISION,
        "decision-1",
        control_plane.policy_decision_payload(decision),
    )
    store.append(
        control_plane.ControlPlaneRecordType.OPERATOR_CONFIRMATION,
        "confirm-placeholder",
        {
            "confirmation_id": "confirm-placeholder",
            "roe_version_id": "roe-1",
            "operator_user_id": "operator-1",
            "confirmed_at": NOW.isoformat(),
            "scope_acknowledged": True,
            "risk_acknowledged": True,
            "stop_conditions_acknowledged": True,
            "policy_decision_id": "decision-1",
        },
    )

    records = store.read_all()
    assert {record.record_type for record in records} == set(control_plane.ControlPlaneRecordType)
    assert all(record.record_hash for record in records)

    path.write_text(path.read_text(encoding="utf-8").replace("Agentique authorized assessment", "tampered"), encoding="utf-8")
    with pytest.raises(ValueError, match="control_plane_record_hash_mismatch"):
        store.read_all()


def test_invalid_roe_inputs_fail_closed_before_approval() -> None:
    state = control_plane.ControlPlaneState().create_engagement(
        engagement(), actor_user_id="owner-1", event_id="event-eng"
    )

    with pytest.raises(ValueError, match="missing_target_allowlist"):
        state.create_roe_draft(
            draft_roe(allowed_targets=()),
            actor_user_id="operator-1",
            event_id="event-roe",
        )

    with pytest.raises(ValueError, match="invalid_time_window"):
        state.create_roe_draft(
            draft_roe(window_start=END, window_end=START),
            actor_user_id="operator-1",
            event_id="event-roe",
        )

    with pytest.raises(ValueError, match="missing_emergency_contact"):
        state.create_roe_draft(
            draft_roe(emergency_contact_method=None),
            actor_user_id="operator-1",
            event_id="event-roe",
        )
