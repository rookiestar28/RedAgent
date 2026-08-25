from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import domain, lab_harness, target_inventory
from redagent_platform.scope_authorization import JobScopeRequest, ScopeTarget, decide_scope


NOW = datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc)


def approval(**overrides: object) -> lab_harness.SandboxApproval:
    values = {
        "approval_id": "sandbox-approval-1",
        "organization_id": "org-1",
        "approved_by_user_id": "lead-1",
        "approved_at": NOW - timedelta(hours=1),
        "expires_at": NOW + timedelta(hours=1),
        "allowed_kinds": (lab_harness.LabTargetKind.JUICE_SHOP, lab_harness.LabTargetKind.CRAPI),
        "allowed_actions": (lab_harness.LabHarnessAction.CONNECT_EXISTING,),
        "plan_reference": "PUBLIC_RELEASE.md",
        "emergency_contact_method": "email",
    }
    values.update(overrides)
    return lab_harness.SandboxApproval(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> lab_harness.LabTargetRequest:
    values = {
        "target_id": "lab-juice-local",
        "organization_id": "org-1",
        "engagement_id": "eng-lab-1",
        "owner_label": "Security Lab",
        "kind": lab_harness.LabTargetKind.JUICE_SHOP,
        "action": lab_harness.LabHarnessAction.CONNECT_EXISTING,
        "base_url": "http://LOCALHOST:3000/",
        "requested_at": NOW,
        "health_path": "/rest/admin/application-version",
        "health_expected_statuses": (200, 401),
        "health_timeout_seconds": 3,
    }
    values.update(overrides)
    return lab_harness.LabTargetRequest(**values)  # type: ignore[arg-type]


def test_register_local_juice_shop_requires_current_sandbox_approval() -> None:
    registration = lab_harness.register_lab_target(request(), approval())

    assert registration.kind is lab_harness.LabTargetKind.JUICE_SHOP
    assert registration.base_url == "http://localhost:3000"
    assert registration.labels == (lab_harness.LAB_ONLY_LABEL,)
    assert registration.sandbox_approval_id == "sandbox-approval-1"


def test_registered_lab_target_cannot_be_confused_with_enterprise_inventory() -> None:
    registration = lab_harness.register_lab_target(request(), approval())
    target = registration.inventory_target

    assert target.target_type is domain.TargetType.LAB_TARGET
    assert target.environment is target_inventory.EnvironmentType.LAB
    assert target.authorization_status is domain.AuthorizationStatus.APPROVED
    assert target.allowed_modes == (domain.TestMode.LAB_ONLY_RUN,)
    assert target.value == "lab:juice_shop/lab-juice-local"
    assert registration.scope_target == ScopeTarget(target_type=domain.TargetType.LAB_TARGET, value=target.value)


def test_crapi_loopback_registration_is_supported() -> None:
    registration = lab_harness.register_lab_target(
        request(
            target_id="lab-crapi-local",
            kind=lab_harness.LabTargetKind.CRAPI,
            base_url="http://127.0.0.1:8888",
            health_path="/identity/health",
        ),
        approval(),
    )

    assert registration.kind is lab_harness.LabTargetKind.CRAPI
    assert registration.base_url == "http://127.0.0.1:8888"
    assert registration.health_check.url == "http://127.0.0.1:8888/identity/health"


def test_missing_or_expired_sandbox_approval_fails_closed() -> None:
    with pytest.raises(ValueError, match="sandbox_approval_not_current"):
        lab_harness.register_lab_target(request(), approval(expires_at=NOW))

    with pytest.raises(ValueError, match="lab_kind_not_approved"):
        lab_harness.register_lab_target(
            request(kind=lab_harness.LabTargetKind.CRAPI),
            approval(allowed_kinds=(lab_harness.LabTargetKind.JUICE_SHOP,)),
        )


def test_lab_action_must_be_explicitly_approved() -> None:
    with pytest.raises(ValueError, match="lab_action_not_approved"):
        lab_harness.register_lab_target(request(action=lab_harness.LabHarnessAction.RUN_LOCAL), approval())


def test_public_demo_and_non_local_hosts_are_rejected() -> None:
    with pytest.raises(ValueError, match="public_demo_forbidden"):
        lab_harness.register_lab_target(request(base_url="https://demo.owasp-juice.shop"), approval())

    with pytest.raises(ValueError, match="local_loopback_required"):
        lab_harness.register_lab_target(request(base_url="https://agentique.io"), approval())


def test_health_check_is_request_metadata_only() -> None:
    registration = lab_harness.register_lab_target(request(), approval())

    assert registration.health_check.method == "GET"
    assert registration.health_check.url == "http://localhost:3000/rest/admin/application-version"
    assert registration.health_check.expected_statuses == (200, 401)
    assert not hasattr(lab_harness, "execute_health_check")


def test_reset_and_teardown_procedures_are_documented_manual_steps() -> None:
    registration = lab_harness.register_lab_target(request(), approval())

    assert registration.reset_procedure.kind is lab_harness.LabProcedureKind.RESET
    assert registration.reset_procedure.destructive
    assert all(step.manual_confirmation_required for step in registration.reset_procedure.steps)
    assert registration.teardown_procedure.kind is lab_harness.LabProcedureKind.TEARDOWN
    assert registration.teardown_procedure.destructive
    assert len(registration.teardown_procedure.steps) >= 3


def test_build_lab_only_scope_allows_only_lab_mode_and_target() -> None:
    registration = lab_harness.register_lab_target(request(), approval())
    scope = lab_harness.build_lab_only_scope(
        registration=registration,
        window_start=NOW - timedelta(minutes=5),
        window_end=NOW + timedelta(minutes=30),
        max_interactions=10,
        max_rate_per_second=1.0,
        emergency_contact_method="email",
        approved_by_user_id="lead-1",
    )

    allowed = decide_scope(
        scope,
        JobScopeRequest(
            target=registration.scope_target,
            mode=domain.TestMode.LAB_ONLY_RUN,
            requested_at=NOW,
            projected_interactions=1,
        ),
    )
    wrong_target = decide_scope(
        scope,
        JobScopeRequest(
            target=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="http://localhost:3000"),
            mode=domain.TestMode.LAB_ONLY_RUN,
            requested_at=NOW,
            projected_interactions=1,
        ),
    )
    wrong_mode = decide_scope(
        scope,
        JobScopeRequest(
            target=registration.scope_target,
            mode=domain.TestMode.PASSIVE_SCAN,
            requested_at=NOW,
            projected_interactions=1,
        ),
    )

    assert allowed.allowed
    assert wrong_target.reason == "target_not_in_allowlist"
    assert wrong_mode.reason == "mode_not_allowed"
