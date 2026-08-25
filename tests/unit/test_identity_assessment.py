from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import evidence_chain, identity_assessment


NOW = datetime(2026, 7, 8, 20, 0, tzinfo=timezone.utc)


def scope(**overrides: object) -> identity_assessment.IdentityTenantScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "tenant_id": "tenant-1",
        "tenant_owner_user_id": "owner-1",
        "approved_by_user_id": "lead-1",
        "window_start": NOW - timedelta(minutes=5),
        "window_end": NOW + timedelta(hours=1),
        "allowed_principal_ids": ("group-security",),
        "allowed_resource_ids": ("tenant-config", "conditional-access"),
        "allowed_read_permissions": ("Directory.Read.All", "Policy.Read.All"),
    }
    values.update(overrides)
    return identity_assessment.IdentityTenantScope(**values)  # type: ignore[arg-type]


def boundary(**overrides: object) -> identity_assessment.IdentityCredentialBoundary:
    values = {
        "credential_reference_id": "cred-ref-1",
        "lease_id": "lease-1",
        "permissions": ("Directory.Read.All", "Policy.Read.All"),
        "read_only": True,
        "expires_at": NOW + timedelta(minutes=30),
        "redaction_label": "identity-readonly-lease",
    }
    values.update(overrides)
    return identity_assessment.IdentityCredentialBoundary(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> identity_assessment.IdentityAssessmentRequest:
    values = {
        "job_id": "identity-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "tenant_id": "tenant-1",
        "mode": identity_assessment.IdentityAssessmentMode.READ_ONLY_CONFIGURATION,
        "requested_at": NOW,
        "requested_permissions": ("Directory.Read.All",),
        "requested_activities": (),
        "operator_user_id": "operator-1",
        "credential_boundary": boundary(),
    }
    values.update(overrides)
    return identity_assessment.IdentityAssessmentRequest(**values)  # type: ignore[arg-type]


def test_owner_approval_and_least_privilege_credential_boundary_are_required() -> None:
    allowed = identity_assessment.evaluate_identity_assessment(scope=scope(), request=request())

    assert allowed.allowed
    assert allowed.reason == "identity_read_only_collection_allowed"
    assert request().credential_boundary is not None
    assert not request().credential_boundary.contains_secret_value

    missing_approval = identity_assessment.evaluate_identity_assessment(
        scope=scope(approved_by_user_id=None),
        request=request(),
    )
    assert not missing_approval.allowed
    assert missing_approval.reason == "tenant_owner_approval_required"

    overprivileged = identity_assessment.evaluate_identity_assessment(
        scope=scope(),
        request=request(credential_boundary=boundary(read_only=False)),
    )
    assert not overprivileged.allowed
    assert overprivileged.reason == "least_privilege_read_only_required"


def test_read_only_collection_plan_is_implemented_before_active_identity_tests() -> None:
    plan = identity_assessment.build_read_only_collection_plan(scope=scope(), request=request())

    assert plan.mode is identity_assessment.IdentityAssessmentMode.READ_ONLY_CONFIGURATION
    assert all(step.read_only for step in plan.steps)
    assert [step.control_area for step in plan.steps] == [
        identity_assessment.IdentityControlArea.SSO_CONFIGURATION,
        identity_assessment.IdentityControlArea.OAUTH_APPLICATIONS,
        identity_assessment.IdentityControlArea.MFA_POLICY,
        identity_assessment.IdentityControlArea.PRIVILEGED_ACCESS,
        identity_assessment.IdentityControlArea.CONDITIONAL_ACCESS,
    ]

    active = identity_assessment.evaluate_identity_assessment(
        scope=scope(),
        request=request(mode=identity_assessment.IdentityAssessmentMode.ACTIVE_IDENTITY_TEST),
    )
    assert not active.allowed
    assert active.reason == "active_identity_test_not_implemented"


def test_forbidden_identity_attack_classes_are_blocked() -> None:
    for activity in identity_assessment.IdentityForbiddenActivity:
        decision = identity_assessment.evaluate_identity_assessment(
            scope=scope(),
            request=request(requested_activities=(activity,)),
        )
        assert not decision.allowed
        assert decision.reason == "forbidden_identity_activity_requested"


def test_identity_findings_map_control_area_affected_entities_redaction_and_remediation() -> None:
    mapping = identity_assessment.build_identity_finding_mapping(
        finding_id="identity-finding-1",
        control_area=identity_assessment.IdentityControlArea.MFA_POLICY,
        affected_principal_ids=("group-security",),
        affected_resource_ids=("tenant-config",),
        evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
        remediation_guidance="Require phishing-resistant MFA for privileged principals.",
    )

    assert mapping.control_area is identity_assessment.IdentityControlArea.MFA_POLICY
    assert mapping.affected_principal_ids == ("group-security",)
    assert mapping.affected_resource_ids == ("tenant-config",)
    assert mapping.evidence_redaction_class is evidence_chain.RedactionStatus.REDACTED
    assert "MFA" in mapping.remediation_guidance

    with pytest.raises(ValueError, match="identity_finding_requires_affected_entity"):
        identity_assessment.build_identity_finding_mapping(
            finding_id="identity-finding-2",
            control_area=identity_assessment.IdentityControlArea.SSO_CONFIGURATION,
            affected_principal_ids=(),
            affected_resource_ids=(),
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            remediation_guidance="Review SSO configuration.",
        )


@pytest.mark.parametrize(
    ("scope_override", "request_override", "expected_reason"),
    (
        (None, {}, "tenant_scope_required"),
        ({}, {"credential_boundary": None}, "credential_boundary_required"),
        ({"window_start": NOW + timedelta(minutes=1)}, {}, "outside_identity_testing_window"),
        ({"approved_by_user_id": None}, {}, "tenant_owner_approval_required"),
        ({}, {"requested_permissions": ("Directory.ReadWrite.All",)}, "identity_permission_not_allowed"),
    ),
)
def test_identity_assessments_fail_closed_when_scope_credentials_window_or_approval_is_missing(
    scope_override: dict[str, object] | None,
    request_override: dict[str, object],
    expected_reason: str,
) -> None:
    active_scope = None if scope_override is None else scope(**scope_override)

    decision = identity_assessment.evaluate_identity_assessment(
        scope=active_scope,
        request=request(**request_override),
    )

    assert not decision.allowed
    assert decision.reason == expected_reason
