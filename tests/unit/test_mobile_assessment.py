import pytest

from redagent_platform import evidence_chain, mobile_assessment
from redagent_platform.findings import Severity


def package(**overrides: object) -> mobile_assessment.MobilePackageAllowlistEntry:
    values = {
        "package_id": "com.example.labapp",
        "platform": mobile_assessment.MobilePlatform.ANDROID,
        "version": "1.0.0",
        "owner_user_id": "owner-1",
        "approved": True,
    }
    values.update(overrides)
    return mobile_assessment.MobilePackageAllowlistEntry(**values)  # type: ignore[arg-type]


def lab_boundary(**overrides: object) -> mobile_assessment.MobileLabBoundary:
    values = {
        "lab_id": "mobile-lab-1",
        "device_label": "android-emulator-1",
        "emulator_or_test_device": True,
        "production_account_forbidden": True,
        "real_user_data_forbidden": True,
    }
    values.update(overrides)
    return mobile_assessment.MobileLabBoundary(**values)  # type: ignore[arg-type]


def privacy_rules(**overrides: object) -> mobile_assessment.MobilePrivacyRules:
    values = {
        "allow_personal_data_capture": False,
        "require_redaction": True,
        "public_store_scraping_allowed": False,
    }
    values.update(overrides)
    return mobile_assessment.MobilePrivacyRules(**values)  # type: ignore[arg-type]


def scope(**overrides: object) -> mobile_assessment.MobileAssessmentScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "approved_by_user_id": "lead-1",
        "package_allowlist": (package(),),
        "lab_boundary": lab_boundary(),
        "privacy_rules": privacy_rules(),
    }
    values.update(overrides)
    return mobile_assessment.MobileAssessmentScope(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> mobile_assessment.MobileAssessmentRequest:
    values = {
        "job_id": "mobile-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "package_id": "com.example.labapp",
        "mode": mobile_assessment.MobileAssessmentMode.STATIC_PACKAGE_REVIEW,
        "requested_activities": (),
    }
    values.update(overrides)
    return mobile_assessment.MobileAssessmentRequest(**values)  # type: ignore[arg-type]


def test_owner_approval_package_allowlist_lab_boundary_and_privacy_rules_are_required() -> None:
    mobile_assessment.validate_mobile_scope(scope())

    cases: tuple[tuple[dict[str, object], str], ...] = (
        ({"approved_by_user_id": ""}, "missing_approved_by_user_id"),
        ({"package_allowlist": ()}, "mobile_package_allowlist_required"),
        ({"lab_boundary": lab_boundary(emulator_or_test_device=False)}, "mobile_test_device_required"),
        ({"privacy_rules": privacy_rules(allow_personal_data_capture=True)}, "mobile_personal_data_capture_forbidden"),
        ({"privacy_rules": privacy_rules(require_redaction=False)}, "mobile_redaction_required"),
    )
    for overrides, expected in cases:
        with pytest.raises(ValueError, match=expected):
            mobile_assessment.validate_mobile_scope(scope(**overrides))


def test_static_and_manifest_review_are_implemented_before_dynamic_modes() -> None:
    decision = mobile_assessment.evaluate_mobile_assessment(scope=scope(), request=request())

    assert decision.allowed
    assert decision.reason == "mobile_static_review_allowed"

    plan = mobile_assessment.build_mobile_static_review_plan(scope=scope(), request=request())

    assert all(step.static_only for step in plan.steps)
    assert [step.mode for step in plan.steps] == [
        mobile_assessment.MobileAssessmentMode.STATIC_PACKAGE_REVIEW,
        mobile_assessment.MobileAssessmentMode.MANIFEST_CONFIGURATION_REVIEW,
    ]

    for mode in (
        mobile_assessment.MobileAssessmentMode.DYNAMIC_INSTRUMENTATION,
        mobile_assessment.MobileAssessmentMode.TRAFFIC_INTERCEPTION,
    ):
        blocked = mobile_assessment.evaluate_mobile_assessment(scope=scope(), request=request(mode=mode))
        assert not blocked.allowed
        assert blocked.reason == "mobile_dynamic_mode_not_implemented"


def test_forbidden_mobile_activities_are_blocked() -> None:
    for activity in mobile_assessment.MobileForbiddenActivity:
        decision = mobile_assessment.evaluate_mobile_assessment(
            scope=scope(),
            request=request(requested_activities=(activity,)),
        )
        assert not decision.allowed
        assert decision.reason == "mobile_forbidden_activity_requested"


def test_mobile_evidence_distinguishes_required_categories() -> None:
    categories = {
        mobile_assessment.MobileEvidenceCategory.STATIC_PACKAGE_FINDING,
        mobile_assessment.MobileEvidenceCategory.RUNTIME_LAB_FINDING,
        mobile_assessment.MobileEvidenceCategory.API_BACKEND_FINDING,
        mobile_assessment.MobileEvidenceCategory.DEVICE_ENVIRONMENT_METADATA,
    }

    for category in categories:
        classified = mobile_assessment.classify_mobile_evidence(
            mobile_assessment.MobileEvidenceClassification(
                evidence_id=f"evidence-{category.value}",
                category=category,
                redaction_status=evidence_chain.RedactionStatus.REDACTED,
                lab_only=True,
            )
        )
        assert classified.category is category

    with pytest.raises(ValueError, match="runtime_mobile_evidence_requires_lab"):
        mobile_assessment.classify_mobile_evidence(
            mobile_assessment.MobileEvidenceClassification(
                evidence_id="runtime-1",
                category=mobile_assessment.MobileEvidenceCategory.RUNTIME_LAB_FINDING,
                redaction_status=evidence_chain.RedactionStatus.REDACTED,
                lab_only=False,
            )
        )


def test_mobile_findings_map_to_masvs_mastg_and_lab_only_reproduction_steps() -> None:
    mapping = mobile_assessment.build_mobile_finding_mapping(
        finding_id="mobile-finding-1",
        masvs_control="MASVS-STORAGE-1",
        mastg_test="MASTG-TEST-0001",
        package_id="com.example.labapp",
        severity=Severity.MEDIUM,
        lab_reproduction_steps=("Install approved lab build.", "Review manifest permissions offline."),
        remediation_guidance="Remove unnecessary permissions from the mobile manifest.",
    )

    assert mapping.masvs_control == "MASVS-STORAGE-1"
    assert mapping.mastg_test == "MASTG-TEST-0001"
    assert mapping.package_id == "com.example.labapp"
    assert mapping.severity is Severity.MEDIUM
    assert len(mapping.lab_reproduction_steps) == 2
    assert "permissions" in mapping.remediation_guidance

    with pytest.raises(ValueError, match="mobile_lab_reproduction_steps_required"):
        mobile_assessment.build_mobile_finding_mapping(
            finding_id="mobile-finding-2",
            masvs_control="MASVS-NETWORK-1",
            mastg_test="MASTG-TEST-0002",
            package_id="com.example.labapp",
            severity=Severity.LOW,
            lab_reproduction_steps=(),
            remediation_guidance="Document lab-only steps.",
        )
