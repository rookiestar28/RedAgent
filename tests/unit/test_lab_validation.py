from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import domain, lab_harness, lab_validation, target_inventory


NOW = datetime(2026, 7, 9, 15, 0, tzinfo=timezone.utc)


def approval() -> lab_harness.SandboxApproval:
    return lab_harness.SandboxApproval(
        approval_id="approval-1",
        organization_id="org-1",
        approved_by_user_id="lead-1",
        approved_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        allowed_kinds=(lab_harness.LabTargetKind.JUICE_SHOP,),
        allowed_actions=(lab_harness.LabHarnessAction.CONNECT_EXISTING,),
        plan_reference="PUBLIC_RELEASE.md",
        emergency_contact_method="email",
    )


def lab_target() -> lab_harness.LabTargetRegistration:
    return lab_harness.register_lab_target(
        lab_harness.LabTargetRequest(
            target_id="lab-juice-local",
            organization_id="org-1",
            engagement_id="eng-1",
            owner_label="Security Lab",
            kind=lab_harness.LabTargetKind.JUICE_SHOP,
            action=lab_harness.LabHarnessAction.CONNECT_EXISTING,
            base_url="http://localhost:3000",
            requested_at=NOW,
        ),
        approval(),
    )


def inventory_target(environment: target_inventory.EnvironmentType) -> target_inventory.InventoryTarget:
    return target_inventory.build_inventory_target(
        target_inventory.TargetImportCandidate(
            id=f"target-{environment.value}",
            organization_id="org-1",
            engagement_id="eng-1",
            owner_label="Owner",
            target_type=domain.TargetType.WEB_ORIGIN,
            value="https://example.test",
            environment=environment,
            data_sensitivity=target_inventory.DataSensitivity.INTERNAL,
            authorization_status=domain.AuthorizationStatus.APPROVED,
            allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
            explicit_review=True,
            review_reason="unit-test",
        )
    )


def profile(**overrides: object) -> lab_validation.ScannerPolicyProfile:
    values = {
        "profile_id": "zap-safe-baseline",
        "module_id": "zap",
        "allowed_modes": (domain.TestMode.ACTIVE_SCAN,),
        "required_fixture_kinds": lab_validation.REQUIRED_GOLDEN_FIXTURE_KINDS,
        "max_age_seconds": 86400,
    }
    values.update(overrides)
    return lab_validation.ScannerPolicyProfile(**values)  # type: ignore[arg-type]


def validation_record(**overrides: object) -> lab_validation.LabValidationRecord:
    fixtures = lab_validation.build_golden_evidence_corpus(policy_profile_id="zap-safe-baseline", generated_at=NOW)
    values = {
        "validation_id": "validation-1",
        "profile": profile(),
        "lab_target": lab_target(),
        "fixtures": fixtures,
        "validated_at": NOW,
        "expires_at": NOW + timedelta(hours=24),
        "passed": True,
    }
    values.update(overrides)
    return lab_validation.record_lab_validation(**values)  # type: ignore[arg-type]


def test_target_registry_distinguishes_lab_staging_and_production() -> None:
    assert lab_validation.classify_target_environment(lab_target().inventory_target) is lab_validation.LabEnvironmentClass.LOCAL_LAB
    assert (
        lab_validation.classify_target_environment(inventory_target(target_inventory.EnvironmentType.STAGING))
        is lab_validation.LabEnvironmentClass.ENTERPRISE_STAGING
    )
    assert (
        lab_validation.classify_target_environment(inventory_target(target_inventory.EnvironmentType.PRODUCTION))
        is lab_validation.LabEnvironmentClass.PRODUCTION
    )


def test_golden_evidence_corpus_covers_required_fixture_kinds() -> None:
    fixtures = lab_validation.build_golden_evidence_corpus(policy_profile_id="zap-safe-baseline", generated_at=NOW)

    assert tuple(fixture.kind for fixture in fixtures) == lab_validation.REQUIRED_GOLDEN_FIXTURE_KINDS
    assert all(fixture.sanitized_artifact_id.startswith("sanitized:") for fixture in fixtures)
    assert all(fixture.policy_profile_id == "zap-safe-baseline" for fixture in fixtures)


def test_record_lab_validation_links_sanitized_artifacts_to_policy_profile() -> None:
    record = validation_record()

    assert record.policy_profile_id == "zap-safe-baseline"
    assert record.module_id == "zap"
    assert record.lab_target_id == "lab-juice-local"
    assert len(record.fixture_ids) == len(lab_validation.REQUIRED_GOLDEN_FIXTURE_KINDS)
    assert all(artifact_id.startswith("sanitized:zap-safe-baseline") for artifact_id in record.sanitized_artifact_ids)


def test_validation_requires_complete_matching_sanitized_fixtures() -> None:
    fixtures = lab_validation.build_golden_evidence_corpus(policy_profile_id="zap-safe-baseline", generated_at=NOW)
    missing = fixtures[:-1]
    unsanitized = (fixtures[0].__class__(**{**fixtures[0].__dict__, "sanitized_artifact_id": "raw-artifact"}),) + fixtures[1:]

    with pytest.raises(ValueError, match="missing_required_golden_fixture"):
        validation_record(fixtures=missing)
    with pytest.raises(ValueError, match="lab_artifact_not_sanitized"):
        validation_record(fixtures=unsanitized)


def test_enterprise_jobs_require_matching_current_lab_validation() -> None:
    staging = inventory_target(target_inventory.EnvironmentType.STAGING)
    production = inventory_target(target_inventory.EnvironmentType.PRODUCTION)
    record = validation_record()

    allowed = lab_validation.validate_enterprise_job_lab_gate(
        target=staging,
        profile=profile(),
        validation_records=(record,),
        requested_at=NOW + timedelta(minutes=1),
    )
    missing = lab_validation.validate_enterprise_job_lab_gate(
        target=production,
        profile=profile(profile_id="different-profile"),
        validation_records=(record,),
        requested_at=NOW + timedelta(minutes=1),
    )
    expired = lab_validation.validate_enterprise_job_lab_gate(
        target=staging,
        profile=profile(),
        validation_records=(record,),
        requested_at=NOW + timedelta(days=2),
    )
    lab_allowed = lab_validation.validate_enterprise_job_lab_gate(
        target=lab_target().inventory_target,
        profile=profile(),
        validation_records=(),
        requested_at=NOW,
    )

    assert allowed.allowed
    assert allowed.validation_id == "validation-1"
    assert missing.reason == "matching_lab_validation_required"
    assert expired.reason == "matching_lab_validation_required"
    assert lab_allowed.reason == "local_lab_target"
