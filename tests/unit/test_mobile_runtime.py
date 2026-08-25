from datetime import datetime, timezone

import pytest

from redagent_platform import (
    domain,
    evidence_chain,
    job_queue,
    mobile_assessment,
    mobile_runtime,
)
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 22, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.MOBILE_PACKAGE, value="com.example.labapp")


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


def assessment_request(**overrides: object) -> mobile_assessment.MobileAssessmentRequest:
    values = {
        "job_id": "mobile-runtime-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "package_id": "com.example.labapp",
        "mode": mobile_assessment.MobileAssessmentMode.STATIC_PACKAGE_REVIEW,
        "requested_activities": (),
    }
    values.update(overrides)
    return mobile_assessment.MobileAssessmentRequest(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> mobile_runtime.MobileRuntimeProfile:
    values = {
        "profile_id": "mobile-runtime-profile",
        "module_id": "mobile-runtime",
        "allowed_package_ids": ("com.example.labapp",),
        "allowed_modes": (
            mobile_assessment.MobileAssessmentMode.STATIC_PACKAGE_REVIEW,
            mobile_assessment.MobileAssessmentMode.MANIFEST_CONFIGURATION_REVIEW,
            mobile_assessment.MobileAssessmentMode.DYNAMIC_INSTRUMENTATION,
            mobile_assessment.MobileAssessmentMode.TRAFFIC_INTERCEPTION,
        ),
        "lab_dynamic_allowed": True,
        "max_results": 20,
        "timeout_seconds": 120,
        "actions": (
            mobile_runtime.MobileRuntimeAction.IMPORT_RESULTS,
            mobile_runtime.MobileRuntimeAction.PREPARE_LAB_DYNAMIC_PLAN,
        ),
    }
    values.update(overrides)
    return mobile_runtime.MobileRuntimeProfile(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.MOBILE_ASSESSMENT,),
        "policy_token_reference": "policy-ref-mobile",
        "target_scope": TARGET,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "mobile_findings", "mobile_report_rows"),
        "cleanup_callback": "cleanup://runner-1/mobile-runtime",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def runtime_request(**overrides: object) -> mobile_runtime.MobileRuntimeRequest:
    values = {
        "runtime_id": "mobile-runtime-1",
        "profile": profile(),
        "scope": scope(),
        "assessment_request": assessment_request(),
        "runner": runner(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return mobile_runtime.MobileRuntimeRequest(**values)  # type: ignore[arg-type]


def result_items() -> tuple[mobile_runtime.MobileRuntimeResultItem, ...]:
    return (
        mobile_runtime.MobileRuntimeResultItem(
            item_id="static-1",
            category=mobile_assessment.MobileEvidenceCategory.STATIC_PACKAGE_FINDING,
            package_id="com.example.labapp",
            masvs_control="MASVS-STORAGE-1",
            mastg_test="MASTG-TEST-0001",
            severity=mobile_runtime.Severity.MEDIUM,
            remediation_guidance="Remove unnecessary storage of sensitive data from the lab build.",
            lab_reproduction_steps=("Review the approved package metadata offline.",),
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            summary="Sanitized static package review finding.",
            lab_only=False,
            component_label="package-metadata",
        ),
        mobile_runtime.MobileRuntimeResultItem(
            item_id="runtime-1",
            category=mobile_assessment.MobileEvidenceCategory.RUNTIME_LAB_FINDING,
            package_id="com.example.labapp",
            masvs_control="MASVS-RESILIENCE-1",
            mastg_test="MASTG-TEST-0002",
            severity=mobile_runtime.Severity.HIGH,
            remediation_guidance="Harden the lab build against approved instrumentation checks.",
            lab_reproduction_steps=("Use only the approved emulator/test-device lab workflow.",),
            evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
            summary="Sanitized lab runtime finding.",
            lab_only=True,
            contains_sensitive_material=True,
            component_label="runtime-lab",
        ),
        mobile_runtime.MobileRuntimeResultItem(
            item_id="api-1",
            category=mobile_assessment.MobileEvidenceCategory.API_BACKEND_FINDING,
            package_id="com.example.labapp",
            masvs_control="MASVS-NETWORK-1",
            mastg_test="MASTG-TEST-0003",
            severity=mobile_runtime.Severity.MEDIUM,
            remediation_guidance="Align backend API transport controls with the mobile client profile.",
            lab_reproduction_steps=("Replay only sanitized lab request metadata.",),
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            summary="Sanitized API/backend correlation finding.",
            lab_only=True,
            component_label="api-backend",
        ),
        mobile_runtime.MobileRuntimeResultItem(
            item_id="device-1",
            category=mobile_assessment.MobileEvidenceCategory.DEVICE_ENVIRONMENT_METADATA,
            package_id="com.example.labapp",
            masvs_control="MASVS-PLATFORM-1",
            mastg_test="MASTG-TEST-0004",
            severity=mobile_runtime.Severity.LOW,
            remediation_guidance="Keep lab device metadata attached to each mobile assessment.",
            lab_reproduction_steps=("Record only approved emulator/test-device metadata.",),
            evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
            summary="Sanitized device environment metadata.",
            lab_only=True,
            contains_sensitive_material=True,
            component_label="android-emulator-1",
        ),
    )


def test_plan_requires_package_allowlist_owner_approval_lab_boundary_and_privacy() -> None:
    plan = mobile_runtime.build_mobile_runtime_plan(runtime_request())

    assert plan.package_id == "com.example.labapp"
    assert plan.mode is mobile_assessment.MobileAssessmentMode.STATIC_PACKAGE_REVIEW
    assert plan.job.mode is domain.TestMode.MOBILE_ASSESSMENT
    assert plan.lab_id == "mobile-lab-1"
    assert not plan.lab_only

    with pytest.raises(ValueError, match="mobile_runtime_package_not_allowlisted"):
        mobile_runtime.build_mobile_runtime_plan(
            runtime_request(assessment_request=assessment_request(package_id="com.other.app"))
        )

    with pytest.raises(ValueError, match="mobile_package_owner_approval_required"):
        mobile_runtime.build_mobile_runtime_plan(
            runtime_request(scope=scope(package_allowlist=(package(approved=False),)))
        )

    with pytest.raises(ValueError, match="mobile_personal_data_capture_forbidden"):
        mobile_runtime.build_mobile_runtime_plan(
            runtime_request(scope=scope(privacy_rules=privacy_rules(allow_personal_data_capture=True)))
        )

    with pytest.raises(ValueError, match="mobile_production_account_must_be_forbidden"):
        mobile_runtime.build_mobile_runtime_plan(
            runtime_request(scope=scope(lab_boundary=lab_boundary(production_account_forbidden=False)))
        )


def test_static_review_and_lab_dynamic_plan_are_separate_and_import_only() -> None:
    static_plan = mobile_runtime.build_mobile_runtime_plan(runtime_request())
    dynamic_plan = mobile_runtime.build_mobile_runtime_plan(
        runtime_request(
            assessment_request=assessment_request(mode=mobile_assessment.MobileAssessmentMode.DYNAMIC_INSTRUMENTATION)
        )
    )

    assert not static_plan.lab_only
    assert dynamic_plan.lab_only
    assert dynamic_plan.actions == (
        mobile_runtime.MobileRuntimeAction.IMPORT_RESULTS,
        mobile_runtime.MobileRuntimeAction.PREPARE_LAB_DYNAMIC_PLAN,
    )

    with pytest.raises(ValueError, match="mobile_lab_dynamic_not_allowed"):
        mobile_runtime.build_mobile_runtime_plan(
            runtime_request(
                profile=profile(lab_dynamic_allowed=False),
                assessment_request=assessment_request(
                    mode=mobile_assessment.MobileAssessmentMode.DYNAMIC_INSTRUMENTATION
                ),
            )
        )

    with pytest.raises(ValueError, match="mobile_runtime_live_action_not_allowed"):
        mobile_runtime.build_mobile_runtime_plan(
            runtime_request(
                profile=profile(
                    actions=(
                        mobile_runtime.MobileRuntimeAction.IMPORT_RESULTS,
                        mobile_runtime.MobileRuntimeAction.START_INSTRUMENTATION,
                    )
                )
            )
        )


def test_runtime_imports_distinct_evidence_categories_and_report_mapping() -> None:
    request_obj = runtime_request(
        assessment_request=assessment_request(mode=mobile_assessment.MobileAssessmentMode.DYNAMIC_INSTRUMENTATION)
    )
    plan = mobile_runtime.build_mobile_runtime_plan(request_obj)
    result = mobile_runtime.execute_mobile_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert len(result.imported_evidence_ids) == 4
    assert len(result.findings) == 4
    assert len(result.report_rows) == 4
    assert {row.category for row in result.report_rows} == {
        mobile_assessment.MobileEvidenceCategory.STATIC_PACKAGE_FINDING,
        mobile_assessment.MobileEvidenceCategory.RUNTIME_LAB_FINDING,
        mobile_assessment.MobileEvidenceCategory.API_BACKEND_FINDING,
        mobile_assessment.MobileEvidenceCategory.DEVICE_ENVIRONMENT_METADATA,
    }
    assert result.report_rows[0].masvs_control == "MASVS-STORAGE-1"
    assert result.report_rows[1].mastg_test == "MASTG-TEST-0002"
    assert result.report_rows[1].evidence_redaction_class is evidence_chain.RedactionStatus.REDACTED
    assert result.findings[0].source == "mobile_runtime"


def test_mobile_result_redaction_and_lab_only_rules_fail_closed() -> None:
    request_obj = runtime_request(
        assessment_request=assessment_request(mode=mobile_assessment.MobileAssessmentMode.DYNAMIC_INSTRUMENTATION)
    )
    plan = mobile_runtime.build_mobile_runtime_plan(request_obj)
    sensitive_raw = result_items()[1].__class__(
        **{**result_items()[1].__dict__, "evidence_redaction_class": evidence_chain.RedactionStatus.NOT_APPLICABLE}
    )
    runtime_not_lab_only = result_items()[1].__class__(**{**result_items()[1].__dict__, "lab_only": False})

    with pytest.raises(ValueError, match="mobile_sensitive_result_requires_redaction"):
        mobile_runtime.execute_mobile_runtime_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(sensitive_raw,),
        )

    with pytest.raises(ValueError, match="runtime_mobile_evidence_requires_lab"):
        mobile_runtime.execute_mobile_runtime_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(runtime_not_lab_only,),
        )


def test_kill_switch_blocks_dispatch_and_cancellation_finishes_without_credentials() -> None:
    request_obj = runtime_request()
    plan = mobile_runtime.build_mobile_runtime_plan(request_obj)
    blocked = mobile_runtime.execute_mobile_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
        kill_switch_scope=mobile_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.MOBILE_ASSESSMENT,),
        ),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert blocked.state.jobs[0].status is domain.JobStatus.QUEUED

    cancelled = mobile_runtime.execute_mobile_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        cancel_requested=True,
    )

    assert cancelled.allowed
    assert cancelled.reason == "cancelled"
    assert not cancelled.cancellation_evidence[0].credential_revoked
