from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    credentials,
    domain,
    evidence_chain,
    identity_assessment,
    identity_runtime,
    job_queue,
)
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 20, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.SAAS_TENANT, value="tenant-1")


def scope(**overrides: object) -> identity_assessment.IdentityTenantScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "tenant_id": "tenant-1",
        "tenant_owner_user_id": "owner-1",
        "approved_by_user_id": "lead-1",
        "window_start": NOW - timedelta(minutes=5),
        "window_end": NOW + timedelta(hours=1),
        "allowed_principal_ids": ("group-security", "role-global-reader"),
        "allowed_resource_ids": ("tenant-config", "conditional-access", "mfa-policy", "oauth-apps"),
        "allowed_read_permissions": ("Directory.Read.All", "Policy.Read.All"),
    }
    values.update(overrides)
    return identity_assessment.IdentityTenantScope(**values)  # type: ignore[arg-type]


def assessment_request(**overrides: object) -> identity_assessment.IdentityAssessmentRequest:
    values = {
        "job_id": "identity-runtime-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "tenant_id": "tenant-1",
        "mode": identity_assessment.IdentityAssessmentMode.READ_ONLY_CONFIGURATION,
        "requested_at": NOW,
        "requested_permissions": ("Directory.Read.All",),
        "requested_activities": (),
        "operator_user_id": "operator-1",
        "credential_boundary": None,
    }
    values.update(overrides)
    return identity_assessment.IdentityAssessmentRequest(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> identity_runtime.IdentityRuntimeProfile:
    values = {
        "profile_id": "identity-runtime-profile",
        "module_id": "identity-runtime",
        "allowed_tenant_ids": ("tenant-1",),
        "allowed_resource_ids": ("tenant-config", "conditional-access", "mfa-policy", "oauth-apps"),
        "allowed_modes": (identity_assessment.IdentityAssessmentMode.READ_ONLY_CONFIGURATION,),
        "max_results": 10,
        "timeout_seconds": 120,
        "actions": (
            identity_runtime.IdentityRuntimeAction.IMPORT_BASELINE_RESULTS,
            identity_runtime.IdentityRuntimeAction.IMPORT_SSO_RESULTS,
            identity_runtime.IdentityRuntimeAction.IMPORT_OAUTH_RESULTS,
            identity_runtime.IdentityRuntimeAction.IMPORT_ACCESS_RESULTS,
        ),
    }
    values.update(overrides)
    return identity_runtime.IdentityRuntimeProfile(**values)  # type: ignore[arg-type]


def lease(**overrides: object) -> credentials.CredentialLease:
    values = {
        "id": "lease-identity",
        "credential_reference_id": "cred-ref-identity",
        "job_id": "identity-runtime-job-1",
        "runner_id": "runner-1",
        "target": TARGET,
        "mode": domain.TestMode.IDENTITY_POSTURE,
        "scoped_permissions": ("Directory.Read.All", "Policy.Read.All"),
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=30),
        "redaction_label": "credential:identity-readonly",
    }
    values.update(overrides)
    return credentials.CredentialLease(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.IDENTITY_POSTURE,),
        "policy_token_reference": "policy-ref-identity",
        "target_scope": TARGET,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "identity_findings", "identity_report_rows"),
        "cleanup_callback": "cleanup://runner-1/identity-runtime",
        "credential_lease_id": "lease-identity",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def runtime_request(**overrides: object) -> identity_runtime.IdentityRuntimeRequest:
    values = {
        "runtime_id": "identity-runtime-1",
        "profile": profile(),
        "scope": scope(),
        "assessment_request": assessment_request(),
        "runner": runner(),
        "credential_lease": lease(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return identity_runtime.IdentityRuntimeRequest(**values)  # type: ignore[arg-type]


def result_items() -> tuple[identity_runtime.IdentityRuntimeResultItem, ...]:
    return (
        identity_runtime.IdentityRuntimeResultItem(
            item_id="scuba-mfa",
            kind=identity_runtime.IdentityRuntimeResultKind.SCUBA_BASELINE,
            control_area=identity_assessment.IdentityControlArea.MFA_POLICY,
            tenant_id="tenant-1",
            affected_principal_ids=("group-security",),
            affected_resource_ids=("mfa-policy",),
            severity=identity_runtime.Severity.HIGH,
            remediation_guidance="Require phishing-resistant MFA for privileged principals.",
            evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
            summary="Sanitized SCuBA-style MFA baseline finding.",
            contains_sensitive_material=True,
            source_policy_id="MS.AAD.3.1",
        ),
        identity_runtime.IdentityRuntimeResultItem(
            item_id="conditional-access",
            kind=identity_runtime.IdentityRuntimeResultKind.CONDITIONAL_ACCESS,
            control_area=identity_assessment.IdentityControlArea.CONDITIONAL_ACCESS,
            tenant_id="tenant-1",
            affected_principal_ids=("role-global-reader",),
            affected_resource_ids=("conditional-access",),
            severity=identity_runtime.Severity.MEDIUM,
            remediation_guidance="Require conditional access for unmanaged devices.",
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            summary="Sanitized conditional access finding.",
            source_policy_id="MS.AAD.7.2",
        ),
    )


def test_plan_requires_tenant_allowlist_owner_approval_read_only_lease_and_permissions() -> None:
    plan = identity_runtime.build_identity_runtime_plan(runtime_request())

    assert plan.tenant_id == "tenant-1"
    assert plan.target == TARGET.normalized()
    assert plan.job.mode is domain.TestMode.IDENTITY_POSTURE

    with pytest.raises(ValueError, match="identity_runtime_tenant_not_allowlisted"):
        identity_runtime.build_identity_runtime_plan(
            runtime_request(assessment_request=assessment_request(tenant_id="tenant-2"))
        )

    with pytest.raises(ValueError, match="identity_assessment_denied:tenant_owner_approval_required"):
        identity_runtime.build_identity_runtime_plan(runtime_request(scope=scope(approved_by_user_id=None)))

    with pytest.raises(ValueError, match="identity_assessment_denied:identity_permission_not_allowed"):
        identity_runtime.build_identity_runtime_plan(
            runtime_request(
                assessment_request=assessment_request(requested_permissions=("Role.Read.All",)),
                credential_lease=lease(scoped_permissions=("Directory.Read.All", "Policy.Read.All", "Role.Read.All")),
            )
        )

    with pytest.raises(ValueError, match="identity_runtime_read_only_credential_required"):
        identity_runtime.build_identity_runtime_plan(
            runtime_request(credential_lease=lease(scoped_permissions=("Directory.ReadWrite.All",)))
        )


def test_runtime_rejects_expired_credential_and_active_identity_actions() -> None:
    with pytest.raises(ValueError, match="credential_lease_expired"):
        identity_runtime.build_identity_runtime_plan(
            runtime_request(credential_lease=lease(expires_at=NOW), requested_at=NOW)
        )

    with pytest.raises(ValueError, match="identity_runtime_active_mode_not_allowed"):
        identity_runtime.build_identity_runtime_plan(
            runtime_request(
                profile=profile(allowed_modes=(identity_assessment.IdentityAssessmentMode.ACTIVE_IDENTITY_TEST,))
            )
        )

    with pytest.raises(ValueError, match="identity_runtime_live_action_not_allowed"):
        identity_runtime.build_identity_runtime_plan(
            runtime_request(profile=profile(actions=(identity_runtime.IdentityRuntimeAction.LIVE_AUTH_TEST,)))
        )

    with pytest.raises(ValueError, match="identity_assessment_denied:forbidden_identity_activity_requested"):
        identity_runtime.build_identity_runtime_plan(
            runtime_request(
                assessment_request=assessment_request(
                    requested_activities=(identity_assessment.IdentityForbiddenActivity.BRUTE_FORCE,)
                )
            )
        )


def test_runtime_imports_scuba_style_results_with_redaction_findings_and_report_rows() -> None:
    request = runtime_request()
    plan = identity_runtime.build_identity_runtime_plan(request)
    result = identity_runtime.execute_identity_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert len(result.imported_evidence_ids) == 2
    assert len(result.findings) == 2
    assert len(result.report_rows) == 2
    assert result.report_rows[0].kind is identity_runtime.IdentityRuntimeResultKind.SCUBA_BASELINE
    assert result.report_rows[0].control_area is identity_assessment.IdentityControlArea.MFA_POLICY
    assert result.report_rows[0].tenant_id == "tenant-1"
    assert result.report_rows[0].affected_principal_ids == ("group-security",)
    assert result.report_rows[0].affected_resource_ids == ("mfa-policy",)
    assert result.report_rows[0].severity is identity_runtime.Severity.HIGH
    assert result.report_rows[0].evidence_redaction_class is evidence_chain.RedactionStatus.REDACTED
    assert "phishing-resistant MFA" in result.report_rows[0].remediation_guidance
    assert result.findings[0].source == "identity_runtime"


def test_sensitive_identity_result_requires_redaction_and_affected_entities_stay_in_scope() -> None:
    request = runtime_request()
    plan = identity_runtime.build_identity_runtime_plan(request)
    unsafe = identity_runtime.IdentityRuntimeResultItem(
        item_id="unsafe",
        kind=identity_runtime.IdentityRuntimeResultKind.MFA_POLICY,
        control_area=identity_assessment.IdentityControlArea.MFA_POLICY,
        tenant_id="tenant-1",
        affected_principal_ids=("group-security",),
        affected_resource_ids=("mfa-policy",),
        severity=identity_runtime.Severity.LOW,
        remediation_guidance="Review identity evidence redaction.",
        evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
        summary="Sensitive identity evidence.",
        contains_sensitive_material=True,
    )
    out_of_scope = identity_runtime.IdentityRuntimeResultItem(
        item_id="out-of-scope",
        kind=identity_runtime.IdentityRuntimeResultKind.OAUTH_APPLICATION,
        control_area=identity_assessment.IdentityControlArea.OAUTH_APPLICATIONS,
        tenant_id="tenant-1",
        affected_principal_ids=(),
        affected_resource_ids=("unapproved-app",),
        severity=identity_runtime.Severity.MEDIUM,
        remediation_guidance="Review unapproved app access.",
        evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
        summary="Sanitized OAuth app finding.",
    )

    with pytest.raises(ValueError, match="identity_sensitive_result_requires_redaction"):
        identity_runtime.execute_identity_runtime_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(unsafe,),
        )

    with pytest.raises(ValueError, match="identity_resource_not_allowlisted"):
        identity_runtime.execute_identity_runtime_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(out_of_scope,),
        )


def test_kill_switch_blocks_dispatch_and_cancellation_revokes_identity_lease() -> None:
    request = runtime_request()
    plan = identity_runtime.build_identity_runtime_plan(request)
    blocked = identity_runtime.execute_identity_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
        kill_switch_scope=identity_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.IDENTITY_POSTURE,),
        ),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert blocked.state.jobs[0].status is domain.JobStatus.QUEUED

    cancelled = identity_runtime.execute_identity_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        cancel_requested=True,
        credential_broker=credentials.CredentialBroker(),
        credential_lease=request.credential_lease,
    )

    assert cancelled.allowed
    assert cancelled.reason == "cancelled"
    assert cancelled.cancellation_evidence[0].credential_revoked
