from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import cloud_posture, cloud_runtime, credentials, domain, evidence_chain, job_queue
from redagent_platform.scope_authorization import ScopeTarget
from redagent_platform.target_inventory import EnvironmentType


NOW = datetime(2026, 7, 9, 18, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.CLOUD_ACCOUNT, value="aws:123456789012")


def scope(**overrides: object) -> cloud_posture.CloudScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "provider": cloud_posture.CloudProvider.AWS,
        "environment": EnvironmentType.TEST,
        "account_ids": ("aws:123456789012",),
        "project_ids": (),
        "subscription_ids": (),
        "cluster_ids": (),
        "regions": ("ap-northeast-1",),
        "owner_approved_by_user_id": "lead-1",
        "credential_reference_id": "cred-ref-cloud",
        "allowed_read_permissions": ("ReadOnlyAccess",),
        "monthly_cost_estimate_usd": 10.0,
        "blast_radius_reviewed": True,
    }
    values.update(overrides)
    return cloud_posture.CloudScope(**values)  # type: ignore[arg-type]


def posture_request(**overrides: object) -> cloud_posture.CloudPostureRequest:
    values = {
        "job_id": "cloud-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "provider": cloud_posture.CloudProvider.AWS,
        "mode": cloud_posture.CloudPostureMode.READ_ONLY_POSTURE,
        "requested_at": NOW,
        "target_id": "aws:123456789012",
        "requested_permissions": ("ReadOnlyAccess",),
        "credential_boundary": None,
    }
    values.update(overrides)
    return cloud_posture.CloudPostureRequest(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> cloud_runtime.CloudRuntimeProfile:
    values = {
        "profile_id": "cloud-runtime-profile",
        "module_id": "cloud-runtime",
        "allowed_providers": (
            cloud_posture.CloudProvider.AWS,
            cloud_posture.CloudProvider.AZURE,
            cloud_posture.CloudProvider.GCP,
            cloud_posture.CloudProvider.KUBERNETES,
        ),
        "allowed_modes": (cloud_posture.CloudPostureMode.READ_ONLY_POSTURE,),
        "max_monthly_cost_usd": 25.0,
        "max_api_calls": 10,
        "max_results": 10,
        "timeout_seconds": 120,
        "actions": (
            cloud_runtime.CloudRuntimeAction.READ_POSTURE,
            cloud_runtime.CloudRuntimeAction.IMPORT_RESULTS,
        ),
    }
    values.update(overrides)
    return cloud_runtime.CloudRuntimeProfile(**values)  # type: ignore[arg-type]


def lease(**overrides: object) -> credentials.CredentialLease:
    values = {
        "id": "lease-cloud",
        "credential_reference_id": "cred-ref-cloud",
        "job_id": "cloud-job-1",
        "runner_id": "runner-1",
        "target": TARGET,
        "mode": domain.TestMode.CLOUD_TECHNIQUE,
        "scoped_permissions": ("ReadOnlyAccess",),
        "issued_at": NOW - timedelta(minutes=1),
        "expires_at": NOW + timedelta(minutes=30),
        "redaction_label": "credential:cloud-readonly",
    }
    values.update(overrides)
    return credentials.CredentialLease(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.CLOUD_TECHNIQUE,),
        "policy_token_reference": "policy-ref-cloud",
        "target_scope": TARGET,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "cloud_findings", "cloud_report_rows"),
        "cleanup_callback": "cleanup://runner-1/cloud-runtime",
        "credential_lease_id": "lease-cloud",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def runtime_request(**overrides: object) -> cloud_runtime.CloudRuntimeRequest:
    values = {
        "runtime_id": "cloud-runtime-1",
        "profile": profile(),
        "scope": scope(),
        "posture_request": posture_request(),
        "runner": runner(),
        "credential_lease": lease(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return cloud_runtime.CloudRuntimeRequest(**values)  # type: ignore[arg-type]


def result_items() -> tuple[cloud_runtime.CloudRuntimeResultItem, ...]:
    return (
        cloud_runtime.CloudRuntimeResultItem(
            item_id="iam-1",
            control_domain=cloud_posture.CloudControlDomain.IDENTITY_ACCESS,
            resource_id="aws:123456789012:role/AdminLike",
            region="ap-northeast-1",
            cluster_id=None,
            severity=cloud_runtime.Severity.HIGH,
            remediation_guidance="Restrict privileged role trust and require approval.",
            evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
            summary="Sanitized IAM posture finding.",
            contains_sensitive_material=True,
        ),
        cloud_runtime.CloudRuntimeResultItem(
            item_id="logging-1",
            control_domain=cloud_posture.CloudControlDomain.LOGGING_MONITORING,
            resource_id="aws:123456789012:trail/org",
            region="ap-northeast-1",
            cluster_id=None,
            severity=cloud_runtime.Severity.MEDIUM,
            remediation_guidance="Enable organization-wide logging controls.",
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            summary="Sanitized logging posture finding.",
        ),
    )


def test_runtime_plan_requires_read_only_credential_lease_and_exact_scope() -> None:
    plan = cloud_runtime.build_cloud_runtime_plan(runtime_request())

    assert plan.provider is cloud_posture.CloudProvider.AWS
    assert plan.target == TARGET.normalized()
    assert plan.credential_lease_id == "lease-cloud"
    assert plan.job.mode is domain.TestMode.CLOUD_TECHNIQUE

    with pytest.raises(ValueError, match="cloud_runtime_read_only_credential_required"):
        cloud_runtime.build_cloud_runtime_plan(
            runtime_request(credential_lease=lease(scoped_permissions=("AdministratorAccess",)))
        )

    with pytest.raises(ValueError, match="credential_lease_target_mismatch"):
        cloud_runtime.build_cloud_runtime_plan(
            runtime_request(
                credential_lease=lease(
                    target=ScopeTarget(target_type=domain.TargetType.CLOUD_ACCOUNT, value="aws:999999999999")
                )
            )
        )


def test_runtime_denies_provider_mismatch_target_allowlist_and_cost_cap() -> None:
    with pytest.raises(ValueError, match="cloud_posture_denied:provider_mismatch"):
        cloud_runtime.build_cloud_runtime_plan(
            runtime_request(posture_request=posture_request(provider=cloud_posture.CloudProvider.GCP))
        )

    with pytest.raises(ValueError, match="cloud_runtime_target_not_allowlisted"):
        cloud_runtime.build_cloud_runtime_plan(runtime_request(posture_request=posture_request(target_id="aws:999999999999")))

    with pytest.raises(ValueError, match="cloud_runtime_cost_cap_exceeded"):
        cloud_runtime.build_cloud_runtime_plan(runtime_request(scope=scope(monthly_cost_estimate_usd=30.0)))


def test_runtime_blocks_mutating_modes_actions_and_production_detonation() -> None:
    with pytest.raises(ValueError, match="cloud_runtime_mutating_mode_not_allowed"):
        cloud_runtime.build_cloud_runtime_plan(
            runtime_request(profile=profile(allowed_modes=(cloud_posture.CloudPostureMode.CLOUD_DETONATION,)))
        )

    with pytest.raises(ValueError, match="cloud_runtime_mutating_action_not_allowed"):
        cloud_runtime.build_cloud_runtime_plan(
            runtime_request(profile=profile(actions=(cloud_runtime.CloudRuntimeAction.DETONATE_CLOUD_TECHNIQUE,)))
        )

    production_scope = scope(environment=EnvironmentType.PRODUCTION)
    production_request = posture_request(mode=cloud_posture.CloudPostureMode.CLOUD_DETONATION)
    decision = cloud_posture.evaluate_cloud_posture(production_scope, production_request)
    assert not decision.allowed
    assert decision.reason == "cloud_mutating_mode_blocked"


def test_azure_subscription_allowlist_is_supported_without_widening_scope() -> None:
    azure_target = ScopeTarget(target_type=domain.TargetType.CLOUD_SUBSCRIPTION, value="azure:sub-1")
    azure_scope = scope(
        provider=cloud_posture.CloudProvider.AZURE,
        account_ids=(),
        subscription_ids=("azure:sub-1",),
        credential_reference_id="cred-ref-azure",
        allowed_read_permissions=("Reader",),
    )
    azure_request = posture_request(
        provider=cloud_posture.CloudProvider.AZURE,
        target_id="azure:sub-1",
        requested_permissions=("Reader",),
    )
    azure_runner = runner(target_scope=azure_target)
    azure_lease = lease(
        credential_reference_id="cred-ref-azure",
        target=azure_target,
        scoped_permissions=("Reader",),
    )

    plan = cloud_runtime.build_cloud_runtime_plan(
        runtime_request(
            scope=azure_scope,
            posture_request=azure_request,
            runner=azure_runner,
            credential_lease=azure_lease,
        )
    )

    assert plan.target.target_type is domain.TargetType.CLOUD_SUBSCRIPTION
    assert plan.target.value == "azure:sub-1"


def test_runtime_imports_results_with_redaction_findings_and_report_rows() -> None:
    request = runtime_request()
    plan = cloud_runtime.build_cloud_runtime_plan(request)
    result = cloud_runtime.execute_cloud_runtime_plan(
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
    assert result.report_rows[0].control_domain is cloud_posture.CloudControlDomain.IDENTITY_ACCESS
    assert result.report_rows[0].resource_id == "aws:123456789012:role/AdminLike"
    assert result.report_rows[0].region == "ap-northeast-1"
    assert result.report_rows[0].severity is cloud_runtime.Severity.HIGH
    assert result.report_rows[0].evidence_redaction_class is evidence_chain.RedactionStatus.REDACTED
    assert "Restrict privileged" in result.report_rows[0].remediation_guidance
    assert result.findings[0].source == "cloud_runtime"
    assert result.findings[0].source_rule_id == cloud_posture.CloudControlDomain.IDENTITY_ACCESS.value


def test_sensitive_result_requires_redaction_before_import() -> None:
    request = runtime_request()
    plan = cloud_runtime.build_cloud_runtime_plan(request)
    unsafe_item = cloud_runtime.CloudRuntimeResultItem(
        item_id="unsafe",
        control_domain=cloud_posture.CloudControlDomain.ENCRYPTION,
        resource_id="aws:123456789012:kms/key",
        region="ap-northeast-1",
        cluster_id=None,
        severity=cloud_runtime.Severity.LOW,
        remediation_guidance="Rotate and restrict access to the key.",
        evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
        summary="Sensitive key metadata.",
        contains_sensitive_material=True,
    )

    with pytest.raises(ValueError, match="cloud_runtime_sensitive_result_requires_redaction"):
        cloud_runtime.execute_cloud_runtime_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(unsafe_item,),
        )


def test_kill_switch_blocks_dispatch_and_cancellation_revokes_cloud_lease() -> None:
    request = runtime_request()
    plan = cloud_runtime.build_cloud_runtime_plan(request)
    blocked = cloud_runtime.execute_cloud_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
        kill_switch_scope=cloud_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.CLOUD_TECHNIQUE,),
        ),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert blocked.state.jobs[0].status is domain.JobStatus.QUEUED

    cancelled = cloud_runtime.execute_cloud_runtime_plan(
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
