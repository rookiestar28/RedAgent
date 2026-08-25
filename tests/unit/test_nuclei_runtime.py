from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    active_policy,
    credentials,
    domain,
    evidence_chain,
    job_queue,
    lab_validation,
    nuclei_execution,
    nuclei_metadata,
    nuclei_runtime,
    target_inventory,
)
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget


NOW = datetime(2026, 7, 9, 20, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")


def template(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "id": "exposure-header-check",
        "info": {"name": "Exposure Header Check", "severity": "low", "tags": "exposure"},
        "http": [{"method": "GET", "path": ["{{BaseURL}}/"]}],
    }
    values.update(overrides)
    return values


def review(template_data: dict[str, object] | None = None) -> nuclei_metadata.NucleiTemplateReview:
    imported = nuclei_metadata.import_nuclei_template_metadata(template_data or template())
    return nuclei_metadata.review_nuclei_template(
        imported,
        reviewer_user_id="reviewer-1",
        status=nuclei_metadata.NucleiReviewStatus.APPROVED,
        reason="Approved low-risk metadata.",
    )


def active_scope() -> EngagementScope:
    return EngagementScope(
        engagement_id="eng-1",
        organization_id="org-1",
        authorization_status=domain.AuthorizationStatus.APPROVED,
        approved_by_user_id="lead-1",
        allowed_targets=(TARGET,),
        forbidden_targets=(),
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        window_start=NOW - timedelta(minutes=5),
        window_end=NOW + timedelta(hours=1),
        max_interactions=20,
        max_rate_per_second=1.0,
        emergency_contact_method="email",
    )


def active_request(**overrides: object) -> active_policy.ActiveJobRequest:
    values = {
        "job_id": "nuclei-runtime-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "module_id": "nuclei-runtime",
        "payload_class": active_policy.PayloadClass.STANDARD_ACTIVE,
        "requested_at": NOW,
        "projected_requests": 5,
        "projected_duration_seconds": 60,
        "requested_rate_per_second": 0.5,
        "operator_confirmation": active_policy.OperatorConfirmation(
            confirmed_by_user_id="operator-1",
            confirmed_at=NOW - timedelta(minutes=1),
            scope_acknowledged=True,
            risk_acknowledged=True,
            stop_conditions_acknowledged=True,
        ),
    }
    values.update(overrides)
    return active_policy.ActiveJobRequest(**values)  # type: ignore[arg-type]


def active_result(request: active_policy.ActiveJobRequest | None = None) -> active_policy.ActivePolicyResult:
    req = request or active_request()
    return active_policy.evaluate_active_policy(
        request=req,
        scope=active_scope(),
        module_policy=active_policy.ActiveModulePolicy(
            module_id="nuclei-runtime",
            allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
            allowed_payload_classes=(active_policy.PayloadClass.STANDARD_ACTIVE,),
            max_rate_per_second=1.0,
            max_requests=10,
            max_duration_seconds=300,
            max_concurrent_per_engagement=2,
            max_concurrent_per_target=1,
            stop_conditions=active_policy.StopConditionPolicy(
                stop_on_scope_violation=True,
                stop_on_error_rate=True,
                max_error_count=3,
                emergency_contact_required=True,
            ),
        ),
        existing_jobs=(),
        audit_chain=evidence_chain.EvidenceChain(),
        decision_id="active-decision-1",
        policy_expires_at=NOW + timedelta(minutes=30),
    )


def execution_policy(**overrides: object) -> nuclei_execution.NucleiExecutionPolicy:
    values = {
        "approved_template_ids": ("exposure-header-check",),
        "allowed_severities": (nuclei_metadata.NucleiSeverity.LOW,),
        "allowed_risk_classes": (domain.TestRiskClass.PASSIVE,),
        "allowed_protocols": ("http",),
        "max_rate_per_second": 1.0,
        "timeout_seconds": 120,
        "max_results": 20,
        "oast_allowed": False,
        "output_redaction_required": True,
        "cancellation_required": True,
    }
    values.update(overrides)
    return nuclei_execution.NucleiExecutionPolicy(**values)  # type: ignore[arg-type]


def execution_plan(template_review: nuclei_metadata.NucleiTemplateReview | None = None, **overrides: object) -> nuclei_execution.NucleiExecutionPlan:
    req = active_request(**overrides.pop("active_request_overrides", {}))
    values = {
        "plan_id": "nuclei-runtime-plan-1",
        "active_request": req,
        "active_policy": active_result(req),
        "template_review": template_review or review(),
        "execution_policy": execution_policy(),
        "planned_at": NOW,
    }
    values.update(overrides)
    return nuclei_execution.build_nuclei_execution_plan(nuclei_execution.NucleiExecutionPlanRequest(**values))  # type: ignore[arg-type]


def runtime_profile(**overrides: object) -> nuclei_runtime.NucleiRuntimeProfile:
    values = {
        "profile_id": "nuclei-runtime-profile",
        "module_id": "nuclei-runtime",
        "allowed_template_ids": ("exposure-header-check",),
        "allowed_severities": (nuclei_metadata.NucleiSeverity.LOW,),
        "allowed_risk_classes": (domain.TestRiskClass.PASSIVE,),
        "allowed_protocols": ("http",),
        "max_rate_per_second": 1.0,
        "timeout_seconds": 120,
        "max_results": 20,
        "lab_profile": lab_validation.ScannerPolicyProfile(
            profile_id="nuclei-runtime-profile",
            module_id="nuclei-runtime",
            allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
            required_fixture_kinds=(lab_validation.LabValidationFixtureKind.NUCLEI,),
            max_age_seconds=86_400,
        ),
        "actions": (
            nuclei_runtime.NucleiRuntimeAction.LOAD_TRUSTED_TEMPLATE,
            nuclei_runtime.NucleiRuntimeAction.START_SCAN,
            nuclei_runtime.NucleiRuntimeAction.POLL_SCAN,
            nuclei_runtime.NucleiRuntimeAction.STOP_SCAN,
            nuclei_runtime.NucleiRuntimeAction.IMPORT_RESULTS,
        ),
    }
    values.update(overrides)
    return nuclei_runtime.NucleiRuntimeProfile(**values)  # type: ignore[arg-type]


def inventory() -> target_inventory.InventoryTarget:
    return target_inventory.InventoryTarget(
        id="target-1",
        organization_id="org-1",
        engagement_id="eng-1",
        owner_label="Ray Chiu",
        target_type=domain.TargetType.WEB_ORIGIN,
        value="https://www.agentique.io",
        environment=target_inventory.EnvironmentType.STAGING,
        data_sensitivity=target_inventory.DataSensitivity.INTERNAL,
        authorization_status=domain.AuthorizationStatus.APPROVED,
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        explicit_review=True,
        review_reason="approved enterprise target",
    )


def validation_record() -> lab_validation.LabValidationRecord:
    return lab_validation.LabValidationRecord(
        validation_id="nuclei-validation-1",
        policy_profile_id="nuclei-runtime-profile",
        module_id="nuclei-runtime",
        lab_target_id="juice-shop-local",
        fixture_ids=("nuclei-runtime-profile:nuclei",),
        sanitized_artifact_ids=("sanitized:nuclei-runtime-profile:nuclei",),
        validated_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(days=1),
        passed=True,
    )


def runner(target: ScopeTarget = TARGET) -> job_queue.RunnerContract:
    return job_queue.RunnerContract(
        runner_id="runner-1",
        organization_id="org-1",
        capabilities=(domain.TestMode.ACTIVE_SCAN,),
        policy_token_reference="policy-ref-1",
        target_scope=target,
        timeout_seconds=120,
        heartbeat_interval_seconds=5,
        result_schema=("evidence_ids", "findings"),
        cleanup_callback="cleanup://runner-1/nuclei-runtime",
    )


def trust(
    *,
    status: nuclei_runtime.NucleiTemplateTrustStatus = nuclei_runtime.NucleiTemplateTrustStatus.SIGNED_VERIFIED,
    template_id: str = "exposure-header-check",
    reviewer_user_id: str = "reviewer-1",
) -> nuclei_runtime.NucleiTemplateTrustRecord:
    return nuclei_runtime.NucleiTemplateTrustRecord(
        template_id=template_id,
        template_digest="sha256:template-digest",
        status=status,
        reviewer_user_id=reviewer_user_id,
        reviewed_at=NOW - timedelta(minutes=5),
        source_label="approved-template-registry",
    )


def credential_lease() -> credentials.CredentialLease:
    return credentials.CredentialLease(
        id="lease-nuclei-runtime",
        credential_reference_id="cred-ref-1",
        job_id="nuclei-runtime-job-1",
        runner_id="runner-1",
        target=TARGET,
        mode=domain.TestMode.ACTIVE_SCAN,
        scoped_permissions=("http:read",),
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=20),
        redaction_label="credential:cred-ref-1",
    )


def runtime_request(**overrides: object) -> nuclei_runtime.NucleiRuntimeRequest:
    review_record = overrides.pop("template_review", review())
    supplied_plan = overrides.pop("execution_plan", None)
    values = {
        "runtime_id": "nuclei-runtime-1",
        "profile": runtime_profile(),
        "runner": runner(),
        "inventory_target": inventory(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
        "execution_plan": supplied_plan or execution_plan(review_record),
        "template_review": review_record,
        "template_trust": trust(),
        "lab_validation_records": (validation_record(),),
        "credential_lease": credential_lease(),
    }
    values.update(overrides)
    return nuclei_runtime.NucleiRuntimeRequest(**values)  # type: ignore[arg-type]


def result(**overrides: object) -> nuclei_execution.NucleiResult:
    values = {
        "template_id": "exposure-header-check",
        "matcher_name": "header-matcher",
        "matched_at": NOW.isoformat(),
        "host": "www.agentique.io",
        "url": "https://www.agentique.io/",
        "extracted_results": ("server header present",),
        "request": "GET / HTTP/1.1\r\n" + "Author" + "ization: Bearer sample",
        "response": "HTTP/1.1 200 OK",
    }
    values.update(overrides)
    return nuclei_execution.NucleiResult(**values)  # type: ignore[arg-type]


def test_runtime_accepts_signed_and_trusted_templates_with_lab_validation() -> None:
    signed = nuclei_runtime.build_nuclei_runtime_plan(runtime_request())
    trusted = nuclei_runtime.build_nuclei_runtime_plan(
        runtime_request(template_trust=trust(status=nuclei_runtime.NucleiTemplateTrustStatus.TRUSTED_INTERNAL))
    )

    assert signed.template_digest == "sha256:template-digest"
    assert signed.lab_validation_id == "nuclei-validation-1"
    assert signed.cancellation_supported
    assert trusted.template_id == "exposure-header-check"


def test_runtime_denies_untrusted_or_high_risk_templates_and_arbitrary_controls() -> None:
    with pytest.raises(ValueError, match="template_trust_required"):
        nuclei_runtime.build_nuclei_runtime_plan(
            runtime_request(template_trust=trust(status=nuclei_runtime.NucleiTemplateTrustStatus.UNTRUSTED))
        )

    high_risk_template = nuclei_metadata.import_nuclei_template_metadata(
        template(info={"name": "Headless", "severity": "low", "tags": "headless"}, headless=[{}], http=[])
    )
    high_risk_review = nuclei_metadata.NucleiTemplateReview(
        template=high_risk_template,
        status=nuclei_metadata.NucleiReviewStatus.APPROVED,
        reviewer_user_id="reviewer-1",
        reason="forced approval for runtime denial test",
        execution_enabled=False,
    )
    plan = replace(execution_plan(), template_id=high_risk_template.template_id, protocols=high_risk_template.protocol_types)

    with pytest.raises(ValueError, match="high_risk_template_denied"):
        nuclei_runtime.build_nuclei_runtime_plan(
            runtime_request(
                execution_plan=plan,
                template_review=high_risk_review,
                template_trust=trust(template_id=high_risk_template.template_id),
            )
        )

    with pytest.raises(ValueError, match="arbitrary_nuclei_control_forbidden"):
        nuclei_runtime.assert_no_arbitrary_nuclei_controls({"template_path": "external.yaml", "url": "https://target"})


def test_runtime_requires_enterprise_lab_validation_and_runner_target_scope() -> None:
    with pytest.raises(ValueError, match="matching_lab_validation_required"):
        nuclei_runtime.build_nuclei_runtime_plan(runtime_request(lab_validation_records=()))

    with pytest.raises(ValueError, match="runner_target_scope_mismatch"):
        nuclei_runtime.build_nuclei_runtime_plan(
            runtime_request(runner=runner(ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://other.example.test")))
        )


def test_runtime_imports_redacted_results_and_normalized_findings() -> None:
    request = runtime_request()
    plan = nuclei_runtime.build_nuclei_runtime_plan(request)
    execution = nuclei_runtime.execute_nuclei_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        execution_plan=request.execution_plan,
        results=(result(),),
    )

    assert execution.allowed
    assert execution.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert execution.imported_evidence_ids == ("nuclei-runtime-1:nuclei-result:1",)
    assert execution.evidence_chain.evidence_records[0].redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert execution.findings[0].source == "nuclei"
    assert execution.findings[0].source_rule_id == "exposure-header-check"
    assert "Nuclei template exposure-header-check matched" in execution.findings[0].reproduction_summary


def test_runtime_cancellation_uses_kill_switch_and_revokes_credentials() -> None:
    request = runtime_request()
    plan = nuclei_runtime.build_nuclei_runtime_plan(request)
    execution = nuclei_runtime.execute_nuclei_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        execution_plan=request.execution_plan,
        cancel_requested=True,
        credential_broker=credentials.CredentialBroker(),
        credential_leases_by_job_id={plan.job.job_id: credential_lease()},
    )

    assert execution.allowed
    assert execution.reason == "cancelled"
    assert execution.state.jobs[0].status is domain.JobStatus.CLEANUP
    assert execution.cancellation_evidence[0].runner_status is nuclei_runtime.RunnerCancellationStatus.TERMINATED
    assert execution.cancellation_evidence[0].credential_revoked
    assert execution.credential_broker.audit_chain.audit_events[0].subject_id == "lease-nuclei-runtime"


def test_runtime_blocks_dispatch_when_kill_switch_scope_matches() -> None:
    request = runtime_request()
    plan = nuclei_runtime.build_nuclei_runtime_plan(request)
    execution = nuclei_runtime.execute_nuclei_runtime_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        execution_plan=request.execution_plan,
        kill_switch_scope=nuclei_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.ACTIVE_SCAN,),
        ),
    )

    assert not execution.allowed
    assert execution.reason == "kill_switch_active"
    assert execution.state.jobs[0].status is domain.JobStatus.QUEUED
