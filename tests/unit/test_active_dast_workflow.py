from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import (
    active_dast_workflow,
    active_policy,
    auth_sessions,
    domain,
    evidence_chain,
    findings,
    job_queue,
    lab_validation,
    nuclei_runtime,
    openapi_harness,
    target_inventory,
    zap_runtime,
)
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget


NOW = datetime(2026, 7, 9, 23, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")


def scope() -> EngagementScope:
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
        max_interactions=30,
        max_rate_per_second=1.0,
        emergency_contact_method="email",
    )


def module_policy(max_requests: int = 20) -> active_policy.ActiveModulePolicy:
    return active_policy.ActiveModulePolicy(
        module_id="dast-workflow",
        allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
        allowed_payload_classes=(active_policy.PayloadClass.STANDARD_ACTIVE,),
        max_rate_per_second=1.0,
        max_requests=max_requests,
        max_duration_seconds=300,
        max_concurrent_per_engagement=2,
        max_concurrent_per_target=1,
        stop_conditions=active_policy.StopConditionPolicy(
            stop_on_scope_violation=True,
            stop_on_error_rate=True,
            max_error_count=3,
            emergency_contact_required=True,
        ),
    )


def active_request(**overrides: object) -> active_policy.ActiveJobRequest:
    values = {
        "job_id": "dast-workflow-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "module_id": "dast-workflow",
        "payload_class": active_policy.PayloadClass.STANDARD_ACTIVE,
        "requested_at": NOW,
        "projected_requests": 8,
        "projected_duration_seconds": 90,
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
        scope=scope(),
        module_policy=module_policy(),
        existing_jobs=(),
        audit_chain=evidence_chain.EvidenceChain(),
        decision_id=f"active-decision-{req.job_id}",
        policy_expires_at=NOW + timedelta(minutes=30),
    )


def crawler_policy(**overrides: object) -> active_dast_workflow.DastCrawlerPolicy:
    values = {
        "max_depth": 2,
        "max_pages": 8,
        "form_submission_allowed": False,
        "parameter_mutation_allowed": False,
        "authentication_allowed": True,
        "destructive_tests_allowed": False,
    }
    values.update(overrides)
    return active_dast_workflow.DastCrawlerPolicy(**values)  # type: ignore[arg-type]


def workflow_policy(**overrides: object) -> active_dast_workflow.DastWorkflowPolicy:
    values = {
        "policy_id": "dast-workflow-policy",
        "module_id": "dast-workflow",
        "max_rate_per_second": 1.0,
        "max_requests": 20,
        "timeout_seconds": 180,
        "crawler": crawler_policy(),
        "lab_profile": lab_validation.ScannerPolicyProfile(
            profile_id="dast-workflow-policy",
            module_id="dast-workflow",
            allowed_modes=(domain.TestMode.ACTIVE_SCAN,),
            required_fixture_kinds=(lab_validation.LabValidationFixtureKind.ZAP,),
            max_age_seconds=86_400,
        ),
    }
    values.update(overrides)
    return active_dast_workflow.DastWorkflowPolicy(**values)  # type: ignore[arg-type]


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
        validation_id="dast-validation-1",
        policy_profile_id="dast-workflow-policy",
        module_id="dast-workflow",
        lab_target_id="juice-shop-local",
        fixture_ids=("dast-workflow-policy:zap",),
        sanitized_artifact_ids=("sanitized:dast-workflow-policy:zap",),
        validated_at=NOW - timedelta(minutes=10),
        expires_at=NOW + timedelta(days=1),
        passed=True,
    )


def runner() -> job_queue.RunnerContract:
    return job_queue.RunnerContract(
        runner_id="runner-1",
        organization_id="org-1",
        capabilities=(domain.TestMode.ACTIVE_SCAN,),
        policy_token_reference="policy-ref-1",
        target_scope=TARGET,
        timeout_seconds=180,
        heartbeat_interval_seconds=5,
        result_schema=("evidence_ids", "findings", "report_summary"),
        cleanup_callback="cleanup://runner-1/dast-workflow",
    )


def auth_context(**overrides: object) -> auth_sessions.AuthenticatedSessionContext:
    values = {
        "session_id": "session-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "credential_lease_id": "lease-1",
        "role_label": "standard-user",
        "created_at": NOW - timedelta(minutes=2),
        "expires_at": NOW + timedelta(minutes=20),
        "redaction_label": "credential:lease-1",
    }
    values.update(overrides)
    return auth_sessions.AuthenticatedSessionContext(**values)  # type: ignore[arg-type]


def workflow_request(**overrides: object) -> active_dast_workflow.DastWorkflowRequest:
    req = active_request()
    values = {
        "workflow_id": "dast-workflow-1",
        "roe_id": "roe-1",
        "active_request": req,
        "active_policy": active_result(req),
        "runner": runner(),
        "inventory_target": inventory(),
        "workflow_policy": workflow_policy(),
        "target_allowlist": (TARGET,),
        "emergency_stop_method": "email",
        "lab_validation_records": (validation_record(),),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
        "crawler_depth": 1,
        "planned_crawl_pages": 4,
        "authentication_requested": True,
        "auth_contexts": (auth_context(),),
    }
    values.update(overrides)
    return active_dast_workflow.DastWorkflowRequest(**values)  # type: ignore[arg-type]


def finding(
    finding_id: str,
    *,
    source: str,
    rule_id: str,
    evidence_id: str,
    redaction_status: evidence_chain.RedactionStatus = evidence_chain.RedactionStatus.NOT_APPLICABLE,
) -> findings.FindingRecord:
    record = findings.FindingRecord(
        id=finding_id,
        title="Reviewable active DAST observation",
        status=domain.FindingStatus.NEEDS_REVIEW,
        affected_asset_id=TARGET.normalized().value,
        affected_asset_value="/",
        confidence=findings.Confidence.MEDIUM,
        risk=findings.RiskFactors(
            severity=findings.Severity.MEDIUM,
            exploit_likelihood=findings.ExploitLikelihood.UNKNOWN,
            asset_criticality=findings.AssetCriticality.UNKNOWN,
            business_impact=findings.BusinessImpact.UNKNOWN,
            vulnerability_intelligence=findings.VulnerabilityIntelligence(cve_ids=(), cwe_ids=("CWE-693",)),
        ),
        reproduction_summary="Supplied scanner observation requires manual review.",
        evidence_links=(
            findings.EvidenceLink(
                evidence_id=evidence_id,
                integrity_hash=f"hash:{evidence_id}",
                redaction_status=redaction_status,
                contains_sensitive_payload=redaction_status is evidence_chain.RedactionStatus.REDACTED,
            ),
        ),
        remediation="Review the affected control and confirm remediation with an approved retest.",
        owner_user_id=None,
        source=source,
        source_rule_id=rule_id,
    )
    findings.validate_finding(record)
    return record


def component_results() -> tuple[
    zap_runtime.ZapRuntimeExecutionResult,
    nuclei_runtime.NucleiRuntimeExecutionResult,
    openapi_harness.OpenApiHarnessExecutionResult,
]:
    zap_finding = finding("finding-zap-1", source="zap_active", rule_id="10021", evidence_id="zap-evidence-1")
    duplicate = replace(zap_finding, id="finding-zap-duplicate")
    api_finding = finding(
        "finding-api-1",
        source="openapi_harness",
        rule_id="authorization_differential",
        evidence_id="api-evidence-1",
        redaction_status=evidence_chain.RedactionStatus.REDACTED,
    )
    return (
        zap_runtime.ZapRuntimeExecutionResult(
            allowed=True,
            reason="succeeded",
            state=job_queue.JobQueueState(),
            evidence_chain=evidence_chain.EvidenceChain(),
            findings=(zap_finding,),
            imported_evidence_ids=("zap-evidence-1",),
        ),
        nuclei_runtime.NucleiRuntimeExecutionResult(
            allowed=True,
            reason="succeeded",
            state=job_queue.JobQueueState(),
            evidence_chain=evidence_chain.EvidenceChain(),
            findings=(duplicate,),
            imported_evidence_ids=("nuclei-evidence-1",),
        ),
        openapi_harness.OpenApiHarnessExecutionResult(
            allowed=True,
            reason="succeeded",
            state=job_queue.JobQueueState(),
            evidence_chain=evidence_chain.EvidenceChain(),
            findings=(api_finding,),
            imported_evidence_ids=("api-evidence-1",),
        ),
    )


def test_safe_active_dast_workflow_merges_deduplicated_findings_and_report_summary() -> None:
    request = workflow_request()
    plan = active_dast_workflow.build_dast_workflow_plan(request)
    result = active_dast_workflow.execute_dast_workflow_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        component_results=component_results(),
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert len(result.findings) == 2
    assert result.evidence_ids[-1] == "dast-workflow-1:report-summary"
    assert result.report_summary is not None
    assert result.report_summary.finding_count == 3
    assert result.report_summary.deduplicated_finding_count == 2
    assert not result.report_summary.unsupported_exploitability_claims
    assert "no exploitability is claimed" in result.report_summary.claim_boundary
    assert result.evidence_chain.evidence_records[0].kind is domain.EvidenceKind.REPORT_SOURCE


def test_policy_denial_blocks_workflow_before_plan_creation() -> None:
    denied_request = active_request(projected_requests=50)
    with pytest.raises(ValueError, match="active_policy_denied:scope_interaction_cap_exceeded"):
        active_dast_workflow.build_dast_workflow_plan(
            workflow_request(active_request=denied_request, active_policy=active_result(denied_request))
        )


def test_kill_switch_blocks_dispatch_before_active_workflow_starts() -> None:
    request = workflow_request()
    plan = active_dast_workflow.build_dast_workflow_plan(request)
    result = active_dast_workflow.execute_dast_workflow_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        component_results=component_results(),
        kill_switch_scope=active_dast_workflow.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.ACTIVE_SCAN,),
        ),
    )

    assert not result.allowed
    assert result.reason == "kill_switch_active"
    assert result.state.jobs[0].status is domain.JobStatus.QUEUED


def test_auth_expiration_fails_closed_for_authenticated_workflow() -> None:
    with pytest.raises(ValueError, match="auth_context_expired"):
        active_dast_workflow.build_dast_workflow_plan(
            workflow_request(auth_contexts=(auth_context(expires_at=NOW - timedelta(seconds=1)),))
        )


def test_crawler_caps_and_individual_active_controls_fail_closed() -> None:
    with pytest.raises(ValueError, match="crawler_page_cap_exceeded"):
        active_dast_workflow.build_dast_workflow_plan(workflow_request(planned_crawl_pages=20))

    with pytest.raises(ValueError, match="form_submission_not_allowed"):
        active_dast_workflow.build_dast_workflow_plan(workflow_request(form_submission_requested=True))

    with pytest.raises(ValueError, match="parameter_mutation_not_allowed"):
        active_dast_workflow.build_dast_workflow_plan(workflow_request(parameter_mutation_requested=True))

    with pytest.raises(ValueError, match="destructive_tests_forbidden"):
        active_dast_workflow.build_dast_workflow_plan(workflow_request(destructive_tests_requested=True))


def test_redaction_propagates_to_report_summary() -> None:
    request = workflow_request()
    plan = active_dast_workflow.build_dast_workflow_plan(request)
    result = active_dast_workflow.execute_dast_workflow_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        component_results=component_results(),
    )

    assert result.report_summary is not None
    assert result.report_summary.redacted_evidence_link_count == 1
    assert any(
        link.redaction_status is evidence_chain.RedactionStatus.REDACTED
        for finding_record in result.findings
        for link in finding_record.evidence_links
    )
