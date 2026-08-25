from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import active_policy, domain, evidence_chain, nuclei_execution, nuclei_metadata
from redagent_platform.scope_authorization import EngagementScope, ScopeTarget


NOW = datetime(2026, 7, 8, 15, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")


def template(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "id": "exposure-header-check",
        "info": {"name": "Exposure Header Check", "severity": "low", "tags": "exposure", "classification": {"cwe-id": ["CWE-200"]}},
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
        max_interactions=20,
        max_rate_per_second=1.0,
        emergency_contact_method="email",
    )


def active_request(**overrides: object) -> active_policy.ActiveJobRequest:
    values = {
        "job_id": "nuclei-job-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": TARGET,
        "mode": domain.TestMode.ACTIVE_SCAN,
        "module_id": "nuclei-controlled",
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
        scope=scope(),
        module_policy=active_policy.ActiveModulePolicy(
            module_id="nuclei-controlled",
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


def policy(**overrides: object) -> nuclei_execution.NucleiExecutionPolicy:
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


def plan_request(**overrides: object) -> nuclei_execution.NucleiExecutionPlanRequest:
    req = active_request()
    values = {
        "plan_id": "nuclei-plan-1",
        "active_request": req,
        "active_policy": active_result(req),
        "template_review": review(),
        "execution_policy": policy(),
        "planned_at": NOW,
    }
    values.update(overrides)
    return nuclei_execution.NucleiExecutionPlanRequest(**values)  # type: ignore[arg-type]


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


def test_nuclei_plan_allows_only_approved_template_ids_under_policy() -> None:
    plan = nuclei_execution.build_nuclei_execution_plan(plan_request())

    assert plan.job.status is domain.JobStatus.AUTHORIZED
    assert plan.template_id == "exposure-header-check"
    assert plan.protocols == ("http",)
    assert plan.rate_limit_per_second == 0.5
    assert plan.timeout_seconds == 60
    assert plan.output_redaction_required
    assert plan.cancellation_supported


@pytest.mark.parametrize(
    ("override", "expected_reason"),
    (
        ({"execution_policy": policy(approved_template_ids=("other",))}, "template_id_not_approved"),
        ({"execution_policy": policy(allowed_severities=(nuclei_metadata.NucleiSeverity.INFO,))}, "severity_not_allowed"),
        ({"template_review": review(template(http=[], dns=[{}])), "execution_policy": policy(approved_template_ids=("exposure-header-check",), allowed_protocols=("http",))}, "protocol_not_allowed"),
        ({"execution_policy": policy(output_redaction_required=False)}, "output_redaction_required"),
        ({"execution_policy": policy(cancellation_required=False)}, "cancellation_required"),
    ),
)
def test_nuclei_plan_fails_closed_for_forbidden_template_policy(override: dict[str, object], expected_reason: str) -> None:
    with pytest.raises(ValueError, match=expected_reason):
        nuclei_execution.build_nuclei_execution_plan(plan_request(**override))


def test_nuclei_plan_rejects_malicious_or_sandbox_only_metadata() -> None:
    high_risk = nuclei_metadata.import_nuclei_template_metadata(template(info={"name": "OAST", "severity": "medium", "tags": ["oast"]}, headless=[{}]))
    sandbox_review = nuclei_metadata.review_nuclei_template(
        high_risk,
        reviewer_user_id="reviewer-1",
        status=nuclei_metadata.NucleiReviewStatus.SANDBOX_ONLY_REQUIRED,
        reason="OAST and headless require sandbox.",
    )

    with pytest.raises(ValueError, match="template_review_must_be_approved"):
        nuclei_execution.build_nuclei_execution_plan(plan_request(template_review=sandbox_review))


def test_nuclei_plan_rejects_out_of_scope_target_from_r017() -> None:
    denied_request = active_request(target=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://admin.agentique.io"))
    denied_policy = active_result(denied_request)

    with pytest.raises(ValueError, match="active_policy_denied:scope_target_not_in_allowlist"):
        nuclei_execution.build_nuclei_execution_plan(plan_request(active_request=denied_request, active_policy=denied_policy))


def test_nuclei_cancellation_plan_is_audited() -> None:
    plan = nuclei_execution.build_nuclei_execution_plan(plan_request())
    cancellation = nuclei_execution.build_nuclei_cancellation_plan(
        plan=plan,
        reason="operator_stop",
        actor_user_id="operator-1",
        event_id="cancel-1",
        occurred_at=NOW + timedelta(minutes=1),
        audit_chain=evidence_chain.EvidenceChain(),
    )

    assert cancellation.status is domain.JobStatus.CANCELLED
    assert cancellation.audit_chain.audit_events[0].action is evidence_chain.AuditAction.SCHEDULER_CONTROL


def test_nuclei_results_normalize_to_evidence_and_findings() -> None:
    plan = nuclei_execution.build_nuclei_execution_plan(plan_request())
    evidence = nuclei_execution.append_nuclei_result_evidence(
        chain=evidence_chain.EvidenceChain(),
        plan=plan,
        result=result(),
        evidence_id="nuclei-evidence-1",
        observed_at=NOW + timedelta(minutes=2),
    )
    finding = nuclei_execution.normalize_nuclei_result_to_finding(
        finding_id="finding-1",
        plan=plan,
        result=result(),
        evidence_record=evidence.record,
        owner_user_id="owner-1",
    )

    assert evidence.record.kind is domain.EvidenceKind.SCANNER_OUTPUT
    assert evidence.record.redaction_status is evidence_chain.RedactionStatus.REDACTED
    assert evidence.sanitized_content["request"] == "GET / HTTP/1.1\r\n" + "Author" + "ization: [redacted]"
    assert finding.source == "nuclei"
    assert finding.source_rule_id == "exposure-header-check"
    assert finding.evidence_links[0].evidence_id == "nuclei-evidence-1"
    assert "Nuclei template exposure-header-check matched" in finding.reproduction_summary
