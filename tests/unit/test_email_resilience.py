from datetime import datetime, timezone

import pytest

from redagent_platform import email_resilience


NOW = datetime(2026, 7, 8, 20, 0, tzinfo=timezone.utc)


def check(
    check_type: email_resilience.DomainControlCheckType,
    status: email_resilience.DomainControlStatus = email_resilience.DomainControlStatus.PRESENT,
) -> email_resilience.DomainControlCheck:
    return email_resilience.DomainControlCheck(
        check_type=check_type,
        status=status,
        observation=f"{check_type.value} observation",
        remediation=f"{check_type.value} remediation",
    )


def domain_assessment(**overrides: object) -> email_resilience.DomainControlAssessment:
    values = {
        "domain": "example.com",
        "checks": tuple(check(check_type) for check_type in email_resilience.DomainControlCheckType),
        "collected_at": NOW,
    }
    values.update(overrides)
    return email_resilience.DomainControlAssessment(**values)  # type: ignore[arg-type]


def approval(**overrides: object) -> email_resilience.SimulationApproval:
    values = {
        "executive_approved_by_user_id": "exec-1",
        "legal_privacy_review_id": "legal-1",
        "audience_scope_id": "audience-1",
        "message_review_id": "message-1",
        "schedule_id": "schedule-1",
        "opt_out_exception_process_id": "opt-out-1",
        "incident_response_coordination_id": "ir-1",
    }
    values.update(overrides)
    return email_resilience.SimulationApproval(**values)  # type: ignore[arg-type]


def recipient_scope(**overrides: object) -> email_resilience.RecipientScope:
    values = {
        "authorized_domains": ("example.com",),
        "requested_recipient_domains": ("example.com",),
        "audience_description": "Employees in approved awareness cohort.",
    }
    values.update(overrides)
    return email_resilience.RecipientScope(**values)  # type: ignore[arg-type]


def simulation_request(**overrides: object) -> email_resilience.PhishingSimulationRequest:
    values = {
        "simulation_id": "sim-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "requested_by_user_id": "operator-1",
        "approval": approval(),
        "recipient_scope": recipient_scope(),
        "requested_activities": (),
        "created_at": NOW,
    }
    values.update(overrides)
    return email_resilience.PhishingSimulationRequest(**values)  # type: ignore[arg-type]


def aggregate_metrics(**overrides: int) -> email_resilience.AggregateCampaignMetrics:
    values = {
        "delivered_count": 100,
        "reported_count": 24,
        "clicked_count": 3,
        "training_completed_count": 97,
    }
    values.update(overrides)
    return email_resilience.AggregateCampaignMetrics(**values)


def test_domain_control_assessment_requires_all_read_only_checks_before_simulation() -> None:
    assessment = domain_assessment()

    summary = email_resilience.summarize_domain_control(assessment)

    assert set(summary) == set(email_resilience.DomainControlCheckType)
    assert summary[email_resilience.DomainControlCheckType.SPF] is email_resilience.DomainControlStatus.PRESENT
    assert summary[email_resilience.DomainControlCheckType.DMARC] is email_resilience.DomainControlStatus.PRESENT
    assert summary[email_resilience.DomainControlCheckType.HSTS] is email_resilience.DomainControlStatus.PRESENT


def test_domain_control_assessment_rejects_missing_required_checks() -> None:
    missing_hsts = tuple(check(check_type) for check_type in email_resilience.DomainControlCheckType if check_type is not email_resilience.DomainControlCheckType.HSTS)

    with pytest.raises(ValueError, match="missing_domain_control_checks:hsts"):
        email_resilience.validate_domain_control_assessment(domain_assessment(checks=missing_hsts))


def test_simulation_requires_all_approval_review_scope_schedule_opt_out_and_ir_fields() -> None:
    decision = email_resilience.evaluate_phishing_simulation_request(
        simulation_request(
            approval=approval(
                executive_approved_by_user_id=None,
                legal_privacy_review_id=None,
                opt_out_exception_process_id=None,
            )
        )
    )

    assert not decision.allowed
    assert decision.reason is email_resilience.SimulationDecisionReason.MISSING_APPROVAL
    assert "executive_approved_by_user_id" in decision.details
    assert "legal_privacy_review_id" in decision.details
    assert "opt_out_exception_process_id" in decision.details


def test_policy_blocks_credential_collection_malware_brand_deception_and_unsanctioned_recipients() -> None:
    prohibited_decision = email_resilience.evaluate_phishing_simulation_request(
        simulation_request(
            requested_activities=(
                email_resilience.ProhibitedSimulationActivity.CREDENTIAL_COLLECTION,
                email_resilience.ProhibitedSimulationActivity.MALWARE_ATTACHMENT,
                email_resilience.ProhibitedSimulationActivity.DECEPTIVE_THIRD_PARTY_BRANDING,
            )
        )
    )
    unsanctioned_decision = email_resilience.evaluate_phishing_simulation_request(
        simulation_request(
            recipient_scope=recipient_scope(
                authorized_domains=("example.com",),
                requested_recipient_domains=("example.com", "external.example"),
            )
        )
    )

    assert not prohibited_decision.allowed
    assert prohibited_decision.reason is email_resilience.SimulationDecisionReason.PROHIBITED_ACTIVITY
    assert prohibited_decision.details == (
        "credential_collection",
        "malware_attachment",
        "deceptive_third_party_branding",
    )
    assert not unsanctioned_decision.allowed
    assert unsanctioned_decision.reason is email_resilience.SimulationDecisionReason.UNSANCTIONED_RECIPIENTS
    assert unsanctioned_decision.details == ("external.example",)


def test_fully_reviewed_simulation_only_enters_policy_review_queue() -> None:
    decision = email_resilience.evaluate_phishing_simulation_request(simulation_request())

    assert decision.allowed
    assert decision.reason is email_resilience.SimulationDecisionReason.APPROVED_FOR_REVIEW_QUEUE
    assert decision.details == ("policy_review_queue_only",)
    assert not hasattr(email_resilience, "send_email")
    assert not hasattr(email_resilience, "execute_campaign")
    assert not hasattr(email_resilience, "collect_credentials")


def test_evidence_exports_aggregate_metrics_and_rejects_personal_mailbox_content() -> None:
    evidence = email_resilience.EmailResilienceEvidence(
        evidence_id="evidence-1",
        domain="example.com",
        aggregate_metrics=aggregate_metrics(),
        domain_control_summary=email_resilience.summarize_domain_control(domain_assessment()),
    )

    exported = email_resilience.export_aggregate_evidence(evidence)

    assert exported["personal_mailbox_content_stored"] is False
    assert exported["aggregate_metrics"] == {
        "delivered_count": 100,
        "reported_count": 24,
        "clicked_count": 3,
        "training_completed_count": 97,
    }
    with pytest.raises(ValueError, match="personal_mailbox_content_forbidden"):
        email_resilience.export_aggregate_evidence(
            email_resilience.EmailResilienceEvidence(
                evidence_id="evidence-2",
                domain="example.com",
                aggregate_metrics=aggregate_metrics(),
                domain_control_summary=email_resilience.summarize_domain_control(domain_assessment()),
                personal_mailbox_content_present=True,
            )
        )


def test_reports_separate_domain_control_findings_from_campaign_outcomes() -> None:
    assessment = domain_assessment(
        checks=(
            check(email_resilience.DomainControlCheckType.SPF),
            check(email_resilience.DomainControlCheckType.DKIM),
            check(email_resilience.DomainControlCheckType.DMARC, email_resilience.DomainControlStatus.WEAK),
            check(email_resilience.DomainControlCheckType.MX),
            check(email_resilience.DomainControlCheckType.HTTPS),
            check(email_resilience.DomainControlCheckType.HSTS),
        )
    )
    evidence = email_resilience.EmailResilienceEvidence(
        evidence_id="evidence-1",
        domain="example.com",
        aggregate_metrics=aggregate_metrics(clicked_count=2),
        domain_control_summary=email_resilience.summarize_domain_control(assessment),
    )

    report = email_resilience.build_email_resilience_report(
        report_id="report-1",
        domain_assessment=assessment,
        evidence=evidence,
    )

    assert report.domain_control_findings[0].keys() == {"domain", "check_type", "status"}
    assert report.campaign_outcomes[0].keys() == {
        "domain",
        "delivered_count",
        "reported_count",
        "clicked_count",
        "training_completed_count",
    }
    assert any(finding["check_type"] == "dmarc" and finding["status"] == "weak" for finding in report.domain_control_findings)
    assert report.campaign_outcomes[0]["clicked_count"] == 2
