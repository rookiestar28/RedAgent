from datetime import datetime, timezone

import pytest

from redagent_platform import domain, email_resilience, email_runtime, evidence_chain, job_queue
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 14, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.DOMAIN, value="example.com")


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


def metrics(**overrides: int) -> email_resilience.AggregateCampaignMetrics:
    values = {
        "delivered_count": 100,
        "reported_count": 24,
        "clicked_count": 3,
        "training_completed_count": 97,
    }
    values.update(overrides)
    return email_resilience.AggregateCampaignMetrics(**values)


def aggregate_evidence(**overrides: object) -> email_resilience.EmailResilienceEvidence:
    values = {
        "evidence_id": "email-evidence-1",
        "domain": "example.com",
        "aggregate_metrics": metrics(),
        "domain_control_summary": email_resilience.summarize_domain_control(domain_assessment()),
        "personal_mailbox_content_present": False,
    }
    values.update(overrides)
    return email_resilience.EmailResilienceEvidence(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> email_runtime.EmailWorkflowProfile:
    values = {
        "profile_id": "email-workflow-profile",
        "module_id": "email-resilience-runtime",
        "allowed_domains": ("example.com",),
        "max_delivered_count": 500,
        "timeout_seconds": 120,
        "kill_switch_enabled": True,
        "actions": (
            email_runtime.EmailWorkflowAction.IMPORT_DOMAIN_CONTROL,
            email_runtime.EmailWorkflowAction.IMPORT_AGGREGATE_EVIDENCE,
            email_runtime.EmailWorkflowAction.PREPARE_REVIEW_QUEUE,
        ),
    }
    values.update(overrides)
    return email_runtime.EmailWorkflowProfile(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.EMAIL_RESILIENCE,),
        "policy_token_reference": "policy-ref-email",
        "target_scope": TARGET,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "email_report_rows"),
        "cleanup_callback": "cleanup://runner-1/email-runtime",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def workflow_request(**overrides: object) -> email_runtime.EmailWorkflowRequest:
    values = {
        "runtime_id": "email-runtime-1",
        "domain_assessment": domain_assessment(),
        "simulation_request": simulation_request(),
        "profile": profile(),
        "runner": runner(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
    }
    values.update(overrides)
    return email_runtime.EmailWorkflowRequest(**values)  # type: ignore[arg-type]


def test_plan_requires_domain_controls_approval_recipient_scope_and_kill_switch() -> None:
    plan = email_runtime.build_email_workflow_plan(workflow_request())

    assert plan.domain == "example.com"
    assert plan.job.mode is domain.TestMode.EMAIL_RESILIENCE
    assert not plan.execution_enabled
    assert set(plan.domain_control_summary) == set(email_resilience.DomainControlCheckType)

    missing_hsts = tuple(
        check(check_type)
        for check_type in email_resilience.DomainControlCheckType
        if check_type is not email_resilience.DomainControlCheckType.HSTS
    )
    with pytest.raises(ValueError, match="missing_domain_control_checks:hsts"):
        email_runtime.build_email_workflow_plan(workflow_request(domain_assessment=domain_assessment(checks=missing_hsts)))

    with pytest.raises(ValueError, match="email_workflow_denied:missing_approval"):
        email_runtime.build_email_workflow_plan(
            workflow_request(simulation_request=simulation_request(approval=approval(executive_approved_by_user_id=None)))
        )

    with pytest.raises(ValueError, match="email_workflow_denied:unsanctioned_recipients"):
        email_runtime.build_email_workflow_plan(
            workflow_request(
                simulation_request=simulation_request(
                    recipient_scope=recipient_scope(requested_recipient_domains=("example.com", "external.test"))
                )
            )
        )

    with pytest.raises(ValueError, match="kill_switch_required"):
        email_runtime.build_email_workflow_plan(workflow_request(profile=profile(kill_switch_enabled=False)))


def test_prohibited_email_actions_and_policy_activities_are_denied() -> None:
    with pytest.raises(ValueError, match="email_workflow_denied:prohibited_activity"):
        email_runtime.build_email_workflow_plan(
            workflow_request(
                simulation_request=simulation_request(
                    requested_activities=(
                        email_resilience.ProhibitedSimulationActivity.CREDENTIAL_COLLECTION,
                    )
                )
            )
        )

    with pytest.raises(ValueError, match="email_sending_or_collection_action_not_allowed"):
        email_runtime.build_email_workflow_plan(
            workflow_request(
                profile=profile(
                    actions=(
                        email_runtime.EmailWorkflowAction.IMPORT_DOMAIN_CONTROL,
                        email_runtime.EmailWorkflowAction.IMPORT_AGGREGATE_EVIDENCE,
                        email_runtime.EmailWorkflowAction.PREPARE_REVIEW_QUEUE,
                        email_runtime.EmailWorkflowAction.SEND_EMAIL,
                    )
                )
            )
        )


def test_aggregate_only_evidence_imports_report_rows_without_mailbox_content() -> None:
    request_obj = workflow_request()
    plan = email_runtime.build_email_workflow_plan(request_obj)
    result = email_runtime.execute_email_workflow_plan(
        plan=plan,
        domain_assessment=request_obj.domain_assessment,
        evidence=aggregate_evidence(),
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
    )

    assert result.allowed
    assert result.state.jobs[0].status is domain.JobStatus.EVIDENCE_LOCKED
    assert result.imported_evidence_ids == ("email-runtime-1:email-aggregate:email-evidence-1",)
    assert any(row.section == "domain_control" and row.key == "dmarc" for row in result.report_rows)
    assert any(row.section == "campaign_outcome" and row.key == "clicked_count" and row.value == 3 for row in result.report_rows)

    with pytest.raises(ValueError, match="personal_mailbox_content_forbidden"):
        email_runtime.execute_email_workflow_plan(
            plan=plan,
            domain_assessment=request_obj.domain_assessment,
            evidence=aggregate_evidence(personal_mailbox_content_present=True),
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
        )


def test_delivered_count_cap_is_enforced_on_imported_aggregate_evidence() -> None:
    request_obj = workflow_request(profile=profile(max_delivered_count=50))
    plan = email_runtime.build_email_workflow_plan(request_obj)

    with pytest.raises(ValueError, match="delivered_count_cap_exceeded"):
        email_runtime.execute_email_workflow_plan(
            plan=plan,
            domain_assessment=request_obj.domain_assessment,
            evidence=aggregate_evidence(),
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
        )


def test_kill_switch_blocks_dispatch_and_cancellation_finishes_without_credentials() -> None:
    request_obj = workflow_request()
    plan = email_runtime.build_email_workflow_plan(request_obj)
    blocked = email_runtime.execute_email_workflow_plan(
        plan=plan,
        domain_assessment=request_obj.domain_assessment,
        evidence=aggregate_evidence(),
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        kill_switch_scope=email_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.EMAIL_RESILIENCE,),
        ),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert blocked.state.jobs[0].status is domain.JobStatus.QUEUED

    cancelled = email_runtime.execute_email_workflow_plan(
        plan=plan,
        domain_assessment=request_obj.domain_assessment,
        evidence=aggregate_evidence(),
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
