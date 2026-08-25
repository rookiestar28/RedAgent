from datetime import datetime, timezone

import pytest

from redagent_platform import (
    ai_agentic,
    ai_agentic_runtime,
    domain,
    evidence_chain,
    job_queue,
)
from redagent_platform.scope_authorization import ScopeTarget
from redagent_platform.test_registry import ReviewStatus


NOW = datetime(2026, 7, 9, 23, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.AI_APPLICATION, value="support-agent")


def ai_case(**overrides: object) -> ai_agentic.AiTestCase:
    values = {
        "test_id": "ai-test-1",
        "version": "1.0.0",
        "category": ai_agentic.AiRiskCategory.PROMPT_INJECTION,
        "risk_class": ai_agentic.AiRiskClass.MEDIUM,
        "review_status": ReviewStatus.APPROVED,
        "reviewer_user_id": "reviewer-1",
        "prompt_template_id": "prompt-template-1",
        "expected_observation": "The application preserves instruction hierarchy.",
    }
    values.update(overrides)
    return ai_agentic.AiTestCase(**values)  # type: ignore[arg-type]


def provider_scope(**overrides: object) -> ai_agentic.LiveProviderScope:
    values = {
        "provider_account_id": "provider-account-1",
        "approved_model_ids": ("model-safe-1",),
        "approved_by_user_id": "lead-1",
        "max_cost_usd": 3.0,
        "max_requests": 8,
        "data_redaction_required": True,
        "logging_boundary": "redacted-lab-logs",
    }
    values.update(overrides)
    return ai_agentic.LiveProviderScope(**values)  # type: ignore[arg-type]


def tool_boundary(**overrides: object) -> ai_agentic.AgentToolBoundary:
    values = {
        "allowed_tool_ids": ("search-fixture", "crm-dry-run"),
        "dry_run": True,
        "side_effect_controls_enabled": True,
        "kill_switch_enabled": True,
    }
    values.update(overrides)
    return ai_agentic.AgentToolBoundary(**values)  # type: ignore[arg-type]


def assessment_request(**overrides: object) -> ai_agentic.AiAssessmentRequest:
    values = {
        "job_id": "ai-runtime-job-1",
        "test_case": ai_case(),
        "provider_scope": provider_scope(),
        "tool_boundary": tool_boundary(),
        "requested_model_id": "model-safe-1",
        "requested_tool_ids": ("search-fixture",),
        "requested_intents": (),
    }
    values.update(overrides)
    return ai_agentic.AiAssessmentRequest(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> ai_agentic_runtime.AiHarnessProfile:
    values = {
        "profile_id": "ai-runtime-profile",
        "module_id": "ai-agentic-runtime",
        "allowed_test_ids": ("ai-test-1",),
        "allowed_provider_account_ids": ("provider-account-1",),
        "allowed_model_ids": ("model-safe-1",),
        "allowed_tool_ids": ("search-fixture", "crm-dry-run"),
        "max_cost_usd": 5.0,
        "max_requests": 10,
        "timeout_seconds": 120,
        "dry_run_default": True,
        "actions": (
            ai_agentic_runtime.AiHarnessAction.IMPORT_RESULTS,
            ai_agentic_runtime.AiHarnessAction.PREPARE_PROMPT_CASE,
            ai_agentic_runtime.AiHarnessAction.PREPARE_DRY_RUN_TOOL_PLAN,
        ),
    }
    values.update(overrides)
    return ai_agentic_runtime.AiHarnessProfile(**values)  # type: ignore[arg-type]


def runner(**overrides: object) -> job_queue.RunnerContract:
    values = {
        "runner_id": "runner-1",
        "organization_id": "org-1",
        "capabilities": (domain.TestMode.AI_AGENTIC_ASSESSMENT,),
        "policy_token_reference": "policy-ref-ai",
        "target_scope": TARGET,
        "timeout_seconds": 120,
        "heartbeat_interval_seconds": 5,
        "result_schema": ("evidence_ids", "ai_findings", "ai_report_rows"),
        "cleanup_callback": "cleanup://runner-1/ai-agentic-runtime",
    }
    values.update(overrides)
    return job_queue.RunnerContract(**values)  # type: ignore[arg-type]


def harness_request(**overrides: object) -> ai_agentic_runtime.AiHarnessRequest:
    values = {
        "runtime_id": "ai-runtime-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target": TARGET,
        "profile": profile(),
        "assessment_request": assessment_request(),
        "runner": runner(),
        "requested_at": NOW,
        "operator_user_id": "operator-1",
        "approved_by_user_id": "lead-1",
    }
    values.update(overrides)
    return ai_agentic_runtime.AiHarnessRequest(**values)  # type: ignore[arg-type]


def result_items() -> tuple[ai_agentic_runtime.AiHarnessResultItem, ...]:
    return (
        ai_agentic_runtime.AiHarnessResultItem(
            item_id="prompt-1",
            category=ai_agentic.AiRiskCategory.PROMPT_INJECTION,
            affected_workflow="support-agent-chat",
            data_boundary="synthetic support ticket fixture only",
            tool_action_boundary="no tool call",
            severity=ai_agentic_runtime.Severity.MEDIUM,
            remediation_guidance="Harden instruction hierarchy and refusal routing.",
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            summary="Sanitized prompt injection dry-run observation.",
            dry_run_only=True,
            cost_usd=0.50,
            request_count=1,
        ),
        ai_agentic_runtime.AiHarnessResultItem(
            item_id="tool-1",
            category=ai_agentic.AiRiskCategory.TOOL_MISUSE,
            affected_workflow="support-agent-refund-flow",
            data_boundary="synthetic customer fixture only",
            tool_action_boundary="dry-run search-fixture only",
            severity=ai_agentic_runtime.Severity.HIGH,
            remediation_guidance="Require policy checks before tool-call planning.",
            evidence_redaction_class=evidence_chain.RedactionStatus.REDACTED,
            summary="Sanitized tool misuse dry-run observation for user test@example.com.",
            dry_run_only=True,
            cost_usd=0.75,
            request_count=2,
            tool_ids=("search-fixture",),
            contains_sensitive_material=True,
        ),
        ai_agentic_runtime.AiHarnessResultItem(
            item_id="cost-1",
            category=ai_agentic.AiRiskCategory.COST_RESOURCE,
            affected_workflow="support-agent-batch-triage",
            data_boundary="synthetic ticket corpus only",
            tool_action_boundary="no side-effecting tools",
            severity=ai_agentic_runtime.Severity.LOW,
            remediation_guidance="Add request and cost guardrails to batch workflows.",
            evidence_redaction_class=evidence_chain.RedactionStatus.NOT_APPLICABLE,
            summary="Sanitized cost/resource guardrail observation.",
            dry_run_only=True,
            cost_usd=0.25,
            request_count=1,
        ),
    )


def skill_spec(**overrides: object) -> ai_agentic_runtime.AiSkillWorkflowSpec:
    values = {
        "request_id": "req-ai-r073",
        "skill_client": "codex",
        "skill_version": "redagent-operator/0.1",
        "owner_label": "Owner",
        "approver_label": "Approver",
        "operator_label": "Codex",
        "authorization_label": "compat_073 local unit authorization",
        "requested_at": NOW,
        "window_start": datetime(2026, 7, 9, 22, 0, tzinfo=timezone.utc),
        "window_end": datetime(2026, 7, 10, 0, 0, tzinfo=timezone.utc),
        "command_log_path": ".local/validation/automated-runs/req-ai-r073-COMMAND_LOG.md",
        "evidence_dir": ".tmp/skill-runs/req-ai-r073",
        "report_path": "reports/assessments/req-ai-r073-report.md",
        "emergency_stop_method": "email",
    }
    values.update(overrides)
    return ai_agentic_runtime.AiSkillWorkflowSpec(**values)  # type: ignore[arg-type]


def test_plan_requires_approved_case_provider_model_cost_redaction_tool_boundary_and_dry_run() -> None:
    plan = ai_agentic_runtime.build_ai_harness_plan(harness_request())

    assert plan.test_id == "ai-test-1"
    assert plan.category is ai_agentic.AiRiskCategory.PROMPT_INJECTION
    assert plan.job.mode is domain.TestMode.AI_AGENTIC_ASSESSMENT
    assert plan.dry_run_only
    assert plan.max_cost_usd == 3.0
    assert plan.max_requests == 8

    with pytest.raises(ValueError, match="ai_assessment_denied:ai_test_case_review_required"):
        ai_agentic_runtime.build_ai_harness_plan(
            harness_request(
                assessment_request=assessment_request(
                    test_case=ai_case(review_status=ReviewStatus.PENDING, reviewer_user_id=None)
                )
            )
        )

    with pytest.raises(ValueError, match="ai_model_not_allowlisted"):
        ai_agentic_runtime.build_ai_harness_plan(harness_request(profile=profile(allowed_model_ids=("model-other",))))

    with pytest.raises(ValueError, match="ai_cost_cap_exceeded"):
        ai_agentic_runtime.build_ai_harness_plan(
            harness_request(assessment_request=assessment_request(provider_scope=provider_scope(max_cost_usd=6.0)))
        )

    with pytest.raises(ValueError, match="ai_assessment_denied:provider_data_redaction_required"):
        ai_agentic_runtime.build_ai_harness_plan(
            harness_request(
                assessment_request=assessment_request(
                    provider_scope=provider_scope(data_redaction_required=False)
                )
            )
        )

    with pytest.raises(ValueError, match="ai_harness_dry_run_default_required"):
        ai_agentic_runtime.build_ai_harness_plan(harness_request(profile=profile(dry_run_default=False)))


def test_prohibited_intents_and_unsafe_tool_actions_are_denied() -> None:
    with pytest.raises(ValueError, match="ai_assessment_denied:prohibited_ai_intent_requested"):
        ai_agentic_runtime.build_ai_harness_plan(
            harness_request(
                assessment_request=assessment_request(
                    requested_intents=(ai_agentic.ProhibitedAiIntent.REAL_SENSITIVE_DATA_EXFILTRATION,)
                )
            )
        )

    with pytest.raises(ValueError, match="ai_assessment_denied:agent_tool_not_allowed"):
        ai_agentic_runtime.build_ai_harness_plan(
            harness_request(assessment_request=assessment_request(requested_tool_ids=("filesystem-write",)))
        )

    with pytest.raises(ValueError, match="ai_harness_live_or_side_effect_action_not_allowed"):
        ai_agentic_runtime.build_ai_harness_plan(
            harness_request(
                profile=profile(
                    actions=(
                        ai_agentic_runtime.AiHarnessAction.IMPORT_RESULTS,
                        ai_agentic_runtime.AiHarnessAction.CALL_LIVE_PROVIDER,
                    )
                )
            )
        )


def test_runtime_imports_ai_results_and_report_mapping_without_provider_or_tool_execution() -> None:
    request_obj = harness_request()
    plan = ai_agentic_runtime.build_ai_harness_plan(request_obj)
    result = ai_agentic_runtime.execute_ai_harness_plan(
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
    assert len(result.imported_evidence_ids) == 3
    assert len(result.findings) == 3
    assert len(result.report_rows) == 3
    assert result.report_rows[0].category is ai_agentic.AiRiskCategory.PROMPT_INJECTION
    assert result.report_rows[1].category is ai_agentic.AiRiskCategory.TOOL_MISUSE
    assert result.report_rows[1].evidence_redaction_class is evidence_chain.RedactionStatus.REDACTED
    assert result.report_rows[2].category is ai_agentic.AiRiskCategory.COST_RESOURCE
    assert result.findings[0].source == "ai_agentic_runtime"


def test_result_redaction_cost_and_tool_rules_fail_closed() -> None:
    request_obj = harness_request()
    plan = ai_agentic_runtime.build_ai_harness_plan(request_obj)
    raw_sensitive = result_items()[1].__class__(
        **{**result_items()[1].__dict__, "evidence_redaction_class": evidence_chain.RedactionStatus.NOT_APPLICABLE}
    )
    side_effect_tool_result = result_items()[1].__class__(**{**result_items()[1].__dict__, "dry_run_only": False})
    over_budget = result_items()[0].__class__(**{**result_items()[0].__dict__, "cost_usd": 99.0})

    with pytest.raises(ValueError, match="ai_sensitive_result_requires_redaction"):
        ai_agentic_runtime.execute_ai_harness_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(raw_sensitive,),
        )

    with pytest.raises(ValueError, match="ai_tool_result_must_be_dry_run"):
        ai_agentic_runtime.execute_ai_harness_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(side_effect_tool_result,),
        )

    with pytest.raises(ValueError, match="ai_result_cost_cap_exceeded"):
        ai_agentic_runtime.execute_ai_harness_plan(
            plan=plan,
            state=job_queue.JobQueueState(jobs=(plan.job,)),
            runner=request_obj.runner,
            evidence_chain=evidence_chain.EvidenceChain(),
            occurred_at=NOW,
            operator_user_id="operator-1",
            result_items=(over_budget,),
        )


def test_skill_driven_workflow_uses_ai_agentic_contract_in_dry_run() -> None:
    request_obj = harness_request()
    plan = ai_agentic_runtime.build_ai_harness_plan(request_obj)
    decision = ai_agentic_runtime.build_ai_skill_workflow_decision(plan, skill_spec())
    output = decision.to_jsonable()

    assert decision.allowed
    assert output["assessment_type"] == "ai_agentic"
    assert output["mode"] == "dry_run"
    assert output["next_action"] == "ready_for_final_confirmation"
    assert output["requested_targets"] == [{"target_type": "ai_application", "value": "support-agent"}]


def test_kill_switch_blocks_dispatch_and_cancellation_finishes_without_credentials() -> None:
    request_obj = harness_request()
    plan = ai_agentic_runtime.build_ai_harness_plan(request_obj)
    blocked = ai_agentic_runtime.execute_ai_harness_plan(
        plan=plan,
        state=job_queue.JobQueueState(jobs=(plan.job,)),
        runner=request_obj.runner,
        evidence_chain=evidence_chain.EvidenceChain(),
        occurred_at=NOW,
        operator_user_id="operator-1",
        result_items=result_items(),
        kill_switch_scope=ai_agentic_runtime.KillSwitchScope(
            engagement_id="eng-1",
            target=TARGET,
            modes=(domain.TestMode.AI_AGENTIC_ASSESSMENT,),
        ),
    )

    assert not blocked.allowed
    assert blocked.reason == "kill_switch_active"
    assert blocked.state.jobs[0].status is domain.JobStatus.QUEUED

    cancelled = ai_agentic_runtime.execute_ai_harness_plan(
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
