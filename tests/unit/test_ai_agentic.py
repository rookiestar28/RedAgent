from redagent_platform import ai_agentic
from redagent_platform.findings import Severity
from redagent_platform.test_registry import ReviewStatus


def ai_case(**overrides: object) -> ai_agentic.AiTestCase:
    values = {
        "test_id": "ai-test-1",
        "version": "1.0.0",
        "category": ai_agentic.AiRiskCategory.PROMPT_INJECTION,
        "risk_class": ai_agentic.AiRiskClass.MEDIUM,
        "review_status": ReviewStatus.APPROVED,
        "reviewer_user_id": "reviewer-1",
        "prompt_template_id": "template-1",
        "expected_observation": "The application refuses unsafe instruction hierarchy changes.",
    }
    values.update(overrides)
    return ai_agentic.AiTestCase(**values)  # type: ignore[arg-type]


def provider_scope(**overrides: object) -> ai_agentic.LiveProviderScope:
    values = {
        "provider_account_id": "provider-account-1",
        "approved_model_ids": ("model-safe-1",),
        "approved_by_user_id": "lead-1",
        "max_cost_usd": 5.0,
        "max_requests": 10,
        "data_redaction_required": True,
        "logging_boundary": "redacted-test-logs",
    }
    values.update(overrides)
    return ai_agentic.LiveProviderScope(**values)  # type: ignore[arg-type]


def tool_boundary(**overrides: object) -> ai_agentic.AgentToolBoundary:
    values = {
        "allowed_tool_ids": ("search-fixture",),
        "dry_run": True,
        "side_effect_controls_enabled": True,
        "kill_switch_enabled": True,
    }
    values.update(overrides)
    return ai_agentic.AgentToolBoundary(**values)  # type: ignore[arg-type]


def request(**overrides: object) -> ai_agentic.AiAssessmentRequest:
    values = {
        "job_id": "ai-job-1",
        "test_case": ai_case(),
        "provider_scope": provider_scope(),
        "tool_boundary": tool_boundary(),
        "requested_model_id": "model-safe-1",
        "requested_tool_ids": ("search-fixture",),
        "requested_intents": (),
    }
    values.update(overrides)
    return ai_agentic.AiAssessmentRequest(**values)  # type: ignore[arg-type]


def test_cases_must_be_reviewed_versioned_and_risk_classified() -> None:
    ai_agentic.validate_ai_test_case(ai_case())

    decision = ai_agentic.evaluate_ai_assessment(
        request(test_case=ai_case(review_status=ReviewStatus.PENDING, reviewer_user_id=None))
    )

    assert not decision.allowed
    assert decision.reason == "ai_test_case_review_required"


def test_live_provider_use_requires_scope_cost_redaction_and_logging_boundaries() -> None:
    decision = ai_agentic.evaluate_ai_assessment(request())

    assert decision.allowed
    assert decision.reason == "ai_assessment_dry_run_plan_allowed"
    assert decision.dry_run_only

    cases: tuple[tuple[dict[str, object], str], ...] = (
        ({"provider_scope": None}, "provider_scope_required"),
        ({"provider_scope": provider_scope(approved_model_ids=())}, "provider_model_allowlist_required"),
        ({"requested_model_id": "model-other"}, "provider_model_not_allowed"),
        ({"provider_scope": provider_scope(max_cost_usd=0)}, "provider_cost_limit_required"),
        ({"provider_scope": provider_scope(data_redaction_required=False)}, "provider_data_redaction_required"),
        ({"provider_scope": provider_scope(logging_boundary="")}, "missing_logging_boundary"),
    )
    for overrides, expected in cases:
        denied = ai_agentic.evaluate_ai_assessment(request(**overrides))
        assert not denied.allowed
        assert denied.reason == expected


def test_agent_tool_use_requires_allowlist_dry_run_side_effect_controls_and_kill_switch() -> None:
    cases: tuple[tuple[dict[str, object], str], ...] = (
        ({"tool_boundary": None}, "agent_tool_boundary_required"),
        ({"tool_boundary": tool_boundary(allowed_tool_ids=())}, "agent_tool_allowlist_required"),
        ({"requested_tool_ids": ("filesystem-write",)}, "agent_tool_not_allowed"),
        ({"tool_boundary": tool_boundary(dry_run=False)}, "agent_tool_dry_run_required"),
        ({"tool_boundary": tool_boundary(side_effect_controls_enabled=False)}, "agent_side_effect_controls_required"),
        ({"tool_boundary": tool_boundary(kill_switch_enabled=False)}, "agent_kill_switch_required"),
    )
    for overrides, expected in cases:
        denied = ai_agentic.evaluate_ai_assessment(request(**overrides))
        assert not denied.allowed
        assert denied.reason == expected


def test_prohibited_ai_intents_are_blocked() -> None:
    for intent in ai_agentic.ProhibitedAiIntent:
        decision = ai_agentic.evaluate_ai_assessment(request(requested_intents=(intent,)))
        assert not decision.allowed
        assert decision.reason == "prohibited_ai_intent_requested"


def test_findings_map_to_ai_risk_workflow_data_tool_boundary_and_remediation() -> None:
    mapping = ai_agentic.build_ai_finding_mapping(
        finding_id="ai-finding-1",
        category=ai_agentic.AiRiskCategory.TOOL_MISUSE,
        affected_workflow="support-agent-refund-flow",
        data_boundary="synthetic customer fixture only",
        tool_action_boundary="dry-run search fixture",
        severity=Severity.MEDIUM,
        remediation_guidance="Require tool-call policy checks before agent action planning.",
    )

    assert mapping.category is ai_agentic.AiRiskCategory.TOOL_MISUSE
    assert mapping.affected_workflow == "support-agent-refund-flow"
    assert mapping.data_boundary == "synthetic customer fixture only"
    assert mapping.tool_action_boundary == "dry-run search fixture"
    assert mapping.severity is Severity.MEDIUM
    assert "tool-call policy" in mapping.remediation_guidance
