"""Reviewed AI/LLM and agentic assessment planning contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from redagent_platform.findings import Severity
from redagent_platform.test_registry import ReviewStatus


class AiRiskCategory(str, Enum):
    PROMPT_INJECTION = "prompt_injection"
    OUTPUT_HANDLING = "output_handling"
    DATA_BOUNDARY = "data_boundary"
    RETRIEVAL_ISSUE = "retrieval_issue"
    EXCESSIVE_AGENCY = "excessive_agency"
    TOOL_MISUSE = "tool_misuse"
    COST_RESOURCE = "cost_resource"


class AiRiskClass(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    LAB_ONLY = "lab_only"


class ProhibitedAiIntent(str, Enum):
    REAL_SENSITIVE_DATA_EXFILTRATION = "real_sensitive_data_exfiltration"
    THIRD_PARTY_SYSTEM_PROMPT_EXTRACTION = "third_party_system_prompt_extraction"
    ACCOUNT_ABUSE = "account_abuse"
    PROVIDER_POLICY_VIOLATION = "provider_policy_violation"


@dataclass(frozen=True, kw_only=True)
class AiTestCase:
    test_id: str
    version: str
    category: AiRiskCategory
    risk_class: AiRiskClass
    review_status: ReviewStatus
    reviewer_user_id: str | None
    prompt_template_id: str
    expected_observation: str


@dataclass(frozen=True, kw_only=True)
class LiveProviderScope:
    provider_account_id: str
    approved_model_ids: tuple[str, ...]
    approved_by_user_id: str
    max_cost_usd: float
    max_requests: int
    data_redaction_required: bool
    logging_boundary: str


@dataclass(frozen=True, kw_only=True)
class AgentToolBoundary:
    allowed_tool_ids: tuple[str, ...]
    dry_run: bool
    side_effect_controls_enabled: bool
    kill_switch_enabled: bool


@dataclass(frozen=True, kw_only=True)
class AiAssessmentRequest:
    job_id: str
    test_case: AiTestCase
    provider_scope: LiveProviderScope | None
    tool_boundary: AgentToolBoundary | None
    requested_model_id: str | None
    requested_tool_ids: tuple[str, ...]
    requested_intents: tuple[ProhibitedAiIntent, ...]


@dataclass(frozen=True, kw_only=True)
class AiAssessmentDecision:
    allowed: bool
    reason: str
    dry_run_only: bool


@dataclass(frozen=True, kw_only=True)
class AiFindingMapping:
    finding_id: str
    category: AiRiskCategory
    affected_workflow: str
    data_boundary: str
    tool_action_boundary: str
    severity: Severity
    remediation_guidance: str


def evaluate_ai_assessment(request: AiAssessmentRequest) -> AiAssessmentDecision:
    try:
        validate_ai_test_case(request.test_case)
    except ValueError as exc:
        return AiAssessmentDecision(allowed=False, reason=str(exc), dry_run_only=True)
    if request.requested_intents:
        return AiAssessmentDecision(allowed=False, reason="prohibited_ai_intent_requested", dry_run_only=True)
    try:
        provider_denial = _provider_scope_denial(request)
    except ValueError as exc:
        return AiAssessmentDecision(allowed=False, reason=str(exc), dry_run_only=True)
    if provider_denial:
        return AiAssessmentDecision(allowed=False, reason=provider_denial, dry_run_only=True)
    tool_denial = _tool_boundary_denial(request)
    if tool_denial:
        return AiAssessmentDecision(allowed=False, reason=tool_denial, dry_run_only=True)
    return AiAssessmentDecision(allowed=True, reason="ai_assessment_dry_run_plan_allowed", dry_run_only=True)


def build_ai_finding_mapping(
    *,
    finding_id: str,
    category: AiRiskCategory,
    affected_workflow: str,
    data_boundary: str,
    tool_action_boundary: str,
    severity: Severity,
    remediation_guidance: str,
) -> AiFindingMapping:
    for field_name, value in (
        ("finding_id", finding_id),
        ("affected_workflow", affected_workflow),
        ("data_boundary", data_boundary),
        ("tool_action_boundary", tool_action_boundary),
        ("remediation_guidance", remediation_guidance),
    ):
        _require_non_empty(field_name, value)
    return AiFindingMapping(
        finding_id=finding_id.strip(),
        category=category,
        affected_workflow=affected_workflow.strip(),
        data_boundary=data_boundary.strip(),
        tool_action_boundary=tool_action_boundary.strip(),
        severity=severity,
        remediation_guidance=remediation_guidance.strip(),
    )


def validate_ai_test_case(test_case: AiTestCase) -> None:
    for field_name, value in (
        ("test_id", test_case.test_id),
        ("version", test_case.version),
        ("prompt_template_id", test_case.prompt_template_id),
        ("expected_observation", test_case.expected_observation),
    ):
        _require_non_empty(field_name, value)
    if test_case.review_status is not ReviewStatus.APPROVED or not test_case.reviewer_user_id:
        raise ValueError("ai_test_case_review_required")


def _provider_scope_denial(request: AiAssessmentRequest) -> str | None:
    scope = request.provider_scope
    if scope is None:
        return "provider_scope_required"
    for field_name, value in (
        ("provider_account_id", scope.provider_account_id),
        ("approved_by_user_id", scope.approved_by_user_id),
        ("logging_boundary", scope.logging_boundary),
    ):
        _require_non_empty(field_name, value)
    if not scope.approved_model_ids:
        return "provider_model_allowlist_required"
    if request.requested_model_id not in scope.approved_model_ids:
        return "provider_model_not_allowed"
    if scope.max_cost_usd <= 0:
        return "provider_cost_limit_required"
    if scope.max_requests <= 0:
        return "provider_request_limit_required"
    if not scope.data_redaction_required:
        return "provider_data_redaction_required"
    return None


def _tool_boundary_denial(request: AiAssessmentRequest) -> str | None:
    if not request.requested_tool_ids:
        return None
    boundary = request.tool_boundary
    if boundary is None:
        return "agent_tool_boundary_required"
    if not boundary.allowed_tool_ids:
        return "agent_tool_allowlist_required"
    if any(tool_id not in boundary.allowed_tool_ids for tool_id in request.requested_tool_ids):
        return "agent_tool_not_allowed"
    if not boundary.dry_run:
        return "agent_tool_dry_run_required"
    if not boundary.side_effect_controls_enabled:
        return "agent_side_effect_controls_required"
    if not boundary.kill_switch_enabled:
        return "agent_kill_switch_required"
    return None


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
