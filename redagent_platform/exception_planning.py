"""Exception-gated planning for specialized high-risk assessment domains."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class SpecializedAssessmentDomain(str, Enum):
    SOCIAL_ENGINEERING = "social_engineering"
    PHYSICAL = "physical"
    WIRELESS = "wireless"
    IOT = "iot"
    OT = "ot"


class ExceptionDecisionReason(str, Enum):
    ACCEPTED_FOR_EXCEPTION_REVIEW = "accepted_for_exception_review"
    MISSING_REQUIRED_CONTROL = "missing_required_control"
    FIELD_PREREQUISITE_MISSING = "field_prerequisite_missing"
    HUMAN_SUBJECT_PRIVACY_GAP = "human_subject_privacy_gap"
    MVP_PROMOTION_REQUIRED = "mvp_promotion_required"
    INVALID_PLAN = "invalid_plan"


FIELD_ACTIVITY_DOMAINS = frozenset(
    {
        SpecializedAssessmentDomain.PHYSICAL,
        SpecializedAssessmentDomain.WIRELESS,
        SpecializedAssessmentDomain.IOT,
        SpecializedAssessmentDomain.OT,
    }
)
HUMAN_SUBJECT_DOMAINS = frozenset({SpecializedAssessmentDomain.SOCIAL_ENGINEERING, SpecializedAssessmentDomain.PHYSICAL})


@dataclass(frozen=True, kw_only=True)
class ExceptionApprovalWorkflow:
    owner_user_id: str | None
    legal_privacy_review_id: str | None
    safety_plan_id: str | None
    location_environment_scope_id: str | None
    emergency_stop_method: str | None
    evidence_boundary_id: str | None
    excluded_actions: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class FieldActivityPrerequisites:
    asset_inventory_id: str | None
    safety_constraints_id: str | None
    lab_or_non_production_preference: bool
    lab_preference_rationale: str | None


@dataclass(frozen=True, kw_only=True)
class HumanSubjectMetricsPlan:
    privacy_aware_metrics: tuple[str, ...]
    personal_data_fields: tuple[str, ...]
    unnecessary_personal_data_collected: bool = False


@dataclass(frozen=True, kw_only=True)
class SpecializedAssessmentPlan:
    plan_id: str
    organization_id: str
    engagement_id: str
    domain: SpecializedAssessmentDomain
    objective: str
    approval_workflow: ExceptionApprovalWorkflow
    field_prerequisites: FieldActivityPrerequisites | None
    human_subject_metrics: HumanSubjectMetricsPlan | None
    created_by_user_id: str
    created_at: datetime
    mvp_promotion_decision_id: str | None = None


@dataclass(frozen=True, kw_only=True)
class PlanningTemplate:
    domain: SpecializedAssessmentDomain
    required_sections: tuple[str, ...]
    execution_enabled: bool = False
    mvp_included: bool = False


@dataclass(frozen=True, kw_only=True)
class ExceptionPlanningDecision:
    allowed_for_exception_review: bool
    reason: ExceptionDecisionReason
    details: tuple[str, ...] = ()
    execution_enabled: bool = False


def build_planning_template(domain: SpecializedAssessmentDomain) -> PlanningTemplate:
    sections = [
        "owner",
        "legal_privacy_review",
        "safety_plan",
        "location_environment_scope",
        "emergency_stop_method",
        "evidence_boundary",
        "excluded_actions",
        "mvp_promotion_decision",
    ]
    if domain in FIELD_ACTIVITY_DOMAINS:
        sections.extend(("asset_inventory", "safety_constraints", "lab_or_non_production_preference"))
    if domain in HUMAN_SUBJECT_DOMAINS:
        sections.extend(("privacy_aware_metrics", "personal_data_minimization"))
    return PlanningTemplate(domain=domain, required_sections=tuple(sections))


def evaluate_specialized_assessment_plan(plan: SpecializedAssessmentPlan) -> ExceptionPlanningDecision:
    try:
        _validate_plan_identity(plan)
    except ValueError as exc:
        return ExceptionPlanningDecision(
            allowed_for_exception_review=False,
            reason=ExceptionDecisionReason.INVALID_PLAN,
            details=(str(exc),),
        )

    missing_controls = _missing_approval_controls(plan.approval_workflow)
    if missing_controls:
        return ExceptionPlanningDecision(
            allowed_for_exception_review=False,
            reason=ExceptionDecisionReason.MISSING_REQUIRED_CONTROL,
            details=missing_controls,
        )
    missing_field = _missing_field_prerequisites(plan)
    if missing_field:
        return ExceptionPlanningDecision(
            allowed_for_exception_review=False,
            reason=ExceptionDecisionReason.FIELD_PREREQUISITE_MISSING,
            details=missing_field,
        )
    privacy_gaps = _human_subject_privacy_gaps(plan)
    if privacy_gaps:
        return ExceptionPlanningDecision(
            allowed_for_exception_review=False,
            reason=ExceptionDecisionReason.HUMAN_SUBJECT_PRIVACY_GAP,
            details=privacy_gaps,
        )
    if plan.mvp_promotion_decision_id:
        return ExceptionPlanningDecision(
            allowed_for_exception_review=False,
            reason=ExceptionDecisionReason.MVP_PROMOTION_REQUIRED,
            details=("promotion_must_be_separate_roadmap_item",),
        )
    return ExceptionPlanningDecision(
        allowed_for_exception_review=True,
        reason=ExceptionDecisionReason.ACCEPTED_FOR_EXCEPTION_REVIEW,
        details=("planning_only_execution_disabled",),
    )


def mvp_exclusion_record(plan: SpecializedAssessmentPlan) -> dict[str, object]:
    _validate_plan_identity(plan)
    return {
        "plan_id": plan.plan_id,
        "domain": plan.domain.value,
        "mvp_included": False,
        "execution_enabled": False,
        "promotion_required": True,
        "promotion_decision_id": plan.mvp_promotion_decision_id,
    }


def _validate_plan_identity(plan: SpecializedAssessmentPlan) -> None:
    for field_name, value in (
        ("plan_id", plan.plan_id),
        ("organization_id", plan.organization_id),
        ("engagement_id", plan.engagement_id),
        ("objective", plan.objective),
        ("created_by_user_id", plan.created_by_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(plan.created_at)


def _missing_approval_controls(workflow: ExceptionApprovalWorkflow) -> tuple[str, ...]:
    missing = []
    for field_name, value in (
        ("owner_user_id", workflow.owner_user_id),
        ("legal_privacy_review_id", workflow.legal_privacy_review_id),
        ("safety_plan_id", workflow.safety_plan_id),
        ("location_environment_scope_id", workflow.location_environment_scope_id),
        ("emergency_stop_method", workflow.emergency_stop_method),
        ("evidence_boundary_id", workflow.evidence_boundary_id),
    ):
        if not value or not value.strip():
            missing.append(field_name)
    if not workflow.excluded_actions:
        missing.append("excluded_actions")
    elif any(not action.strip() for action in workflow.excluded_actions):
        missing.append("excluded_actions")
    return tuple(missing)


def _missing_field_prerequisites(plan: SpecializedAssessmentPlan) -> tuple[str, ...]:
    if plan.domain not in FIELD_ACTIVITY_DOMAINS:
        return ()
    prerequisites = plan.field_prerequisites
    if prerequisites is None:
        return ("field_prerequisites",)
    missing = []
    for field_name, value in (
        ("asset_inventory_id", prerequisites.asset_inventory_id),
        ("safety_constraints_id", prerequisites.safety_constraints_id),
        ("lab_preference_rationale", prerequisites.lab_preference_rationale),
    ):
        if not value or not value.strip():
            missing.append(field_name)
    if not prerequisites.lab_or_non_production_preference:
        missing.append("lab_or_non_production_preference")
    return tuple(missing)


def _human_subject_privacy_gaps(plan: SpecializedAssessmentPlan) -> tuple[str, ...]:
    if plan.domain not in HUMAN_SUBJECT_DOMAINS:
        return ()
    metrics = plan.human_subject_metrics
    if metrics is None:
        return ("human_subject_metrics",)
    gaps = []
    if not metrics.privacy_aware_metrics:
        gaps.append("privacy_aware_metrics")
    elif any(not metric.strip() for metric in metrics.privacy_aware_metrics):
        gaps.append("privacy_aware_metrics")
    if metrics.unnecessary_personal_data_collected:
        gaps.append("unnecessary_personal_data_collected")
    if metrics.personal_data_fields:
        gaps.append("personal_data_fields")
    return tuple(gaps)


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
