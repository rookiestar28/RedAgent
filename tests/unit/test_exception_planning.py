from datetime import datetime, timezone

import pytest

from redagent_platform import exception_planning


NOW = datetime(2026, 7, 8, 21, 0, tzinfo=timezone.utc)


def approval(**overrides: object) -> exception_planning.ExceptionApprovalWorkflow:
    values = {
        "owner_user_id": "owner-1",
        "legal_privacy_review_id": "legal-1",
        "safety_plan_id": "safety-1",
        "location_environment_scope_id": "location-1",
        "emergency_stop_method": "security-lead-phone",
        "evidence_boundary_id": "evidence-boundary-1",
        "excluded_actions": ("no coercion", "no production disruption", "no credential collection"),
    }
    values.update(overrides)
    return exception_planning.ExceptionApprovalWorkflow(**values)  # type: ignore[arg-type]


def field_prerequisites(**overrides: object) -> exception_planning.FieldActivityPrerequisites:
    values = {
        "asset_inventory_id": "asset-inventory-1",
        "safety_constraints_id": "safety-constraints-1",
        "lab_or_non_production_preference": True,
        "lab_preference_rationale": "Use lab or non-production environment before any field activity.",
    }
    values.update(overrides)
    return exception_planning.FieldActivityPrerequisites(**values)  # type: ignore[arg-type]


def human_metrics(**overrides: object) -> exception_planning.HumanSubjectMetricsPlan:
    values = {
        "privacy_aware_metrics": ("aggregate_report_rate", "aggregate_training_completion_rate"),
        "personal_data_fields": (),
        "unnecessary_personal_data_collected": False,
    }
    values.update(overrides)
    return exception_planning.HumanSubjectMetricsPlan(**values)  # type: ignore[arg-type]


def plan(**overrides: object) -> exception_planning.SpecializedAssessmentPlan:
    values = {
        "plan_id": "exception-plan-1",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "domain": exception_planning.SpecializedAssessmentDomain.WIRELESS,
        "objective": "Plan specialized assessment controls without execution.",
        "approval_workflow": approval(),
        "field_prerequisites": field_prerequisites(),
        "human_subject_metrics": None,
        "created_by_user_id": "planner-1",
        "created_at": NOW,
    }
    values.update(overrides)
    return exception_planning.SpecializedAssessmentPlan(**values)  # type: ignore[arg-type]


def test_templates_are_planning_only_with_execution_disabled_by_default() -> None:
    template = exception_planning.build_planning_template(exception_planning.SpecializedAssessmentDomain.OT)

    assert "owner" in template.required_sections
    assert "asset_inventory" in template.required_sections
    assert "safety_constraints" in template.required_sections
    assert not template.execution_enabled
    assert not template.mvp_included
    assert not hasattr(exception_planning, "execute_assessment")
    assert not hasattr(exception_planning, "run_field_activity")


def test_each_domain_requires_owner_legal_safety_scope_stop_evidence_and_exclusions() -> None:
    decision = exception_planning.evaluate_specialized_assessment_plan(
        plan(
            approval_workflow=approval(
                owner_user_id=None,
                legal_privacy_review_id=None,
                emergency_stop_method=None,
                excluded_actions=(),
            )
        )
    )

    assert not decision.allowed_for_exception_review
    assert decision.reason is exception_planning.ExceptionDecisionReason.MISSING_REQUIRED_CONTROL
    assert "owner_user_id" in decision.details
    assert "legal_privacy_review_id" in decision.details
    assert "emergency_stop_method" in decision.details
    assert "excluded_actions" in decision.details
    assert not decision.execution_enabled


@pytest.mark.parametrize(
    "domain",
    (
        exception_planning.SpecializedAssessmentDomain.PHYSICAL,
        exception_planning.SpecializedAssessmentDomain.WIRELESS,
        exception_planning.SpecializedAssessmentDomain.IOT,
        exception_planning.SpecializedAssessmentDomain.OT,
    ),
)
def test_field_activity_domains_require_asset_inventory_safety_constraints_and_lab_preference(
    domain: exception_planning.SpecializedAssessmentDomain,
) -> None:
    decision = exception_planning.evaluate_specialized_assessment_plan(
        plan(
            domain=domain,
            field_prerequisites=field_prerequisites(
                asset_inventory_id=None,
                safety_constraints_id=None,
                lab_or_non_production_preference=False,
            ),
            human_subject_metrics=human_metrics() if domain is exception_planning.SpecializedAssessmentDomain.PHYSICAL else None,
        )
    )

    assert not decision.allowed_for_exception_review
    assert decision.reason is exception_planning.ExceptionDecisionReason.FIELD_PREREQUISITE_MISSING
    assert "asset_inventory_id" in decision.details
    assert "safety_constraints_id" in decision.details
    assert "lab_or_non_production_preference" in decision.details


def test_human_subject_testing_requires_privacy_aware_metrics_and_personal_data_minimization() -> None:
    decision = exception_planning.evaluate_specialized_assessment_plan(
        plan(
            domain=exception_planning.SpecializedAssessmentDomain.SOCIAL_ENGINEERING,
            field_prerequisites=None,
            human_subject_metrics=human_metrics(
                privacy_aware_metrics=(),
                personal_data_fields=("mailbox_body",),
                unnecessary_personal_data_collected=True,
            ),
        )
    )

    assert not decision.allowed_for_exception_review
    assert decision.reason is exception_planning.ExceptionDecisionReason.HUMAN_SUBJECT_PRIVACY_GAP
    assert "privacy_aware_metrics" in decision.details
    assert "personal_data_fields" in decision.details
    assert "unnecessary_personal_data_collected" in decision.details


def test_complete_plan_enters_exception_review_only_and_never_enables_execution() -> None:
    decision = exception_planning.evaluate_specialized_assessment_plan(plan())

    assert decision.allowed_for_exception_review
    assert decision.reason is exception_planning.ExceptionDecisionReason.ACCEPTED_FOR_EXCEPTION_REVIEW
    assert decision.details == ("planning_only_execution_disabled",)
    assert not decision.execution_enabled


def test_mvp_exclusion_requires_later_explicit_promotion_decision() -> None:
    planned = plan()
    exclusion = exception_planning.mvp_exclusion_record(planned)
    promoted = exception_planning.evaluate_specialized_assessment_plan(plan(mvp_promotion_decision_id="promotion-1"))

    assert exclusion == {
        "plan_id": "exception-plan-1",
        "domain": "wireless",
        "mvp_included": False,
        "execution_enabled": False,
        "promotion_required": True,
        "promotion_decision_id": None,
    }
    assert not promoted.allowed_for_exception_review
    assert promoted.reason is exception_planning.ExceptionDecisionReason.MVP_PROMOTION_REQUIRED
    assert promoted.details == ("promotion_must_be_separate_roadmap_item",)
