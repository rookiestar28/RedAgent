from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import attack_campaigns, domain, evidence_chain


NOW = datetime(2026, 7, 8, 16, 0, tzinfo=timezone.utc)


def technique(**overrides: object) -> attack_campaigns.AttackTechniqueSelection:
    values = {
        "tactic_id": "TA0001",
        "tactic_name": "Initial Access",
        "technique_id": "T1190",
        "technique_name": "Exploit Public-Facing Application",
        "subtechnique_id": None,
    }
    values.update(overrides)
    return attack_campaigns.AttackTechniqueSelection(**values)  # type: ignore[arg-type]


def campaign(**overrides: object) -> attack_campaigns.AttackCampaign:
    values = {
        "campaign_id": "campaign-1",
        "name": "Web Initial Access Detection Validation",
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "target_classes": (domain.TargetType.WEB_ORIGIN,),
        "techniques": (technique(),),
        "prerequisites": (
            attack_campaigns.CampaignPrerequisite(
                name="Approved lab target",
                description="A local or approved lab target is available.",
                required_permission="lab_operator",
            ),
        ),
        "allowed_windows": (
            attack_campaigns.CampaignWindow(
                start=NOW,
                end=NOW + timedelta(hours=2),
                timezone_label="Asia/Taipei",
            ),
        ),
        "expected_telemetry": (
            attack_campaigns.ExpectedTelemetry(
                source=attack_campaigns.TelemetrySource.APPLICATION_LOG,
                event_name="web_request_validation_event",
                detection_owner="blue-team",
                success_criteria="Application logs show controlled validation traffic.",
            ),
        ),
        "safety_class": attack_campaigns.AttackSafetyClass.PLANNING_ONLY,
        "risk_class": domain.TestRiskClass.LAB_ONLY,
        "detection_objectives": ("Confirm web request telemetry routing.",),
        "cleanup_needs": ("No runtime cleanup because compat_022 is planning-only.",),
        "created_by_user_id": "planner-1",
        "created_at": NOW,
    }
    values.update(overrides)
    return attack_campaigns.AttackCampaign(**values)  # type: ignore[arg-type]


def test_campaign_supports_required_attack_planning_fields() -> None:
    planned = campaign()

    attack_campaigns.validate_campaign(planned)

    assert planned.techniques[0].tactic_id == "TA0001"
    assert planned.techniques[0].technique_id == "T1190"
    assert planned.prerequisites[0].required_permission == "lab_operator"
    assert planned.target_classes == (domain.TargetType.WEB_ORIGIN,)
    assert planned.allowed_windows[0].timezone_label == "Asia/Taipei"
    assert planned.expected_telemetry[0].source is attack_campaigns.TelemetrySource.APPLICATION_LOG
    assert planned.safety_class is attack_campaigns.AttackSafetyClass.PLANNING_ONLY


def test_campaign_preview_shows_blast_radius_permissions_cleanup_and_detection_objectives() -> None:
    preview = attack_campaigns.preview_campaign(campaign())

    assert preview.blast_radius == "planning-only"
    assert preview.target_class_count == 1
    assert preview.technique_count == 1
    assert preview.required_permissions == ("lab_operator",)
    assert preview.cleanup_needs == ("No runtime cleanup because compat_022 is planning-only.",)
    assert preview.detection_objectives == ("Confirm web request telemetry routing.",)
    assert not preview.execution_enabled


def test_campaign_exports_reviewable_plan_with_attack_mapping_and_audit() -> None:
    result = attack_campaigns.export_reviewable_campaign_plan(
        campaign=campaign(),
        audit_chain=evidence_chain.EvidenceChain(),
        event_id="campaign-plan-1",
    )

    assert result.plan.campaign_id == "campaign-1"
    assert result.plan.attack_mapping[0]["tactic_id"] == "TA0001"
    assert result.plan.attack_mapping[0]["technique_id"] == "T1190"
    assert result.plan.target_classes == ("web_origin",)
    assert result.plan.expected_telemetry[0]["event_name"] == "web_request_validation_event"
    assert not result.plan.execution_enabled
    assert len(result.plan.plan_hash) == 64
    assert result.audit_chain.audit_events[0].action is evidence_chain.AuditAction.TEST_DEFINITION_CHANGE


def test_campaign_validation_rejects_missing_or_invalid_required_inputs() -> None:
    with pytest.raises(ValueError, match="missing_attack_techniques"):
        attack_campaigns.validate_campaign(campaign(techniques=()))

    with pytest.raises(ValueError, match="invalid_attack_tactic_id"):
        attack_campaigns.validate_campaign(campaign(techniques=(technique(tactic_id="T0001"),)))

    with pytest.raises(ValueError, match="missing_expected_telemetry"):
        attack_campaigns.validate_campaign(campaign(expected_telemetry=()))

    with pytest.raises(ValueError, match="planning_only_requires_lab_risk_class"):
        attack_campaigns.validate_campaign(campaign(risk_class=domain.TestRiskClass.ACTIVE_INTRUSIVE))


def test_no_campaign_execution_path_exists() -> None:
    assert not hasattr(attack_campaigns, "execute_campaign")
    assert not hasattr(attack_campaigns, "run_campaign")
    assert not hasattr(attack_campaigns, "dispatch_campaign")
