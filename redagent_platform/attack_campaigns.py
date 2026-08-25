"""ATT&CK campaign planning and reviewable export contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform.domain import TargetType, TestRiskClass
from redagent_platform.evidence_chain import AuditAction, EvidenceChain


class AttackSafetyClass(str, Enum):
    PLANNING_ONLY = "planning_only"
    LAB_ONLY = "lab_only"
    CONTROLLED_ACTIVE = "controlled_active"
    HIGH_RISK_REVIEW_REQUIRED = "high_risk_review_required"


class TelemetrySource(str, Enum):
    SIEM = "siem"
    EDR = "edr"
    CLOUD_AUDIT = "cloud_audit"
    APPLICATION_LOG = "application_log"
    NETWORK_SENSOR = "network_sensor"


@dataclass(frozen=True, kw_only=True)
class AttackTechniqueSelection:
    tactic_id: str
    tactic_name: str
    technique_id: str
    technique_name: str
    subtechnique_id: str | None = None


@dataclass(frozen=True, kw_only=True)
class CampaignPrerequisite:
    name: str
    description: str
    required_permission: str


@dataclass(frozen=True, kw_only=True)
class ExpectedTelemetry:
    source: TelemetrySource
    event_name: str
    detection_owner: str
    success_criteria: str


@dataclass(frozen=True, kw_only=True)
class CampaignWindow:
    start: datetime
    end: datetime
    timezone_label: str


@dataclass(frozen=True, kw_only=True)
class AttackCampaign:
    campaign_id: str
    name: str
    organization_id: str
    engagement_id: str
    target_classes: tuple[TargetType, ...]
    techniques: tuple[AttackTechniqueSelection, ...]
    prerequisites: tuple[CampaignPrerequisite, ...]
    allowed_windows: tuple[CampaignWindow, ...]
    expected_telemetry: tuple[ExpectedTelemetry, ...]
    safety_class: AttackSafetyClass
    risk_class: TestRiskClass
    detection_objectives: tuple[str, ...]
    cleanup_needs: tuple[str, ...]
    created_by_user_id: str
    created_at: datetime


@dataclass(frozen=True, kw_only=True)
class CampaignPreview:
    campaign_id: str
    blast_radius: str
    target_class_count: int
    technique_count: int
    required_permissions: tuple[str, ...]
    cleanup_needs: tuple[str, ...]
    detection_objectives: tuple[str, ...]
    execution_enabled: bool = False


@dataclass(frozen=True, kw_only=True)
class ReviewableCampaignPlan:
    campaign_id: str
    name: str
    attack_mapping: tuple[dict[str, str | None], ...]
    target_classes: tuple[str, ...]
    allowed_windows: tuple[dict[str, str], ...]
    expected_telemetry: tuple[dict[str, str], ...]
    prerequisites: tuple[dict[str, str], ...]
    preview: CampaignPreview
    safety_class: str
    risk_class: str
    execution_enabled: bool
    plan_hash: str


@dataclass(frozen=True, kw_only=True)
class CampaignPlanResult:
    plan: ReviewableCampaignPlan
    audit_chain: EvidenceChain


_TACTIC_ID = re.compile(r"^TA\d{4}$")
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def preview_campaign(campaign: AttackCampaign) -> CampaignPreview:
    validate_campaign(campaign)
    permissions = tuple(sorted({prereq.required_permission for prereq in campaign.prerequisites}))
    return CampaignPreview(
        campaign_id=campaign.campaign_id,
        blast_radius=_blast_radius(campaign),
        target_class_count=len(campaign.target_classes),
        technique_count=len(campaign.techniques),
        required_permissions=permissions,
        cleanup_needs=tuple(campaign.cleanup_needs),
        detection_objectives=tuple(campaign.detection_objectives),
    )


def export_reviewable_campaign_plan(
    *,
    campaign: AttackCampaign,
    audit_chain: EvidenceChain,
    event_id: str,
) -> CampaignPlanResult:
    _require_non_empty("event_id", event_id)
    preview = preview_campaign(campaign)
    plan_without_hash = {
        "campaign_id": campaign.campaign_id,
        "name": campaign.name,
        "attack_mapping": tuple(_technique_to_dict(technique) for technique in campaign.techniques),
        "target_classes": tuple(target.value for target in campaign.target_classes),
        "allowed_windows": tuple(_window_to_dict(window) for window in campaign.allowed_windows),
        "expected_telemetry": tuple(_telemetry_to_dict(item) for item in campaign.expected_telemetry),
        "prerequisites": tuple(_prerequisite_to_dict(item) for item in campaign.prerequisites),
        "preview": _preview_to_dict(preview),
        "safety_class": campaign.safety_class.value,
        "risk_class": campaign.risk_class.value,
        "execution_enabled": False,
    }
    plan = ReviewableCampaignPlan(
        campaign_id=campaign.campaign_id,
        name=campaign.name,
        attack_mapping=plan_without_hash["attack_mapping"],  # type: ignore[arg-type]
        target_classes=plan_without_hash["target_classes"],  # type: ignore[arg-type]
        allowed_windows=plan_without_hash["allowed_windows"],  # type: ignore[arg-type]
        expected_telemetry=plan_without_hash["expected_telemetry"],  # type: ignore[arg-type]
        prerequisites=plan_without_hash["prerequisites"],  # type: ignore[arg-type]
        preview=preview,
        safety_class=campaign.safety_class.value,
        risk_class=campaign.risk_class.value,
        execution_enabled=False,
        plan_hash=_canonical_sha256(plan_without_hash),
    )
    next_chain = audit_chain.append_audit_event(
        event_id=event_id,
        organization_id=campaign.organization_id,
        actor_user_id=campaign.created_by_user_id,
        action=AuditAction.TEST_DEFINITION_CHANGE,
        subject_type="attack_campaign_plan",
        subject_id=campaign.campaign_id,
        occurred_at=campaign.created_at,
        details={
            "technique_count": len(campaign.techniques),
            "target_class_count": len(campaign.target_classes),
            "safety_class": campaign.safety_class.value,
            "execution_enabled": False,
            "plan_hash": plan.plan_hash,
        },
    )
    return CampaignPlanResult(plan=plan, audit_chain=next_chain)


def validate_campaign(campaign: AttackCampaign) -> None:
    for field_name, value in (
        ("campaign_id", campaign.campaign_id),
        ("name", campaign.name),
        ("organization_id", campaign.organization_id),
        ("engagement_id", campaign.engagement_id),
        ("created_by_user_id", campaign.created_by_user_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(campaign.created_at)
    if not campaign.target_classes:
        raise ValueError("missing_target_classes")
    if not campaign.techniques:
        raise ValueError("missing_attack_techniques")
    if not campaign.prerequisites:
        raise ValueError("missing_prerequisites")
    if not campaign.allowed_windows:
        raise ValueError("missing_allowed_windows")
    if not campaign.expected_telemetry:
        raise ValueError("missing_expected_telemetry")
    if not campaign.detection_objectives:
        raise ValueError("missing_detection_objectives")
    if not campaign.cleanup_needs:
        raise ValueError("missing_cleanup_needs")
    for technique in campaign.techniques:
        _validate_technique(technique)
    for prerequisite in campaign.prerequisites:
        _validate_prerequisite(prerequisite)
    for window in campaign.allowed_windows:
        _validate_window(window)
    for telemetry in campaign.expected_telemetry:
        _validate_telemetry(telemetry)
    if campaign.safety_class is AttackSafetyClass.PLANNING_ONLY and campaign.risk_class is not TestRiskClass.LAB_ONLY:
        raise ValueError("planning_only_requires_lab_risk_class")


def _blast_radius(campaign: AttackCampaign) -> str:
    if campaign.safety_class is AttackSafetyClass.PLANNING_ONLY:
        return "planning-only"
    if len(campaign.target_classes) == 1 and len(campaign.techniques) <= 2:
        return "single-target-class-limited"
    if len(campaign.target_classes) <= 2 and len(campaign.techniques) <= 5:
        return "multi-technique-controlled"
    return "broad-review-required"


def _validate_technique(technique: AttackTechniqueSelection) -> None:
    for field_name, value in (
        ("tactic_id", technique.tactic_id),
        ("tactic_name", technique.tactic_name),
        ("technique_id", technique.technique_id),
        ("technique_name", technique.technique_name),
    ):
        _require_non_empty(field_name, value)
    if not _TACTIC_ID.fullmatch(technique.tactic_id):
        raise ValueError("invalid_attack_tactic_id")
    if not _TECHNIQUE_ID.fullmatch(technique.technique_id):
        raise ValueError("invalid_attack_technique_id")
    if technique.subtechnique_id and not _TECHNIQUE_ID.fullmatch(technique.subtechnique_id):
        raise ValueError("invalid_attack_subtechnique_id")


def _validate_prerequisite(prerequisite: CampaignPrerequisite) -> None:
    for field_name, value in (
        ("prerequisite_name", prerequisite.name),
        ("prerequisite_description", prerequisite.description),
        ("required_permission", prerequisite.required_permission),
    ):
        _require_non_empty(field_name, value)


def _validate_window(window: CampaignWindow) -> None:
    _require_timezone(window.start)
    _require_timezone(window.end)
    _require_non_empty("timezone_label", window.timezone_label)
    if window.start >= window.end:
        raise ValueError("invalid_campaign_window")


def _validate_telemetry(telemetry: ExpectedTelemetry) -> None:
    for field_name, value in (
        ("telemetry_event_name", telemetry.event_name),
        ("detection_owner", telemetry.detection_owner),
        ("success_criteria", telemetry.success_criteria),
    ):
        _require_non_empty(field_name, value)


def _technique_to_dict(technique: AttackTechniqueSelection) -> dict[str, str | None]:
    return {
        "tactic_id": technique.tactic_id,
        "tactic_name": technique.tactic_name,
        "technique_id": technique.technique_id,
        "technique_name": technique.technique_name,
        "subtechnique_id": technique.subtechnique_id,
    }


def _window_to_dict(window: CampaignWindow) -> dict[str, str]:
    return {"start": window.start.isoformat(), "end": window.end.isoformat(), "timezone": window.timezone_label}


def _telemetry_to_dict(telemetry: ExpectedTelemetry) -> dict[str, str]:
    return {
        "source": telemetry.source.value,
        "event_name": telemetry.event_name,
        "detection_owner": telemetry.detection_owner,
        "success_criteria": telemetry.success_criteria,
    }


def _prerequisite_to_dict(prerequisite: CampaignPrerequisite) -> dict[str, str]:
    return {
        "name": prerequisite.name,
        "description": prerequisite.description,
        "required_permission": prerequisite.required_permission,
    }


def _preview_to_dict(preview: CampaignPreview) -> dict[str, object]:
    return {
        "campaign_id": preview.campaign_id,
        "blast_radius": preview.blast_radius,
        "target_class_count": preview.target_class_count,
        "technique_count": preview.technique_count,
        "required_permissions": preview.required_permissions,
        "cleanup_needs": preview.cleanup_needs,
        "detection_objectives": preview.detection_objectives,
        "execution_enabled": preview.execution_enabled,
    }


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
