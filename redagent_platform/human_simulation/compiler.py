"""Closed compat_112 compiler binding campaign, approvals, authorization, and sink-only limits."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json

from redagent_platform.human_simulation.contracts import CampaignApproval, CampaignAuthorization, CampaignManifest, campaign_sha256


@dataclass(frozen=True, kw_only=True)
class CompiledCampaignPlan:
    campaign_id: str; campaign_sha256: str; rendered_sha256: str; test_delivery_sha256: str
    sender: str; recipient: str; subject: str; body: str; canary_id: str; sink_id: str
    max_deliveries: int; rate_per_minute: int; retention_seconds: int; delivery_lease_id: str; stop_switch_id: str
    human_delivery: bool; external_delivery: bool; relay_allowed: bool; forwarding_allowed: bool; tracking_allowed: bool
    plan_sha256: str


def compile_campaign_plan(*, campaign: CampaignManifest, approval: CampaignApproval,
                          authorization: CampaignAuthorization, now: datetime) -> CompiledCampaignPlan:
    _active(now, approval.approved_at, approval.expires_at, "human_approval_inactive")
    _active(now, authorization.approved_at, authorization.expires_at, "human_authorization_inactive")
    digest = campaign_sha256(campaign)
    if approval.campaign_id != campaign.campaign_id or approval.campaign_sha256 != digest or authorization.campaign_sha256 != digest:
        raise ValueError("human_campaign_digest_mismatch")
    values = dict(campaign_id=campaign.campaign_id, campaign_sha256=digest, rendered_sha256=approval.rendered_sha256,
        test_delivery_sha256=approval.test_delivery_sha256, sender=campaign.sender, recipient=campaign.recipient,
        subject=campaign.subject, body=campaign.body, canary_id=campaign.canary_id, sink_id=campaign.sink_id,
        max_deliveries=1, rate_per_minute=1, retention_seconds=300, delivery_lease_id=authorization.delivery_lease_id,
        stop_switch_id=authorization.stop_switch_id, human_delivery=False, external_delivery=False,
        relay_allowed=False, forwarding_allowed=False, tracking_allowed=False)
    return CompiledCampaignPlan(**values, plan_sha256=_digest(values))


def verify_plan_integrity(plan: CompiledCampaignPlan) -> None:
    values = asdict(plan); asserted = values.pop("plan_sha256")
    if asserted != _digest(values):
        raise ValueError("human_plan_integrity_invalid")
    if any((plan.human_delivery, plan.external_delivery, plan.relay_allowed, plan.forwarding_allowed, plan.tracking_allowed)):
        raise ValueError("human_plan_delivery_boundary_invalid")


def _digest(values: dict[str, object]) -> str:
    material = {"schema": "redagent.r112-campaign-plan/v1", **values}
    return hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _active(now: datetime, start: datetime, end: datetime, error: str) -> None:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("human_time_invalid")
    if now < start or now >= end:
        raise ValueError(error)
