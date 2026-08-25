"""Deterministic compat_112 fixtures shared by tests and qualification tooling."""

from datetime import datetime, timedelta

from redagent_platform.human_simulation.catalog import certified_campaign
from redagent_platform.human_simulation.compiler import CompiledCampaignPlan, compile_campaign_plan
from redagent_platform.human_simulation.contracts import CampaignApproval, CampaignAuthorization, campaign_sha256


def compiled_sink_plan(*, now: datetime) -> CompiledCampaignPlan:
    campaign = certified_campaign(); digest = campaign_sha256(campaign)
    approval = CampaignApproval(approval_id="approval-r112", campaign_id=campaign.campaign_id,
        campaign_sha256=digest, rendered_sha256="a" * 64, test_delivery_sha256="b" * 64,
        requester_id="requester-r112", preview_reviewer_id="reviewer-r112", send_approver_id="approver-r112",
        approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    authorization = CampaignAuthorization(authorization_id="auth-r112", policy_decision_id="policy-r112",
        policy_revision="r112-v1", roe_revision="roe-r112", reservation_id="reservation-r112",
        delivery_lease_id="lease-r112", stop_switch_id="stop-r112", quota_id="quota-r112",
        campaign_sha256=digest, approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    return compile_campaign_plan(campaign=campaign, approval=approval, authorization=authorization, now=now)
