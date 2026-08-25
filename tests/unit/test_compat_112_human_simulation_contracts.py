from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.human_simulation.catalog import certified_campaign
from redagent_platform.human_simulation.compiler import compile_campaign_plan
from redagent_platform.human_simulation.contracts import CampaignApproval, CampaignAuthorization, campaign_sha256


NOW = datetime(2026, 7, 11, 16, 0, tzinfo=timezone.utc)


def _inputs(**approval_overrides):
    campaign = certified_campaign(); digest = campaign_sha256(campaign)
    approval_values = dict(approval_id="approval-r112", campaign_id=campaign.campaign_id, campaign_sha256=digest,
        rendered_sha256="a" * 64, test_delivery_sha256="b" * 64, requester_id="requester-r112",
        preview_reviewer_id="reviewer-r112", send_approver_id="approver-r112",
        approved_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=10))
    approval_values.update(approval_overrides)
    authorization = CampaignAuthorization(authorization_id="auth-r112", policy_decision_id="policy-r112",
        policy_revision="r112-v1", roe_revision="roe-r112", reservation_id="reservation-r112",
        delivery_lease_id="lease-r112", stop_switch_id="stop-r112", quota_id="quota-r112",
        campaign_sha256=digest, approved_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(minutes=10))
    return campaign, CampaignApproval(**approval_values), authorization


def test_campaign_compiles_to_exact_sink_only_plan():
    campaign, approval, authorization = _inputs()
    first = compile_campaign_plan(campaign=campaign, approval=approval, authorization=authorization, now=NOW)
    second = compile_campaign_plan(campaign=campaign, approval=approval, authorization=authorization, now=NOW)
    assert first == second and first.recipient == "simulation-recipient@redagent.invalid"
    assert first.human_delivery is False and first.external_delivery is False and first.max_deliveries == 1


def test_campaign_rejects_self_approval_digest_drift_and_expiry():
    with pytest.raises(ValueError, match="human_approval_separation_invalid"):
        _inputs(send_approver_id="reviewer-r112")
    campaign, approval, authorization = _inputs(campaign_sha256="c" * 64)
    with pytest.raises(ValueError, match="human_campaign_digest_mismatch"):
        compile_campaign_plan(campaign=campaign, approval=approval, authorization=authorization, now=NOW)
    campaign, approval, authorization = _inputs()
    with pytest.raises(ValueError, match="human_authorization_inactive"):
        compile_campaign_plan(campaign=campaign, approval=approval,
            authorization=CampaignAuthorization(**{**authorization.__dict__, "expires_at": NOW}), now=NOW)
