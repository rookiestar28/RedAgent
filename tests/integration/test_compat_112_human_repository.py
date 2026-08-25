from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.human_simulation.catalog import certified_campaign
from redagent_platform.human_simulation.compiler import compile_campaign_plan
from redagent_platform.human_simulation.contracts import CampaignApproval, CampaignAuthorization, campaign_sha256
from redagent_platform.human_simulation.provisioning import register_human_simulation_capability
from redagent_platform.human_simulation.repository import HumanSimulationRepository
from redagent_platform.persistence.database import load_database_settings


ROOT = Path(__file__).resolve().parents[2]


def test_r112_repository_persists_exact_approval_run_stop_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    now = datetime(2026, 7, 12, tzinfo=timezone.utc); tenant = f"tenant-r112-{uuid4().hex[:8]}"
    campaign = certified_campaign(); digest = campaign_sha256(campaign)
    approval = CampaignApproval(approval_id="approval-r112", campaign_id=campaign.campaign_id, campaign_sha256=digest,
        rendered_sha256="a" * 64, test_delivery_sha256="b" * 64, requester_id="requester-r112",
        preview_reviewer_id="reviewer-r112", send_approver_id="approver-r112",
        approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    authorization = CampaignAuthorization(authorization_id="auth-r112", policy_decision_id="policy-r112",
        policy_revision="r112-v1", roe_revision="roe-r112", reservation_id="reservation-r112",
        delivery_lease_id="lease-r112", stop_switch_id="stop-r112", quota_id="quota-r112", campaign_sha256=digest,
        approved_at=now - timedelta(minutes=1), expires_at=now + timedelta(minutes=10))
    compiled = compile_campaign_plan(campaign=campaign, approval=approval, authorization=authorization, now=now)
    settings = load_database_settings(ROOT, env=os.environ); engine = create_async_engine(settings.url); factory = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with factory.begin() as session:
            registered = await register_human_simulation_capability(session, workspace=ROOT, tenant_id=tenant,
                actor_user_id="operator-r112", correlation_id="corr-r112-capability", occurred_at=now)
            assert registered["capability_id"] == "human-simulation-sink"
            repository = HumanSimulationRepository(session, tenant_id=tenant, actor_user_id="operator-r112", correlation_id="corr-r112")
            foundation = await repository.certify_foundation(occurred_at=now); assert foundation["campaign"]["human_delivery"] is False
            await repository.store_approval(approval=approval, occurred_at=now)
            await repository.store_plan(plan_id="plan-r112", compiled=compiled, approval=approval, authorization=authorization, occurred_at=now)
            run = await repository.create_run(run_id="run-r112", plan_id="plan-r112", job_id="job-r112", runner_id="runner-r112", occurred_at=now)
            stopped = await repository.request_stop(run_id="run-r112", expected_version=run["version"], occurred_at=now)
            assert stopped["new_delivery_blocked"] is True and stopped["human_delivery_count"] == 0
            dashboard = await repository.dashboard(); assert len(dashboard["campaigns"]) == 1 and len(dashboard["runs"]) == 1
            assert len(dashboard["approval_options"]) == 1
            assert dashboard["approval_options"][0]["approval_state"] == "send-approved-exact"
            assert dashboard["runner_options"] == [] and dashboard["job_options"] == [] and dashboard["reservation_options"] == []
        async with factory.begin() as session:
            other = await HumanSimulationRepository(session, tenant_id=f"other-{tenant}", actor_user_id="operator-r112", correlation_id="corr-r112-other").dashboard()
            assert all(not rows for rows in other.values())
    finally:
        await engine.dispose()
