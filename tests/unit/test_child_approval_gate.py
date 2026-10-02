from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta

import pytest

from redagent_platform.campaign_service.application_contracts import ApplicationDependencyUnavailable, ApplicationPlanInvalid, AutonomousCampaignMode
from redagent_platform.campaign_service.child_lineage import ChildLineageConflict
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.approval_contracts import ApproveAutonomousCampaignPlanV1
from tests.unit.test_autonomous_campaign_plan_approval import ApprovalContextProvider, Repository, _service, _stage_command
from tests.unit.test_campaign_planning_contracts import NOW


def _scenario(verifier=None):
    stage, key = _stage_command()
    repo = Repository()
    asyncio.run(_service(repo, stage, key).stage_plan(stage))
    repo.preview = replace(repo.preview, execution_mode=AutonomousCampaignMode.BOUNDED_REPLAN, child_lineage_sha256="a" * 64)
    service = AutonomousCampaignApplicationService(repo, mode=AutonomousCampaignMode.BOUNDED_REPLAN,
        approval_context_provider=ApprovalContextProvider(stage), trusted_approval_keys={"key-a": key},
        child_lineage_verifier=verifier)
    preview = repo.preview
    command = ApproveAutonomousCampaignPlanV1(schema_version="redagent.autonomous-campaign-plan-approve/v1",
        tenant_id=preview.tenant_id, campaign_id=preview.campaign_id, preview_id=preview.preview_id,
        preview_sha256=preview.preview_sha256, actor_user_id="approver-a", actor_permissions=("campaign:approve",),
        policy_reference="policy:approval", expected_revision=preview.application_revision,
        idempotency_key="child-approval-a", correlation_id="child-approval-correlation", occurred_at=NOW + timedelta(seconds=4))
    return service, repo, command


def test_child_approval_requires_server_lineage_verifier_before_decision_write():
    service, repo, command = _scenario()
    with pytest.raises(ApplicationDependencyUnavailable, match="child_lineage_verifier"):
        asyncio.run(service.approve_plan(command))
    assert repo.decision_calls == 0


def test_child_approval_rechecks_current_lineage_and_denies_changed_parent():
    class Deny:
        calls = 0

        async def verify(self, **values):
            self.calls += 1
            assert values["preview"].child_lineage_sha256 is not None
            assert values["now"] == NOW + timedelta(seconds=4)
            raise ChildLineageConflict("parent_report_changed")

    verifier = Deny()
    service, repo, command = _scenario(verifier)
    with pytest.raises(ApplicationPlanInvalid, match="child_lineage_not_current"):
        asyncio.run(service.approve_plan(command))
    assert verifier.calls == 1
    assert repo.decision_calls == 0
