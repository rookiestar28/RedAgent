from __future__ import annotations

import asyncio
from dataclasses import asdict, replace

import pytest

from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.application_repository import _json_payload, _verified_preview_from_payload
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from tests.unit.test_autonomous_campaign_plan_approval import Repository, _service, _stage_command


def _preview():
    command, key = _stage_command()
    return asyncio.run(_service(Repository(), command, key).stage_plan(command)).preview


def test_optional_child_lineage_preserves_legacy_preview_digest_and_binds_fresh_approval():
    legacy = _preview()
    payload = asdict(legacy)
    payload.pop("execution_mode")
    payload.pop("execution_bindings")
    payload.pop("child_lineage_sha256", None)
    assert legacy.preview_sha256 == canonical_planning_sha256(payload)
    bounded = replace(legacy, execution_mode=AutonomousCampaignMode.BOUNDED_REPLAN)
    child = replace(bounded, child_lineage_sha256="a" * 64)
    assert child.preview_sha256 != bounded.preview_sha256
    assert _verified_preview_from_payload(_json_payload(child), child.preview_sha256) == child
    from redagent_platform.campaign_service.approval_api import AutonomousCampaignPlanPreviewData, _preview_payload
    assert AutonomousCampaignPlanPreviewData.model_validate(_preview_payload(child)).child_lineage_sha256 == child.child_lineage_sha256
    assert replace(child, child_lineage_sha256="b" * 64).preview_sha256 != child.preview_sha256


@pytest.mark.parametrize("value", ["not-a-digest", "", 1, False])
def test_child_preview_rejects_invalid_lineage(value):
    with pytest.raises(ValueError, match="lineage"):
        replace(_preview(), execution_mode=AutonomousCampaignMode.BOUNDED_REPLAN, child_lineage_sha256=value)


@pytest.mark.parametrize("mode", [AutonomousCampaignMode.PLAN_ONLY, AutonomousCampaignMode.OWNED_LOOPBACK_AUTO])
def test_child_lineage_cannot_be_attached_to_other_execution_modes(mode):
    with pytest.raises(ValueError, match="lineage"):
        replace(_preview(), execution_mode=mode, child_lineage_sha256="a" * 64)
