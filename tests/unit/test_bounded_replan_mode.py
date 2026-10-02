from __future__ import annotations

import asyncio
from dataclasses import replace

import pytest

from redagent_platform.campaign_service.application_contracts import (
    ApplicationPlanInvalid,
    AutonomousCampaignMode,
    load_autonomous_campaign_mode,
)
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from tests.unit.test_autonomous_campaign_application_contracts import _create
from tests.unit.test_autonomous_campaign_plan_approval import (
    ApprovalContextProvider,
    Repository,
    _service,
    _stage_command,
    _state,
)
from tests.unit.test_owned_execution_mode import _full_binding


def _mode():
    return load_autonomous_campaign_mode({"REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "bounded_replan"})


def test_bounded_replan_is_explicit_server_owned_intent_mode():
    assert load_autonomous_campaign_mode({}) is AutonomousCampaignMode.PLAN_ONLY
    bounded = _mode()
    assert bounded.value == "bounded_replan"

    class IntentRepository:
        async def create_intent(self, command):
            return command

    explicit = AutonomousCampaignApplicationService(IntentRepository(), mode=bounded)
    assert asyncio.run(explicit.create_intent(_create())).mode is bounded
    default = AutonomousCampaignApplicationService(IntentRepository())
    assert asyncio.run(default.create_intent(replace(_create(), mode=bounded))).mode is AutonomousCampaignMode.PLAN_ONLY


def test_bounded_preview_requires_full_current_execution_bindings():
    command, key = _stage_command()
    service = _service(Repository(), command, key)
    context = ApprovalContextProvider(command).context
    with pytest.raises(ApplicationPlanInvalid, match="bindings_missing"):
        service._build_preview(command, replace(_state(), mode=_mode()), context)


def test_bounded_preview_does_not_share_parent_auto_approval_digest():
    command, key = _stage_command()
    service = _service(Repository(), command, key)
    context = replace(ApprovalContextProvider(command).context,
                      execution_bindings=(_full_binding(command.domain.operators[0].capability),))
    auto = service._build_preview(command, replace(_state(), mode=AutonomousCampaignMode.OWNED_LOOPBACK_AUTO), context)
    bounded = service._build_preview(command, replace(_state(), mode=_mode()), context)
    assert bounded.execution_bindings == auto.execution_bindings
    assert bounded.preview_sha256 != auto.preview_sha256
