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
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1


def test_auto_is_explicit_and_server_binds_new_intent_mode() -> None:
    assert load_autonomous_campaign_mode({}) is AutonomousCampaignMode.PLAN_ONLY
    auto = load_autonomous_campaign_mode({"REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "owned_loopback_auto"})

    class IntentRepository:
        async def create_intent(self, command):
            return command

    service = AutonomousCampaignApplicationService(IntentRepository(), mode=auto)
    persisted = asyncio.run(service.create_intent(_create()))
    assert persisted.mode is auto
    # Client material cannot override the current server mode.
    service = AutonomousCampaignApplicationService(IntentRepository())
    persisted = asyncio.run(service.create_intent(replace(_create(), mode=auto)))
    assert persisted.mode is AutonomousCampaignMode.PLAN_ONLY


def test_exact_preview_digest_distinguishes_execution_authority() -> None:
    command, key = _stage_command()
    repository = Repository()
    service = _service(repository, command, key)
    context = ApprovalContextProvider(command).context
    plan_only = service._build_preview(command, _state(), context)
    auto = load_autonomous_campaign_mode({"REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "owned_loopback_auto"})
    context = replace(context, execution_bindings=(_full_binding(command.domain.operators[0].capability),))
    executable = service._build_preview(command, replace(_state(), mode=auto), context)
    assert executable.execution_mode is auto
    assert executable.preview_sha256 != plan_only.preview_sha256
    with pytest.raises(ApplicationPlanInvalid, match="bindings_missing"):
        service._build_preview(command, replace(_state(), mode=auto), replace(context, execution_bindings=()))


def _full_binding(capability):
    from dataclasses import asdict

    return CapabilityBindingKeyV1(
        schema_version="redagent.r119-capability-binding/v1", **asdict(capability),
        semantics_revision=1, semantics_sha256="3" * 64,
        normalized_output_sha256="4" * 64, projection_revision=1, projection_sha256="5" * 64,
    )
