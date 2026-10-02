from __future__ import annotations

import asyncio
import importlib
from types import SimpleNamespace

import pytest

from redagent_platform.campaign_service.application_contracts import ApplicationModeDisabled, AutonomousCampaignMode
from tests.unit.test_canonical_child_preparation import _material
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.application_contracts import ApplicationDependencyUnavailable


@pytest.mark.parametrize("mode", [AutonomousCampaignMode.PLAN_ONLY, AutonomousCampaignMode.OWNED_LOOPBACK_AUTO,
                                  AutonomousCampaignMode.DISABLED, AutonomousCampaignMode.BOUNDED_REPLAN])
def test_child_service_requires_explicit_bounded_mode_before_transaction_or_provider_contact(mode):
    values = _material()

    class Store:
        calls = 0

        async def stage_child(self, command, **kwargs):
            self.calls += 1
            assert command is values["command"]
            assert kwargs["trusted_keys"] == values["trusted_keys"]
            return "staged-by-owner"

    class Provider:
        async def read_current_approval_context(self, **kwargs):
            raise AssertionError("Only the transaction owner may invoke the context provider")

    store = Store()
    service_type = getattr(importlib.import_module("redagent_platform.campaign_service.child_replan_service"),
                           "CanonicalChildReplanService", None)
    assert service_type is not None
    service = service_type(store, application_service=SimpleNamespace(mode=mode),
                           context_provider=Provider(), trusted_keys=values["trusted_keys"])
    if mode is AutonomousCampaignMode.BOUNDED_REPLAN:
        assert asyncio.run(service.prepare_child(values["command"])) == "staged-by-owner"
        assert store.calls == 1
    else:
        with pytest.raises(ApplicationModeDisabled):
            asyncio.run(service.prepare_child(values["command"]))
        assert store.calls == 0


def test_application_child_port_is_unavailable_without_explicit_current_dependencies():
    service = AutonomousCampaignApplicationService(object(), mode=AutonomousCampaignMode.BOUNDED_REPLAN)
    with pytest.raises(ApplicationDependencyUnavailable):
        asyncio.run(service.prepare_child(_material()["command"]))
