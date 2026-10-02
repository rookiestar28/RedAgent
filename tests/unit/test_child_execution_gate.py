from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
import importlib

import pytest

from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from tests.unit.test_child_preview_lineage import _preview
from tests.unit.test_campaign_planning_contracts import NOW


def _invoke(preview, verifier=None):
    operation = importlib.import_module("redagent_platform.campaign_service.child_lineage").require_current_child_lineage
    return asyncio.run(operation(preview=preview, tenant_id=preview.tenant_id, campaign_id=preview.campaign_id,
        now=NOW + timedelta(seconds=4), verifier=verifier, session="caller-owned-session"))


def test_legacy_execution_needs_no_child_lineage_dependency():
    assert _invoke(_preview()) is None


def test_child_execution_denies_missing_current_source_verifier():
    child = replace(_preview(), execution_mode=AutonomousCampaignMode.BOUNDED_REPLAN, child_lineage_sha256="a" * 64)
    with pytest.raises(RuntimeError, match="child_lineage_verifier"):
        _invoke(child)


def test_child_execution_reverifies_in_caller_transaction_and_propagates_owner_denial():
    class Deny:
        calls = 0

        async def verify(self, **values):
            self.calls += 1
            assert values["session"] == "caller-owned-session"
            raise RuntimeError("parent_cleanup_changed")

    child = replace(_preview(), execution_mode=AutonomousCampaignMode.BOUNDED_REPLAN, child_lineage_sha256="a" * 64)
    verifier = Deny()
    with pytest.raises(RuntimeError, match="parent_cleanup_changed"):
        _invoke(child, verifier)
    assert verifier.calls == 1
