from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
import importlib

import pytest

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.application_repository import _json_payload
from tests.unit.test_child_preview_lineage import _preview
from tests.unit.test_campaign_planning_contracts import NOW


class Rows:
    def __init__(self, rows):
        self.rows = rows

    def mappings(self):
        return self

    def all(self):
        return self.rows


class Session:
    def __init__(self, rows):
        self.rows = rows

    async def execute(self, query):
        assert "FOR UPDATE" in str(query)
        return Rows(self.rows)


def _repository(verifier=None):
    child = replace(_preview(), execution_mode=AutonomousCampaignMode.BOUNDED_REPLAN, child_lineage_sha256="a" * 64)
    vector = CampaignBudgetVectorV1(duration_seconds=60, requests=20, rate_per_minute=60,
                                  concurrency=1, risk_micropoints=1, cost_microunits=1, evidence_bytes=1024, data_bytes=2048)
    parent = dict(_json_payload(vector), id="parent-reservation")
    cls = importlib.import_module("redagent_platform.campaign_service.child_admission").CanonicalChildAdmissionRepository
    return cls(Session([parent]), tenant_id="tenant-a", actor_user_id="operator-a", correlation_id="correlation-a",
               preview=child, verifier=verifier, now=NOW + timedelta(seconds=65)), vector


def test_child_admission_denies_missing_fresh_verifier_without_reading_charged_rows():
    repo, vector = _repository()
    with pytest.raises(RuntimeError, match="child_lineage_verifier"):
        asyncio.run(repo.residual_for_locked_ledger(dict(_json_payload(vector), id="ledger-a")))


def test_child_admission_rechecks_under_budget_lock_and_keeps_all_parent_cumulative_charges():
    class Verifier:
        calls = 0

        async def verify(self, **values):
            from redagent_platform.campaign_service.child_lineage import VerifiedChildLineageV1
            self.calls += 1
            assert values["session"] is not None
            preview = values["preview"]
            return VerifiedChildLineageV1("parent-reservation", "run-parent", 7, "b" * 64,
                preview.authority_sha256, preview.signed_authority_sha256, values["now"], NOW, NOW + timedelta(seconds=60))

    verifier = Verifier()
    repo, vector = _repository(verifier)
    authorized = vector.add(CampaignBudgetVectorV1(0, 0, 10, 60, 2, 2, 2048, 4096))
    residual = asyncio.run(repo.residual_for_locked_ledger(dict(_json_payload(authorized), id="ledger-a")))
    assert verifier.calls == 1
    assert residual == authorized.subtract(replace(vector, rate_per_minute=0, concurrency=0))
