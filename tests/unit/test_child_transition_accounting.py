from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import timedelta
import importlib

import pytest

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.application_repository import _json_payload
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.child_replan_contracts import CHILD_LINEAGE_SCHEMA_VERSION, ChildReplanLineageV1
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from tests.unit.test_campaign_planning_contracts import NOW
from tests.unit.test_child_preview_lineage import _preview


def _material():
    preview = replace(_preview(), execution_mode=AutonomousCampaignMode.BOUNDED_REPLAN, child_lineage_sha256="a" * 64)
    parent = dict(id="parent-run", tenant_id=preview.tenant_id, campaign_id=preview.campaign_id,
                  version=7, run_state="contained", active_concurrency=0, reservation_id="parent-charge",
                  admission_receipt_sha256="c" * 64)
    run = dict(id="child-run", tenant_id=preview.tenant_id, campaign_id=preview.campaign_id,
               reservation_id="child-charge", admission_receipt_sha256="d" * 64)
    payload = dict(schema_version="redagent.canonical-child-capacity-settlement/v1",
        tenant_id=preview.tenant_id, application_id=preview.campaign_id,
        parent_execution_run_id=parent["id"], parent_run_version=7, parent_reservation_id="parent-charge",
        parent_admission_receipt_sha256="c" * 64, source_provenance_sha256="e" * 64,
        parent_effect_receipt_sha256="f" * 64, child_revision_sha256=preview.plan_revision_sha256,
        proposal_sha256="b" * 64, latest_effect_completed_at=NOW,
        capacity_available_at=NOW + timedelta(seconds=60), settled_at=NOW + timedelta(seconds=61))
    settlement = dict(_json_payload(payload), latest_effect_completed_at=NOW,
        capacity_available_at=NOW + timedelta(seconds=60), settlement_payload=_json_payload(payload),
        settlement_sha256=canonical_planning_sha256(payload))
    lineage = ChildReplanLineageV1(schema_version=CHILD_LINEAGE_SCHEMA_VERSION,
        parent_execution_run_id=parent["id"], parent_revision_sha256="9" * 64,
        parent_admission_receipt_sha256="c" * 64, observation_history_sha256="8" * 64,
        proposal_sha256="b" * 64, subset_proof_sha256="7" * 64,
        settlement_sha256=settlement["settlement_sha256"], child_revision_sha256=preview.plan_revision_sha256)
    preview = replace(preview, child_lineage_sha256=lineage.lineage_sha256)
    child = dict(tenant_id=preview.tenant_id, application_id=preview.campaign_id,
        parent_execution_run_id=parent["id"], parent_run_version=7, preview_id=preview.preview_id,
        preview_sha256=preview.preview_sha256, child_revision_sha256=preview.plan_revision_sha256,
        settlement_sha256=settlement["settlement_sha256"], proposal_sha256="b" * 64,
        created_at=NOW + timedelta(seconds=61), lineage_payload=_json_payload(lineage), lineage_sha256=lineage.lineage_sha256)
    return dict(run=run, preview=preview, child=child, settlement=settlement,
                parent_run=parent, now=NOW + timedelta(seconds=65))


def _verify(values):
    module = importlib.import_module("redagent_platform.campaign_service.child_admission")
    return module.verify_child_transition_settlement(**values)


def test_completed_parent_settlement_remains_bookkeeping_after_observation_expiry():
    values = _material()
    values["now"] = NOW + timedelta(seconds=200)
    verified = _verify(values)
    assert verified.parent_reservation_id == "parent-charge"
    assert verified.parent_completed_at == NOW


@pytest.mark.parametrize("kind", ["digest", "parent_version", "parent_state", "inflight", "cooldown", "scope", "preview", "admission"])
def test_transition_accounting_denies_changed_or_unsettled_parent_ownership(kind):
    values = _material()
    if kind == "digest":
        values["settlement"]["settlement_payload"]["source_provenance_sha256"] = "0" * 64
    elif kind == "parent_version":
        values["parent_run"]["version"] += 1
    elif kind == "parent_state":
        values["parent_run"]["run_state"] = "running"
    elif kind == "inflight":
        values["parent_run"]["active_concurrency"] = 1
    elif kind == "cooldown":
        values["now"] = NOW + timedelta(seconds=59)
    elif kind == "scope":
        values["run"]["tenant_id"] = "another-tenant"
    elif kind == "preview":
        values["child"]["preview_sha256"] = "0" * 64
    else:
        values["parent_run"]["admission_receipt_sha256"] = "0" * 64
    with pytest.raises(RuntimeError, match="child_transition"):
        _verify(values)


def test_lifecycle_projection_preserves_parent_and_child_cumulative_charges():
    values = _material()
    verified = _verify(values)
    module = importlib.import_module("redagent_platform.campaign_service.child_admission")
    vector = CampaignBudgetVectorV1(60, 20, 60, 1, 1, 1, 1024, 2048)
    authorized = vector.add(replace(vector, rate_per_minute=0, concurrency=0))
    parent = dict(_json_payload(vector), id="parent-charge")
    child = dict(_json_payload(vector), id="child-charge")
    with pytest.raises(ValueError, match="campaign_budget_underflow"):
        authorized.subtract(vector.add(vector))
    residual = module.child_transition_residual(authorized=authorized, rows=(parent, child),
        verified=verified, child_reservation_id="child-charge", now=values["now"])
    assert residual == CampaignBudgetVectorV1(0, 0, 0, 0, 0, 0, 0, 0)
    after_release = module.child_transition_residual(authorized=authorized, rows=(parent,),
        verified=verified, child_reservation_id="child-charge", now=values["now"])
    assert after_release == vector
    with pytest.raises(RuntimeError, match="child_transition"):
        module.child_transition_residual(authorized=authorized, rows=(parent,),
            verified=verified, child_reservation_id="parent-charge", now=values["now"])


def test_settlement_transition_cannot_mutate_a_different_reservation():
    from redagent_platform.campaign_service.admission_contracts import CampaignReservationState

    values = _material()
    module = importlib.import_module("redagent_platform.campaign_service.child_admission")
    repo = module._ChildSettlementTransitionRepository(None, run=values["run"], preview=values["preview"],
        actor_user_id="operator-a", correlation_id="transition-a", now=values["now"])
    with pytest.raises(RuntimeError, match="child_transition_reservation_binding"):
        asyncio.run(repo.transition_reservation(reservation_id="parent-charge", target=CampaignReservationState.RELEASED,
            effect_started=False, reconciliation_code="not_started", now=values["now"]))
    with pytest.raises(RuntimeError, match="child_transition_new_admission_forbidden"):
        asyncio.run(repo.admit(None))
    with pytest.raises(RuntimeError, match="child_transition_new_reservation_forbidden"):
        asyncio.run(repo.create_reservation(ledger={}, campaign_id="another-campaign", plan_sha256="a" * 64,
            request_sha256="b" * 64, idempotency_key="new-reservation", budget=CampaignBudgetVectorV1(0, 0, 0, 0, 0, 0, 0, 0),
            lease_expires_at=values["now"], occurred_at=values["now"]))


def test_non_child_transition_selector_keeps_generic_owner():
    from redagent_platform.campaign_service.admission_repository import CampaignAdmissionRepository

    class Result:
        def mappings(self):
            return self

        def one_or_none(self):
            return None

    class Session:
        async def execute(self, query):
            return Result()

    module = importlib.import_module("redagent_platform.campaign_service.child_admission")
    repo = asyncio.run(module.transition_repository_for_run(Session(), run=_material()["run"],
        actor_user_id="operator-a", correlation_id="transition-a", now=NOW))
    assert type(repo) is CampaignAdmissionRepository
