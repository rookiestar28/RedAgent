from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.application_repository import _json_payload
from redagent_platform.campaign_service.operations import CampaignOperationsSource, _budget
from tests.unit.test_child_transition_accounting import _material


def _source(values):
    charge = CampaignBudgetVectorV1(60, 20, 60, 1, 1, 1, 1024, 2048)
    authorized = charge.add(replace(charge, rate_per_minute=0, concurrency=0))
    return CampaignOperationsSource(campaign={"id": values["preview"].campaign_id}, execution=values["run"],
        ledger=_json_payload(authorized), reservations=(
            dict(_json_payload(charge), id="parent-charge", reservation_state="held"),
            dict(_json_payload(charge), id="child-charge", reservation_state="consumed")))


def test_operator_projects_settled_parent_peaks_once_and_preserves_all_cumulative_work():
    from redagent_platform.campaign_service.operator_repository import _settled_operator_reservations

    values = _material()
    source = _source(values)
    with pytest.raises(RuntimeError, match="operations_budget_rate_per_minute_overcommitted"):
        _budget(source)
    projected = _settled_operator_reservations(source, **values)
    assert projected[0]["rate_per_minute"] == projected[0]["concurrency"] == 0
    assert source.reservations[0]["rate_per_minute"] == 60
    for field in ("duration_seconds", "requests", "risk_micropoints", "cost_microunits", "evidence_bytes", "data_bytes"):
        assert projected[0][field] == source.reservations[0][field]
    dimensions = _budget(replace(source, reservations=projected))["dimensions"]
    assert all(item["residual"] == 0 for item in dimensions.values())
    values["now"] += timedelta(seconds=200)
    assert _settled_operator_reservations(source, **values) == projected


@pytest.mark.parametrize("kind", ["digest", "parent_version", "inflight", "cooldown", "scope", "missing_charge"])
def test_operator_peak_projection_rejects_invalid_or_missing_native_settlement(kind):
    from redagent_platform.campaign_service.operator_repository import _settled_operator_reservations

    values = _material()
    source = _source(values)
    if kind == "digest":
        values["settlement"]["settlement_sha256"] = "0" * 64
    elif kind == "parent_version":
        values["parent_run"]["version"] += 1
    elif kind == "inflight":
        values["parent_run"]["active_concurrency"] = 1
    elif kind == "cooldown":
        values["now"] -= timedelta(seconds=10)
    elif kind == "scope":
        values["run"]["tenant_id"] = "foreign-tenant"
    else:
        source = replace(source, reservations=source.reservations[1:])
    with pytest.raises(RuntimeError):
        _settled_operator_reservations(source, **values)
