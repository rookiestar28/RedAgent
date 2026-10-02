from __future__ import annotations

from datetime import timedelta
import importlib

import pytest

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from tests.unit.test_campaign_planning_contracts import NOW


def _project(**overrides):
    try:
        module = importlib.import_module("redagent_platform.campaign_service.child_replan_contracts")
    except ModuleNotFoundError:
        pytest.fail("Canonical child peak-capacity settlement is not implemented")
    values = dict(
        authorized=CampaignBudgetVectorV1(180, 60, 60, 1, 30, 300, 14 * 1024 * 1024, 60 * 1024 * 1024),
        parent_charge=CampaignBudgetVectorV1(120, 40, 60, 1, 20, 200, 12 * 1024 * 1024, 40 * 1024 * 1024),
        other_charges=(),
        parent_completed_at=NOW,
        capacity_available_at=NOW + timedelta(seconds=60),
        now=NOW + timedelta(seconds=60),
    )
    values.update(overrides)
    return module.project_sequential_child_residual(**values)


def test_only_peak_dimensions_reopen_after_terminal_settlement():
    residual = _project()
    assert residual == CampaignBudgetVectorV1(60, 20, 60, 1, 10, 100, 2 * 1024 * 1024, 20 * 1024 * 1024)


def test_full_parent_charge_cannot_be_refunded_when_child_has_no_cumulative_room():
    with pytest.raises(ValueError, match="underflow"):
        _project(authorized=CampaignBudgetVectorV1(119, 60, 60, 1, 30, 300, 14 * 1024 * 1024, 60 * 1024 * 1024))


@pytest.mark.parametrize("changes", [
    {"now": NOW + timedelta(seconds=59, microseconds=999999)},
    {"capacity_available_at": NOW + timedelta(seconds=59)},
    {"parent_completed_at": NOW + timedelta(seconds=61)},
    {"now": NOW.replace(tzinfo=None)},
])
def test_future_invalid_or_unelapsed_capacity_proof_denies(changes):
    with pytest.raises(ValueError, match="capacity"):
        _project(**changes)


def test_other_outstanding_capacity_still_blocks_a_child():
    other = CampaignBudgetVectorV1(0, 0, 60, 1, 0, 0, 0, 0)
    residual = _project(other_charges=(other,))
    assert residual.rate_per_minute == 0 and residual.concurrency == 0
    assert not CampaignBudgetVectorV1(60, 20, 60, 1, 10, 100, 2 * 1024 * 1024, 20 * 1024 * 1024).fits_within(residual)


def test_generic_vector_arithmetic_keeps_charging_peak_dimensions():
    full = CampaignBudgetVectorV1(180, 60, 60, 1, 30, 300, 14 * 1024 * 1024, 60 * 1024 * 1024)
    parent = CampaignBudgetVectorV1(120, 40, 60, 1, 20, 200, 12 * 1024 * 1024, 40 * 1024 * 1024)
    unchanged = full.subtract(parent)
    assert unchanged.rate_per_minute == unchanged.concurrency == 0
