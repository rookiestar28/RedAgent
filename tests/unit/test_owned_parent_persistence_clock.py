from dataclasses import replace

import pytest

from redagent_platform.campaign_service import replanning_repository as repository
from tests.unit.test_canonical_child_preparation import _material, _prepare


def _inputs():
    values = _material()
    return values, _prepare(values).proposal


def test_generic_proposal_persistence_uses_current_time_without_completion_source():
    values, proposal = _inputs()
    assert repository._proposal_parent_admission_at(
        tenant_id=values["command"].tenant_id, proposal=proposal,
        occurred_at=values["command"].occurred_at, source=None,
    ) == values["command"].occurred_at


def test_owned_proposal_persistence_uses_verified_actual_completion_time():
    values, proposal = _inputs()
    source = values["parent"].source
    assert repository._proposal_parent_admission_at(
        tenant_id=values["command"].tenant_id, proposal=proposal,
        occurred_at=values["command"].occurred_at, source=source,
    ) == source.effect_receipt.completed_at


@pytest.mark.parametrize("kind", ["unsealed", "scope", "plan", "revision", "authority", "epochs", "future"])
def test_owned_proposal_persistence_rejects_mismatched_completion_source(kind):
    values, proposal = _inputs()
    source = values["parent"].source
    tenant_id = values["command"].tenant_id
    occurred_at = values["command"].occurred_at
    if kind == "unsealed":
        source = object()
    elif kind == "scope":
        tenant_id = "another-tenant"
    elif kind == "plan":
        proposal = replace(proposal, parent_plan_sha256="a" * 64)
    elif kind == "revision":
        proposal = replace(proposal, parent_revision_sha256="a" * 64)
    elif kind == "authority":
        proposal = replace(proposal, parent_authority_sha256="a" * 64)
    elif kind == "epochs":
        proposal = replace(proposal, lifecycle_epoch=proposal.lifecycle_epoch + 1)
    else:
        occurred_at = source.effect_receipt.started_at
    with pytest.raises(repository.ReplanningPersistenceConflict, match="historical_parent_source_mismatch"):
        repository._proposal_parent_admission_at(
            tenant_id=tenant_id, proposal=proposal, occurred_at=occurred_at, source=source,
        )
