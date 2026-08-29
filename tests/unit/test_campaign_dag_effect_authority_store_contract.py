from __future__ import annotations

import ast
from pathlib import Path

import pytest

from redagent_platform.campaign_service.dag_effect_authority_store import (
    PostgresDagEffectAuthorityStateOwner,
)


ROOT = Path(__file__).resolve().parents[2]


def test_authority_state_owner_requires_bounded_identity() -> None:
    with pytest.raises(ValueError, match="dag_authority_store_actor_invalid"):
        PostgresDagEffectAuthorityStateOwner(object(), actor_user_id="", correlation_prefix="dag")
    with pytest.raises(ValueError, match="dag_authority_store_correlation_invalid"):
        PostgresDagEffectAuthorityStateOwner(object(), actor_user_id="actor-a", correlation_prefix="")


def test_authority_state_owner_is_the_only_pre_io_fact_writer() -> None:
    source_path = ROOT / "redagent_platform/campaign_service/dag_effect_authority_store.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imports = {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "campaign_execution_authority_observations" in source
    assert "pre_io_policy_decision_id" in source
    assert "pre_io_policy_input_sha256" in source
    assert "pre_io_policy_valid_until" in source
    assert "pre_io_authorized_at" in source
    assert "CampaignReservationState.HELD" in source
    assert source.count(".with_for_update()") >= 4
    assert not {
        item for item in imports if any(part in item for part in ("runner_service", "zap_service", "nuclei_service"))
    }
