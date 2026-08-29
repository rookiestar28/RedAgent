from __future__ import annotations

import ast
from pathlib import Path

import pytest

from redagent_platform.campaign_service.dag_execution_store import (
    CampaignDagExecutionRepository,
    PostgresDagExecutionStartStore,
)


ROOT = Path(__file__).resolve().parents[2]


def test_store_requires_bounded_owner_identity() -> None:
    with pytest.raises(ValueError, match="dag_store_actor_invalid"):
        PostgresDagExecutionStartStore(object(), actor_user_id="", correlation_prefix="dag")
    with pytest.raises(ValueError, match="dag_store_correlation_invalid"):
        PostgresDagExecutionStartStore(object(), actor_user_id="actor-a", correlation_prefix="")


def test_store_source_owns_atomic_admission_recheck_and_outbox_without_execution_imports() -> None:
    source_path = ROOT / "redagent_platform/campaign_service/dag_execution_store.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported = {
        node.module or ""
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
    }
    assert "plan_admission_receipts" in source
    assert "campaign_budget_reservations" in source
    assert "campaign.dag.start.requested.v1" in source
    assert "pg_advisory_xact_lock" in source
    assert ".with_for_update()" in source
    assert not {
        item
        for item in imported
        if any(part in item for part in ("temporal", "runner_service", "zap_service", "nuclei_service"))
    }
    assert CampaignDagExecutionRepository.__name__ == "CampaignDagExecutionRepository"
