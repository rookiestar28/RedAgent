from __future__ import annotations

import pytest

from redagent_platform.campaign_service.admission_start_store import (
    PostgresAutonomousCampaignAdmissionStartStore,
    deterministic_autonomous_execution_id,
)


def test_execution_identity_is_stable_and_tenant_partitioned() -> None:
    first = deterministic_autonomous_execution_id(
        "tenant-a", "campaign-a", "approval-a"
    )
    assert first == deterministic_autonomous_execution_id(
        "tenant-a", "campaign-a", "approval-a"
    )
    assert first != deterministic_autonomous_execution_id(
        "tenant-b", "campaign-a", "approval-a"
    )
    assert first.startswith("autonomous-execution-")


@pytest.mark.parametrize(
    "value",
    ("", " space", "../escape"),
)
def test_execution_identity_rejects_unclosed_identifiers(value: str) -> None:
    with pytest.raises(ValueError, match="autonomous_execution_identity_invalid"):
        deterministic_autonomous_execution_id(value, "campaign-a", "approval-a")


def test_store_exposes_the_full_r158_transaction_adapter() -> None:
    for method in ("replay", "preview_residual", "admit", "deny"):
        assert callable(getattr(PostgresAutonomousCampaignAdmissionStartStore, method, None))
