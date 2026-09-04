from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone

import pytest

from redagent_platform.campaign_service.application_contracts import (
    APPLICATION_CONTRACT_VERSION,
    ApplicationTransitionConflict,
    AutonomousCampaignLifecycle,
    AutonomousCampaignMode,
    CreateAutonomousCampaignIntentV1,
    RevokeAutonomousCampaignIntentV1,
    assert_lifecycle_transition,
    load_autonomous_campaign_mode,
)


NOW = datetime(2026, 9, 4, 12, 0, tzinfo=timezone.utc)
DIGEST = "a" * 64


def _create(**changes: object) -> CreateAutonomousCampaignIntentV1:
    values: dict[str, object] = {
        "schema_version": APPLICATION_CONTRACT_VERSION,
        "tenant_id": "tenant-r171",
        "campaign_id": "campaign-r171",
        "engagement_id": "engagement-r171",
        "target_id": "target-r171",
        "actor_user_id": "user-r171",
        "intent_sha256": DIGEST,
        "source_binding_sha256": "b" * 64,
        "expected_revision": 0,
        "idempotency_key": "create-r171",
        "correlation_id": "correlation-r171",
        "occurred_at": NOW,
    }
    values.update(changes)
    return CreateAutonomousCampaignIntentV1(**values)


def test_r171_contract_is_versioned_plan_only_and_closed() -> None:
    command = _create()
    assert command.schema_version == "redagent.autonomous-campaign-application/v1"
    assert load_autonomous_campaign_mode({}) is AutonomousCampaignMode.PLAN_ONLY
    assert load_autonomous_campaign_mode({"REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "disabled"}) is (
        AutonomousCampaignMode.DISABLED
    )
    with pytest.raises(ValueError, match="autonomous_campaign_mode_invalid"):
        load_autonomous_campaign_mode({"REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "owned_loopback_auto"})


@pytest.mark.parametrize(
    ("changes", "message"),
    (
        ({"schema_version": "redagent.autonomous-campaign-application/v2"}, "schema_version_unsupported"),
        ({"intent_sha256": "not-a-digest"}, "intent_sha256_invalid"),
        ({"expected_revision": 1}, "create_expected_revision_invalid"),
        ({"expected_revision": 0.0}, "create_expected_revision_invalid"),
        ({"occurred_at": datetime(2026, 9, 4)}, "occurred_at_timezone_required"),
    ),
)
def test_create_intent_rejects_unknown_or_untrusted_material(changes: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        _create(**changes)


def test_lifecycle_graph_is_closed_and_revoke_is_safety_preserving() -> None:
    assert_lifecycle_transition(
        AutonomousCampaignLifecycle.INTENT_CREATED,
        AutonomousCampaignLifecycle.REVOKED,
    )
    assert_lifecycle_transition(
        AutonomousCampaignLifecycle.PLAN_VALIDATED,
        AutonomousCampaignLifecycle.AWAITING_APPROVAL,
    )
    with pytest.raises(ApplicationTransitionConflict, match="lifecycle_transition_denied"):
        assert_lifecycle_transition(
            AutonomousCampaignLifecycle.INTENT_CREATED,
            AutonomousCampaignLifecycle.RUNNING,
        )
    with pytest.raises(ApplicationTransitionConflict, match="lifecycle_transition_denied"):
        assert_lifecycle_transition(
            AutonomousCampaignLifecycle.REVOKED,
            AutonomousCampaignLifecycle.INTENT_CREATED,
        )


def test_revoke_requires_current_predecessor_revision_and_digest_reason() -> None:
    command = RevokeAutonomousCampaignIntentV1(
        schema_version=APPLICATION_CONTRACT_VERSION,
        tenant_id="tenant-r171",
        campaign_id="campaign-r171",
        actor_user_id="user-r171",
        reason_sha256="c" * 64,
        expected_revision=1,
        idempotency_key="revoke-r171",
        correlation_id="correlation-r171",
        occurred_at=NOW,
    )
    with pytest.raises(ValueError, match="expected_revision_invalid"):
        replace(command, expected_revision=0)
    with pytest.raises(ValueError, match="expected_revision_invalid"):
        replace(command, expected_revision=1.0)
    with pytest.raises(ValueError, match="reason_sha256_invalid"):
        replace(command, reason_sha256="reason text")
