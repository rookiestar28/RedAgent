from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import pytest

from redagent_platform.campaign_service.service import (
    IdempotencyConflict,
    CampaignCoreAuthorizedResource,
    CampaignCoreService,
    CampaignCoreCreateDisabled,
    CampaignCoreEtagConflict,
)


NOW = datetime(2026, 8, 24, 12, 0, tzinfo=timezone.utc)


class Options:
    def __init__(self) -> None:
        self.engagements = (
            CampaignCoreAuthorizedResource(
                resource_id="engagement-internal-1",
                label="Owned loopback engagement",
                revision="7",
                freshness="current",
                eligible=True,
                unavailable_reason=None,
            ),
            CampaignCoreAuthorizedResource(
                resource_id="engagement-internal-stale",
                label="Expired engagement",
                revision="2",
                freshness="stale",
                eligible=False,
                unavailable_reason="roe_expired",
            ),
        )
        self.targets = (
            CampaignCoreAuthorizedResource(
                resource_id="target-internal-1",
                label="Owned HTTP fixture",
                revision="11",
                freshness="current",
                eligible=True,
                unavailable_reason=None,
                parent_id="engagement-internal-1",
            ),
            CampaignCoreAuthorizedResource(
                resource_id="artifact-binding-internal-1",
                label="Repository snapshot: canonical data-only binding",
                revision="1:11",
                freshness="current",
                eligible=True,
                unavailable_reason=None,
                parent_id="engagement-internal-1",
                target_class="repository-snapshot",
            ),
        )

    async def list_engagements(self, **_values):
        return self.engagements

    async def list_targets(self, **_values):
        return self.targets


class Starter:
    def __init__(self) -> None:
        self.calls = []
        self.replay_calls = []
        self.replay_result = None

    async def replay(self, **values):
        self.replay_calls.append(values)
        return self.replay_result

    async def start(self, request, **values):
        self.calls.append((request, values))
        return type("Receipt", (), {
            "campaign_id": "campaign-server-generated",
            "aggregate_sequence": 1,
        })()


class Presentation:
    def __init__(self) -> None:
        self.calls = []

    async def list_campaigns(self, **values):
        self.calls.append(("list", values))
        return {"data": [], "page": {"limit": values["limit"], "next_cursor": None}}

    async def read_campaign(self, **values):
        self.calls.append(("read", values))
        return {"data": {
            "campaign_id": values["campaign_id"],
            "aggregate_sequence": 4,
            "status": "workflow_started",
        }}

    async def inspect_campaign(self, **values):
        self.calls.append(("inspect", values))
        return {"data": {"campaign_id": values["campaign_id"], "plan_sha256": "a" * 64}}

    async def list_attention(self, **values):
        self.calls.append(("attention", values))
        return {"data": [], "page": {"limit": values["limit"], "next_cursor": None}}


class Recovery:
    def __init__(self) -> None:
        self.calls = []

    async def recover(self, **values):
        self.calls.append(values)
        if values["expected_revision"] != 4:
            raise CampaignCoreEtagConflict("r124_etag_conflict")
        return type("Commit", (), {
            "state": "manual_review_required",
            "revision": values["expected_revision"] + 1,
            "replayed": False,
        })()


def test_option_bindings_are_stable_non_identifying_and_ineligibility_is_visible() -> None:
    service = CampaignCoreService(Options(), Starter())

    first = asyncio.run(service.list_engagement_options(
        tenant_id="tenant-r124", principal_id="operator-r124", limit=50,
        cursor=None, now=NOW,
    ))
    second = asyncio.run(service.list_engagement_options(
        tenant_id="tenant-r124", principal_id="operator-r124", limit=50,
        cursor=None, now=NOW,
    ))

    assert first == second
    assert first["page"] == {"limit": 50, "next_cursor": None}
    assert len(first["data"]) == 2
    assert first["data"][0]["binding"].startswith("r124-engagement-")
    assert "engagement-internal" not in str(first)
    assert first["data"][1]["eligible"] is False
    assert first["data"][1]["unavailable_reason"] == "roe_expired"


def test_start_resolves_bindings_server_side_and_preserves_transport_idempotency() -> None:
    starter = Starter()
    service = CampaignCoreService(Options(), starter)
    engagements = asyncio.run(service.list_engagement_options(
        tenant_id="tenant-r124", principal_id="operator-r124", limit=50,
        cursor=None, now=NOW,
    ))
    engagement = engagements["data"][0]["binding"]
    targets = asyncio.run(service.list_target_options(
        tenant_id="tenant-r124", principal_id="operator-r124",
        engagement_binding=engagement, limit=50, cursor=None, now=NOW,
    ))
    target = targets["data"][0]["binding"]
    risks = asyncio.run(service.list_risk_profile_options(
        tenant_id="tenant-r124", principal_id="operator-r124",
        engagement_binding=engagement, target_binding=target,
        limit=50, cursor=None, now=NOW,
    ))
    risk = risks["data"][0]["binding"]

    result = asyncio.run(service.start_campaign(
        type("Intent", (), {
            "engagement_binding": engagement,
            "target_binding": target,
            "objective": "Assess HTTP security posture",
            "risk_profile": risk,
        })(),
        tenant_id="tenant-r124",
        principal_id="operator-r124",
        idempotency_key="transport-generated-key",
        now=NOW,
    ))

    request, values = starter.calls[0]
    assert request.tenant_id == "tenant-r124"
    assert request.principal_id == "operator-r124"
    assert request.engagement_id == "engagement-internal-1"
    assert request.target_id == "target-internal-1"
    assert request.objective_kind == "http_posture"
    assert values["now"] == NOW
    assert values["idempotency_key"] == "transport-generated-key"
    assert len(values["request_sha256"]) == 64
    assert result["data"] == {
        "campaign_id": "campaign-server-generated",
        "status": "dispatch_pending",
        "aggregate_sequence": 1,
        "etag": '"campaign-server-generated:1"',
        "replayed": False,
    }


def test_repository_objective_accepts_only_opaque_repository_snapshot_target() -> None:
    starter = Starter()
    service = CampaignCoreService(Options(), starter)
    engagement = asyncio.run(service.list_engagement_options(
        tenant_id="tenant-r124", principal_id="operator-r124", limit=50,
        cursor=None, now=NOW,
    ))["data"][0]["binding"]
    targets = asyncio.run(service.list_target_options(
        tenant_id="tenant-r124", principal_id="operator-r124",
        engagement_binding=engagement, limit=50, cursor=None, now=NOW,
    ))
    http_target, artifact_target = (item["binding"] for item in targets["data"])
    risk = asyncio.run(service.list_risk_profile_options(
        tenant_id="tenant-r124", principal_id="operator-r124",
        engagement_binding=engagement, target_binding=artifact_target,
        limit=50, cursor=None, now=NOW,
    ))["data"][0]["binding"]

    intent = type("Intent", (), {
        "engagement_binding": engagement,
        "target_binding": artifact_target,
        "objective": "Assess repository snapshot posture",
        "risk_profile": risk,
    })()
    asyncio.run(service.start_campaign(
        intent,
        tenant_id="tenant-r124",
        principal_id="operator-r124",
        idempotency_key="artifact-campaign-key",
        now=NOW,
    ))

    request = starter.calls[0][0]
    assert request.target_id == "artifact-binding-internal-1"
    assert request.objective_kind == "repository_snapshot_posture"
    assert not hasattr(request, "artifact_receipt")
    intent.target_binding = http_target
    with pytest.raises(ValueError, match="objective_target_class_mismatch"):
        asyncio.run(service.start_campaign(
            intent,
            tenant_id="tenant-r124",
            principal_id="operator-r124",
            idempotency_key="artifact-campaign-wrong-target",
            now=NOW,
        ))


def test_stale_forged_wrong_parent_and_arbitrary_objective_fail_before_start() -> None:
    starter = Starter()
    service = CampaignCoreService(Options(), starter)
    engagements = asyncio.run(service.list_engagement_options(
        tenant_id="tenant-r124", principal_id="operator-r124", limit=50,
        cursor=None, now=NOW,
    ))
    current = engagements["data"][0]["binding"]
    stale = engagements["data"][1]["binding"]
    targets = asyncio.run(service.list_target_options(
        tenant_id="tenant-r124", principal_id="operator-r124",
        engagement_binding=current, limit=50, cursor=None, now=NOW,
    ))
    target = targets["data"][0]["binding"]
    risks = asyncio.run(service.list_risk_profile_options(
        tenant_id="tenant-r124", principal_id="operator-r124",
        engagement_binding=current, target_binding=target,
        limit=50, cursor=None, now=NOW,
    ))
    risk = risks["data"][0]["binding"]

    for engagement, target_binding, objective, error in (
        ("r124-engagement-forged", target, "Assess HTTP security posture", "engagement_binding_invalid"),
        (stale, target, "Assess HTTP security posture", "engagement_binding_ineligible"),
        (current, "r124-target-forged", "Assess HTTP security posture", "target_binding_invalid"),
        (current, target, "Run arbitrary command", "objective_unsupported"),
    ):
        with pytest.raises(ValueError, match=error):
            asyncio.run(service.start_campaign(
                type("Intent", (), {
                    "engagement_binding": engagement,
                    "target_binding": target_binding,
                    "objective": objective,
                    "risk_profile": risk,
                })(),
                tenant_id="tenant-r124", principal_id="operator-r124",
                idempotency_key="transport-generated-key", now=NOW,
            ))
    assert starter.calls == []


def test_projection_and_recovery_delegate_to_canonical_owners_with_etag() -> None:
    presentation = Presentation()
    recovery = Recovery()
    service = CampaignCoreService(
        Options(), Starter(), presentation=presentation, recovery=recovery
    )

    listed = asyncio.run(service.list_campaigns(
        tenant_id="tenant-r124", principal_id="operator-r124",
        limit=20, cursor=None, now=NOW,
    ))
    inspected = asyncio.run(service.inspect_campaign(
        tenant_id="tenant-r124", principal_id="operator-r124",
        campaign_id="campaign-server-generated", now=NOW,
    ))
    attention = asyncio.run(service.list_attention(
        tenant_id="tenant-r124", principal_id="operator-r124",
        limit=20, cursor=None, now=NOW,
    ))
    stopped = asyncio.run(service.recover_campaign(
        action="stop",
        reason="Emergency operator requested containment",
        tenant_id="tenant-r124",
        principal_id="operator-r124",
        campaign_id="campaign-server-generated",
        expected_etag='"campaign-server-generated:4"',
        idempotency_key="transport-stop-key",
        now=NOW,
    ))

    assert listed["page"]["limit"] == 20
    assert inspected["data"]["plan_sha256"] == "a" * 64
    assert attention["data"] == []
    assert recovery.calls[0]["tenant_id"] == "tenant-r124"
    assert recovery.calls[0]["campaign_id"] == "campaign-server-generated"
    assert recovery.calls[0]["signal_id"].startswith("r124-stop-")
    assert recovery.calls[0]["reason_sha256"] != "Emergency operator requested containment"
    assert recovery.calls[0]["expected_revision"] == 4
    assert recovery.calls[0]["idempotency_key"] == "transport-stop-key"
    assert stopped["data"] == {
        "campaign_id": "campaign-server-generated",
        "status": "manual_review_required",
        "aggregate_sequence": 5,
        "etag": '"campaign-server-generated:5"',
        "replayed": False,
    }

    with pytest.raises(CampaignCoreEtagConflict, match="r124_etag_conflict"):
        asyncio.run(service.recover_campaign(
            action="revoke", reason="Revoke stale campaign authority now",
            tenant_id="tenant-r124", principal_id="operator-r124",
            campaign_id="campaign-server-generated",
            expected_etag='"campaign-server-generated:3"',
            idempotency_key="transport-revoke-key", now=NOW,
        ))
    assert len(recovery.calls) == 2


def test_feature_rollback_disables_create_without_disabling_recovery() -> None:
    recovery = Recovery()
    service = CampaignCoreService(
        Options(), Starter(), presentation=Presentation(), recovery=recovery,
        create_enabled=False,
    )

    with pytest.raises(CampaignCoreCreateDisabled, match="r124_campaign_create_disabled"):
        asyncio.run(service.start_campaign(
            object(), tenant_id="tenant-r124", principal_id="operator-r124",
            idempotency_key="transport-create-key", now=NOW,
        ))

    result = asyncio.run(service.recover_campaign(
        action="stop", reason="Emergency operator requested containment",
        tenant_id="tenant-r124", principal_id="operator-r124",
        campaign_id="campaign-server-generated",
        expected_etag='"campaign-server-generated:4"',
        idempotency_key="transport-stop-key", now=NOW,
    ))
    assert result["data"]["status"] == "manual_review_required"


def test_start_replay_precedes_mutable_options_and_create_feature_flag() -> None:
    class UnavailableOptions:
        async def list_engagements(self, **values):
            del values
            raise AssertionError("mutable options must not run for a replay")

        async def list_targets(self, **values):
            del values
            raise AssertionError("mutable options must not run for a replay")

    starter = Starter()
    starter.replay_result = type("Receipt", (), {
        "campaign_id": "campaign-already-committed",
        "aggregate_sequence": 3,
        "replayed": True,
    })()
    service = CampaignCoreService(
        UnavailableOptions(), starter, create_enabled=False
    )
    intent = type("Intent", (), {
        "engagement_binding": "opaque-original-engagement",
        "target_binding": "opaque-original-target",
        "objective": "Assess HTTP security posture",
        "risk_profile": "opaque-original-risk",
    })()

    result = asyncio.run(service.start_campaign(
        intent,
        tenant_id="tenant-r124",
        principal_id="operator-r124",
        idempotency_key="transport-retry-key",
        now=NOW,
    ))

    assert result["data"] == {
        "campaign_id": "campaign-already-committed",
        "status": "dispatch_pending",
        "aggregate_sequence": 3,
        "etag": '"campaign-already-committed:3"',
        "replayed": True,
    }
    assert len(starter.replay_calls) == 1
    assert starter.calls == []


def test_start_replay_rejects_same_key_with_different_original_intent() -> None:
    class ConflictingStarter(Starter):
        async def replay(self, **values):
            self.replay_calls.append(values)
            raise IdempotencyConflict("idempotency_key_request_mismatch")

    starter = ConflictingStarter()
    service = CampaignCoreService(Options(), starter)

    with pytest.raises(IdempotencyConflict, match="idempotency_key_request_mismatch"):
        asyncio.run(service.start_campaign(
            type("Intent", (), {
                "engagement_binding": "changed-engagement",
                "target_binding": "changed-target",
                "objective": "Assess HTTP security posture",
                "risk_profile": "changed-risk",
            })(),
            tenant_id="tenant-r124",
            principal_id="operator-r124",
            idempotency_key="transport-retry-key",
            now=NOW,
        ))
    assert starter.calls == []
