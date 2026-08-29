from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from redagent_platform.campaign_service.dag_policy import DagPolicyDecisionAdapter
from redagent_platform.policy_service.contracts import (
    PolicyBoundary,
    PolicyDecision,
    PolicyDecisionInput,
    PolicyObligation,
    policy_input_hash,
)


NOW = datetime(2026, 8, 29, 11, tzinfo=timezone.utc)


def _request() -> PolicyDecisionInput:
    return PolicyDecisionInput(
        boundary=PolicyBoundary.WORKFLOW,
        action="campaign.node.execute",
        tenant_id="tenant-a",
        subject_id="operator-a",
        roles=("operator",),
        permissions=("campaign:execute",),
        resource_type="campaign_execution_node",
        resource_id="run-a:node-a",
        policy_reference="policy-v1",
        roe_version_id="roe-a",
        correlation_id="corr-a",
        requested_at=NOW,
        attributes={"campaign_policy_bundle_sha256": "a" * 64},
    )


class Provider:
    def __init__(self, *, ready=True):
        self.ready = ready
        self.calls = []

    async def assess_readiness(self, *, required_revision):
        self.calls.append(("ready", required_revision))
        return SimpleNamespace(
            ready=self.ready,
            active_revision=required_revision,
            bundle_plugin_state="OK",
        )

    async def decide(self, request, *, required_revision, now):
        self.calls.append(("decide", required_revision, now))
        return PolicyDecision(
            decision_id="decision-a",
            bundle_revision=required_revision,
            input_hash=policy_input_hash(request),
            allowed=True,
            reason_code="allowed",
            obligations=(
                PolicyObligation.AUDIT,
                PolicyObligation.REQUIRE_EXPECTED_VERSION,
            ),
            issued_at=now,
            valid_until=now + timedelta(seconds=30),
        )


def test_dag_policy_adapter_requires_current_revision_and_returns_fresh_decision() -> None:
    provider = Provider()
    decision = asyncio.run(DagPolicyDecisionAdapter(provider).decide(_request(), now=NOW))
    assert decision.allowed is True
    assert provider.calls == [
        ("ready", "policy-v1"),
        ("decide", "policy-v1", NOW),
    ]


def test_dag_policy_adapter_fails_closed_when_provider_not_ready() -> None:
    with pytest.raises(ValueError, match="dag_policy_not_ready"):
        asyncio.run(DagPolicyDecisionAdapter(Provider(ready=False)).decide(_request(), now=NOW))
