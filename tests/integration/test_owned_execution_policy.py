from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone

import httpx

from redagent_platform.campaign_service.dag_effect_authority import _policy_request
from redagent_platform.campaign_service.dag_policy import DagPolicyDecisionAdapter
from redagent_platform.policy_service.providers import OpaPolicyDecisionProvider
from scripts import opa_conformance
from tests.unit.test_campaign_dag_effect_authority import _material, _lifecycle
from tests.unit.test_compat_123_effect_coordinator import _command


def test_real_opa_owned_effect_allows_only_current_closed_metadata():
    with opa_conformance.opa_fixture_lease():
        assert opa_conformance._provision()["ok"]
        try:
            asyncio.run(_scenario())
        finally:
            opa_conformance._scoped_cleanup()


async def _scenario():
    now = datetime.now(timezone.utc)
    async with httpx.AsyncClient(timeout=5) as client:
        provider = OpaPolicyDecisionProvider(client, endpoint=opa_conformance.opa_endpoint(), token_source=lambda: opa_conformance.APP_TOKEN)
        policy = DagPolicyDecisionAdapter(provider)
        material = _material(policy_bundle_revision="r099-v1", rate_limit=60, reservation_lease_expires_at=now + timedelta(seconds=60))
        lifecycle = _lifecycle(observed_at=now, valid_until=now + timedelta(seconds=60))
        request = _policy_request(material, _command(), lifecycle, runner_binding_sha256="f" * 64, roe_version_id="roe-owned", now=now)
        for capability in ("zap-controlled-runtime", "nuclei-trusted-runtime"):
            current = replace(request, attributes={**request.attributes, "campaign_capability_id": capability})
            assert (await policy.decide(current, now=now)).allowed
        for key, invalid in (
            ("campaign_environment_class", "internet"), ("campaign_capability_id", "arbitrary-shell"),
            ("campaign_credential_class", "admin"), ("campaign_effect_class", "disruptive"),
            ("campaign_lifecycle_state", "revoked"), ("campaign_rate_limit", 61),
            ("campaign_active_concurrency", 1), ("campaign_rate_claimed_requests", 60),
            ("campaign_reservation_state", "released"), ("campaign_runner_binding_sha256", "invalid"),
            ("campaign_reservation_lease_expires_at", (now - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")),
        ):
            denied = replace(request, attributes={**request.attributes, key: invalid})
            assert not (await policy.decide(denied, now=now)).allowed, key
        assert not (await policy.decide(replace(request, permissions=("campaign:read",), attributes=dict(request.attributes)), now=now)).allowed
