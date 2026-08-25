from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx

from redagent_platform.policy_service.contracts import PolicyBoundary, PolicyDecisionInput
from redagent_platform.policy_service.providers import OpaPolicyDecisionProvider
from scripts import opa_conformance


TOKEN = "redagent-r099-app"  # pragma: allowlist secret


def test_real_opa_signed_bundle_status_decision_and_api_authorization() -> None:
    with opa_conformance.opa_fixture_lease():
        provisioned = opa_conformance._provision()
        assert provisioned["ok"] is True
        try:
            asyncio.run(_scenario())
        finally:
            # IMPORTANT: leave the shared local fixture absent for the next live
            # scenario; lifecycle tests deliberately replace its signed bundle.
            opa_conformance._scoped_cleanup()


async def _scenario() -> None:
    endpoint = opa_conformance.opa_endpoint()
    now = datetime.now(timezone.utc).replace(microsecond=0)
    request = PolicyDecisionInput(
        boundary=PolicyBoundary.API, action="job.create", tenant_id="tenant-1",
        subject_id="operator-1", roles=("operator",), permissions=("job:create",),
        resource_type="job", resource_id="job-1", policy_reference="policy:compat_099:1",
        roe_version_id="roe-1", correlation_id="r099-live-1", requested_at=now,
        attributes={"job_status": "pending", "resource_version": 1},
    )
    async with httpx.AsyncClient(timeout=5) as client:
        provider = OpaPolicyDecisionProvider(
            client, endpoint=endpoint, token_source=lambda: TOKEN,
        )
        readiness = await provider.assess_readiness(required_revision="r099-v1")
        assert readiness.ready and readiness.active_revision == "r099-v1"
        decision = await provider.decide(request, required_revision="r099-v1", now=now)
        assert decision.allowed
        assert decision.bundle_revision == "r099-v1"
        assert decision.reason_code == "boundary_authorized"

        headers = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}
        for method, path, payload in (
            ("PUT", "/v1/policies/redagent", {"rego": "package forbidden"}),
            ("POST", "/v1/compile", {"query": "data"}),
            ("POST", "/v1/data/arbitrary", {"input": {}}),
        ):
            response = await client.request(method, f"{endpoint}{path}", headers=headers, json=payload)
            assert response.status_code in {401, 403}
        anonymous = await client.get(f"{endpoint}/v1/status")
        assert anonymous.status_code in {401, 403}
