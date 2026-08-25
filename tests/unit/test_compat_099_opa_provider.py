from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json

import pytest

from redagent_platform.policy_service.contracts import PolicyBoundary, PolicyDecisionInput, PolicyObligation, policy_input_hash
from redagent_platform.policy_service.providers import OpaPolicyDecisionProvider, PolicyProviderError


NOW = datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc)


class Response:
    def __init__(self, status: int, payload: dict[str, object], *, content_type: str = "application/json") -> None:
        self.status_code = status
        self.content = json.dumps(payload).encode()
        self.headers = {"content-type": content_type}

    def json(self):
        return json.loads(self.content)


class Client:
    def __init__(self, responses: list[Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    async def request(self, method: str, url: str, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def test_readiness_requires_exact_active_revision_and_ok_bundle_plugin() -> None:
    client = Client([
        Response(200, {}),
        Response(200, {"result": {"bundles": {"redagent": {"active_revision": "r099-v1"}}, "plugins": {"bundle": {"state": "OK"}}}}),
    ])
    readiness = asyncio.run(_provider(client).assess_readiness(required_revision="r099-v1"))
    assert readiness.ready and readiness.active_revision == "r099-v1"
    assert [call[1] for call in client.calls] == [
        "http://127.0.0.1:58181/health?bundles&plugins",
        "http://127.0.0.1:58181/v1/status",
    ]


def test_decision_requires_closed_result_decision_id_revision_hash_and_deadline() -> None:
    request = _request()
    client = Client([Response(200, {
        "decision_id": "opa-decision-1",
        "result": {
            "allowed": True, "reason_code": "boundary_authorized", "bundle_revision": "r099-v1",
            "input_hash": policy_input_hash(request), "obligations": ["audit", "require_expected_version"],
            "issued_at": NOW.isoformat(), "valid_until": (NOW + timedelta(seconds=30)).isoformat(),
        },
    })])
    decision = asyncio.run(_provider(client).decide(request, required_revision="r099-v1", now=NOW))
    assert decision.allowed and decision.obligations == (PolicyObligation.AUDIT, PolicyObligation.REQUIRE_EXPECTED_VERSION)
    method, url, options = client.calls[0]
    assert (method, url) == ("POST", "http://127.0.0.1:58181/v1/data/redagent/decision")
    assert options["headers"]["Authorization"] == "Bearer synthetic-opa-token"  # pragma: allowlist secret
    assert options["json"]["input"]["tenant_id"] == "tenant-1"
    assert options["json"]["input"]["input_hash"] == policy_input_hash(request)
    assert options["json"]["input"]["required_revision"] == "r099-v1"


@pytest.mark.parametrize("payload", ({}, {"decision_id": "decision-1"}, {"decision_id": "decision-1", "result": True}))
def test_http_200_undefined_or_malformed_result_denies(payload) -> None:
    with pytest.raises(PolicyProviderError, match="opa_decision_undefined_or_invalid"):
        asyncio.run(_provider(Client([Response(200, payload)])).decide(_request(), required_revision="r099-v1", now=NOW))


def test_transport_status_content_type_and_response_body_fail_with_stable_errors() -> None:
    cases = (
        (Client([Response(503, {"error": "sensitive detail"})]), "opa_http_status:503"),
        (Client([Response(200, {}, content_type="text/plain")]), "opa_response_content_type_invalid"),
    )
    for client, reason in cases:
        with pytest.raises(PolicyProviderError, match=reason) as captured:
            asyncio.run(_provider(client).decide(_request(), required_revision="r099-v1", now=NOW))
        assert "sensitive detail" not in str(captured.value)


def _provider(client: Client) -> OpaPolicyDecisionProvider:
    return OpaPolicyDecisionProvider(
        client, endpoint="http://127.0.0.1:58181", token_source=lambda: "synthetic-opa-token",
    )


def _request() -> PolicyDecisionInput:
    return PolicyDecisionInput(
        boundary=PolicyBoundary.API, action="job.create", tenant_id="tenant-1", subject_id="operator-1",
        roles=("operator",), permissions=("job:create",), resource_type="job", resource_id="job-1",
        policy_reference="policy:compat_099:1", roe_version_id="roe-1", correlation_id="correlation-1",
        requested_at=NOW, attributes={"job_status": "pending", "resource_version": 1},
    )
