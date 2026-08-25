from __future__ import annotations

import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import PolicyPromotionRequest, PolicySimulationRequest


ROUTES = {
    "/api/v1/policy/status", "/api/v1/policy/decisions", "/api/v1/policy/bundles",
    "/api/v1/policy/simulations", "/api/v1/policy/promotions", "/api/v1/policy/rollbacks",
}


def test_policy_routes_are_typed_and_expose_no_generic_opa_proxy() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    assert ROUTES <= set(schema["paths"])
    rendered = str({path: schema["paths"][path] for path in ROUTES}).lower()
    for forbidden in ("rego_source", "policy_text", "bundle_bytes", "bundle_url", "private_key", "decision_path"):
        assert forbidden not in rendered
    assert "/api/v1/policy/query" not in schema["paths"]


def test_simulation_and_promotion_requests_are_closed_fixed_inputs() -> None:
    assert PolicySimulationRequest(fixture="api-job-create").fixture == "api-job-create"
    with pytest.raises(ValidationError):
        PolicySimulationRequest.model_validate({"fixture": "arbitrary", "input": {"allow": True}})
    promotion = PolicyPromotionRequest(
        revision="r099-v1", expected_version=1, reason="Reviewed converged policy promotion",
    )
    assert promotion.revision == "r099-v1"
    with pytest.raises(ValidationError):
        PolicyPromotionRequest.model_validate({
            **promotion.model_dump(), "bundle_url": "https://example.test/policy.tar.gz",
        })
