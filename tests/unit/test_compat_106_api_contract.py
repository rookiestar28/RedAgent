from __future__ import annotations

import asyncio

import httpx
from pydantic import ValidationError
import pytest

import redagent_platform.api.routers.api_differential as api_differential_routes
from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import ApiDifferentialCompileRequest


def test_api_differential_routes_are_registered_and_compile_schema_has_no_native_transport_surface() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    expected = {
        "/api/v1/api-differential/profiles",
        "/api/v1/api-differential/plans",
        "/api/v1/api-differential/runs",
        "/api/v1/api-differential/runs/{run_id}/cancel",
        "/api/v1/api-differential/dashboard",
    }
    assert expected <= set(schema["paths"])
    compile_schema = schema["components"]["schemas"]["ApiDifferentialCompileRequest"]
    assert compile_schema["additionalProperties"] is False
    serialized = " ".join(compile_schema["properties"]).lower()
    for forbidden in ("url", "header", "cookie", "token", "credential", "body", "request", "callback", "webhook", "flag", "config"):
        assert forbidden not in serialized

    payload = {
        "plan_id": "plan-r106", "profile_id": "openapi-authorization-differential-v1",
        "target_id": "r106-owned-api-fixture", "target_attestation_sha256": "a" * 64,
        "policy_decision_id": "decision-r106", "policy_revision": "r099-v1",
        "roe_version_id": "roe-r106", "seed": 10620260711,
    }
    assert ApiDifferentialCompileRequest.model_validate(payload).seed == 10620260711
    with pytest.raises(ValidationError):
        ApiDifferentialCompileRequest.model_validate(payload | {"raw_request": "GET /admin/audit"})


def test_profile_discovery_fails_closed_without_leaking_promotion_error(monkeypatch) -> None:
    def unavailable(*args, **kwargs):
        del args, kwargs
        raise ValueError("synthetic_r106_promotion_drift")

    monkeypatch.setattr(
        api_differential_routes,
        "verify_api_differential_promotion",
        unavailable,
    )
    asyncio.run(_scenario())


async def _scenario() -> None:
    app = create_app(test_issuer_enabled=True)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://testserver",
        ) as client:
            response = await client.get("/api/v1/api-differential/profiles", headers={
                "X-RedAgent-Test-Subject": "operator-r106",
                "X-RedAgent-Test-Tenant": "tenant-r106",
                "X-RedAgent-Test-Permissions": "job:read",
            })
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "api_diff_supply_chain_unavailable"
    assert "synthetic_r106_promotion_drift" not in response.text
