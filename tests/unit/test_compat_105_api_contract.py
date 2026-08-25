from __future__ import annotations

import asyncio

import httpx

import redagent_platform.api.routers.nuclei as nuclei_routes
from redagent_platform.api.app import create_app


def test_nuclei_dashboard_projects_only_domain_owned_execution_choices() -> None:
    schemas = create_app(test_issuer_enabled=True).openapi()["components"]["schemas"]
    properties = schemas["NucleiDashboardData"]["properties"]
    assert {"target_options", "runner_options", "job_options"} <= set(properties)
    assert set(schemas["NucleiTargetOptionData"]["properties"]) == {
        "target_id", "attestation_sha256", "attestation_state", "non_production", "expires_at",
    }
    assert set(schemas["NucleiRunnerOptionData"]["properties"]) == {
        "runner_id", "environment", "network_plane", "required_policy_revision", "registration_state", "expires_at",
    }
    assert set(schemas["NucleiJobOptionData"]["properties"]) == {
        "job_id", "engagement_id", "roe_version_id", "status", "current_gate", "dispatch_blocked", "stop_requested",
    }


def test_profile_discovery_fails_closed_when_signed_bundle_verification_is_unavailable(monkeypatch) -> None:
    def unavailable(now):
        del now
        raise ValueError("synthetic_bundle_drift")

    monkeypatch.setattr(nuclei_routes, "_load_r105_bundle", unavailable)
    asyncio.run(_scenario())


async def _scenario() -> None:
    app = create_app(test_issuer_enabled=True)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
            base_url="http://testserver",
        ) as client:
            response = await client.get("/api/v1/nuclei/profiles", headers={
                "X-RedAgent-Test-Subject": "operator-r105",
                "X-RedAgent-Test-Tenant": "tenant-r105",
                "X-RedAgent-Test-Permissions": "job:read",
            })
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "nuclei_supply_chain_unavailable"
    assert "synthetic_bundle_drift" not in response.text
