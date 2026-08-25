from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

import httpx
from pydantic import ValidationError
import pytest

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import JitGrantCreateRequest


R095_ROUTES = {
    "/api/v1/context",
    "/api/v1/identity/memberships",
    "/api/v1/jit-grants",
    "/api/v1/jit-grants/{grant_id}/approve",
    "/api/v1/jit-grants/{grant_id}/revoke",
    "/api/v1/jit-grants/{grant_id}/review",
    "/api/v1/activity",
}


def test_r095_console_routes_and_strict_schemas_are_in_openapi() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()

    assert R095_ROUTES <= set(schema["paths"])
    for model_name in (
        "JitGrantCreateRequest",
        "JitGrantReviewRequest",
        "JitGrantRevokeRequest",
    ):
        assert schema["components"]["schemas"][model_name]["additionalProperties"] is False
    roe = schema["components"]["schemas"]["RoeVersionData"]["properties"]
    assert {"policy_reference", "approval_id"} <= set(roe)


def test_jit_request_schema_is_bounded_typed_and_rejects_unknown_fields() -> None:
    now = datetime.now(timezone.utc)
    payload = {
        "grant_id": "grant-1",
        "role": "operator",
        "permission": "job:execute",
        "scope_type": "engagement",
        "scope_id": "engagement-1",
        "reason": "Controlled synthetic execution",
        "expires_at": now + timedelta(minutes=15),
        "break_glass": False,
    }
    assert JitGrantCreateRequest.model_validate(payload).scope_type == "engagement"
    with pytest.raises(ValidationError):
        JitGrantCreateRequest.model_validate({**payload, "unexpected": "blocked"})
    with pytest.raises(ValidationError):
        JitGrantCreateRequest.model_validate({**payload, "expires_at": now + timedelta(hours=25)})


def test_console_identity_and_jit_routes_deny_before_database_access() -> None:
    app = create_app(test_issuer_enabled=True)
    base_headers = {
        "X-RedAgent-Test-Subject": "operator-1",
        "X-RedAgent-Test-Tenant": "tenant-1",
        "X-RedAgent-Test-Permissions": "engagement:read",
    }
    memberships = _request(app, "GET", "/api/v1/identity/memberships", headers=base_headers)
    assert memberships.status_code == 403
    assert memberships.json()["error"]["code"] == "permission_denied"

    jit = _request(
        app,
        "POST",
        "/api/v1/jit-grants",
        headers={
            **base_headers,
            "X-RedAgent-Policy-Reference": "identity-policy:1",
            "Idempotency-Key": "jit-grant-1",
        },
        json={
            "grant_id": "grant-1",
            "role": "operator",
            "permission": "job:execute",
            "scope_type": "engagement",
            "scope_id": "engagement-1",
            "reason": "Controlled synthetic execution",
            "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
            "break_glass": False,
        },
    )
    assert jit.status_code == 403
    assert jit.json()["error"]["code"] == "permission_denied"


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())
