from __future__ import annotations

import asyncio

import httpx
import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app
from redagent_platform.api.runtime import derive_operator_shell_context
from redagent_platform.api.schemas import OperatorShellContextData


AUTH_HEADERS = {
    "X-RedAgent-Test-Subject": "operator-r127",
    "X-RedAgent-Test-Tenant": "tenant-r127",
    "X-RedAgent-Test-Permissions": "engagement:read,campaign:read",
}


def test_operator_shell_context_is_strict_and_fail_closed() -> None:
    unavailable = OperatorShellContextData()
    assert unavailable.model_dump() == {
        "schema_version": "1",
        "environment": "unknown",
        "safety_profile": "unknown",
        "status": "unavailable",
    }

    with pytest.raises(ValidationError):
        OperatorShellContextData.model_validate({
            "environment": "local",
            "safety_profile": "synthetic-local",
            "status": "ready",
            "client_claimed_safe": True,
        })

    with pytest.raises(ValidationError, match="operator_shell_ready_profile_mismatch"):
        OperatorShellContextData(
            environment="local",
            safety_profile="production",
            status="ready",
        )


@pytest.mark.parametrize(
    ("values", "expected"),
    [
        ({}, ("unknown", "unknown", "unavailable")),
        ({"REDAGENT_PROFILE": "local"}, ("local", "unknown", "unavailable")),
        (
            {"REDAGENT_PROFILE": "local", "REDAGENT_POLICY_PROFILE": "synthetic-local"},
            ("local", "synthetic-local", "ready"),
        ),
        (
            {"REDAGENT_PROFILE": "production", "REDAGENT_POLICY_PROFILE": "production"},
            ("production", "production", "ready"),
        ),
        (
            {"REDAGENT_PROFILE": "local", "REDAGENT_POLICY_PROFILE": "production"},
            ("local", "unknown", "unavailable"),
        ),
    ],
)
def test_runtime_derivation_never_converts_missing_or_inconsistent_values_to_safe(
    values: dict[str, str],
    expected: tuple[str, str, str],
) -> None:
    context = derive_operator_shell_context(values)
    assert (context.environment, context.safety_profile, context.status) == expected


def test_authenticated_context_includes_injected_server_owned_shell_context() -> None:
    shell = OperatorShellContextData(
        environment="local",
        safety_profile="synthetic-local",
        status="ready",
    )
    response = _request(
        create_app(test_issuer_enabled=True, operator_shell_context=shell),
        "/api/v1/context",
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["data"] == {
        "subject": "operator-r127",
        "tenant_id": "tenant-r127",
        "permissions": ["campaign:read", "engagement:read"],
        "roles": [],
        "operator_shell": {
            "schema_version": "1",
            "environment": "local",
            "safety_profile": "synthetic-local",
            "status": "ready",
        },
    }


def test_direct_app_context_is_explicitly_unavailable() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "/api/v1/context",
        headers=AUTH_HEADERS,
    )

    assert response.status_code == 200
    assert response.json()["data"]["operator_shell"] == {
        "schema_version": "1",
        "environment": "unknown",
        "safety_profile": "unknown",
        "status": "unavailable",
    }


def _request(app, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.get(path, **kwargs)

    return asyncio.run(send())
