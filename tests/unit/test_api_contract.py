from __future__ import annotations

import asyncio
import httpx
from pydantic import ValidationError
import pytest

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import EngagementCreateRequest, PaginationQuery


EXPECTED_BUSINESS_ROUTES = {
    "/api/v1/engagements",
    "/api/v1/engagements/{engagement_id}",
    "/api/v1/engagements/{engagement_id}/targets",
    "/api/v1/engagements/{engagement_id}/roe-versions",
    "/api/v1/roe-versions/{roe_version_id}/approve",
    "/api/v1/jobs",
    "/api/v1/jobs/{job_id}",
    "/api/v1/findings/ingest",
}


def test_versioned_route_inventory_and_openapi_contract_are_registered() -> None:
    app = create_app(test_issuer_enabled=True)
    schema = app.openapi()

    assert EXPECTED_BUSINESS_ROUTES <= set(schema["paths"])
    assert "/health/live" in schema["paths"]
    assert "/health/ready" in schema["paths"]
    assert schema["info"]["version"] == "1.0.0"
    assert schema["components"]["schemas"]["EngagementCreateRequest"]["additionalProperties"] is False


def test_liveness_has_defense_in_depth_security_headers() -> None:
    response = _request(create_app(test_issuer_enabled=True), "GET", "/health/live")

    assert response.status_code == 200
    assert response.json() == {"status": "alive"}
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["x-frame-options"] == "DENY"
    assert response.headers["content-security-policy"] == "default-src 'none'; frame-ancestors 'none'"
    assert response.headers["cache-control"] == "no-store"


def test_business_route_denies_missing_security_context_before_database_access() -> None:
    response = _request(create_app(test_issuer_enabled=True), "GET", "/api/v1/engagements")

    assert response.status_code == 401
    assert response.json() == {
        "error": {
            "code": "security_context_required",
            "message": "Validated security context is required.",
            "correlation_id": response.headers["x-correlation-id"],
        }
    }
    assert "traceback" not in response.text.lower()
    assert "sql" not in response.text.lower()


def test_strict_request_and_bounded_pagination_reject_unknown_or_excessive_input() -> None:
    with pytest.raises(ValidationError):
        EngagementCreateRequest.model_validate(
            {
                "engagement_id": "eng-1",
                "name": "Synthetic engagement",
                "owner_user_id": "user-1",
                "unexpected": "blocked",
            }
        )
    with pytest.raises(ValidationError):
        PaginationQuery(limit=501, offset=0)


def test_mutation_requires_correlation_and_idempotency_before_service_invocation() -> None:
    headers = {
        "X-RedAgent-Test-Subject": "user-1",
        "X-RedAgent-Test-Tenant": "tenant-1",
        "X-RedAgent-Test-Permissions": "engagement:create",
        "X-RedAgent-Policy-Reference": "policy-bootstrap:1",
    }

    response = _request(
        create_app(test_issuer_enabled=True),
        "POST",
        "/api/v1/engagements",
        headers=headers,
        json={"engagement_id": "eng-1", "name": "Synthetic engagement", "owner_user_id": "user-1"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "idempotency_key_required"


def test_mutation_requires_policy_reference_before_database_access() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "POST",
        "/api/v1/engagements",
        headers={
            "X-RedAgent-Test-Subject": "user-1",
            "X-RedAgent-Test-Tenant": "tenant-1",
            "X-RedAgent-Test-Permissions": "engagement:create",
            "Idempotency-Key": "create-eng-1",
        },
        json={"engagement_id": "eng-1", "name": "Synthetic engagement", "owner_user_id": "user-1"},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "policy_reference_required"


def test_permission_denial_precedes_database_access() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "POST",
        "/api/v1/engagements",
        headers={
            "X-RedAgent-Test-Subject": "user-1",
            "X-RedAgent-Test-Tenant": "tenant-1",
            "X-RedAgent-Test-Permissions": "engagement:read",
            "Idempotency-Key": "create-eng-1",
            "X-RedAgent-Policy-Reference": "policy-bootstrap:1",
        },
        json={"engagement_id": "eng-1", "name": "Synthetic engagement", "owner_user_id": "user-1"},
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"


def test_patch_is_a_mutation_and_requires_idempotency() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "PATCH",
        "/api/v1/engagements/eng-1",
        headers={
            "X-RedAgent-Test-Subject": "user-1",
            "X-RedAgent-Test-Tenant": "tenant-1",
            "X-RedAgent-Test-Permissions": "engagement:update",
            "X-RedAgent-Policy-Reference": "policy-bootstrap:1",
        },
        json={"name": "Updated", "expected_version": 1},
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "idempotency_key_required"


def test_validation_errors_use_stable_secret_free_envelope() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "POST",
        "/api/v1/engagements",
        headers={
            "X-RedAgent-Test-Subject": "user-1",
            "X-RedAgent-Test-Tenant": "tenant-1",
            "X-RedAgent-Test-Permissions": "engagement:create",
            "Idempotency-Key": "create-eng-1",
            "X-RedAgent-Policy-Reference": "policy-bootstrap:1",
        },
        json={"engagement_id": "eng-1", "owner_user_id": "user-1", "secret": "must-not-echo"},
    )

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"
    assert "must-not-echo" not in response.text


def test_openapi_operation_ids_are_unique_and_all_mutation_models_are_strict() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    operation_ids = [
        operation["operationId"]
        for path in schema["paths"].values()
        for operation in path.values()
        if isinstance(operation, dict) and "operationId" in operation
    ]

    assert len(operation_ids) == len(set(operation_ids))
    for name, model in schema["components"]["schemas"].items():
        if name.endswith("Request"):
            assert model.get("additionalProperties") is False, name


def test_test_issuer_is_disabled_by_default() -> None:
    response = _request(
        create_app(),
        "GET",
        "/api/v1/engagements",
        headers={
            "X-RedAgent-Test-Subject": "user-1",
            "X-RedAgent-Test-Tenant": "tenant-1",
            "X-RedAgent-Test-Permissions": "engagement:read",
        },
    )

    assert response.status_code == 401
    assert response.json()["error"]["code"] == "production_identity_not_configured"


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())
