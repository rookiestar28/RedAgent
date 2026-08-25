from __future__ import annotations

import asyncio

import httpx

from redagent_platform.api.app import create_app


R097_ROUTES = {
    "/api/v1/evidence/artifacts",
    "/api/v1/evidence/artifacts/{artifact_id}",
    "/api/v1/evidence/artifacts/{artifact_id}/selection",
    "/api/v1/evidence/artifacts/{artifact_id}/derive",
    "/api/v1/evidence/artifacts/{artifact_id}/verify",
    "/api/v1/evidence/artifacts/{artifact_id}/legal-hold",
    "/api/v1/evidence/synthetic",
}


def test_r097_evidence_routes_and_strict_schemas_are_in_openapi() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    assert R097_ROUTES <= set(schema["paths"])
    for model_name in (
        "EvidenceSyntheticRegisterRequest",
        "EvidenceDeriveRequest",
        "EvidenceLegalHoldRequest",
    ):
        assert schema["components"]["schemas"][model_name]["additionalProperties"] is False
    synthetic = schema["components"]["schemas"]["EvidenceSyntheticRegisterRequest"]["properties"]
    for forbidden in ("content", "path", "url", "bucket", "key", "endpoint", "credential", "kms_reference", "delete", "bypass"):
        assert forbidden not in synthetic


def test_evidence_read_and_retention_admin_permissions_are_separate() -> None:
    app = create_app(test_issuer_enabled=True)
    denied_read = _request(
        app,
        "GET",
        "/api/v1/evidence/artifacts",
        headers=_headers("evidence:write"),
    )
    assert denied_read.status_code == 403
    denied_hold = _request(
        app,
        "POST",
        "/api/v1/evidence/artifacts/artifact-1/legal-hold",
        headers={
            **_headers("evidence:write,evidence:read"),
            "X-RedAgent-Policy-Reference": "policy:compat_097:1",
            "Idempotency-Key": "hold-artifact-1",
        },
        json={"expected_version": 1},
    )
    assert denied_hold.status_code == 403


def test_synthetic_registration_fails_closed_when_runtime_flag_is_disabled() -> None:
    response = _request(
        create_app(test_issuer_enabled=True),
        "POST",
        "/api/v1/evidence/synthetic",
        headers={
            **_headers("evidence:write"),
            "X-RedAgent-Policy-Reference": "policy:compat_097:1",
            "Idempotency-Key": "synthetic-1",
        },
        json={
            "artifact_id": "artifact-1",
            "engagement_id": "engagement-1",
            "job_id": "job-1",
            "fixture_kind": "sanitized-log",
            "retention_days": 30,
        },
    )
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "synthetic_evidence_disabled"


def _headers(permissions: str) -> dict[str, str]:
    return {
        "X-RedAgent-Test-Subject": "operator-1",
        "X-RedAgent-Test-Tenant": "tenant-1",
        "X-RedAgent-Test-Permissions": permissions,
    }


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://testserver",
        ) as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())
