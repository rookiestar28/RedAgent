from __future__ import annotations

import asyncio
import base64
import json
from pathlib import Path
import subprocess
import sys

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient
from sqlalchemy.engine import URL

from redagent_platform.api.runtime import (
    ApiRuntimeError,
    build_runtime_app,
    validate_runtime_bind,
    validate_runtime_tls,
)


ROOT = Path(__file__).resolve().parents[2]


def test_r093_runtime_is_loopback_only_and_has_bounded_port() -> None:
    assert validate_runtime_bind("127.0.0.1", 58000) == ("127.0.0.1", 58000)
    assert validate_runtime_bind("::1", 58000) == ("::1", 58000)
    with pytest.raises(ApiRuntimeError, match="api_bind_must_be_loopback"):
        validate_runtime_bind("0.0.0.0", 58000)
    assert validate_runtime_bind("0.0.0.0", 58000, private_cluster_bind=True) == ("0.0.0.0", 58000)
    with pytest.raises(ApiRuntimeError, match="api_bind_must_be_loopback"):
        validate_runtime_bind("192.0.2.10", 58000, private_cluster_bind=True)
    with pytest.raises(ApiRuntimeError, match="api_port_invalid"):
        validate_runtime_bind("127.0.0.1", 80)


def test_private_cluster_runtime_requires_an_available_tls_pair(tmp_path: Path) -> None:
    with pytest.raises(ApiRuntimeError, match="api_private_cluster_tls_required"):
        validate_runtime_tls(private_cluster_bind=True, certificate_file=None, private_key_file=None)
    with pytest.raises(ApiRuntimeError, match="api_tls_pair_required"):
        validate_runtime_tls(
            private_cluster_bind=True,
            certificate_file=tmp_path / "tls.crt",
            private_key_file=None,
        )
    certificate = tmp_path / "tls.crt"
    private_key = tmp_path / "tls.key"
    certificate.write_text("synthetic-certificate", encoding="utf-8")
    private_key.write_text("synthetic-private-key", encoding="utf-8")
    assert validate_runtime_tls(
        private_cluster_bind=True,
        certificate_file=certificate,
        private_key_file=private_key,
    ) == (str(certificate), str(private_key))


def test_runtime_app_keeps_test_issuer_disabled_unless_explicit(tmp_path: Path) -> None:
    secret = tmp_path / ".local" / "database-url"
    secret.parent.mkdir(parents=True)
    url = URL.create(
        "postgresql+asyncpg",
        "runtime",
        "synthetic",
        "127.0.0.1",
        55432,
        "redagent",
    )
    secret.write_text(url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    app = build_runtime_app(
        tmp_path,
        env={"REDAGENT_DATABASE_URL_FILE": str(secret)},
        test_issuer_enabled=False,
    )

    response = _request(
        app,
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


def test_runtime_identity_configuration_is_all_or_nothing_and_installs_bff(tmp_path: Path) -> None:
    secret = tmp_path / ".local" / "database-url"
    secret.parent.mkdir(parents=True)
    url = URL.create("postgresql+asyncpg", "runtime", "synthetic", "127.0.0.1", 55432, "redagent")
    secret.write_text(url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    with pytest.raises(ApiRuntimeError, match="identity_runtime_configuration_incomplete"):
        build_runtime_app(
            tmp_path,
            env={
                "REDAGENT_DATABASE_URL_FILE": str(secret),
                "REDAGENT_IDENTITY_PROVIDER_ID": "fixture",
            },
        )

    identity_config = tmp_path / "config" / "identity.json"
    identity_config.parent.mkdir(parents=True)
    identity_config.write_text(
        json.dumps(
            {
                "schema_version": "1.0",
                "providers": [
                    {
                        "provider_id": "fixture",
                        "issuer": "https://idp.example.test",
                        "discovery_url": "https://idp.example.test/.well-known/openid-configuration",
                        "client_id": "redagent-bff",
                        "audience": "redagent-bff",
                        "redirect_uri": "https://redagent.example.test/auth/callback",
                        "post_logout_redirect_uri": "https://redagent.example.test/auth/logged-out",
                        "allowed_algorithms": ["RS256"],
                        "scopes": ["openid"],
                        "tenant_claim": "redagent_tenant",
                        "roles_claim_path": ["realm_access", "roles"],
                        "token_endpoint_auth_method": "none",
                        "clock_skew_seconds": 30,
                        "http_timeout_seconds": 5,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    key = tmp_path / ".local" / "identity-key"
    key.write_bytes(bytes(range(32)))
    app = build_runtime_app(
        tmp_path,
        env={
            "REDAGENT_DATABASE_URL_FILE": str(secret),
            "REDAGENT_IDENTITY_CONFIG_FILE": str(identity_config),
            "REDAGENT_IDENTITY_PROVIDER_ID": "fixture",
            "REDAGENT_SESSION_KEY_FILE": str(key),
            "REDAGENT_PUBLIC_ORIGIN": "https://redagent.example.test",
        },
    )

    paths = {route.path for route in app.routes}
    assert {"/auth/login", "/auth/callback", "/auth/session", "/auth/logout"} <= paths


def test_runtime_cli_help_does_not_require_database_or_start_server() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "redagent_control_plane_api.py"), "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--enable-test-issuer" in completed.stdout
    assert "--host" in completed.stdout


def test_runtime_mounts_only_an_explicit_workspace_local_console_build(tmp_path: Path) -> None:
    secret = tmp_path / ".local" / "database-url"
    secret.parent.mkdir(parents=True)
    url = URL.create("postgresql+asyncpg", "runtime", "synthetic", "127.0.0.1", 55432, "redagent")
    secret.write_text(url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    dist = tmp_path / "frontend" / "dist"
    dist.mkdir(parents=True)
    (dist / "index.html").write_text("<main>runtime console</main>", encoding="utf-8")

    app = build_runtime_app(
        tmp_path,
        env={
            "REDAGENT_DATABASE_URL_FILE": str(secret),
            "REDAGENT_STATIC_DIRECTORY": "frontend/dist",
        },
    )
    response = _request(app, "GET", "/")
    assert response.status_code == 200
    assert "runtime console" in response.text

    with pytest.raises(ApiRuntimeError, match="static_directory_outside_workspace"):
        build_runtime_app(
            tmp_path,
            env={
                "REDAGENT_DATABASE_URL_FILE": str(secret),
                "REDAGENT_STATIC_DIRECTORY": str(tmp_path.parent),
            },
        )


def test_runtime_temporal_configuration_is_all_or_nothing_and_key_file_only(tmp_path: Path) -> None:
    database = tmp_path / ".local" / "database-url"
    database.parent.mkdir(parents=True)
    url = URL.create("postgresql+asyncpg", "runtime", "synthetic", "127.0.0.1", 55432, "redagent")
    database.write_text(url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    with pytest.raises(ApiRuntimeError, match="temporal_runtime_configuration_incomplete"):
        build_runtime_app(
            tmp_path,
            env={
                "REDAGENT_DATABASE_URL_FILE": str(database),
                "REDAGENT_TEMPORAL_TARGET": "127.0.0.1:57233",
            },
        )

    key = tmp_path / ".local" / "temporal-key"
    key.write_text(base64.urlsafe_b64encode(b"t" * 32).decode("ascii") + "\n", encoding="ascii")
    app = build_runtime_app(
        tmp_path,
        env={
            "REDAGENT_DATABASE_URL_FILE": str(database),
            "REDAGENT_TEMPORAL_TARGET": "127.0.0.1:57233",
            "REDAGENT_TEMPORAL_NAMESPACE": "redagent-local",
            "REDAGENT_TEMPORAL_TASK_QUEUE": "redagent-r096-v1",
            "REDAGENT_TEMPORAL_CODEC_KEY_FILE": str(key),
            "REDAGENT_TEMPORAL_CODEC_KEY_ID": "local-r096-v1",
            "REDAGENT_TEMPORAL_TLS": "false",
        },
    )
    assert app.state.temporal_required is True


def test_runtime_evidence_configuration_is_fail_closed_and_local_synthetic_is_explicit(tmp_path: Path) -> None:
    database = tmp_path / ".local" / "database-url"
    database.parent.mkdir(parents=True)
    url = URL.create("postgresql+asyncpg", "runtime", "synthetic", "127.0.0.1", 55432, "redagent")
    database.write_text(url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    with pytest.raises(ApiRuntimeError, match="evidence_runtime_configuration_incomplete"):
        build_runtime_app(
            tmp_path,
            env={
                "REDAGENT_DATABASE_URL_FILE": str(database),
                "REDAGENT_EVIDENCE_PROFILE": "synthetic-local",
            },
        )

    root = tmp_path / ".local" / "evidence"
    app = build_runtime_app(
        tmp_path,
        env={
            "REDAGENT_DATABASE_URL_FILE": str(database),
            "REDAGENT_EVIDENCE_PROFILE": "synthetic-local",
            "REDAGENT_EVIDENCE_BACKEND": "local-append-only",
            "REDAGENT_EVIDENCE_LOCAL_ROOT": str(root),
        },
    )
    assert app.state.evidence_backend is not None
    assert app.state.synthetic_evidence_enabled is True

    record = tmp_path / "config" / "evidence-capability.json"
    record.parent.mkdir(parents=True, exist_ok=True)
    record.write_text(json.dumps({
        "schema_version": "1.0", "status": "passed",
        "endpoint": "https://s3.example.test", "bucket": "redagent-evidence",
        "checked_at": "2026-01-01T00:00:00+00:00", "expires_at": "2026-01-02T00:00:00+00:00",
    }), encoding="utf-8")
    with pytest.raises(ApiRuntimeError, match="evidence_capability_record_not_current"):
        build_runtime_app(
            tmp_path,
            env={
                "REDAGENT_DATABASE_URL_FILE": str(database),
                "REDAGENT_EVIDENCE_PROFILE": "production",
                "REDAGENT_EVIDENCE_BACKEND": "s3",
                "REDAGENT_EVIDENCE_ENDPOINT": "https://s3.example.test",
                "REDAGENT_EVIDENCE_BUCKET": "redagent-evidence",
                "REDAGENT_EVIDENCE_REGION": "us-east-1",
                "REDAGENT_EVIDENCE_KMS_REFERENCE": "kms:redagent:evidence",
                "REDAGENT_EVIDENCE_CAPABILITY_RECORD": str(record),
            },
        )


def test_runtime_policy_configuration_is_all_or_nothing_and_fake_is_synthetic_only(tmp_path: Path) -> None:
    database = tmp_path / ".local" / "database-url"
    database.parent.mkdir(parents=True)
    url = URL.create("postgresql+asyncpg", "runtime", "synthetic", "127.0.0.1", 55432, "redagent")
    database.write_text(url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    with pytest.raises(ApiRuntimeError, match="policy_runtime_configuration_incomplete"):
        build_runtime_app(tmp_path, env={
            "REDAGENT_DATABASE_URL_FILE": str(database),
            "REDAGENT_POLICY_PROFILE": "synthetic-local",
        })
    app = build_runtime_app(tmp_path, env={
        "REDAGENT_DATABASE_URL_FILE": str(database),
        "REDAGENT_POLICY_PROFILE": "synthetic-local",
        "REDAGENT_POLICY_PROVIDER": "fake",
    })
    assert app.state.policy_required is True


def test_enabled_r123_runtime_installs_stock_services_during_database_lifespan(
    tmp_path: Path,
) -> None:
    database = tmp_path / ".local" / "database-url"
    database.parent.mkdir(parents=True)
    url = URL.create(
        "postgresql+asyncpg",
        "runtime",
        "synthetic",
        "127.0.0.1",
        55432,
        "redagent",
    )
    database.write_text(url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    key = tmp_path / ".local" / "r123-signing.pem"
    key.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ))
    app = build_runtime_app(tmp_path, env={
        "REDAGENT_DATABASE_URL_FILE": str(database),
        "REDAGENT_STRATEGY_LOOP_MODE": "two_capability",
        "REDAGENT_R123_SIGNING_KEY_FILE": str(key),
        "REDAGENT_R123_SIGNING_KEY_ID": "r123-local-signing-v1",
        "REDAGENT_EVIDENCE_PROFILE": "synthetic-local",
        "REDAGENT_EVIDENCE_BACKEND": "local-append-only",
        "REDAGENT_EVIDENCE_LOCAL_ROOT": str(tmp_path / ".local" / "evidence"),
    })

    assert app.state.r123_status_service.mode.value == "disabled"
    with TestClient(app):
        assert app.state.r123_qualification_service is not None
        assert app.state.r123_status_service.mode.value == "two_capability"
        assert app.state.r123_campaign_status_owner is not None
        assert app.state.session_factory is not None
    assert app.state.r123_qualification_service is None
    assert app.state.r123_status_service.mode.value == "disabled"
    assert app.state.r123_campaign_status_owner is None


def _request(app, method: str, path: str, **kwargs) -> httpx.Response:
    async def send() -> httpx.Response:
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            return await client.request(method, path, **kwargs)

    return asyncio.run(send())
