from __future__ import annotations

import json
from pathlib import Path

import pytest

from redagent_platform.identity.config import IdentityConfigError, load_oidc_provider_config
from redagent_platform.local_stack_config import load_local_stack_config


ROOT = Path(__file__).resolve().parents[2]


def _provider(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "provider_id": "local-keycloak",
        "issuer": "http://127.0.0.1:18080/realms/redagent-local",
        "discovery_url": "http://127.0.0.1:18080/realms/redagent-local/.well-known/openid-configuration",
        "client_id": "redagent-local-bff",
        "audience": "redagent-local-bff",
        "redirect_uri": "https://127.0.0.1:58000/auth/callback",
        "post_logout_redirect_uri": "https://127.0.0.1:58000/auth/logged-out",
        "allowed_algorithms": ["RS256"],
        "scopes": ["openid", "profile", "email"],
        "tenant_claim": "redagent_tenant",
        "roles_claim_path": ["realm_access", "roles"],
        "token_endpoint_auth_method": "none",
        "clock_skew_seconds": 30,
        "http_timeout_seconds": 5,
    }
    values.update(overrides)
    return values


def _write(tmp_path: Path, provider: dict[str, object]) -> Path:
    path = tmp_path / "config" / "identity-providers.json"
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema_version": "1.0", "providers": [provider]}), encoding="utf-8")
    return path


def test_oidc_provider_config_is_exact_and_secret_free(tmp_path: Path) -> None:
    path = _write(tmp_path, _provider())

    config = load_oidc_provider_config(tmp_path, path, provider_id="local-keycloak")

    assert config.issuer == "http://127.0.0.1:18080/realms/redagent-local"
    assert config.redirect_uri == "https://127.0.0.1:58000/auth/callback"
    assert config.allowed_algorithms == ("RS256",)
    assert config.scopes[0] == "openid"
    assert "secret" not in repr(config).lower()


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("redirect_uri", "https://127.0.0.1:58000/*", "oidc_redirect_uri_invalid"),
        ("redirect_uri", "https://127.0.0.1:58000/auth/callback?next=x", "oidc_redirect_uri_invalid"),
        ("issuer", "http://idp.example.com/realms/redagent", "oidc_https_required"),
        ("discovery_url", "https://attacker.invalid/.well-known/openid-configuration", "oidc_discovery_mismatch"),
        ("allowed_algorithms", ["none"], "oidc_algorithm_forbidden"),
        ("scopes", ["profile"], "oidc_openid_scope_required"),
        ("token_endpoint_auth_method", "client_secret_post", "oidc_auth_method_forbidden"),
    ],
)
def test_oidc_provider_config_rejects_wildcards_downgrade_and_unsafe_flows(
    tmp_path: Path,
    field: str,
    value: object,
    error: str,
) -> None:
    path = _write(tmp_path, _provider(**{field: value}))

    with pytest.raises(IdentityConfigError, match=error):
        load_oidc_provider_config(tmp_path, path, provider_id="local-keycloak")


def test_repo_keycloak_fixture_uses_exact_bff_redirect_and_forbids_legacy_flows() -> None:
    realm = json.loads((ROOT / "config" / "keycloak" / "redagent-local-realm.json").read_text(encoding="utf-8"))
    client = realm["clients"][0]

    assert client["clientId"] == "redagent-local-bff"
    assert client["redirectUris"] == ["https://127.0.0.1:58000/auth/callback"]
    assert client["webOrigins"] == ["https://127.0.0.1:58000"]
    assert client["standardFlowEnabled"] is True
    assert client["implicitFlowEnabled"] is False
    assert client["directAccessGrantsEnabled"] is False
    assert client["serviceAccountsEnabled"] is False
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert client["attributes"]["post.logout.redirect.uris"] == "https://127.0.0.1:58000/auth/logged-out"
    assert client["attributes"]["backchannel.logout.url"] == (
        "https://127.0.0.1:58000/auth/backchannel-logout/local-tenant"
    )
    mapper = client["protocolMappers"][0]
    assert mapper["protocolMapper"] == "oidc-hardcoded-claim-mapper"
    assert mapper["config"]["claim.name"] == "redagent_tenant"
    assert mapper["config"]["claim.value"] == "local-tenant"


def test_committed_identity_provider_config_matches_keycloak_fixture() -> None:
    config = load_oidc_provider_config(
        ROOT,
        ROOT / "config" / "identity-providers.json",
        provider_id="local-keycloak",
    )
    realm = json.loads((ROOT / "config" / "keycloak" / "redagent-local-realm.json").read_text(encoding="utf-8"))
    client = realm["clients"][0]

    assert config.client_id == client["clientId"]
    assert config.redirect_uri == client["redirectUris"][0]
    assert config.post_logout_redirect_uri == client["attributes"]["post.logout.redirect.uris"]


def test_committed_identity_provider_config_uses_default_local_keycloak_endpoint() -> None:
    config = load_oidc_provider_config(
        ROOT,
        ROOT / "config" / "identity-providers.json",
        provider_id="local-keycloak",
    )
    local_stack = load_local_stack_config(ROOT, env={})

    assert config.issuer == (
        f"http://{local_stack.bind_host}:{local_stack.keycloak_port}/realms/redagent-local"
    )
    assert config.discovery_url == config.issuer + "/.well-known/openid-configuration"
