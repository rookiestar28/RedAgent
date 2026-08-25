from __future__ import annotations

import asyncio
import json

import pytest

from redagent_platform.secret_service.providers import (
    OpenBaoSecretProvider,
    ProviderCapabilityError,
    ProviderLeaseStatus,
    SecretRoleMapping,
    SECRET_PROVIDER_CONTRACT_VERSION,
    SecretProvider,
)


class Response:
    def __init__(self, status_code: int, payload: dict[str, object] | None = None) -> None:
        self.status_code = status_code
        self.content = json.dumps(payload or {}).encode("utf-8")

    def json(self):
        return json.loads(self.content)


class Client:
    def __init__(self, responses: list[Response]) -> None:
        self.responses = responses
        self.calls: list[tuple[str, str, dict[str, object]]] = []

    async def request(self, method: str, url: str, **kwargs):
        self.calls.append((method, url, kwargs))
        return self.responses.pop(0)


def mapping() -> SecretRoleMapping:
    return SecretRoleMapping(
        role_reference="role:database-readonly-v1",
        issue_path="database/creds/redagent-readonly",
        material_fields=("username", "password"),
        max_ttl_seconds=600,
    )


def provider(client: Client, *, endpoint: str = "https://bao.example.test") -> OpenBaoSecretProvider:
    return OpenBaoSecretProvider(
        client,
        endpoint=endpoint,
        token_source=lambda: "synthetic-narrow-app-token",  # pragma: allowlist secret
        role_mappings={mapping().role_reference: mapping()},
        minimum_version=(2, 5, 5),
    )


def test_capability_check_requires_health_seal_version_and_two_audits() -> None:
    client = Client([
        Response(200, {"initialized": True, "sealed": False, "standby": False, "version": "2.5.5"}),
        Response(200, {"initialized": True, "sealed": False, "version": "2.5.5"}),
        Response(200, {"data": {"file-a/": {"type": "file"}, "file-b/": {"type": "file"}}}),
    ])
    capabilities = asyncio.run(provider(client).assess_capabilities())
    assert capabilities.production_ready is True
    assert capabilities.audit_device_count == 2
    assert client.calls[0][1] == "https://bao.example.test/v1/sys/health?standbyok=true"
    assert "X-Vault-Token" not in client.calls[0][2]["headers"]
    assert client.calls[2][2]["headers"]["X-Vault-Token"] == "synthetic-narrow-app-token"  # pragma: allowlist secret


def test_capability_check_fails_closed_for_seal_old_version_or_audit_gap() -> None:
    cases = (
        ({"initialized": True, "sealed": True, "standby": False, "version": "2.5.5"}, "openbao_sealed"),
        ({"initialized": True, "sealed": False, "standby": False, "version": "2.5.4"}, "openbao_version_unsupported"),
    )
    for health, reason in cases:
        with pytest.raises(ProviderCapabilityError, match=reason):
            asyncio.run(provider(Client([Response(200, health)])).assess_capabilities())
    with pytest.raises(ProviderCapabilityError, match="openbao_multiple_audit_devices_required"):
        asyncio.run(provider(Client([
            Response(200, {"initialized": True, "sealed": False, "standby": False, "version": "2.5.5"}),
            Response(200, {"initialized": True, "sealed": False, "version": "2.5.5"}),
            Response(200, {"data": {"file-a/": {"type": "file"}}}),
        ])).assess_capabilities())


def test_issue_uses_configured_path_and_reduces_response_to_redacted_envelope() -> None:
    client = Client([Response(200, {
        "lease_id": "database/creds/redagent-readonly/opaque-1",
        "lease_duration": 300,
        "renewable": True,
        "data": {"username": "synthetic-user", "password": "synthetic-canary"},  # pragma: allowlist secret
    })])
    envelope = asyncio.run(provider(client).issue("role:database-readonly-v1"))
    assert client.calls[0][0:2] == ("GET", "https://bao.example.test/v1/database/creds/redagent-readonly")
    assert client.calls[0][2]["headers"]["X-Vault-Request"] == "true"
    assert "synthetic-canary" not in repr(envelope)  # pragma: allowlist secret
    with envelope.material.expose_once() as fields:
        assert bytes(fields["username"]) == b"synthetic-user"
        assert bytes(fields["password"]) == b"synthetic-canary"  # pragma: allowlist secret
    assert envelope.material.cleared


def test_renew_lookup_and_exact_sync_revoke_use_only_current_lease_endpoints() -> None:
    client = Client([
        Response(200, {"lease_id": "lease/opaque-1", "lease_duration": 120, "renewable": True}),
        Response(200, {"data": {"ttl": 110, "renewable": True}}),
        Response(204),
    ])
    adapter = provider(client)
    renewed = asyncio.run(adapter.renew("lease/opaque-1", increment_seconds=120))
    status = asyncio.run(adapter.lookup_status("lease/opaque-1"))
    asyncio.run(adapter.revoke_sync("lease/opaque-1"))
    assert renewed.duration_seconds == 120 and renewed.renewable
    assert status == ProviderLeaseStatus(active=True, ttl_seconds=110, renewable=True)
    assert [(method, url.removeprefix("https://bao.example.test/v1")) for method, url, _ in client.calls] == [
        ("POST", "/sys/leases/renew"),
        ("POST", "/sys/leases/lookup"),
        ("POST", "/sys/leases/revoke"),
    ]
    assert client.calls[2][2]["json"] == {"lease_id": "lease/opaque-1", "sync": True}
    rendered = str(client.calls)
    for forbidden in ("/sys/renew", "/sys/revoke", "revoke-prefix", "revoke-force", "/tidy"):
        assert forbidden not in rendered


def test_provider_errors_are_stable_and_never_include_response_body() -> None:
    client = Client([Response(503, {"errors": ["sensitive provider detail"]})])
    with pytest.raises(ProviderCapabilityError) as captured:
        asyncio.run(provider(client).issue("role:database-readonly-v1"))
    assert "sensitive provider detail" not in str(captured.value)


def test_fake_and_openbao_implement_versioned_closed_provider_contract() -> None:
    from redagent_platform.secret_service.fakes import DeterministicFakeSecretProvider

    assert SECRET_PROVIDER_CONTRACT_VERSION == "1.0"
    assert isinstance(DeterministicFakeSecretProvider(), SecretProvider)
    assert isinstance(provider(Client([])), SecretProvider)
