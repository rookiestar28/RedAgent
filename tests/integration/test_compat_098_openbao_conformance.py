from __future__ import annotations

import asyncio
import os
from pathlib import Path

import asyncpg
import httpx

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.secret_service.providers import OpenBaoSecretProvider, load_role_mappings


ROOT = Path(__file__).resolve().parents[2]
RUNTIME = ROOT / ".local" / "redagent" / "openbao"


def test_real_openbao_dynamic_lease_renew_exact_revoke_and_audit_readiness() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    database = load_database_settings(ROOT, env=os.environ)
    assert database.url.port is not None
    token_file = RUNTIME / "app-token"
    mapping_file = RUNTIME / "role-mappings.json"
    assert token_file.is_file() and mapping_file.is_file(), "run scripts/openbao_conformance.py provision"
    async with httpx.AsyncClient(timeout=10) as client:
        provider = OpenBaoSecretProvider(
            client,
            endpoint="http://127.0.0.1:58200",
            token_source=lambda: token_file.read_text(encoding="utf-8").strip(),
            role_mappings=load_role_mappings(mapping_file),
            minimum_version=(2, 5, 5),
        )
        capabilities = await provider.assess_capabilities()
        assert capabilities.version == "2.5.5"
        assert capabilities.audit_device_count == 2
        assert capabilities.production_ready is False
        denied_paths = [
            "sys/mounts", "sys/policies/acl/redagent-r098", "sys/audit/x",
            "sys/leases/revoke-prefix/x", "sys/leases/revoke-force/x", "sys/leases/tidy", "sys/seal",
        ]
        capability_response = await client.post(
            "http://127.0.0.1:58200/v1/sys/capabilities-self",
            headers={"X-Vault-Request": "true", "X-Vault-Token": token_file.read_text(encoding="utf-8").strip()},
            json={"paths": denied_paths},
        )
        assert capability_response.status_code == 200
        assert capability_response.json()["data"] == {path: ["deny"] for path in denied_paths}

        envelope = await provider.issue("role:database-readonly-v1")
        lease_reference = envelope.provider_lease_reference
        assert lease_reference.startswith("database/creds/redagent-r098/")
        try:
            with envelope.material.expose_once() as material:
                username = bytes(material["username"]).decode("utf-8")
                password = bytes(material["password"]).decode("utf-8")  # pragma: allowlist secret
                connection = await asyncpg.connect(
                    host="127.0.0.1", port=database.url.port, database="redagent",
                    user=username, password=password, timeout=5,
                )
                try:
                    assert await connection.fetchval("SELECT 1") == 1
                finally:
                    await connection.close()
        finally:
            assert envelope.material.cleared

        renewed = await provider.renew(lease_reference, increment_seconds=120)
        assert renewed.duration_seconds > 0 and renewed.renewable
        active = await provider.lookup_status(lease_reference)
        assert active.active and active.ttl_seconds > 0
        await provider.revoke_sync(lease_reference)
        revoked = await provider.lookup_status(lease_reference)
        assert not revoked.active
        # Exact duplicate revoke is accepted; no prefix/force endpoint is exposed by the adapter.
        await provider.revoke_sync(lease_reference)
