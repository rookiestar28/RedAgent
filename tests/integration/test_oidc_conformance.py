from __future__ import annotations

import asyncio
from pathlib import Path

from redagent_platform.identity.config import load_oidc_provider_config
from redagent_platform.local_stack import effective_runtime_config
from redagent_platform.identity.http_transport import HttpOidcTransport
from redagent_platform.local_stack_config import load_local_stack_config


ROOT = Path(__file__).resolve().parents[2]


def test_live_local_keycloak_discovery_jwks_and_exact_endpoint_conformance() -> None:
    asyncio.run(_local_keycloak_conformance())


async def _local_keycloak_conformance() -> None:
    configured_stack = load_local_stack_config(ROOT)
    runtime_env = configured_stack.state_dir / "runtime" / "local-stack.env"
    effective_stack = effective_runtime_config(configured_stack, runtime_env)
    runtime_config = effective_stack.state_dir / "runtime" / "identity-providers.json"
    assert runtime_config.is_file(), "local_stack_runtime_oidc_config_missing"
    config = load_oidc_provider_config(
        ROOT,
        runtime_config,
        provider_id="local-keycloak",
    )
    assert config.issuer == (
        f"http://{effective_stack.bind_host}:{effective_stack.keycloak_port}/realms/redagent-local"
    )
    transport = HttpOidcTransport()
    metadata = await transport.discover(config)

    assert metadata.issuer == config.issuer
    assert metadata.authorization_endpoint.startswith(config.issuer + "/")
    assert metadata.token_endpoint.startswith(config.issuer + "/")
    assert metadata.jwks_uri.startswith(config.issuer + "/")
    assert metadata.end_session_endpoint is not None
    jwks = await transport.jwks(config, metadata)
    assert jwks["keys"]
    assert all(key.get("kty") == "RSA" for key in jwks["keys"])
