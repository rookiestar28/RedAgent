"""Bounded, redirect-free HTTP transport for allowlisted OIDC provider endpoints."""

from __future__ import annotations

import json

import httpx

from redagent_platform.identity.bff import OidcProviderMetadata
from redagent_platform.identity.config import OidcProviderConfig


class OidcTransportError(RuntimeError):
    """Fixed-code provider transport failure without request or token disclosure."""


class HttpOidcTransport:
    def __init__(self, *, transport: httpx.AsyncBaseTransport | None = None) -> None:
        self._transport = transport

    async def discover(self, config: OidcProviderConfig) -> OidcProviderMetadata:
        payload = await self._json_get(config.discovery_url, config=config, maximum=64 * 1024)
        required = {"issuer", "authorization_endpoint", "token_endpoint", "jwks_uri"}
        if not required <= set(payload):
            raise OidcTransportError("oidc_discovery_invalid")
        try:
            return OidcProviderMetadata(
                issuer=_text(payload["issuer"], 500),
                authorization_endpoint=_text(payload["authorization_endpoint"], 1000),
                token_endpoint=_text(payload["token_endpoint"], 1000),
                jwks_uri=_text(payload["jwks_uri"], 1000),
                end_session_endpoint=(
                    _text(payload["end_session_endpoint"], 1000)
                    if payload.get("end_session_endpoint") is not None
                    else None
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise OidcTransportError("oidc_discovery_invalid") from exc

    async def exchange_code(
        self,
        config: OidcProviderConfig,
        metadata: OidcProviderMetadata,
        *,
        code: str,
        code_verifier: str,
    ) -> dict[str, object]:
        if config.token_endpoint_auth_method != "none":
            raise OidcTransportError("oidc_client_auth_not_configured")
        if not code or len(code) > 4096 or not 43 <= len(code_verifier) <= 128:
            raise OidcTransportError("oidc_exchange_input_invalid")
        try:
            async with httpx.AsyncClient(
                timeout=config.http_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                async with client.stream(
                    "POST",
                    metadata.token_endpoint,
                    data={
                        "grant_type": "authorization_code",
                        "client_id": config.client_id,
                        "code": code,
                        "redirect_uri": config.redirect_uri,
                        "code_verifier": code_verifier,
                    },
                    headers={"Accept": "application/json"},
                ) as response:
                    return await _stream_json(response, maximum=64 * 1024)
        except OidcTransportError:
            raise
        except Exception as exc:
            # CRITICAL: HTTP exceptions may contain authorization codes or response bodies; expose only a fixed code.
            raise OidcTransportError("oidc_token_endpoint_failed") from exc

    async def jwks(
        self, config: OidcProviderConfig, metadata: OidcProviderMetadata
    ) -> dict[str, object]:
        payload = await self._json_get(metadata.jwks_uri, config=config, maximum=256 * 1024)
        keys = payload.get("keys")
        if not isinstance(keys, list) or not keys or len(keys) > 100:
            raise OidcTransportError("oidc_jwks_invalid")
        return payload

    async def _json_get(
        self,
        url: str,
        *,
        config: OidcProviderConfig,
        maximum: int,
    ) -> dict[str, object]:
        try:
            async with httpx.AsyncClient(
                timeout=config.http_timeout_seconds,
                follow_redirects=False,
                trust_env=False,
                transport=self._transport,
            ) as client:
                async with client.stream("GET", url, headers={"Accept": "application/json"}) as response:
                    return await _stream_json(response, maximum=maximum)
        except OidcTransportError:
            raise
        except Exception as exc:
            raise OidcTransportError("oidc_provider_request_failed") from exc


async def _stream_json(response: httpx.Response, *, maximum: int) -> dict[str, object]:
    if response.status_code != 200:
        raise OidcTransportError("oidc_provider_response_invalid")
    declared = response.headers.get("content-length")
    if declared is not None and (not declared.isdigit() or int(declared) > maximum):
        raise OidcTransportError("oidc_provider_response_invalid")
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"application/json", "application/jwk-set+json"}:
        raise OidcTransportError("oidc_provider_content_type_invalid")
    content = bytearray()
    async for chunk in response.aiter_bytes():
        content.extend(chunk)
        if len(content) > maximum:
            raise OidcTransportError("oidc_provider_response_invalid")
    try:
        payload = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise OidcTransportError("oidc_provider_json_invalid") from exc
    if not isinstance(payload, dict):
        raise OidcTransportError("oidc_provider_json_invalid")
    return payload


def _text(value: object, maximum: int) -> str:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError("oidc_metadata_text_invalid")
    return value
