"""Closed loopback-only HTTP transport for the repo-owned compat_108 emulator."""

from __future__ import annotations

import json
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlparse
from urllib.request import HTTPRedirectHandler, OpenerDirector, ProxyHandler, Request, build_opener

from redagent_platform.cloud_connectors.collector import CollectionPage
from redagent_platform.cloud_connectors.contracts import ProviderIdentity, ProviderKind


class _DenyRedirects(HTTPRedirectHandler):
    def redirect_request(self, req: Request, fp: object, code: int, msg: str, headers: object, newurl: str) -> None:
        return None


class ClosedHttpCollectionTransport:
    def __init__(
        self, *, endpoint: str, expected_port: int, lease_reference: str, max_response_bytes: int
    ) -> None:
        parsed = urlparse(endpoint)
        # CRITICAL: this transport is a qualification-only loopback client, never a provider URL passthrough.
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.port != expected_port
            or parsed.username is not None
            or parsed.password is not None
            or parsed.path not in {"", "/"}
            or parsed.query
            or parsed.fragment
        ):
            raise ValueError("cloud_emulator_endpoint_forbidden")
        if not isinstance(max_response_bytes, int) or max_response_bytes < 1:
            raise ValueError("cloud_response_budget_invalid")
        self.endpoint = endpoint.rstrip("/")
        self.lease_reference = lease_reference
        self.max_response_bytes = max_response_bytes
        self._opener: OpenerDirector = build_opener(ProxyHandler({}), _DenyRedirects())

    def verify_identity(self) -> ProviderIdentity:
        value = self._get("/identity")
        try:
            return ProviderIdentity(
                provider=ProviderKind(str(value["provider"])),
                tenant=str(value["tenant"]),
                parent=str(value["parent"]) if value.get("parent") is not None else None,
            )
        except (KeyError, ValueError, TypeError) as exc:
            raise ValueError("cloud_identity_response_invalid") from exc

    def fetch_page(self, *, operation_id: str, cursor: str | None) -> CollectionPage:
        query = "" if cursor is None else "?" + urlencode({"cursor": cursor})
        value = self._get(f"/operations/{quote(operation_id, safe='')}" + query)
        try:
            resources = value["resources"]
            if not isinstance(resources, list) or any(not isinstance(item, dict) for item in resources):
                raise TypeError
            return CollectionPage(
                operation_id=str(value["operation_id"]),
                page_index=int(value["page_index"]),
                next_cursor=str(value["next_cursor"]) if value.get("next_cursor") is not None else None,
                resources=tuple(resources),
                response_bytes=len(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()),
                partial_reason=str(value["partial_reason"]) if value.get("partial_reason") is not None else None,
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("cloud_page_response_invalid") from exc

    def _get(self, path: str) -> dict[str, object]:
        request = Request(
            self.endpoint + path,
            headers={"Accept": "application/json", "X-RedAgent-Lease-Reference": self.lease_reference},
            method="GET",
        )
        try:
            with self._opener.open(request, timeout=5) as response:
                body = response.read(self.max_response_bytes + 1)
        except HTTPError as exc:
            if 300 <= exc.code < 400:
                raise ValueError("cloud_http_redirect_denied") from exc
            raise ValueError(f"cloud_http_status_denied:{exc.code}") from exc
        if len(body) > self.max_response_bytes:
            raise ValueError("cloud_response_budget_exceeded")
        try:
            value = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("cloud_http_json_invalid") from exc
        if not isinstance(value, dict):
            raise ValueError("cloud_http_json_invalid")
        return value
