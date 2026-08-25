"""Repo-owned compat_109 SaaS emulator with no external routing capability."""

from __future__ import annotations

from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
import json
from urllib.parse import parse_qs, urlparse

from redagent_platform.identity_saas.contracts import IdentityProviderProfile


@dataclass
class IdentityEmulatorScenario:
    profile: IdentityProviderProfile; pages: dict[str, tuple[dict[str, object], ...]]
    tenant_id: str; audience: str; consent_mode: str; redirect_binding: bool = False
    external_contact_count: int = 0; mutation_attempt_count: int = 0; request_count: int = 0

    @classmethod
    def for_profile(cls, profile: IdentityProviderProfile) -> "IdentityEmulatorScenario":
        operation = profile.operations[0]
        defaults = {"id": f"{profile.provider.value}-resource-r109", "displayName": "Synthetic tenant", "tenantType": "AAD",
            "name": "Synthetic group", "directMembersCount": "2", "type": "OKTA_GROUP", "created": "2026-07-11T00:00:00Z"}
        resource = {field: defaults[field] for field in operation.selected_fields}
        return cls(profile=profile, pages={operation.operation_id: (resource,)}, tenant_id=profile.tenant_id,
            audience=profile.audience, consent_mode=profile.consent_mode.value)


class IdentityEmulatorHandler(BaseHTTPRequestHandler):
    scenario: IdentityEmulatorScenario
    server_version = "RedAgentR109IdentityEmulator/1"

    def do_GET(self) -> None:  # noqa: N802
        self.scenario.request_count += 1
        if self.headers.get("X-RedAgent-Lease-Reference") != "lease-r109": return self._json(HTTPStatus.FORBIDDEN, {"error": "lease_reference_denied"})
        parsed = urlparse(self.path)
        if parsed.path == "/binding":
            if self.scenario.redirect_binding:
                self.send_response(HTTPStatus.FOUND); self.send_header("Location", "http://127.0.0.1:1/forbidden"); self.end_headers(); return
            return self._json(HTTPStatus.OK, {"provider": self.scenario.profile.provider.value, "tenant_id": self.scenario.tenant_id, "audience": self.scenario.audience, "consent_mode": self.scenario.consent_mode})
        if not parsed.path.startswith("/operations/"): return self._json(HTTPStatus.NOT_FOUND, {"error": "operation_unknown"})
        operation_id = parsed.path.removeprefix("/operations/")
        if operation_id not in self.scenario.pages: return self._json(HTTPStatus.FORBIDDEN, {"error": "operation_denied"})
        cursor = parse_qs(parsed.query).get("cursor", []); index = int(cursor[0]) if cursor else 0
        return self._json(HTTPStatus.OK, {"operation_id": operation_id, "page_index": index, "next_cursor": None,
            "resources": list(self.scenario.pages[operation_id]), "partial_reason": None})

    def do_POST(self) -> None:  # noqa: N802
        self.scenario.mutation_attempt_count += 1; self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "mutation_denied"})

    def log_message(self, _format: str, *args: object) -> None: return

    def _json(self, status: HTTPStatus, value: dict[str, object]) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode(); self.send_response(status)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
