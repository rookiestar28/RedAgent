"""Repo-owned deterministic compat_108 provider emulator; never a general proxy."""

from __future__ import annotations

from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
import json
from urllib.parse import parse_qs, urlparse

from redagent_platform.cloud_connectors.contracts import ProviderProfile


@dataclass
class EmulatorScenario:
    profile: ProviderProfile
    identity_pages: dict[str, tuple[dict[str, object], ...]]
    redirect_identity: bool = False
    external_contact_count: int = 0
    mutation_attempt_count: int = 0
    request_count: int = 0

    @classmethod
    def for_profile(cls, profile: ProviderProfile, *, redirect_identity: bool = False) -> "EmulatorScenario":
        resources = ({
            "resource_id": f"{profile.provider.value}:{profile.expected_identity.tenant}:resource-1",
            "encryption_enabled": profile.provider.value != "kubernetes",
            "mfa_required": True,
            "read_only_root_filesystem": profile.provider.value == "kubernetes",
        },)
        return cls(
            profile=profile,
            identity_pages={profile.operations[0].operation_id: resources},
            redirect_identity=redirect_identity,
        )


class EmulatorHandler(BaseHTTPRequestHandler):
    scenario: EmulatorScenario
    server_version = "RedAgentR108Emulator/1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler contract
        self.scenario.request_count += 1
        if self.headers.get("X-RedAgent-Lease-Reference") != "lease-r108":
            self._json(HTTPStatus.FORBIDDEN, {"error": "lease_reference_denied"})
            return
        parsed = urlparse(self.path)
        if parsed.path == "/identity":
            if self.scenario.redirect_identity:
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "http://127.0.0.1:1/forbidden")
                self.end_headers()
                return
            identity = self.scenario.profile.expected_identity
            self._json(HTTPStatus.OK, {"provider": identity.provider.value, "tenant": identity.tenant, "parent": identity.parent})
            return
        prefix = "/operations/"
        if not parsed.path.startswith(prefix):
            self._json(HTTPStatus.NOT_FOUND, {"error": "operation_unknown"})
            return
        operation_id = parsed.path.removeprefix(prefix)
        if operation_id not in self.scenario.identity_pages:
            self._json(HTTPStatus.FORBIDDEN, {"error": "operation_denied"})
            return
        cursor_values = parse_qs(parsed.query).get("cursor", [])
        index = int(cursor_values[0]) if cursor_values else 0
        resources = self.scenario.identity_pages[operation_id]
        self._json(HTTPStatus.OK, {
            "operation_id": operation_id,
            "page_index": index,
            "next_cursor": None,
            "resources": list(resources),
            "partial_reason": None,
        })

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler contract
        self.scenario.mutation_attempt_count += 1
        self._json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "mutation_denied"})

    def log_message(self, _format: str, *args: object) -> None:
        return

    def _json(self, status: HTTPStatus, value: dict[str, object]) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
