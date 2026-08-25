"""Owned deterministic dual-tenant API fixture for R106 authorization differentials."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import threading
from urllib.parse import urlsplit


_LOCK = threading.Lock()
_DOCUMENTS = {
    "document-owner-a": {"id": "document-owner-a", "tenant_id": "tenant-a", "owner_id": "user-a", "title": "Owner A document"},
    "document-safe-a": {"id": "document-safe-a", "tenant_id": "tenant-a", "owner_id": "user-a", "title": "Safe authorization document"},
}
_PROFILES = {
    "user-a": {"id": "user-a", "tenant_id": "tenant-a", "display_name": "Owner A", "internal_note": "synthetic restricted note"},
}


class Handler(BaseHTTPRequestHandler):
    server_version = "RedAgentR106Fixture/1.0"

    def do_GET(self) -> None:  # noqa: N802
        principal = self._principal()
        if principal is None:
            return
        path = urlsplit(self.path).path
        if path.startswith("/documents/") and path.count("/") == 2:
            self._get_document(path.rsplit("/", 1)[1], principal)
        elif path.startswith("/profiles/") and path.count("/") == 2:
            self._get_profile(path.rsplit("/", 1)[1], principal)
        elif path == "/admin/audit":
            # Deliberate local-only BFLA oracle: a peer receives the admin representation.
            self._send_json(200, {"events": 1, "scope": "synthetic-audit"})
        else:
            self._send_json(404, {"error": "not_found"})

    def do_POST(self) -> None:  # noqa: N802
        principal = self._principal()
        if principal is None:
            return
        path = urlsplit(self.path).path
        if path == "/documents":
            body = self._json_body()
            if body is None or not isinstance(body.get("title"), str) or not body["title"]:
                self._send_json(400, {"error": "invalid_document"})
                return
            key = self.headers.get("X-R106-Idempotency-Key", "")
            if not key or len(key) > 150:
                self._send_json(400, {"error": "idempotency_required"})
                return
            resource_id = f"generated-{hashlib.sha256(key.encode()).hexdigest()[:12]}"
            document = {
                "id": resource_id, "tenant_id": principal["tenant_id"],
                "owner_id": principal["user_id"], "title": body["title"][:100],
            }
            with _LOCK:
                _DOCUMENTS.setdefault(resource_id, document)
            self._send_json(201, document)
            return
        if path.startswith("/documents/") and path.endswith("/transfer"):
            resource_id = path.split("/")[2]
            body = self._json_body()
            if body is None or not isinstance(body.get("new_owner_id"), str):
                self._send_json(400, {"error": "invalid_transfer"})
                return
            with _LOCK:
                document = _DOCUMENTS.get(resource_id)
                if document is None:
                    self._send_json(404, {"error": "not_found"})
                    return
                if document["tenant_id"] != principal["tenant_id"] or document["owner_id"] != principal["user_id"]:
                    self._send_json(403, {"error": "forbidden"})
                    return
                document["owner_id"] = body["new_owner_id"]
                response = dict(document)
            self._send_json(200, response)
            return
        self._send_json(404, {"error": "not_found"})

    def do_DELETE(self) -> None:  # noqa: N802
        principal = self._principal()
        if principal is None:
            return
        path = urlsplit(self.path).path
        if not path.startswith("/documents/") or path.count("/") != 2:
            self._send_json(404, {"error": "not_found"})
            return
        resource_id = path.rsplit("/", 1)[1]
        with _LOCK:
            document = _DOCUMENTS.get(resource_id)
            if document is None:
                self._send_json(404, {"error": "not_found"})
                return
            if document["tenant_id"] != principal["tenant_id"] or document["owner_id"] != principal["user_id"]:
                self._send_json(403, {"error": "forbidden"})
                return
            if resource_id.startswith("generated-"):
                del _DOCUMENTS[resource_id]
        self.send_response(204)
        self.send_header("Cache-Control", "no-store")
        self.end_headers()

    def _get_document(self, resource_id: str, principal: dict[str, str]) -> None:
        with _LOCK:
            document = _DOCUMENTS.get(resource_id)
            response = None if document is None else dict(document)
        if response is None or response["tenant_id"] != principal["tenant_id"]:
            self._send_json(404, {"error": "not_found"})
            return
        if response["owner_id"] != principal["user_id"] and principal["role"] != "tenant_admin":
            if resource_id == "document-safe-a":
                self._send_json(404, {"error": "not_found"})
                return
            # Deliberate local-only BOLA oracle for document-owner-a.
        response.pop("tenant_id", None)
        self._send_json(200, response)

    def _get_profile(self, profile_id: str, principal: dict[str, str]) -> None:
        profile = _PROFILES.get(profile_id)
        if profile is None or profile["tenant_id"] != principal["tenant_id"]:
            self._send_json(404, {"error": "not_found"})
            return
        response = dict(profile)
        response.pop("tenant_id", None)
        # Deliberate local-only BOPLA oracle: peers also receive internal_note.
        self._send_json(200, response)

    def _principal(self) -> dict[str, str] | None:
        if self.headers.get("X-R106-Gateway-Marker") != "r106-owned-gateway":
            self._send_json(403, {"error": "gateway_required"})
            return None
        state = self.headers.get("X-R106-Identity-State", "")
        if state in {"anonymous", "expired", "revoked"}:
            self._send_json(401, {"error": "session_inactive"})
            return None
        values = {
            "tenant_id": self.headers.get("X-R106-Tenant", ""),
            "user_id": self.headers.get("X-R106-User", ""),
            "role": self.headers.get("X-R106-Role", ""),
        }
        if any(not value for value in values.values()):
            self._send_json(401, {"error": "identity_required"})
            return None
        return values

    def _json_body(self) -> dict[str, object] | None:
        try:
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 16 * 1024 or self.headers.get_content_type() != "application/json":
                return None
            value = json.loads(self.rfile.read(size))
            return value if isinstance(value, dict) else None
        except (OSError, ValueError, json.JSONDecodeError):
            return None

    def _send_json(self, status: int, value: object) -> None:
        body = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: object) -> None:
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
