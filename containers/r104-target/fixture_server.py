"""Benign, deterministic R104 web qualification fixture."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


AUTH_FILE = Path("/run/redagent/r104-auth")
ROUTES = frozenset({
    "/health/ready", "/passive/missing-header", "/auth/protected",
    "/browser/start", "/browser/client-route", "/active/reflected-input",
})


class Handler(BaseHTTPRequestHandler):
    server_version = "RedAgentR104Fixture/1.0"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.path not in ROUTES:
            self._send(404, b"not-found", "text/plain; charset=utf-8")
            return
        if parsed.path == "/health/ready":
            self._json({"ok": True, "fixture": "r104-owned-web", "non_production": True})
        elif parsed.path == "/passive/missing-header":
            self._send(200, b"r104-passive-fixture", "text/plain; charset=utf-8")
        elif parsed.path == "/auth/protected":
            expected = AUTH_FILE.read_text(encoding="utf-8").strip() if AUTH_FILE.is_file() else ""
            supplied = self.headers.get("X-RedAgent-Lab-Auth", "")
            if not expected or supplied != expected:
                self._send(401, b"authorization-required", "text/plain; charset=utf-8")
            else:
                self._send(200, b"r104-authenticated-fixture", "text/plain; charset=utf-8")
        elif parsed.path == "/browser/start":
            body = (
                b"<!doctype html><html><body><a href='/browser/client-route'>client route</a>"
                b"<script>fetch('/browser/client-route')</script></body></html>"
            )
            self._send(200, body, "text/html; charset=utf-8")
        elif parsed.path == "/browser/client-route":
            self._json({"ok": True, "route": "browser-client-route"})
        else:
            reflected = parse_qs(parsed.query, keep_blank_values=True).get("q", [""])[0][:2048]
            body = f"<!doctype html><html><body>R104 reflected value: {reflected}</body></html>"
            # The fixture intentionally preserves text reflection for certified rule 40012 qualification.
            self._send(200, body.encode("utf-8"), "text/html; charset=utf-8")

    def do_HEAD(self) -> None:  # noqa: N802
        self.do_GET()

    def do_POST(self) -> None:  # noqa: N802
        self._send(405, b"method-denied", "text/plain; charset=utf-8")

    def log_message(self, format: str, *args: object) -> None:
        return

    def _json(self, value: object) -> None:
        self._send(200, json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8"), "application/json")

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
