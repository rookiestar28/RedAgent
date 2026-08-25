"""Benign deterministic target for the single certified R105 finding."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from urllib.parse import urlsplit


class Handler(BaseHTTPRequestHandler):
    server_version = "RedAgentR105Fixture/1.0"

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        if parsed.query or parsed.path != "/nuclei/missing-header":
            self._send(404, b"not-found", "text/plain; charset=utf-8")
            return
        self._send(200, b"r105-owned-benign-fixture", "text/plain; charset=utf-8")

    def _deny_method(self) -> None:
        self._send(405, b"method-denied", "text/plain; charset=utf-8")

    do_HEAD = _deny_method
    do_POST = _deny_method
    do_PUT = _deny_method
    do_PATCH = _deny_method
    do_DELETE = _deny_method
    do_OPTIONS = _deny_method
    do_CONNECT = _deny_method

    def log_message(self, format: str, *args: object) -> None:
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
