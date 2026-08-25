"""Deterministic, benign R103 local-lab HTTP fixture."""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
from pathlib import Path


SCHEMA = "redagent.local-lab/v1"
SEED = "r103-synthetic-seed-v1"


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


GOLDEN = json.loads(Path("/app/r103-golden-findings.json").read_text(encoding="utf-8"))
EXPECTED = GOLDEN["expectations"]
MANIFEST = {
    "schema": SCHEMA,
    "bundle_id": "r103-synthetic-lab",
    "revision": 1,
    "non_production": True,
    "synthetic_data_revision": SEED,
    "fixture_kinds": ["web", "api", "network", "identity", "artifact"],
    "allowed_test_classes": ["health", "happy_path", "authorization", "finding_mapping", "evidence", "redaction", "cancellation", "outage", "backup_restore", "migration"],
}
MANIFEST["expected_findings_sha256"] = hashlib.sha256(canonical(GOLDEN)).hexdigest()


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        routes = {
            "/health/ready": {"ok": True, "schema": SCHEMA, "non_production": True},
            "/api/v1/profile": {
                "schema": SCHEMA,
                "identity_id": "synthetic-operator-001",
                "display_name": "R103 Training Operator",
                "training_marker": True,
            },
            "/api/v1/expected-findings": {"schema": SCHEMA, "findings": EXPECTED},
            "/artifact/manifest": MANIFEST,
        }
        payload = routes.get(self.path)
        if payload is None:
            self._write(404, {"ok": False, "reason_code": "synthetic_route_not_found"})
            return
        self._write(200, payload)

    def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
        self._write(405, {"ok": False, "reason_code": "synthetic_fixture_read_only"})

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def _write(self, status: int, value: object) -> None:
        body = canonical(value)
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-RedAgent-Training", "r103-benign-synthetic")
        self.end_headers()
        self.wfile.write(body)


if __name__ == "__main__":
    server = ThreadingHTTPServer(("0.0.0.0", 8080), FixtureHandler)
    server.serve_forever()
