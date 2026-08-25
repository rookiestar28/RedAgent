#!/usr/bin/env python3
"""Run bounded SDK -> digest-pinned Collector -> fixed loopback OTLP conformance."""

from __future__ import annotations

from datetime import datetime, timezone
import gzip
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import queue
import subprocess
import sys
from threading import Thread
import time
from urllib.request import urlopen
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
# IMPORTANT: direct execution places scripts/ on sys.path; keep repo imports deterministic.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.proto.collector.trace.v1.trace_service_pb2 import (
    ExportTraceServiceRequest, ExportTraceServiceResponse,
)
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor

from redagent_platform.telemetry_service.contracts import (
    TELEMETRY_SCHEMA, ResourceType, ServiceName, SignalKind, SignalOutcome, TelemetryEnvelope,
)
from redagent_platform.telemetry_service.sdk import OpenTelemetrySink


RECEIPTS: queue.Queue[bytes] = queue.Queue(maxsize=4)


class ConformanceError(RuntimeError):
    pass


class _Receiver(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("content-length", "0"))
        if self.path != "/v1/traces" or not 0 < length <= 64 * 1024:
            self.send_error(400)
            return
        body = self.rfile.read(length)
        if self.headers.get("content-encoding", "").lower() == "gzip":
            body = gzip.decompress(body)
        RECEIPTS.put_nowait(body)
        response = ExportTraceServiceResponse().SerializeToString()
        self.send_response(200)
        self.send_header("Content-Type", "application/x-protobuf")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, _format: str, *args: object) -> None:
        return


def conformance() -> dict[str, object]:
    lock = json.loads((ROOT / "config" / "otel-collector-conformance-image.json").read_text(encoding="utf-8"))
    image = str(lock["reference"])
    name = f"redagent-r102-otel-{uuid4().hex[:10]}"
    server = ThreadingHTTPServer(("127.0.0.1", 58432), _Receiver)
    Thread(target=server.serve_forever, daemon=True).start()
    try:
        inspect = _docker("image", "inspect", image, "--format", "{{index .RepoDigests 0}}")
        if str(lock["index_digest"]) not in inspect:
            raise ConformanceError("collector_image_digest_mismatch")
        config = ROOT / "config" / "otel-collector" / "collector-conformance.yaml"
        _docker(
            "run", "--detach", "--name", name, "--read-only", "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges:true", "--memory", "256m",
            "--pids-limit", "128", "--cpus", "0.5", "--tmpfs", "/tmp",
            "--add-host", "host.docker.internal:host-gateway",
            "--publish", "127.0.0.1:58431:4317", "--publish", "127.0.0.1:51318:13133",
            "--volume", f"{config}:/etc/otelcol-contrib/config.yaml:ro",
            image, "--config=/etc/otelcol-contrib/config.yaml",
        )
        _wait_health(name)
        exporter = OTLPSpanExporter(endpoint="127.0.0.1:58431", insecure=True, timeout=3)
        provider = TracerProvider()
        provider.add_span_processor(SimpleSpanProcessor(exporter))
        envelope = TelemetryEnvelope(
            schema=TELEMETRY_SCHEMA, event_id="event-r102-live", tenant_id="tenant-r102-live",
            correlation_id="correlation-r102-live", trace_id="5" * 32, span_id="6" * 16,
            parent_span_id=None, sampled=True, kind=SignalKind.EVENT,
            service_name=ServiceName.CONTAINMENT, service_version="0.1.0",
            service_instance_id="containment-live-1", resource_type=ResourceType.INCIDENT,
            resource_id="incident-r102-live", operation="containment.incident.opened",
            outcome=SignalOutcome.FAILURE, reason_code="containment_incomplete",
            occurred_at=datetime.now(timezone.utc), duration_ms=9,
            measurement_name=None, measurement_value=None,
        )
        OpenTelemetrySink(provider=provider).emit(envelope)
        body = RECEIPTS.get(timeout=10)
        request = ExportTraceServiceRequest.FromString(body)
        attributes = _attributes(request)
        expected = {
            "redagent.schema": TELEMETRY_SCHEMA,
            "redagent.correlation.id": "correlation-r102-live",
            "service.name": "containment",
            "redagent.reason_code": "containment_incomplete",
        }
        if any(attributes.get(key) != value for key, value in expected.items()):
            raise ConformanceError("collector_attribute_contract_mismatch")
        serialized = json.dumps(attributes, sort_keys=True).lower()
        forbidden = ("authorization", "cookie", "password", "secret=", "token=", "prompt", "db.statement", "http.url")
        if any(marker in serialized for marker in forbidden):
            raise ConformanceError("collector_sensitive_value_leak")
        return {
            "ok": True, "schema": attributes["redagent.schema"],
            "correlation_id": attributes["redagent.correlation.id"],
            "service_name": attributes["service.name"], "attribute_count": len(attributes),
            "collector_digest": lock["index_digest"], "loopback_receiver": True,
            "read_only_root": True, "cap_drop": ["ALL"], "bounded_receipt_bytes": len(body),
        }
    finally:
        server.shutdown()
        subprocess.run(["docker", "rm", "--force", name], cwd=ROOT, capture_output=True, check=False)


def _attributes(request: ExportTraceServiceRequest) -> dict[str, object]:
    result: dict[str, object] = {}
    for resource_spans in request.resource_spans:
        for item in resource_spans.resource.attributes:
            result[item.key] = _value(item.value)
        for scope_spans in resource_spans.scope_spans:
            for span in scope_spans.spans:
                for item in span.attributes:
                    result[item.key] = _value(item.value)
    return result


def _value(value) -> object:
    field = value.WhichOneof("value")
    return getattr(value, field) if field else None


def _wait_health(name: str) -> None:
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        try:
            with urlopen("http://127.0.0.1:51318/", timeout=1) as response:  # noqa: S310
                if response.status == 200:
                    return
        except OSError:
            time.sleep(0.25)
        status = _docker("inspect", name, "--format", "{{.State.Status}}", check=False)
        if status.strip() == "exited":
            logs = _docker("logs", name, check=False)
            raise ConformanceError(f"collector_start_failed:{logs[-1000:]}")
    raise ConformanceError("collector_health_timeout")


def _docker(*args: str, check: bool = True) -> str:
    completed = subprocess.run(
        ["docker", *args], cwd=ROOT, text=True, capture_output=True, timeout=60, check=False,
    )
    if check and completed.returncode != 0:
        raise ConformanceError(f"docker_failed:{args[0]}:{completed.stderr.strip()[-1000:]}")
    return completed.stdout.strip()


if __name__ == "__main__":
    if sys.argv[1:] != ["conformance"]:
        raise SystemExit("usage: otel_conformance.py conformance")
    try:
        print(json.dumps(conformance(), sort_keys=True))
    except (ConformanceError, OSError, queue.Empty) as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(1) from exc
