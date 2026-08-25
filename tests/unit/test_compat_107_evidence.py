from redagent_platform.network_service.connector import (
    CleanupReceipt,
    ConnectionState,
    NetworkExecutionResult,
    NetworkObservation,
)
from redagent_platform.network_service.evidence import project_execution_evidence


def result() -> NetworkExecutionResult:
    return NetworkExecutionResult(
        run_id="run-r107", plan_sha256="a" * 64,
        observations=(NetworkObservation(
            tuple_id="tuple-r107", ip="10.107.0.10", port=8080,
            state=ConnectionState.OPEN, latency_bucket="lt_10ms", service_class="http",
            sample_sha256="b" * 64, uncertainty="low", reason="network_connect_open",
        ),),
        completed_count=1, denied_count=0, total_count=1,
        partial=False, cancelled=False, cancellation=None,
        cleanup=CleanupReceipt(residual_resource_count=0, transient_data_erased=True),
    )


def test_network_evidence_is_deterministic_bounded_and_hash_only() -> None:
    first = project_execution_evidence(result())
    second = project_execution_evidence(result())
    assert first == second
    assert len(first.content) < 64 * 1024
    assert first.redaction_state == "redacted-hash-only"
    assert first.classification == "confidential"
    text = first.content.decode()
    assert "tuple-r107" in text and "10.107.0.10" in text
    assert "HTTP/1.1" not in text and "Server:" not in text
    assert "password" not in text.lower() and "authorization" not in text.lower()
