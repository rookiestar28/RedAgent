from __future__ import annotations

from datetime import datetime, timedelta, timezone
import importlib

import pytest


NOW = datetime(2026, 7, 12, 2, 0, tzinfo=timezone.utc)


def _module(name: str):
    try:
        return importlib.import_module(f"redagent_platform.agent_kernel.{name}")
    except ModuleNotFoundError:
        pytest.fail(f"compat_113 RED: agent kernel module {name!r} is not implemented")


def test_working_memory_is_encrypted_tenant_scoped_bounded_and_expires() -> None:
    contracts = _module("contracts")
    memory = _module("memory")
    vault = memory.WorkingMemoryVault(key=b"k" * 32, max_plaintext_bytes=64)
    record = vault.put(
        tenant_id="tenant-a",
        memory_id="memory-1",
        plaintext=b"untrusted synthetic context",
        trust_label=contracts.TrustLabel.UNTRUSTED_TOOL,
        now=NOW,
        ttl=timedelta(minutes=5),
    )
    assert b"untrusted synthetic context" not in record.ciphertext
    assert "untrusted synthetic context" not in repr(record)
    assert vault.get(tenant_id="tenant-a", memory_id="memory-1", now=NOW + timedelta(minutes=1)) == b"untrusted synthetic context"
    with pytest.raises(ValueError, match="memory_tenant_mismatch"):
        vault.get(tenant_id="tenant-b", memory_id="memory-1", now=NOW)
    with pytest.raises(ValueError, match="memory_expired"):
        vault.get(tenant_id="tenant-a", memory_id="memory-1", now=NOW + timedelta(minutes=6))
    with pytest.raises(ValueError, match="memory_size_exceeded"):
        vault.put(
            tenant_id="tenant-a",
            memory_id="memory-2",
            plaintext=b"x" * 65,
            trust_label=contracts.TrustLabel.UNTRUSTED_MODEL,
            now=NOW,
            ttl=timedelta(minutes=1),
        )


def test_untrusted_output_cannot_become_reviewed_fact_without_independent_provenance_review() -> None:
    memory = _module("memory")
    with pytest.raises(ValueError, match="fact_review_separation_required"):
        memory.ReviewedFact.from_candidate(
            fact_id="fact-1",
            tenant_id="tenant-a",
            candidate_sha256="1" * 64,
            provenance_sha256="2" * 64,
            proposed_by="operator-a",
            reviewed_by="operator-a",
            reviewed_at=NOW,
            expires_at=NOW + timedelta(days=1),
        )
    fact = memory.ReviewedFact.from_candidate(
        fact_id="fact-1",
        tenant_id="tenant-a",
        candidate_sha256="1" * 64,
        provenance_sha256="2" * 64,
        proposed_by="operator-a",
        reviewed_by="operator-b",
        reviewed_at=NOW,
        expires_at=NOW + timedelta(days=1),
    )
    assert fact.trust_label == "reviewed_fact" and not hasattr(fact, "content")


def test_trace_envelope_is_digest_only_redacted_and_has_stable_otlp_projection() -> None:
    traces = _module("traces")
    envelope = traces.TraceEnvelope(
        trace_id="trace-1",
        span_id="span-1",
        parent_span_id=None,
        tenant_id="tenant-a",
        run_id="run-1",
        event_type="proposal.created",
        state="awaiting_approval",
        input_sha256="1" * 64,
        output_sha256="2" * 64,
        policy_decision_id="decision-1",
        approval_id=None,
        evidence_id=None,
        error_code=None,
        occurred_at=NOW,
    )
    rendered = repr(envelope).lower()
    for forbidden in ("prompt", "password", "credential", "raw_input", "reasoning", "tool_output"):
        assert forbidden not in rendered
    attrs = traces.to_otlp_attributes(envelope)
    assert attrs["gen_ai.operation.name"] == "proposal.created"
    assert attrs["redagent.run.id"] == "run-1"
    assert "input" not in attrs and "output" not in attrs
