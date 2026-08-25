from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.finding_operations.connectors import (
    CallbackEnvelope,
    ConnectorProfile,
    DeliveryLedger,
    create_delivery,
    verify_callback,
)
from redagent_platform.finding_operations.reporting import (
    PublicationBlock,
    ReportClaimInput,
    ReportSnapshotInput,
    build_report_snapshot,
)


NOW = datetime(2026, 7, 12, 12, tzinfo=timezone.utc)


def valid_report(**changes: object) -> ReportSnapshotInput:
    values = dict(
        report_id="report-1", tenant_id="tenant-a", audience="technical",
        policy_revision="policy-r99-v1", roe_version_id="roe-1",
        reviewed_snapshot_sha256="a" * 64, coverage_state="complete",
        partial_coverage_disclosed=False, independently_reviewed=True,
        evidence_redaction_state="report_safe", generated_at=NOW,
        claims=(ReportClaimInput(
            claim_id="claim-1", text="HSTS is absent at the approved resource.",
            evidence_sha256s=("b" * 64,), reviewer_adopted=True, ai_drafted=False,
        ),),
    )
    values.update(changes)
    return ReportSnapshotInput(**values)


def test_report_generation_is_deterministic_and_content_addressed() -> None:
    first = build_report_snapshot(valid_report())
    second = build_report_snapshot(valid_report())
    assert first == second
    assert first.publication_blocks == ()
    assert len(first.snapshot_sha256) == 64
    assert first.rendered_bytes.startswith(b"{")


@pytest.mark.parametrize(
    ("changes", "block"),
    [
        ({"independently_reviewed": False}, PublicationBlock.MISSING_REVIEW),
        ({"evidence_redaction_state": "restricted"}, PublicationBlock.UNSAFE_EVIDENCE),
        ({"coverage_state": "partial"}, PublicationBlock.PARTIAL_COVERAGE_UNDISCLOSED),
        ({"policy_revision": "stale"}, PublicationBlock.STALE_POLICY),
    ],
)
def test_report_publication_blocks_unsafe_inputs(changes: dict[str, object], block: PublicationBlock) -> None:
    result = build_report_snapshot(valid_report(**changes))
    assert block in result.publication_blocks


def test_ai_draft_cannot_self_adopt_or_publish() -> None:
    claim = ReportClaimInput(
        claim_id="claim-ai", text="Potential business impact.", evidence_sha256s=(),
        reviewer_adopted=False, ai_drafted=True,
    )
    result = build_report_snapshot(valid_report(claims=(claim,)))
    assert PublicationBlock.UNSUPPORTED_CLAIM in result.publication_blocks
    assert PublicationBlock.AI_NOT_ADOPTED in result.publication_blocks


def test_fixture_connector_is_allowlisted_idempotent_and_network_free() -> None:
    profile = ConnectorProfile.fixture(
        profile_id="fixture-ticket-v1", tenant_id="tenant-a",
        allowed_fields=("issue_id", "severity", "snapshot_sha256"),
    )
    ledger = DeliveryLedger.empty()
    first = create_delivery(
        ledger, profile=profile, delivery_id="delivery-1", snapshot_sha256="a" * 64,
        destination_object_key="fixture-project:SEC", fields={"issue_id": "issue-1", "severity": "high"},
        idempotency_key="deliver-report-1", occurred_at=NOW,
    )
    replay = create_delivery(
        first, profile=profile, delivery_id="delivery-2", snapshot_sha256="a" * 64,
        destination_object_key="fixture-project:SEC", fields={"issue_id": "issue-1", "severity": "high"},
        idempotency_key="deliver-report-1", occurred_at=NOW,
    )
    assert len(replay.deliveries) == 1
    assert replay.deliveries[0].network_contact_count == 0
    with pytest.raises(ValueError, match="connector_field_not_allowlisted"):
        create_delivery(
            ledger, profile=profile, delivery_id="delivery-bad", snapshot_sha256="a" * 64,
            destination_object_key="fixture-project:SEC", fields={"raw_evidence": "forbidden"},
            idempotency_key="bad", occurred_at=NOW,
        )


def test_callback_signature_timestamp_and_nonce_are_verified() -> None:
    secret = b"fixture-callback-key"
    envelope = CallbackEnvelope.sign(
        delivery_id="delivery-1", state="delivered", nonce="nonce-1",
        occurred_at=NOW, key=secret,
    )
    seen: set[str] = set()
    verify_callback(envelope, key=secret, now=NOW + timedelta(seconds=10), seen_nonces=seen)
    with pytest.raises(ValueError, match="connector_callback_replay"):
        verify_callback(envelope, key=secret, now=NOW + timedelta(seconds=11), seen_nonces=seen)
    forged = envelope.__class__(**{**envelope.__dict__, "signature_sha256": "0" * 64})
    with pytest.raises(ValueError, match="connector_callback_signature_invalid"):
        verify_callback(forged, key=secret, now=NOW, seen_nonces=set())
