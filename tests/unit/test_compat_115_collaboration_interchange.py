from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.finding_operations.connectors import (
    CallbackEnvelope,
    ConnectorProfile,
    DeliveryLedger,
    apply_callback,
    attempt_fixture_delivery,
    create_delivery,
    reconcile_delivery,
    revoke_profile,
)
from redagent_platform.finding_operations.interchange import (
    InterchangeFinding,
    export_cyclonedx_vex,
    export_ocsf,
    export_sarif,
)
from redagent_platform.finding_operations.lifecycle import (
    FindingLifecycle,
    RunCoverage,
    compare_runs,
)


NOW = datetime(2026, 7, 12, 15, tzinfo=timezone.utc)


def test_assignment_comment_retest_close_reopen_and_run_comparison_are_append_only() -> None:
    lifecycle = FindingLifecycle.bootstrap(
        tenant_id="tenant-a", issue_ids=("issue-a",), occurrence_ids=("occ-a",), occurred_at=NOW,
    )
    lifecycle = lifecycle.assign(issue_id="issue-a", owner_id="owner-1", actor_id="reviewer-1", occurred_at=NOW)
    lifecycle = lifecycle.comment(
        issue_id="issue-a", author_id="reviewer-1", comment="Validated compensating control.", occurred_at=NOW,
    )
    lifecycle = lifecycle.request_retest(
        issue_id="issue-a", retest_id="retest-1", baseline_run_id="run-1",
        actor_id="reviewer-1", occurred_at=NOW,
    )
    lifecycle = lifecycle.complete_retest(
        retest_id="retest-1", retest_run_id="run-2", coverage_state="complete",
        result_state="passed", actor_id="reviewer-2", occurred_at=NOW + timedelta(hours=1),
    )
    lifecycle = lifecycle.close(
        issue_id="issue-a", actor_id="reviewer-2", reason="complete-retest-passed", occurred_at=NOW,
    )
    lifecycle = lifecycle.reopen(
        issue_id="issue-a", actor_id="reviewer-2", reason="new-reviewed-occurrence", occurred_at=NOW,
    )
    assert lifecycle.issues["issue-a"].owner_id == "owner-1"
    assert len(lifecycle.comments) == 1 and len(lifecycle.comments[0].comment_sha256) == 64
    assert lifecycle.retests["retest-1"].result_state == "passed"
    assert lifecycle.issues["issue-a"].state == "active"
    assert [operation.kind for operation in lifecycle.operations] == [
        "issue_assigned", "comment_added", "retest_requested", "retest_completed", "issue_closed", "issue_reopened",
    ]
    comparison = compare_runs(
        RunCoverage(run_id="run-1", complete=True, issue_fingerprints=("a", "b")),
        RunCoverage(run_id="run-2", complete=True, issue_fingerprints=("b", "c")),
    )
    assert comparison.new == ("c",) and comparison.unchanged == ("b",) and comparison.absent == ("a",)
    partial = compare_runs(
        RunCoverage(run_id="run-1", complete=True, issue_fingerprints=("a",)),
        RunCoverage(run_id="run-3", complete=False, issue_fingerprints=()),
    )
    assert partial.absent == () and partial.unknown_absence == ("a",)


def finding() -> InterchangeFinding:
    return InterchangeFinding(
        issue_id="issue-1", fingerprint="a" * 64, rule_id="RULE-1", title="Missing HSTS",
        severity="medium", disposition="confirmed", resource_id="resource-1", location_id="location-1",
        evidence_sha256="b" * 64, cve_ids=("CVE-2026-12345",), cwe_ids=("CWE-319",),
        component_purl="pkg:pypi/example@1.0.0", reviewed=True,
    )


def test_sarif_ocsf_and_vex_exports_are_closed_versioned_minimized_and_deterministic() -> None:
    item = finding()
    sarif = export_sarif((item,)); ocsf = export_ocsf((item,)); vex = export_cyclonedx_vex((item,))
    assert sarif == export_sarif((item,)) and sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["partialFingerprints"]["redagent/v1"] == item.fingerprint
    assert ocsf["metadata"]["version"] == "1.8.0" and ocsf["class_name"] == "Vulnerability Finding"
    assert vex["specVersion"] == "1.6" and vex["vulnerabilities"][0]["analysis"]["state"] == "exploitable"
    forbidden = "raw_evidence token credential password command environment destination_url"
    rendered = f"{sarif}{ocsf}{vex}".lower()
    assert all(term not in rendered for term in forbidden.split())
    with pytest.raises(ValueError, match="interchange_review_required"):
        export_cyclonedx_vex((item.__class__(**{**item.__dict__, "reviewed": False}),))


def test_connector_retry_dead_letter_callback_reconcile_and_revoke_remain_network_free() -> None:
    profile = ConnectorProfile.fixture(
        profile_id="fixture-ticket-v1", tenant_id="tenant-a",
        allowed_fields=("issue_id", "severity", "snapshot_sha256"),
    )
    ledger = create_delivery(
        DeliveryLedger.empty(), profile=profile, delivery_id="delivery-1", snapshot_sha256="a" * 64,
        destination_object_key="fixture-project:SEC", fields={"issue_id": "issue-1"},
        idempotency_key="delivery-key", occurred_at=NOW,
    )
    for attempt in range(1, 4):
        ledger = attempt_fixture_delivery(
            ledger, delivery_id="delivery-1", outcome="transient_failure", occurred_at=NOW,
        )
        assert ledger.deliveries[0].attempt_count == attempt
        assert ledger.deliveries[0].network_contact_count == 0
    assert ledger.deliveries[0].state == "dead_letter"
    profile = revoke_profile(profile)
    with pytest.raises(ValueError, match="connector_profile_disabled"):
        create_delivery(
            ledger, profile=profile, delivery_id="delivery-2", snapshot_sha256="a" * 64,
            destination_object_key="fixture-project:SEC", fields={"issue_id": "issue-1"},
            idempotency_key="delivery-key-2", occurred_at=NOW,
        )

    successful = create_delivery(
        DeliveryLedger.empty(), profile=ConnectorProfile.fixture(
            profile_id="fixture-ticket-v1", tenant_id="tenant-a", allowed_fields=("issue_id",),
        ), delivery_id="delivery-3", snapshot_sha256="c" * 64,
        destination_object_key="fixture-project:SEC", fields={"issue_id": "issue-1"},
        idempotency_key="delivery-key-3", occurred_at=NOW,
    )
    envelope = CallbackEnvelope.sign(
        delivery_id="delivery-3", state="delivered", nonce="nonce-3", occurred_at=NOW, key=b"fixture-key",
    )
    successful = apply_callback(
        successful, envelope=envelope, key=b"fixture-key", now=NOW, seen_nonces=set(),
    )
    successful = reconcile_delivery(
        successful, delivery_id="delivery-3", external_state="delivered", occurred_at=NOW,
    )
    assert successful.deliveries[0].state == "reconciled"
    assert successful.deliveries[0].network_contact_count == 0
