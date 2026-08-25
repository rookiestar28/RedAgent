from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.finding_operations.contracts import (
    CoverageState,
    Disposition,
    FindingOccurrenceInput,
    ImportBatch,
    ReviewSnapshot,
)
from redagent_platform.finding_operations.correlation import correlate_import
from redagent_platform.finding_operations.lifecycle import (
    FindingLifecycle,
    expire_risk_acceptance,
    merge_issues,
    split_occurrence,
)


NOW = datetime(2026, 7, 12, 12, tzinfo=timezone.utc)


def occurrence(*, source_record_id: str = "source-1", resource: str = "asset-1") -> FindingOccurrenceInput:
    return FindingOccurrenceInput(
        source_record_id=source_record_id,
        tool="nuclei",
        tool_version="3.4.0",
        rule_id="http-missing-hsts",
        rule_version="bundle-r105",
        database_version="db-2026-07-12",
        title="Missing HSTS",
        resource_identity=resource,
        location="https-root",
        severity="medium",
        confidence="confirmed",
        taxonomy_ids=("CWE-319",),
        control_ids=("ASVS-V14.4.5",),
        evidence_id="evidence-redacted-1",
        evidence_sha256="a" * 64,
        redaction_state="report_safe",
        observed_at=NOW,
    )


def test_correlation_is_deterministic_explainable_and_tenant_scoped() -> None:
    batch = ImportBatch(
        import_id="import-1", tenant_id="tenant-a", adapter_id="nuclei-r105",
        run_id="run-1", coverage_state=CoverageState.COMPLETE,
        comparable_baseline_run_id="run-0", records=(occurrence(),), imported_at=NOW,
    )
    first = correlate_import(batch, existing=())
    second = correlate_import(batch, existing=())
    assert first == second
    assert first.outcomes[0].tenant_id == "tenant-a"
    assert first.outcomes[0].recipe_version == "redagent-fingerprint-v1"
    assert first.outcomes[0].reason_codes == ("no_existing_candidate", "create_issue")
    assert len(first.outcomes[0].issue_fingerprint) == 64
    assert len(first.import_sha256) == 64


def test_reimport_preserves_reviewed_disposition_and_partial_absence_is_unknown() -> None:
    reviewed = ReviewSnapshot(
        issue_id="issue-1", tenant_id="tenant-a", issue_fingerprint="f" * 64,
        disposition=Disposition.RISK_ACCEPTED, disposition_revision=4,
        reviewer_id="reviewer-1", rationale_sha256="b" * 64,
        risk_acceptance_expires_at=NOW + timedelta(days=30),
    )
    batch = ImportBatch(
        import_id="import-2", tenant_id="tenant-a", adapter_id="nuclei-r105",
        run_id="run-2", coverage_state=CoverageState.PARTIAL,
        comparable_baseline_run_id="run-1", records=(), imported_at=NOW,
    )
    result = correlate_import(batch, existing=(reviewed,))
    assert result.preserved_dispositions == (Disposition.RISK_ACCEPTED,)
    assert result.absence_state == "unknown_partial_coverage"
    assert result.reopen_issue_ids == ()


def test_merge_and_split_preserve_lineage_and_never_destroy_occurrences() -> None:
    lifecycle = FindingLifecycle.bootstrap(
        tenant_id="tenant-a", issue_ids=("issue-a", "issue-b"),
        occurrence_ids=("occ-a", "occ-b"), occurred_at=NOW,
    )
    merged = merge_issues(
        lifecycle, source_issue_ids=("issue-a", "issue-b"), successor_issue_id="issue-c",
        actor_id="reviewer-1", rationale="same weakness and resource identity", occurred_at=NOW,
    )
    assert merged.issues["issue-a"].state == "merged"
    assert merged.issues["issue-b"].state == "merged"
    assert merged.issues["issue-c"].predecessor_issue_ids == ("issue-a", "issue-b")
    assert set(merged.occurrences) == {"occ-a", "occ-b"}

    split = split_occurrence(
        merged, source_issue_id="issue-c", occurrence_id="occ-b", successor_issue_id="issue-d",
        actor_id="reviewer-1", rationale="different affected control", occurred_at=NOW,
    )
    assert split.occurrences["occ-b"].issue_id == "issue-d"
    assert split.issues["issue-d"].predecessor_issue_ids == ("issue-c",)
    assert len(split.operations) == 2


def test_risk_acceptance_expiry_reopens_for_review_not_confirmed() -> None:
    lifecycle = FindingLifecycle.bootstrap(
        tenant_id="tenant-a", issue_ids=("issue-a",), occurrence_ids=("occ-a",), occurred_at=NOW,
    ).accept_risk(
        issue_id="issue-a", reviewer_id="reviewer-1", rationale="temporary compensating control",
        expires_at=NOW + timedelta(days=1), occurred_at=NOW,
    )
    still_valid = expire_risk_acceptance(lifecycle, occurred_at=NOW + timedelta(hours=23))
    assert still_valid.issues["issue-a"].disposition is Disposition.RISK_ACCEPTED
    expired = expire_risk_acceptance(lifecycle, occurred_at=NOW + timedelta(days=2))
    assert expired.issues["issue-a"].disposition is Disposition.NEEDS_REVIEW
    assert expired.operations[-1].kind == "risk_acceptance_expired"


def test_cross_tenant_existing_snapshot_is_rejected() -> None:
    reviewed = ReviewSnapshot(
        issue_id="issue-1", tenant_id="tenant-b", issue_fingerprint="f" * 64,
        disposition=Disposition.FALSE_POSITIVE, disposition_revision=2,
        reviewer_id="reviewer-1", rationale_sha256="b" * 64,
    )
    batch = ImportBatch(
        import_id="import-3", tenant_id="tenant-a", adapter_id="nuclei-r105",
        run_id="run-3", coverage_state=CoverageState.COMPLETE,
        comparable_baseline_run_id=None, records=(occurrence(),), imported_at=NOW,
    )
    with pytest.raises(ValueError, match="finding_cross_tenant_snapshot_forbidden"):
        correlate_import(batch, existing=(reviewed,))
