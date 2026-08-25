from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.finding_operations.contracts import CoverageState, FindingOccurrenceInput, ImportBatch
from redagent_platform.finding_operations.repository import FindingOperationsRepository
from redagent_platform.finding_operations.reporting import ReportClaimInput, ReportSnapshotInput
from redagent_platform.persistence.database import load_database_settings


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 12, 14, tzinfo=timezone.utc)


def test_repository_persists_import_review_report_delivery_audit_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex
    tenant = f"tenant-r115-{suffix}"
    record = FindingOccurrenceInput(
        source_record_id=f"source-{suffix}", tool="nuclei", tool_version="3.4.0",
        rule_id="http-missing-hsts", rule_version="bundle-r105", database_version="db-2026-07-12",
        title="Missing HSTS", resource_identity=f"asset-{suffix}", location="https-root",
        severity="medium", confidence="confirmed", taxonomy_ids=("CWE-319",),
        control_ids=("ASVS-V14.4.5",), evidence_id=f"evidence-{suffix}", evidence_sha256="a" * 64,
        redaction_state="report_safe", observed_at=NOW,
    )
    batch = ImportBatch(
        import_id=f"import-{suffix}", tenant_id=tenant, adapter_id="nuclei-r105",
        run_id=f"run-{suffix}", coverage_state=CoverageState.COMPLETE,
        comparable_baseline_run_id=None, records=(record,), imported_at=NOW,
    )
    async with sessions() as session:
        async with session.begin():
            repo = FindingOperationsRepository(
                session, tenant_id=tenant, actor_user_id="operator-r115", correlation_id=f"corr-{suffix}",
            )
            first = await repo.import_batch(batch)
            replay = await repo.import_batch(batch)
            assert first["issue_ids"] == replay["issue_ids"] and replay["replayed"] is True
            issue_id = str(first["issue_ids"][0])
            reviewed = await repo.review_issue(
                issue_id=issue_id, operation_id=f"review-{suffix}", disposition="false_positive",
                rationale="fixture parser produced a reviewed false positive", occurred_at=NOW,
            )
            assert reviewed["disposition"] == "false_positive"
            reimport = replace(
                batch, import_id=f"reimport-{suffix}", run_id=f"run-2-{suffix}",
                comparable_baseline_run_id=batch.run_id,
                records=(replace(record, source_record_id=f"source-2-{suffix}"),),
            )
            reimported = await repo.import_batch(reimport)
            assert reimported["issue_ids"] == (issue_id,)
            await repo.assign_issue(
                issue_id=issue_id, operation_id=f"assign-{suffix}", owner_id="owner-r115",
                occurred_at=NOW,
            )
            await repo.add_comment(
                issue_id=issue_id, comment_id=f"comment-{suffix}",
                comment="Reviewed fixture comment is stored only as a digest.", occurred_at=NOW,
            )
            await repo.accept_risk(
                issue_id=issue_id, acceptance_id=f"acceptance-{suffix}",
                rationale="temporary fixture compensating control", expires_at=NOW + timedelta(hours=1),
                occurred_at=NOW,
            )
            expired = await repo.expire_risk_acceptances(occurred_at=NOW + timedelta(hours=2))
            assert expired == 1
            await repo.request_retest(
                issue_id=issue_id, retest_id=f"retest-{suffix}", baseline_run_id=batch.run_id,
                occurred_at=NOW,
            )
            await repo.complete_retest(
                retest_id=f"retest-{suffix}", retest_run_id=f"retest-run-{suffix}",
                coverage_state="complete", result_state="passed", occurred_at=NOW + timedelta(hours=3),
            )
            closed = await repo.close_issue(
                issue_id=issue_id, operation_id=f"close-{suffix}", reason_code="complete-retest-passed",
                occurred_at=NOW + timedelta(hours=3),
            )
            assert closed["issue_state"] == "closed"
            reopened = await repo.reopen_issue(
                issue_id=issue_id, operation_id=f"reopen-{suffix}", reason_code="new-reviewed-occurrence",
                occurred_at=NOW + timedelta(hours=4),
            )
            assert reopened["issue_state"] == "active" and reopened["disposition"] == "needs_review"
            reviewed_again = await repo.review_issue(
                issue_id=issue_id, operation_id=f"review-again-{suffix}", disposition="confirmed",
                rationale="independent review after the new occurrence", occurred_at=NOW + timedelta(hours=5),
            )
            assert reviewed_again["disposition"] == "confirmed"
            with pytest.raises(ValueError, match="finding_reviewed_snapshot_required"):
                await repo.store_report(ReportSnapshotInput(
                    report_id=f"report-invalid-{suffix}", tenant_id=tenant, audience="technical",
                    policy_revision="policy-r99-v1", roe_version_id="roe-r115",
                    reviewed_snapshot_sha256="f" * 64, coverage_state="complete",
                    partial_coverage_disclosed=False, independently_reviewed=True,
                    evidence_redaction_state="report_safe", generated_at=NOW,
                    claims=(ReportClaimInput(
                        claim_id=f"claim-invalid-{suffix}", text="Unsupported arbitrary snapshot.",
                        evidence_sha256s=("a" * 64,), reviewer_adopted=True, ai_drafted=False,
                    ),),
                ))
            report = await repo.store_report(ReportSnapshotInput(
                report_id=f"report-{suffix}", tenant_id=tenant, audience="technical",
                policy_revision="policy-r99-v1", roe_version_id="roe-r115",
                reviewed_snapshot_sha256=str(reviewed_again["issue_fingerprint"]), coverage_state="complete",
                partial_coverage_disclosed=False, independently_reviewed=True,
                evidence_redaction_state="report_safe", generated_at=NOW,
                claims=(ReportClaimInput(
                    claim_id=f"claim-{suffix}", text="Reviewed fixture observation.",
                    evidence_sha256s=("a" * 64,), reviewer_adopted=True, ai_drafted=False,
                ),),
            ))
            assert report["report_state"] == "publishable"
            with pytest.raises(ValueError, match="finding_publication_separation_required"):
                await repo.publish_report(
                    report_id=f"report-{suffix}", report_sha256=str(report["report_sha256"]),
                    publication_id=f"publication-self-{suffix}", occurred_at=NOW,
                )
            publisher_repo = FindingOperationsRepository(
                session, tenant_id=tenant, actor_user_id="publisher-r115", correlation_id=f"publish-{suffix}",
            )
            publication = await publisher_repo.publish_report(
                report_id=f"report-{suffix}", report_sha256=str(report["report_sha256"]),
                publication_id=f"publication-{suffix}", occurred_at=NOW,
            )
            assert publication["publisher_id"] == "publisher-r115"
            profile = await publisher_repo.ensure_fixture_profile(profile_id="fixture-ticket-v1", occurred_at=NOW)
            assert profile["network_enabled"] is False
            delivery = await publisher_repo.queue_fixture_delivery(
                delivery_id=f"delivery-{suffix}", profile_id="fixture-ticket-v1",
                report_id=f"report-{suffix}", snapshot_sha256=str(report["report_sha256"]),
                destination_key="fixture-project:SEC", fields=("issue_id", "severity"),
                idempotency_key=f"deliver-{suffix}", occurred_at=NOW,
            )
            assert delivery["delivery_state"] == "queued" and delivery["attempt_count"] == 0
            dashboard = await repo.dashboard()
            assert len(dashboard["issues"]) == 1 and len(dashboard["occurrences"]) == 2
            assert len(dashboard["imports"]) == 2
            assert len(dashboard["comments"]) == len(dashboard["risk_acceptances"]) == len(dashboard["retests"]) == 1
            assert len(dashboard["operations"]) >= 10
            assert len(dashboard["reports"]) == len(dashboard["deliveries"]) == 1
            assert len(dashboard["publications"]) == 1
            assert dashboard["issues"][0]["disposition"] == "confirmed"
            assert dashboard["issues"][0]["owner_id"] == "owner-r115"
            assert dashboard["deliveries"][0]["network_contact_count"] == 0
            second_record = replace(
                record, source_record_id=f"source-merge-{suffix}", resource_identity=f"asset-merge-{suffix}",
            )
            second_batch = replace(
                batch, import_id=f"import-merge-{suffix}", run_id=f"run-merge-{suffix}", records=(second_record,),
            )
            second_issue_id = str((await repo.import_batch(second_batch))["issue_ids"][0])
            merged = await repo.merge_issues(
                source_issue_ids=(issue_id, second_issue_id), successor_issue_id=f"issue-merged-{suffix}",
                operation_id=f"merge-{suffix}", rationale="reviewed equivalent weakness identity",
                occurred_at=NOW + timedelta(hours=6),
            )
            merged_dashboard = await repo.dashboard()
            split_occurrence_id = str(next(
                row["occurrence_id"] for row in merged_dashboard["occurrences"]
                if row["issue_record_id"] == merged["id"]
            ))
            split = await repo.split_occurrence(
                source_issue_id=str(merged["issue_id"]), occurrence_id=split_occurrence_id,
                successor_issue_id=f"issue-split-{suffix}", operation_id=f"split-{suffix}",
                rationale="reviewed distinct affected location", occurred_at=NOW + timedelta(hours=7),
            )
            assert split["fingerprint_recipe"] == "redagent-split-v1"
            lineage_dashboard = await repo.dashboard()
            assert len(lineage_dashboard["issues"]) == 4
            assert len(lineage_dashboard["occurrences"]) == 3
    async with sessions() as session:
        async with session.begin():
            other = await FindingOperationsRepository(
                session, tenant_id=f"other-{suffix}", actor_user_id="other-r115",
                correlation_id=f"other-corr-{suffix}",
            ).dashboard()
            assert all(not rows for rows in other.values())
    await engine.dispose()
