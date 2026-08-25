"""PostgreSQL-authoritative compat_115 finding and publication operations."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.finding_operations.contracts import ImportBatch
from redagent_platform.finding_operations.correlation import FINGERPRINT_RECIPE_VERSION, correlate_import
from redagent_platform.finding_operations.reporting import ReportSnapshotInput, build_report_snapshot
from redagent_platform.persistence.models import metadata


class FindingOperationsRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str,
                 correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _id(tenant_id)
        self.actor_user_id = _id(actor_user_id)
        self.correlation_id = _id(correlation_id)

    async def import_batch(self, batch: ImportBatch) -> dict[str, object]:
        await self._context()
        await self._lock(f"import:{batch.import_id}")
        if batch.tenant_id != self.tenant_id:
            raise ValueError("finding_import_tenant_mismatch")
        correlation = correlate_import(batch, existing=())
        existing = await self._find("finding_import_sessions", {"import_id": batch.import_id})
        if existing is not None:
            if existing["import_sha256"] != correlation.import_sha256:
                raise ValueError("finding_import_idempotency_conflict")
            issue_ids = await self._issue_ids_for_import(str(existing["id"]))
            return {"import_id": batch.import_id, "import_sha256": correlation.import_sha256,
                    "issue_ids": issue_ids, "replayed": True}
        import_row = self._owned("import", batch.imported_at) | {
            "import_id": _id(batch.import_id), "adapter_id": _id(batch.adapter_id),
            "run_id": _id(batch.run_id), "baseline_run_id": batch.comparable_baseline_run_id,
            "coverage_state": batch.coverage_state.value, "recipe_version": FINGERPRINT_RECIPE_VERSION,
            "import_sha256": correlation.import_sha256, "record_count": len(batch.records),
            "import_state": "accepted", "imported_at": batch.imported_at,
        }
        await self.session.execute(insert(metadata.tables["finding_import_sessions"]).values(**import_row))
        issue_ids: list[str] = []
        for record, outcome in zip(batch.records, correlation.outcomes, strict=True):
            issue = await self._find("managed_issues", {"issue_fingerprint": outcome.issue_fingerprint})
            if issue is None:
                issue = self._owned("issue", batch.imported_at) | {
                    "issue_id": f"issue-{uuid4().hex[:24]}", "issue_fingerprint": outcome.issue_fingerprint,
                    "fingerprint_recipe": FINGERPRINT_RECIPE_VERSION, "title": record.title,
                    "severity": record.severity, "confidence": record.confidence,
                    "taxonomy_sha256": _digest(record.taxonomy_ids), "controls_sha256": _digest(record.control_ids),
                    "disposition": "needs_review", "disposition_revision": 1, "owner_id": None,
                    "sla_due_at": None, "remediation_sha256": _digest(""),
                    "first_seen_at": record.observed_at, "last_seen_at": record.observed_at,
                    "issue_state": "active",
                }
                await self.session.execute(insert(metadata.tables["managed_issues"]).values(**issue))
            else:
                # IMPORTANT: reimport refreshes occurrence truth but cannot reset reviewed disposition.
                await self.session.execute(update(metadata.tables["managed_issues"]).where(
                    metadata.tables["managed_issues"].c.id == issue["id"],
                ).values(last_seen_at=record.observed_at, updated_at=batch.imported_at,
                         version=int(issue["version"]) + 1))
            issue_ids.append(str(issue["issue_id"]))
            import_record = self._owned("import-record", batch.imported_at) | {
                "import_record_id": f"record-{uuid4().hex[:24]}", "import_record_ref": import_row["id"],
                "source_record_id": _id(record.source_record_id), "source_record_sha256": _digest(asdict(record)),
                "issue_fingerprint": outcome.issue_fingerprint, "candidate_sha256": _digest((issue["issue_id"],)),
                "reason_codes_sha256": _digest(outcome.reason_codes), "correlation_state": "matched",
            }
            await self.session.execute(insert(metadata.tables["finding_import_records"]).values(**import_record))
            occurrence = self._owned("occurrence", batch.imported_at) | {
                "occurrence_id": f"occurrence-{uuid4().hex[:24]}", "issue_record_id": issue["id"],
                "import_record_ref": import_record["id"], "resource_sha256": _digest(record.resource_identity),
                "location_sha256": _digest(record.location), "tool_id": record.tool,
                "tool_version": record.tool_version, "rule_id": record.rule_id,
                "rule_version": record.rule_version, "database_version": record.database_version,
                "coverage_state": batch.coverage_state.value, "occurrence_state": "observed",
                "observed_at": record.observed_at,
            }
            await self.session.execute(insert(metadata.tables["finding_occurrences"]).values(**occurrence))
            evidence = self._owned("evidence-link", batch.imported_at) | {
                "evidence_link_id": f"link-{uuid4().hex[:24]}", "occurrence_record_id": occurrence["id"],
                "evidence_id": _id(record.evidence_id), "evidence_sha256": _sha(record.evidence_sha256),
                "redaction_state": record.redaction_state, "purpose": "report",
                "link_state": "approved",
            }
            await self.session.execute(insert(metadata.tables["finding_evidence_links"]).values(**evidence))
        await self._audit("finding.import.accepted", batch.import_id,
                          {"import_sha256": correlation.import_sha256, "record_count": len(batch.records)},
                          batch.imported_at)
        return {"import_id": batch.import_id, "import_sha256": correlation.import_sha256,
                "issue_ids": tuple(issue_ids), "replayed": False}

    async def review_issue(self, *, issue_id: str, operation_id: str, disposition: str,
                           rationale: str, occurred_at: datetime) -> dict[str, object]:
        await self._context()
        await self._lock(f"review:{issue_id}")
        allowed = {"confirmed", "false_positive", "risk_accepted", "duplicate", "mitigated",
                   "out_of_scope", "closed", "needs_review"}
        if disposition not in allowed or len(rationale.strip()) < 10:
            raise ValueError("finding_review_invalid")
        issue = await self._find("managed_issues", {"issue_id": _id(issue_id)})
        if issue is None:
            raise ValueError("finding_issue_not_found")
        existing = await self._find("finding_operations", {"operation_id": _id(operation_id)})
        operation_sha = _digest((issue_id, issue["disposition"], disposition, rationale))
        if existing is not None:
            if existing["operation_sha256"] != operation_sha:
                raise ValueError("finding_operation_immutable")
            return issue
        operation = self._owned("operation", occurred_at) | {
            "operation_id": operation_id, "issue_record_id": issue["id"], "operation_kind": "review",
            "actor_id": self.actor_user_id, "from_state": issue["disposition"], "to_state": disposition,
            "operation_sha256": operation_sha, "predecessor_sha256": _digest(issue["disposition"]),
            "successor_sha256": _digest(disposition), "occurred_at": occurred_at,
        }
        await self.session.execute(insert(metadata.tables["finding_operations"]).values(**operation))
        await self.session.execute(update(metadata.tables["managed_issues"]).where(
            metadata.tables["managed_issues"].c.id == issue["id"],
        ).values(disposition=disposition, disposition_revision=int(issue["disposition_revision"]) + 1,
                 version=int(issue["version"]) + 1, updated_at=occurred_at))
        await self._audit("finding.issue.reviewed", issue_id,
                          {"disposition": disposition, "operation_sha256": operation_sha}, occurred_at)
        return issue | {"disposition": disposition,
                        "disposition_revision": int(issue["disposition_revision"]) + 1}

    async def merge_issues(self, *, source_issue_ids: tuple[str, ...], successor_issue_id: str,
                           operation_id: str, rationale: str, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"merge:{successor_issue_id}")
        if len(set(source_issue_ids)) < 2 or len(rationale.strip()) < 10:
            raise ValueError("finding_merge_invalid")
        sources = [await self._required_issue(issue_id) for issue_id in source_issue_ids]
        if await self._find("managed_issues", {"issue_id": _id(successor_issue_id)}) is not None:
            raise ValueError("finding_successor_exists")
        primary = sources[0]
        successor = self._owned("issue", occurred_at) | {
            "issue_id": _id(successor_issue_id),
            "issue_fingerprint": _digest(tuple(sorted(str(row["issue_fingerprint"]) for row in sources))),
            "fingerprint_recipe": "redagent-merge-v1", "title": primary["title"],
            "severity": primary["severity"], "confidence": primary["confidence"],
            "taxonomy_sha256": primary["taxonomy_sha256"], "controls_sha256": primary["controls_sha256"],
            "disposition": "needs_review", "disposition_revision": 1, "owner_id": primary["owner_id"],
            "sla_due_at": primary["sla_due_at"], "remediation_sha256": primary["remediation_sha256"],
            "first_seen_at": min(row["first_seen_at"] for row in sources),
            "last_seen_at": max(row["last_seen_at"] for row in sources), "issue_state": "active",
        }
        await self.session.execute(insert(metadata.tables["managed_issues"]).values(**successor))
        source_records = [str(row["id"]) for row in sources]
        await self.session.execute(update(metadata.tables["finding_occurrences"]).where(
            metadata.tables["finding_occurrences"].c.tenant_id == self.tenant_id,
            metadata.tables["finding_occurrences"].c.issue_record_id.in_(source_records),
        ).values(issue_record_id=successor["id"], updated_at=occurred_at,
                 version=metadata.tables["finding_occurrences"].c.version + 1))
        for index, source in enumerate(sources):
            await self.session.execute(update(metadata.tables["managed_issues"]).where(
                metadata.tables["managed_issues"].c.id == source["id"],
            ).values(issue_state="merged", version=int(source["version"]) + 1, updated_at=occurred_at))
            await self._record_issue_operation(
                source, operation_id=_derived_id(f"{operation_id}-{index}", successor_issue_id),
                kind="merge", to_state="merged", detail=(successor_issue_id, rationale),
                occurred_at=occurred_at,
            )
        return successor

    async def split_occurrence(self, *, source_issue_id: str, occurrence_id: str,
                               successor_issue_id: str, operation_id: str, rationale: str,
                               occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"split:{occurrence_id}")
        source = await self._required_issue(source_issue_id)
        occurrence = await self._find("finding_occurrences", {"occurrence_id": _id(occurrence_id)})
        if occurrence is None or occurrence["issue_record_id"] != source["id"] or len(rationale.strip()) < 10:
            raise ValueError("finding_split_invalid")
        if await self._find("managed_issues", {"issue_id": _id(successor_issue_id)}) is not None:
            raise ValueError("finding_successor_exists")
        successor = self._owned("issue", occurred_at) | {
            "issue_id": successor_issue_id,
            "issue_fingerprint": _digest((source["issue_fingerprint"], occurrence_id)),
            "fingerprint_recipe": "redagent-split-v1", "title": source["title"],
            "severity": source["severity"], "confidence": source["confidence"],
            "taxonomy_sha256": source["taxonomy_sha256"], "controls_sha256": source["controls_sha256"],
            "disposition": "needs_review", "disposition_revision": 1, "owner_id": source["owner_id"],
            "sla_due_at": source["sla_due_at"], "remediation_sha256": source["remediation_sha256"],
            "first_seen_at": occurrence["observed_at"], "last_seen_at": occurrence["observed_at"],
            "issue_state": "active",
        }
        await self.session.execute(insert(metadata.tables["managed_issues"]).values(**successor))
        await self.session.execute(update(metadata.tables["finding_occurrences"]).where(
            metadata.tables["finding_occurrences"].c.id == occurrence["id"],
        ).values(issue_record_id=successor["id"], version=int(occurrence["version"]) + 1,
                 updated_at=occurred_at))
        await self._record_issue_operation(
            source, operation_id=_id(operation_id), kind="split", to_state="split",
            detail=(occurrence_id, successor_issue_id, rationale), occurred_at=occurred_at,
        )
        return successor

    async def assign_issue(self, *, issue_id: str, operation_id: str, owner_id: str,
                           occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"assign:{issue_id}")
        issue = await self._required_issue(issue_id)
        await self._record_issue_operation(issue, operation_id=operation_id, kind="assign",
                                           to_state="assigned", detail=owner_id, occurred_at=occurred_at)
        await self.session.execute(update(metadata.tables["managed_issues"]).where(
            metadata.tables["managed_issues"].c.id == issue["id"],
        ).values(owner_id=_id(owner_id), version=int(issue["version"]) + 1, updated_at=occurred_at))
        return issue | {"owner_id": owner_id, "version": int(issue["version"]) + 1}

    async def add_comment(self, *, issue_id: str, comment_id: str, comment: str,
                          occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"comment:{comment_id}")
        issue = await self._required_issue(issue_id)
        if len(comment.strip()) < 10:
            raise ValueError("finding_comment_invalid")
        digest = _digest(comment.strip())
        existing = await self._find("finding_comments", {"comment_id": _id(comment_id)})
        if existing is not None:
            if existing["comment_sha256"] != digest:
                raise ValueError("finding_comment_immutable")
            return existing
        row = self._owned("comment", occurred_at) | {
            "comment_id": comment_id, "issue_record_id": issue["id"], "author_id": self.actor_user_id,
            "comment_sha256": digest, "visibility": "tenant-reviewers", "comment_state": "active",
        }
        await self.session.execute(insert(metadata.tables["finding_comments"]).values(**row))
        await self._record_issue_operation(issue, operation_id=_derived_id("comment", comment_id),
                                           kind="comment", to_state=str(issue["disposition"]),
                                           detail=digest, occurred_at=occurred_at)
        return row

    async def accept_risk(self, *, issue_id: str, acceptance_id: str, rationale: str,
                          expires_at: datetime, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"accept-risk:{issue_id}")
        issue = await self._required_issue(issue_id)
        if expires_at <= occurred_at or len(rationale.strip()) < 10:
            raise ValueError("finding_risk_acceptance_invalid")
        row = self._owned("acceptance", occurred_at) | {
            "acceptance_id": _id(acceptance_id), "issue_record_id": issue["id"],
            "approver_id": self.actor_user_id, "rationale_sha256": _digest(rationale.strip()),
            "accepted_at": occurred_at, "expires_at": expires_at, "acceptance_state": "active",
        }
        await self.session.execute(insert(metadata.tables["finding_risk_acceptances"]).values(**row))
        await self._record_issue_operation(issue, operation_id=_derived_id("accept", acceptance_id),
                                           kind="risk_accept", to_state="risk_accepted",
                                           detail=row["rationale_sha256"], occurred_at=occurred_at)
        await self.session.execute(update(metadata.tables["managed_issues"]).where(
            metadata.tables["managed_issues"].c.id == issue["id"],
        ).values(disposition="risk_accepted", disposition_revision=int(issue["disposition_revision"]) + 1,
                 version=int(issue["version"]) + 1, updated_at=occurred_at))
        return row

    async def expire_risk_acceptances(self, *, occurred_at: datetime) -> int:
        await self._context(); await self._lock("expire-risk")
        table = metadata.tables["finding_risk_acceptances"]
        rows = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.acceptance_state == "active",
            table.c.expires_at <= occurred_at,
        ))).mappings().all()
        for raw in rows:
            row = dict(raw); issue = await self._find("managed_issues", {"id": row["issue_record_id"]})
            if issue is None:
                raise ValueError("finding_risk_acceptance_issue_missing")
            await self.session.execute(update(table).where(table.c.id == row["id"]).values(
                acceptance_state="expired", version=int(row["version"]) + 1, updated_at=occurred_at,
            ))
            await self.session.execute(update(metadata.tables["managed_issues"]).where(
                metadata.tables["managed_issues"].c.id == issue["id"],
            ).values(disposition="needs_review", disposition_revision=int(issue["disposition_revision"]) + 1,
                     version=int(issue["version"]) + 1, updated_at=occurred_at))
            await self._record_issue_operation(issue, operation_id=_derived_id("expiry", str(row["acceptance_id"])),
                                               kind="risk_expiry", to_state="needs_review",
                                               detail="scheduled-expiry", occurred_at=occurred_at)
        return len(rows)

    async def request_retest(self, *, issue_id: str, retest_id: str, baseline_run_id: str,
                             occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"retest:{retest_id}")
        issue = await self._required_issue(issue_id)
        row = self._owned("retest", occurred_at) | {
            "retest_id": _id(retest_id), "issue_record_id": issue["id"],
            "baseline_run_id": _id(baseline_run_id), "retest_run_id": None,
            "coverage_state": "unknown", "result_state": "requested",
            "requested_by": self.actor_user_id, "requested_at": occurred_at, "completed_at": None,
        }
        await self.session.execute(insert(metadata.tables["finding_retests"]).values(**row))
        await self._record_issue_operation(issue, operation_id=_derived_id("retest", retest_id),
                                           kind="retest_request", to_state="retest_requested",
                                           detail=baseline_run_id, occurred_at=occurred_at)
        return row

    async def complete_retest(self, *, retest_id: str, retest_run_id: str, coverage_state: str,
                              result_state: str, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"retest:{retest_id}")
        retest = await self._find("finding_retests", {"retest_id": _id(retest_id)})
        if (retest is None or retest["result_state"] != "requested" or coverage_state not in {"complete", "partial"}
                or result_state not in {"passed", "failed"} or (result_state == "passed" and coverage_state != "complete")):
            raise ValueError("finding_retest_completion_invalid")
        issue = await self._find("managed_issues", {"id": retest["issue_record_id"]})
        if issue is None:
            raise ValueError("finding_retest_issue_missing")
        await self.session.execute(update(metadata.tables["finding_retests"]).where(
            metadata.tables["finding_retests"].c.id == retest["id"],
        ).values(retest_run_id=_id(retest_run_id), coverage_state=coverage_state, result_state=result_state,
                 completed_at=occurred_at, version=int(retest["version"]) + 1, updated_at=occurred_at))
        await self._record_issue_operation(issue, operation_id=_derived_id("complete", retest_id),
                                           kind="retest_complete", to_state=result_state,
                                           detail=coverage_state, occurred_at=occurred_at)
        return retest | {"retest_run_id": retest_run_id, "coverage_state": coverage_state,
                         "result_state": result_state, "completed_at": occurred_at}

    async def close_issue(self, *, issue_id: str, operation_id: str, reason_code: str,
                          occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"close:{issue_id}")
        issue = await self._required_issue(issue_id); retests = metadata.tables["finding_retests"]
        passed = await self.session.scalar(select(text("count(*)")).select_from(retests).where(
            retests.c.tenant_id == self.tenant_id, retests.c.issue_record_id == issue["id"],
            retests.c.coverage_state == "complete", retests.c.result_state == "passed",
        ))
        if not passed:
            raise ValueError("finding_complete_retest_required")
        await self._record_issue_operation(issue, operation_id=operation_id, kind="close", to_state="closed",
                                           detail=reason_code, occurred_at=occurred_at)
        await self.session.execute(update(metadata.tables["managed_issues"]).where(
            metadata.tables["managed_issues"].c.id == issue["id"],
        ).values(issue_state="closed", disposition="closed", version=int(issue["version"]) + 1,
                 disposition_revision=int(issue["disposition_revision"]) + 1, updated_at=occurred_at))
        return issue | {"issue_state": "closed", "disposition": "closed"}

    async def reopen_issue(self, *, issue_id: str, operation_id: str, reason_code: str,
                           occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"reopen:{issue_id}")
        issue = await self._required_issue(issue_id)
        if issue["issue_state"] != "closed":
            raise ValueError("finding_closed_issue_required")
        await self._record_issue_operation(issue, operation_id=operation_id, kind="reopen",
                                           to_state="needs_review", detail=reason_code, occurred_at=occurred_at)
        await self.session.execute(update(metadata.tables["managed_issues"]).where(
            metadata.tables["managed_issues"].c.id == issue["id"],
        ).values(issue_state="active", disposition="needs_review", version=int(issue["version"]) + 1,
                 disposition_revision=int(issue["disposition_revision"]) + 1, updated_at=occurred_at))
        return issue | {"issue_state": "active", "disposition": "needs_review"}

    async def store_report(self, value: ReportSnapshotInput) -> dict[str, object]:
        await self._context()
        await self._lock(f"report:{value.report_id}")
        if value.tenant_id != self.tenant_id:
            raise ValueError("finding_report_tenant_mismatch")
        reviewed_issue = await self._find("managed_issues", {
            "issue_fingerprint": _sha(value.reviewed_snapshot_sha256),
        })
        if reviewed_issue is None or reviewed_issue["disposition"] == "needs_review":
            raise ValueError("finding_reviewed_snapshot_required")
        snapshot = build_report_snapshot(value)
        existing = await self._find("finding_report_snapshots", {
            "report_id": value.report_id, "report_sha256": snapshot.snapshot_sha256,
        })
        if existing is not None:
            return existing
        row = self._owned("report", value.generated_at) | {
            "report_id": _id(value.report_id), "audience": value.audience,
            "reviewed_snapshot_sha256": _sha(value.reviewed_snapshot_sha256),
            "policy_revision": _id(value.policy_revision), "roe_version_id": _id(value.roe_version_id),
            "coverage_state": value.coverage_state, "report_sha256": snapshot.snapshot_sha256,
            "generation_profile": "deterministic-json-v1",
            "publication_block_sha256": _digest(tuple(block.value for block in snapshot.publication_blocks)),
            "report_state": "publishable" if not snapshot.publication_blocks else "blocked",
            "generated_by": self.actor_user_id,
            "generated_at": value.generated_at,
        }
        await self.session.execute(insert(metadata.tables["finding_report_snapshots"]).values(**row))
        for claim in value.claims:
            claim_row = self._owned("claim", value.generated_at) | {
                "claim_id": _id(claim.claim_id), "report_record_id": row["id"],
                "claim_sha256": _digest(claim.text), "evidence_set_sha256": _digest(claim.evidence_sha256s),
                "provenance": "ai_draft" if claim.ai_drafted else "reviewer",
                "reviewer_adopted": claim.reviewer_adopted,
                "claim_state": "adopted" if claim.reviewer_adopted else "draft",
            }
            await self.session.execute(insert(metadata.tables["finding_report_claims"]).values(**claim_row))
        await self._audit("finding.report.generated", value.report_id,
                          {"report_sha256": snapshot.snapshot_sha256, "report_state": row["report_state"]},
                          value.generated_at)
        return row

    async def ensure_fixture_profile(self, *, profile_id: str, occurred_at: datetime) -> dict[str, object]:
        await self._context()
        existing = await self._find("finding_connector_profiles", {"profile_id": _id(profile_id),
                                                                      "profile_revision": 1})
        if existing is not None:
            return existing
        row = self._owned("connector-profile", occurred_at) | {
            "profile_id": profile_id, "profile_revision": 1, "connector_kind": "fixture-ticket",
            "destination_allowlist_sha256": _digest(("fixture-project:",)),
            "field_allowlist_sha256": _digest(("issue_id", "severity", "snapshot_sha256")),
            "credential_reference_id": None, "callback_key_reference_id": "fixture-key-reference",
            "network_enabled": False, "profile_state": "enabled-fixture-only",
        }
        await self.session.execute(insert(metadata.tables["finding_connector_profiles"]).values(**row))
        return row

    async def publish_report(self, *, report_id: str, report_sha256: str, publication_id: str,
                             occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"publish:{report_id}")
        report = await self._find("finding_report_snapshots", {
            "report_id": _id(report_id), "report_sha256": _sha(report_sha256),
        })
        if report is None or report["report_state"] != "publishable":
            raise ValueError("finding_publishable_report_required")
        # CRITICAL: the report generator cannot be its independent publisher, including AI/service identities.
        if report["generated_by"] == self.actor_user_id:
            raise ValueError("finding_publication_separation_required")
        existing = await self._find("finding_publications", {"publication_id": _id(publication_id)})
        if existing is not None:
            if existing["report_sha256"] != report_sha256:
                raise ValueError("finding_publication_immutable")
            return existing
        row = self._owned("publication", occurred_at) | {
            "publication_id": publication_id, "report_record_id": report["id"],
            "report_sha256": report_sha256, "reviewer_id": report["generated_by"],
            "publisher_id": self.actor_user_id, "publication_state": "published",
            "published_at": occurred_at,
        }
        await self.session.execute(insert(metadata.tables["finding_publications"]).values(**row))
        await self._audit("finding.report.published", publication_id,
                          {"report_sha256": report_sha256, "separation_enforced": True}, occurred_at)
        return row

    async def queue_fixture_delivery(self, *, delivery_id: str, profile_id: str, report_id: str,
                                     snapshot_sha256: str, destination_key: str, fields: tuple[str, ...],
                                     idempotency_key: str, occurred_at: datetime) -> dict[str, object]:
        await self._context()
        await self._lock(f"delivery:{profile_id}:{idempotency_key}")
        profile = await self._find("finding_connector_profiles", {"profile_id": _id(profile_id),
                                                                     "profile_revision": 1})
        report = await self._find("finding_report_snapshots", {"report_id": _id(report_id),
                                                                  "report_sha256": _sha(snapshot_sha256)})
        if profile is None or profile["network_enabled"] or profile["profile_state"] != "enabled-fixture-only":
            raise ValueError("finding_fixture_connector_required")
        if report is None or report["report_state"] != "publishable":
            raise ValueError("finding_publishable_report_required")
        publication = await self._find("finding_publications", {"report_record_id": report["id"],
                                                                  "publication_state": "published"})
        if publication is None:
            raise ValueError("finding_published_report_required")
        if not destination_key.startswith("fixture-project:") or not set(fields).issubset(
            {"issue_id", "severity", "snapshot_sha256"}
        ):
            raise ValueError("finding_connector_allowlist_denied")
        existing = await self._find("finding_connector_deliveries", {
            "profile_record_id": profile["id"], "idempotency_key": _id(idempotency_key),
        })
        fields_sha = _digest(tuple(sorted(fields)))
        if existing is not None:
            if existing["snapshot_sha256"] != snapshot_sha256 or existing["fields_sha256"] != fields_sha:
                raise ValueError("finding_connector_idempotency_conflict")
            return existing | {"network_contact_count": 0}
        row = self._owned("delivery", occurred_at) | {
            "delivery_id": _id(delivery_id), "profile_record_id": profile["id"],
            "report_record_id": report["id"], "snapshot_sha256": snapshot_sha256,
            "destination_key_sha256": _digest(destination_key), "fields_sha256": fields_sha,
            "idempotency_key": idempotency_key, "delivery_state": "queued",
            "next_attempt_at": occurred_at, "attempt_count": 0,
        }
        await self.session.execute(insert(metadata.tables["finding_connector_deliveries"]).values(**row))
        await self._audit("finding.connector.queued", delivery_id,
                          {"snapshot_sha256": snapshot_sha256, "network_enabled": False}, occurred_at)
        return row | {"network_contact_count": 0}

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context()
        result: dict[str, list[dict[str, object]]] = {}
        for key, table_name in (
            ("imports", "finding_import_sessions"), ("issues", "managed_issues"),
            ("occurrences", "finding_occurrences"), ("evidence_links", "finding_evidence_links"),
            ("operations", "finding_operations"), ("reports", "finding_report_snapshots"),
            ("publications", "finding_publications"),
            ("comments", "finding_comments"), ("risk_acceptances", "finding_risk_acceptances"),
            ("retests", "finding_retests"),
            ("profiles", "finding_connector_profiles"), ("deliveries", "finding_connector_deliveries"),
        ):
            table = metadata.tables[table_name]
            # IMPORTANT: dashboard reads are bounded; dedicated paginated search owns larger result sets.
            rows = (await self.session.execute(select(table).where(table.c.tenant_id == self.tenant_id)
                                               .order_by(table.c.created_at, table.c.id).limit(500))).mappings().all()
            result[key] = [dict(row) for row in rows]
        for delivery in result["deliveries"]:
            delivery["network_contact_count"] = 0
        return result

    async def _required_issue(self, issue_id: str) -> dict[str, object]:
        issue = await self._find("managed_issues", {"issue_id": _id(issue_id)})
        if issue is None:
            raise ValueError("finding_issue_not_found")
        return issue

    async def _record_issue_operation(self, issue: dict[str, object], *, operation_id: str, kind: str,
                                      to_state: str, detail: object, occurred_at: datetime) -> dict[str, object]:
        digest = _digest((issue["issue_id"], kind, issue["disposition"], to_state, detail))
        existing = await self._find("finding_operations", {"operation_id": _id(operation_id)})
        if existing is not None:
            if existing["operation_sha256"] != digest:
                raise ValueError("finding_operation_immutable")
            return existing
        row = self._owned("operation", occurred_at) | {
            "operation_id": operation_id, "issue_record_id": issue["id"], "operation_kind": kind,
            "actor_id": self.actor_user_id, "from_state": str(issue["disposition"]), "to_state": to_state,
            "operation_sha256": digest, "predecessor_sha256": _digest(issue["disposition"]),
            "successor_sha256": _digest(to_state), "occurred_at": occurred_at,
        }
        await self.session.execute(insert(metadata.tables["finding_operations"]).values(**row))
        return row

    async def _issue_ids_for_import(self, import_record_ref: str) -> tuple[str, ...]:
        records = metadata.tables["finding_import_records"]
        issues = metadata.tables["managed_issues"]
        rows = (await self.session.execute(select(issues.c.issue_id).join(
            records, records.c.issue_fingerprint == issues.c.issue_fingerprint,
        ).where(records.c.tenant_id == self.tenant_id, issues.c.tenant_id == self.tenant_id,
                records.c.import_record_ref == import_record_ref).order_by(records.c.created_at))).scalars().all()
        return tuple(str(row) for row in rows)

    async def _find(self, table_name: str, conditions: dict[str, object]) -> dict[str, object] | None:
        table = metadata.tables[table_name]
        statement = select(table).where(table.c.tenant_id == self.tenant_id)
        for key, value in conditions.items():
            statement = statement.where(table.c[key] == value)
        row = (await self.session.execute(statement.limit(1))).mappings().first()
        return dict(row) if row is not None else None

    def _owned(self, prefix: str, occurred_at: datetime) -> dict[str, object]:
        return {"id": f"r115-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id, "version": 1,
                "created_at": occurred_at, "updated_at": occurred_at}

    async def _context(self) -> None:
        await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
                                   {"tenant": self.tenant_id})

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                                   {"scope": f"{self.tenant_id}:{scope}"})

    async def _audit(self, event: str, subject: str, details: dict[str, object],
                     occurred_at: datetime) -> None:
        owned = {"tenant_id": self.tenant_id, "version": 1, "created_at": occurred_at,
                 "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", actor_user_id=self.actor_user_id, action=event,
            subject_type="finding_operations", subject_id=subject[:64], correlation_id=self.correlation_id,
            details=details, **owned,
        ))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", event_type=event, aggregate_id=subject[:64], payload=details,
            published=False, **owned,
        ))


def _id(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 200 or not all(
        character.isalnum() or character in "._:-" for character in value
    ):
        raise ValueError("finding_repository_identifier_invalid")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError("finding_repository_sha256_invalid")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _derived_id(prefix: str, value: str) -> str:
    return f"{prefix}-{hashlib.sha256(value.encode()).hexdigest()[:24]}"
