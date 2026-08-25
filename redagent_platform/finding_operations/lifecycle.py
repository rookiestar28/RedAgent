"""Append-only collaborative finding lifecycle."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
import hashlib

from redagent_platform.finding_operations.contracts import Disposition


@dataclass(frozen=True, kw_only=True)
class IssueState:
    issue_id: str
    state: str
    disposition: Disposition
    predecessor_issue_ids: tuple[str, ...] = ()
    risk_acceptance_expires_at: datetime | None = None
    owner_id: str | None = None


@dataclass(frozen=True, kw_only=True)
class OccurrenceState:
    occurrence_id: str
    issue_id: str


@dataclass(frozen=True, kw_only=True)
class LifecycleOperation:
    kind: str
    actor_id: str
    rationale: str
    occurred_at: datetime
    source_issue_ids: tuple[str, ...]
    successor_issue_ids: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class CommentRecord:
    issue_id: str
    author_id: str
    comment_sha256: str
    occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class RetestRecord:
    retest_id: str
    issue_id: str
    baseline_run_id: str
    retest_run_id: str | None
    coverage_state: str
    result_state: str


@dataclass(frozen=True, kw_only=True)
class FindingLifecycle:
    tenant_id: str
    issues: dict[str, IssueState]
    occurrences: dict[str, OccurrenceState]
    operations: tuple[LifecycleOperation, ...]
    comments: tuple[CommentRecord, ...]
    retests: dict[str, RetestRecord]

    @classmethod
    def bootstrap(cls, *, tenant_id: str, issue_ids: tuple[str, ...], occurrence_ids: tuple[str, ...],
                  occurred_at: datetime) -> "FindingLifecycle":
        del occurred_at
        if not tenant_id or not issue_ids:
            raise ValueError("finding_lifecycle_identity_required")
        issues = {item: IssueState(issue_id=item, state="active", disposition=Disposition.NEEDS_REVIEW)
                  for item in issue_ids}
        occurrences = {item: OccurrenceState(occurrence_id=item, issue_id=issue_ids[index % len(issue_ids)])
                       for index, item in enumerate(occurrence_ids)}
        return cls(tenant_id=tenant_id, issues=issues, occurrences=occurrences, operations=(), comments=(), retests={})

    def accept_risk(self, *, issue_id: str, reviewer_id: str, rationale: str, expires_at: datetime,
                    occurred_at: datetime) -> "FindingLifecycle":
        if expires_at <= occurred_at or issue_id not in self.issues:
            raise ValueError("finding_risk_acceptance_invalid")
        issues = dict(self.issues)
        issues[issue_id] = replace(issues[issue_id], disposition=Disposition.RISK_ACCEPTED,
                                   risk_acceptance_expires_at=expires_at)
        operation = LifecycleOperation(kind="risk_accepted", actor_id=reviewer_id, rationale=rationale,
                                       occurred_at=occurred_at, source_issue_ids=(issue_id,),
                                       successor_issue_ids=(issue_id,))
        return replace(self, issues=issues, operations=self.operations + (operation,))

    def assign(self, *, issue_id: str, owner_id: str, actor_id: str,
               occurred_at: datetime) -> "FindingLifecycle":
        issue = self._issue(issue_id)
        issues = dict(self.issues); issues[issue_id] = replace(issue, owner_id=owner_id)
        return self._append(issues, "issue_assigned", actor_id, owner_id, occurred_at, issue_id)

    def comment(self, *, issue_id: str, author_id: str, comment: str,
                occurred_at: datetime) -> "FindingLifecycle":
        self._issue(issue_id)
        if len(comment.strip()) < 10:
            raise ValueError("finding_comment_invalid")
        record = CommentRecord(issue_id=issue_id, author_id=author_id,
                               comment_sha256=hashlib.sha256(comment.strip().encode()).hexdigest(),
                               occurred_at=occurred_at)
        result = self._append(dict(self.issues), "comment_added", author_id, record.comment_sha256,
                              occurred_at, issue_id)
        return replace(result, comments=self.comments + (record,))

    def request_retest(self, *, issue_id: str, retest_id: str, baseline_run_id: str,
                       actor_id: str, occurred_at: datetime) -> "FindingLifecycle":
        self._issue(issue_id)
        if retest_id in self.retests:
            raise ValueError("finding_retest_immutable")
        retests = dict(self.retests); retests[retest_id] = RetestRecord(
            retest_id=retest_id, issue_id=issue_id, baseline_run_id=baseline_run_id,
            retest_run_id=None, coverage_state="unknown", result_state="requested",
        )
        result = self._append(dict(self.issues), "retest_requested", actor_id, baseline_run_id,
                              occurred_at, issue_id)
        return replace(result, retests=retests)

    def complete_retest(self, *, retest_id: str, retest_run_id: str, coverage_state: str,
                        result_state: str, actor_id: str, occurred_at: datetime) -> "FindingLifecycle":
        retest = self.retests.get(retest_id)
        if retest is None or coverage_state not in {"complete", "partial"} or result_state not in {"passed", "failed"}:
            raise ValueError("finding_retest_completion_invalid")
        if result_state == "passed" and coverage_state != "complete":
            raise ValueError("finding_retest_complete_coverage_required")
        retests = dict(self.retests); retests[retest_id] = replace(
            retest, retest_run_id=retest_run_id, coverage_state=coverage_state, result_state=result_state,
        )
        result = self._append(dict(self.issues), "retest_completed", actor_id, result_state,
                              occurred_at, retest.issue_id)
        return replace(result, retests=retests)

    def close(self, *, issue_id: str, actor_id: str, reason: str,
              occurred_at: datetime) -> "FindingLifecycle":
        issue = self._issue(issue_id)
        if not any(item.issue_id == issue_id and item.result_state == "passed" and item.coverage_state == "complete"
                   for item in self.retests.values()):
            raise ValueError("finding_complete_retest_required")
        issues = dict(self.issues); issues[issue_id] = replace(issue, state="closed", disposition=Disposition.CLOSED)
        return self._append(issues, "issue_closed", actor_id, reason, occurred_at, issue_id)

    def reopen(self, *, issue_id: str, actor_id: str, reason: str,
               occurred_at: datetime) -> "FindingLifecycle":
        issue = self._issue(issue_id)
        if issue.state != "closed":
            raise ValueError("finding_closed_issue_required")
        issues = dict(self.issues); issues[issue_id] = replace(
            issue, state="active", disposition=Disposition.NEEDS_REVIEW,
        )
        return self._append(issues, "issue_reopened", actor_id, reason, occurred_at, issue_id)

    def _issue(self, issue_id: str) -> IssueState:
        issue = self.issues.get(issue_id)
        if issue is None:
            raise ValueError("finding_issue_not_found")
        return issue

    def _append(self, issues: dict[str, IssueState], kind: str, actor_id: str, rationale: str,
                occurred_at: datetime, issue_id: str) -> "FindingLifecycle":
        operation = LifecycleOperation(kind=kind, actor_id=actor_id, rationale=rationale,
                                       occurred_at=occurred_at, source_issue_ids=(issue_id,),
                                       successor_issue_ids=(issue_id,))
        return replace(self, issues=issues, operations=self.operations + (operation,))


def merge_issues(lifecycle: FindingLifecycle, *, source_issue_ids: tuple[str, ...], successor_issue_id: str,
                 actor_id: str, rationale: str, occurred_at: datetime) -> FindingLifecycle:
    if len(set(source_issue_ids)) < 2 or any(item not in lifecycle.issues for item in source_issue_ids):
        raise ValueError("finding_merge_sources_invalid")
    issues = dict(lifecycle.issues)
    for item in source_issue_ids:
        issues[item] = replace(issues[item], state="merged")
    issues[successor_issue_id] = IssueState(issue_id=successor_issue_id, state="active",
                                            disposition=Disposition.NEEDS_REVIEW,
                                            predecessor_issue_ids=tuple(sorted(source_issue_ids)))
    occurrences = {key: replace(value, issue_id=successor_issue_id) if value.issue_id in source_issue_ids else value
                   for key, value in lifecycle.occurrences.items()}
    operation = LifecycleOperation(kind="issues_merged", actor_id=actor_id, rationale=rationale,
                                   occurred_at=occurred_at, source_issue_ids=source_issue_ids,
                                   successor_issue_ids=(successor_issue_id,))
    return replace(lifecycle, issues=issues, occurrences=occurrences, operations=lifecycle.operations + (operation,))


def split_occurrence(lifecycle: FindingLifecycle, *, source_issue_id: str, occurrence_id: str,
                     successor_issue_id: str, actor_id: str, rationale: str,
                     occurred_at: datetime) -> FindingLifecycle:
    occurrence = lifecycle.occurrences.get(occurrence_id)
    if occurrence is None or occurrence.issue_id != source_issue_id:
        raise ValueError("finding_split_occurrence_invalid")
    issues = dict(lifecycle.issues)
    issues[successor_issue_id] = IssueState(issue_id=successor_issue_id, state="active",
                                            disposition=Disposition.NEEDS_REVIEW,
                                            predecessor_issue_ids=(source_issue_id,))
    occurrences = dict(lifecycle.occurrences)
    occurrences[occurrence_id] = replace(occurrence, issue_id=successor_issue_id)
    operation = LifecycleOperation(kind="occurrence_split", actor_id=actor_id, rationale=rationale,
                                   occurred_at=occurred_at, source_issue_ids=(source_issue_id,),
                                   successor_issue_ids=(source_issue_id, successor_issue_id))
    return replace(lifecycle, issues=issues, occurrences=occurrences, operations=lifecycle.operations + (operation,))


def expire_risk_acceptance(lifecycle: FindingLifecycle, *, occurred_at: datetime) -> FindingLifecycle:
    issues = dict(lifecycle.issues)
    operations = lifecycle.operations
    for issue_id, issue in lifecycle.issues.items():
        if (issue.disposition is Disposition.RISK_ACCEPTED and issue.risk_acceptance_expires_at is not None
                and issue.risk_acceptance_expires_at <= occurred_at):
            issues[issue_id] = replace(issue, disposition=Disposition.NEEDS_REVIEW,
                                       risk_acceptance_expires_at=None)
            operations += (LifecycleOperation(
                kind="risk_acceptance_expired", actor_id="system", rationale="scheduled exception expiry",
                occurred_at=occurred_at, source_issue_ids=(issue_id,), successor_issue_ids=(issue_id,),
            ),)
    return replace(lifecycle, issues=issues, operations=operations)


@dataclass(frozen=True, kw_only=True)
class RunCoverage:
    run_id: str
    complete: bool
    issue_fingerprints: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class RunComparison:
    baseline_run_id: str
    current_run_id: str
    new: tuple[str, ...]
    unchanged: tuple[str, ...]
    absent: tuple[str, ...]
    unknown_absence: tuple[str, ...]


def compare_runs(baseline: RunCoverage, current: RunCoverage) -> RunComparison:
    baseline_set = set(baseline.issue_fingerprints); current_set = set(current.issue_fingerprints)
    missing = tuple(sorted(baseline_set - current_set))
    return RunComparison(
        baseline_run_id=baseline.run_id, current_run_id=current.run_id,
        new=tuple(sorted(current_set - baseline_set)), unchanged=tuple(sorted(current_set & baseline_set)),
        absent=missing if current.complete else (), unknown_absence=() if current.complete else missing,
    )
