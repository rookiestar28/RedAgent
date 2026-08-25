"""Deterministic, evidence-gated compat_115 report snapshots."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json


class PublicationBlock(str, Enum):
    MISSING_REVIEW = "missing_review"
    UNSAFE_EVIDENCE = "unsafe_evidence"
    PARTIAL_COVERAGE_UNDISCLOSED = "partial_coverage_undisclosed"
    STALE_POLICY = "stale_policy"
    UNSUPPORTED_CLAIM = "unsupported_claim"
    AI_NOT_ADOPTED = "ai_not_adopted"


@dataclass(frozen=True, kw_only=True)
class ReportClaimInput:
    claim_id: str
    text: str
    evidence_sha256s: tuple[str, ...]
    reviewer_adopted: bool
    ai_drafted: bool


@dataclass(frozen=True, kw_only=True)
class ReportSnapshotInput:
    report_id: str
    tenant_id: str
    audience: str
    policy_revision: str
    roe_version_id: str
    reviewed_snapshot_sha256: str
    coverage_state: str
    partial_coverage_disclosed: bool
    independently_reviewed: bool
    evidence_redaction_state: str
    generated_at: datetime
    claims: tuple[ReportClaimInput, ...]


@dataclass(frozen=True, kw_only=True)
class ReportSnapshot:
    snapshot_sha256: str
    rendered_bytes: bytes
    publication_blocks: tuple[PublicationBlock, ...]


def build_report_snapshot(value: ReportSnapshotInput) -> ReportSnapshot:
    blocks: list[PublicationBlock] = []
    if not value.independently_reviewed:
        blocks.append(PublicationBlock.MISSING_REVIEW)
    if value.evidence_redaction_state not in {"report_safe", "export_safe"}:
        blocks.append(PublicationBlock.UNSAFE_EVIDENCE)
    if value.coverage_state != "complete" and not value.partial_coverage_disclosed:
        blocks.append(PublicationBlock.PARTIAL_COVERAGE_UNDISCLOSED)
    if value.policy_revision == "stale":
        blocks.append(PublicationBlock.STALE_POLICY)
    for claim in value.claims:
        if not claim.evidence_sha256s or not claim.reviewer_adopted:
            blocks.append(PublicationBlock.UNSUPPORTED_CLAIM)
        if claim.ai_drafted and not claim.reviewer_adopted:
            blocks.append(PublicationBlock.AI_NOT_ADOPTED)
    payload = asdict(value)
    payload["generated_at"] = value.generated_at.isoformat()
    rendered = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return ReportSnapshot(snapshot_sha256=hashlib.sha256(rendered).hexdigest(), rendered_bytes=rendered,
                          publication_blocks=tuple(dict.fromkeys(blocks)))
