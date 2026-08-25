"""Scanner finding normalization and deduplication contracts.

This module never executes scanners, parses external payload files, contacts
targets, or exports to issue trackers. It normalizes supplied `FindingRecord`
objects into scanner envelopes with stable deduplication and evidence lineage.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from enum import Enum

from redagent_platform.evidence_chain import RedactionStatus
from redagent_platform.findings import Confidence, EvidenceLink, FindingRecord, Severity, validate_finding


class ScannerSourceFamily(str, Enum):
    ZAP = "zap"
    NUCLEI = "nuclei"
    OPENAPI = "openapi"
    CLOUD = "cloud"
    SUPPLY_CHAIN = "supply_chain"
    FUTURE = "future"


@dataclass(frozen=True, kw_only=True)
class ScannerEvidenceLineage:
    evidence_id: str
    integrity_hash: str
    redaction_status: RedactionStatus
    contains_sensitive_payload: bool


@dataclass(frozen=True, kw_only=True)
class NormalizedScannerFinding:
    finding: FindingRecord
    source_family: ScannerSourceFamily
    source_result_id: str
    source_rule_id: str | None
    normalized_severity: Severity
    normalized_confidence: Confidence
    evidence_lineage: tuple[ScannerEvidenceLineage, ...]
    deduplication_key: str
    conflict_key: str


@dataclass(frozen=True, kw_only=True)
class ScannerDeduplicationGroup:
    deduplication_key: str
    primary: NormalizedScannerFinding
    duplicates: tuple[NormalizedScannerFinding, ...]
    merged_evidence_lineage: tuple[ScannerEvidenceLineage, ...]


@dataclass(frozen=True, kw_only=True)
class ScannerSourceConflict:
    conflict_key: str
    sources: tuple[str, ...]
    severities: tuple[Severity, ...]
    finding_ids: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class ScannerNormalizationReport:
    total_findings: int
    unique_groups: tuple[ScannerDeduplicationGroup, ...]
    duplicate_count: int
    source_conflicts: tuple[ScannerSourceConflict, ...]


_SEVERITY_ALIASES = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
    "none": Severity.INFO,
}

_CONFIDENCE_ALIASES = {
    "confirmed": Confidence.CONFIRMED,
    "high": Confidence.HIGH,
    "medium": Confidence.MEDIUM,
    "moderate": Confidence.MEDIUM,
    "low": Confidence.LOW,
    "unknown": Confidence.LOW,
}


def normalize_severity_label(value: str | Severity) -> Severity:
    if isinstance(value, Severity):
        return value
    normalized = value.strip().lower()
    if normalized not in _SEVERITY_ALIASES:
        raise ValueError("unknown_severity_label")
    return _SEVERITY_ALIASES[normalized]


def normalize_confidence_label(value: str | Confidence) -> Confidence:
    if isinstance(value, Confidence):
        return value
    normalized = value.strip().lower()
    if normalized not in _CONFIDENCE_ALIASES:
        raise ValueError("unknown_confidence_label")
    return _CONFIDENCE_ALIASES[normalized]


def normalize_scanner_finding(
    *,
    finding: FindingRecord,
    source_family: ScannerSourceFamily,
    source_result_id: str,
) -> NormalizedScannerFinding:
    validate_finding(finding)
    _require_non_empty("source_result_id", source_result_id)
    lineage = tuple(_lineage_from_evidence(link) for link in finding.evidence_links)
    return NormalizedScannerFinding(
        finding=finding,
        source_family=source_family,
        source_result_id=source_result_id.strip(),
        source_rule_id=finding.source_rule_id,
        normalized_severity=finding.risk.severity,
        normalized_confidence=finding.confidence,
        evidence_lineage=lineage,
        deduplication_key=_dedupe_key(finding, source_family, lineage),
        conflict_key=_conflict_key(finding),
    )


def deduplicate_scanner_findings(findings: tuple[NormalizedScannerFinding, ...]) -> ScannerNormalizationReport:
    groups_by_key: dict[str, list[NormalizedScannerFinding]] = {}
    for finding in findings:
        groups_by_key.setdefault(finding.deduplication_key, []).append(finding)
    groups: list[ScannerDeduplicationGroup] = []
    duplicate_count = 0
    for key in sorted(groups_by_key):
        members = groups_by_key[key]
        primary = members[0]
        duplicates = tuple(members[1:])
        duplicate_count += len(duplicates)
        groups.append(
            ScannerDeduplicationGroup(
                deduplication_key=key,
                primary=primary,
                duplicates=duplicates,
                merged_evidence_lineage=_merge_lineage(tuple(member for member in members)),
            )
        )
    return ScannerNormalizationReport(
        total_findings=len(findings),
        unique_groups=tuple(groups),
        duplicate_count=duplicate_count,
        source_conflicts=_detect_source_conflicts(findings),
    )


def _lineage_from_evidence(link: EvidenceLink) -> ScannerEvidenceLineage:
    _require_non_empty("evidence_id", link.evidence_id)
    _require_non_empty("integrity_hash", link.integrity_hash)
    return ScannerEvidenceLineage(
        evidence_id=link.evidence_id,
        integrity_hash=link.integrity_hash,
        redaction_status=link.redaction_status,
        contains_sensitive_payload=link.contains_sensitive_payload,
    )


def _dedupe_key(
    finding: FindingRecord,
    source_family: ScannerSourceFamily,
    lineage: tuple[ScannerEvidenceLineage, ...],
) -> str:
    intel = finding.risk.vulnerability_intelligence
    payload = {
        "source_family": source_family.value,
        "source": finding.source.strip().lower(),
        "source_rule_id": (finding.source_rule_id or "").strip().lower(),
        "cve_ids": tuple(sorted(intel.cve_ids)),
        "cwe_ids": tuple(sorted(intel.cwe_ids)),
        "asset": finding.affected_asset_id.strip().lower(),
        "path_component": _normalize_component(finding.affected_asset_value),
        "severity": finding.risk.severity.value,
        "evidence_hashes": tuple(sorted(item.integrity_hash for item in lineage)),
    }
    return _canonical_sha256(payload)


def _conflict_key(finding: FindingRecord) -> str:
    intel = finding.risk.vulnerability_intelligence
    payload = {
        "rule_or_title": (finding.source_rule_id or finding.title).strip().lower(),
        "cve_ids": tuple(sorted(intel.cve_ids)),
        "cwe_ids": tuple(sorted(intel.cwe_ids)),
        "asset": finding.affected_asset_id.strip().lower(),
        "path_component": _normalize_component(finding.affected_asset_value),
    }
    return _canonical_sha256(payload)


def _merge_lineage(members: tuple[NormalizedScannerFinding, ...]) -> tuple[ScannerEvidenceLineage, ...]:
    merged: dict[tuple[str, str], ScannerEvidenceLineage] = {}
    for member in members:
        for lineage in member.evidence_lineage:
            merged.setdefault((lineage.evidence_id, lineage.integrity_hash), lineage)
    return tuple(merged[key] for key in sorted(merged))


def _detect_source_conflicts(findings: tuple[NormalizedScannerFinding, ...]) -> tuple[ScannerSourceConflict, ...]:
    by_conflict_key: dict[str, list[NormalizedScannerFinding]] = {}
    for finding in findings:
        by_conflict_key.setdefault(finding.conflict_key, []).append(finding)
    conflicts: list[ScannerSourceConflict] = []
    for key in sorted(by_conflict_key):
        members = by_conflict_key[key]
        sources = tuple(sorted({member.source_family.value for member in members}))
        severities = tuple(sorted({member.normalized_severity for member in members}, key=lambda item: item.value))
        if len(sources) <= 1 and len(severities) <= 1:
            continue
        conflicts.append(
            ScannerSourceConflict(
                conflict_key=key,
                sources=sources,
                severities=severities,
                finding_ids=tuple(member.finding.id for member in members),
            )
        )
    return tuple(conflicts)


def _normalize_component(value: str) -> str:
    return " ".join(value.strip().lower().rstrip("/").split())


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
