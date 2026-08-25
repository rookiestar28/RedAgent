"""Finding normalization, risk factors, and safe export contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum

from redagent_platform.domain import FindingStatus
from redagent_platform.evidence_chain import RedactionStatus
from redagent_platform.redaction import RedactionArtifactClass, assert_no_sensitive_output


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Confidence(str, Enum):
    CONFIRMED = "confirmed"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class ExploitLikelihood(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class BusinessImpact(str, Enum):
    SEVERE = "severe"
    HIGH = "high"
    MODERATE = "moderate"
    LOW = "low"
    UNKNOWN = "unknown"


class AssetCriticality(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass(frozen=True, kw_only=True)
class VulnerabilityIntelligence:
    cve_ids: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    cvss_score: float | None = None
    epss_probability: float | None = None
    kev_listed: bool = False


@dataclass(frozen=True, kw_only=True)
class RiskFactors:
    severity: Severity
    exploit_likelihood: ExploitLikelihood
    asset_criticality: AssetCriticality
    business_impact: BusinessImpact
    vulnerability_intelligence: VulnerabilityIntelligence


@dataclass(frozen=True, kw_only=True)
class EvidenceLink:
    evidence_id: str
    integrity_hash: str
    redaction_status: RedactionStatus
    contains_sensitive_payload: bool = False


@dataclass(frozen=True, kw_only=True)
class FindingRecord:
    id: str
    title: str
    status: FindingStatus
    affected_asset_id: str
    affected_asset_value: str
    confidence: Confidence
    risk: RiskFactors
    reproduction_summary: str
    evidence_links: tuple[EvidenceLink, ...]
    remediation: str
    owner_user_id: str | None
    source: str
    source_rule_id: str | None = None

    @property
    def severity(self) -> Severity:
        return self.risk.severity


_CVE = re.compile(r"^CVE-\d{4}-\d{4,}$")
_CWE = re.compile(r"^CWE-\d+$")
_SCORE_BY_SEVERITY = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}
_SCORE_BY_LIKELIHOOD = {
    ExploitLikelihood.HIGH: 3,
    ExploitLikelihood.MEDIUM: 2,
    ExploitLikelihood.LOW: 1,
    ExploitLikelihood.UNKNOWN: 0,
}
_SCORE_BY_ASSET = {
    AssetCriticality.CRITICAL: 3,
    AssetCriticality.HIGH: 2,
    AssetCriticality.MEDIUM: 1,
    AssetCriticality.LOW: 0,
    AssetCriticality.UNKNOWN: 0,
}
_SCORE_BY_BUSINESS = {
    BusinessImpact.SEVERE: 3,
    BusinessImpact.HIGH: 2,
    BusinessImpact.MODERATE: 1,
    BusinessImpact.LOW: 0,
    BusinessImpact.UNKNOWN: 0,
}


def validate_finding(finding: FindingRecord) -> None:
    for field_name, value in (
        ("id", finding.id),
        ("title", finding.title),
        ("affected_asset_id", finding.affected_asset_id),
        ("affected_asset_value", finding.affected_asset_value),
        ("reproduction_summary", finding.reproduction_summary),
        ("remediation", finding.remediation),
        ("source", finding.source),
    ):
        _require_non_empty(field_name, value)
    if not finding.evidence_links:
        raise ValueError("missing_evidence_links")
    for cve_id in finding.risk.vulnerability_intelligence.cve_ids:
        if not _CVE.fullmatch(cve_id):
            raise ValueError("invalid_cve_id")
    for cwe_id in finding.risk.vulnerability_intelligence.cwe_ids:
        if not _CWE.fullmatch(cwe_id):
            raise ValueError("invalid_cwe_id")
    cvss_score = finding.risk.vulnerability_intelligence.cvss_score
    if cvss_score is not None and not (0.0 <= cvss_score <= 10.0):
        raise ValueError("invalid_cvss_score")
    epss_probability = finding.risk.vulnerability_intelligence.epss_probability
    if epss_probability is not None and not (0.0 <= epss_probability <= 1.0):
        raise ValueError("invalid_epss_probability")
    for evidence in finding.evidence_links:
        _require_non_empty("evidence_id", evidence.evidence_id)
        _require_non_empty("integrity_hash", evidence.integrity_hash)


def priority_score(risk: RiskFactors) -> int:
    """Return a coarse priority score while keeping input factors separate."""
    score = (
        _SCORE_BY_SEVERITY[risk.severity] * 10
        + _SCORE_BY_LIKELIHOOD[risk.exploit_likelihood] * 4
        + _SCORE_BY_ASSET[risk.asset_criticality] * 3
        + _SCORE_BY_BUSINESS[risk.business_impact] * 3
    )
    if risk.vulnerability_intelligence.kev_listed:
        score += 5
    if risk.vulnerability_intelligence.epss_probability is not None:
        score += round(risk.vulnerability_intelligence.epss_probability * 5)
    return score


def duplicate_correlation_key(finding: FindingRecord) -> str:
    validate_finding(finding)
    payload = {
        "source": finding.source.strip().lower(),
        "source_rule_id": (finding.source_rule_id or "").strip().lower(),
        "affected_asset_id": finding.affected_asset_id.strip().lower(),
        "title": _normalize_text(finding.title),
        "cve_ids": sorted(finding.risk.vulnerability_intelligence.cve_ids),
        "cwe_ids": sorted(finding.risk.vulnerability_intelligence.cwe_ids),
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def export_sanitized_finding(finding: FindingRecord) -> dict[str, object]:
    validate_finding(finding)
    _ensure_no_secret_like_text(finding.title)
    _ensure_no_secret_like_text(finding.reproduction_summary)
    _ensure_no_secret_like_text(finding.remediation)
    for evidence in finding.evidence_links:
        if evidence.contains_sensitive_payload and evidence.redaction_status not in {
            RedactionStatus.REDACTED,
            RedactionStatus.BLOCKED,
        }:
            raise ValueError("unredacted_sensitive_evidence_forbidden")
    return {
        "id": finding.id,
        "title": finding.title,
        "status": finding.status.value,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "affected_asset_id": finding.affected_asset_id,
        "affected_asset_value": finding.affected_asset_value,
        "risk": {
            "severity": finding.risk.severity.value,
            "exploit_likelihood": finding.risk.exploit_likelihood.value,
            "asset_criticality": finding.risk.asset_criticality.value,
            "business_impact": finding.risk.business_impact.value,
            "priority_score": priority_score(finding.risk),
        },
        "vulnerability_intelligence": {
            "cve_ids": finding.risk.vulnerability_intelligence.cve_ids,
            "cwe_ids": finding.risk.vulnerability_intelligence.cwe_ids,
            "cvss_score": finding.risk.vulnerability_intelligence.cvss_score,
            "epss_probability": finding.risk.vulnerability_intelligence.epss_probability,
            "kev_listed": finding.risk.vulnerability_intelligence.kev_listed,
        },
        "reproduction_summary": finding.reproduction_summary,
        "evidence": tuple(
            {
                "evidence_id": evidence.evidence_id,
                "integrity_hash": evidence.integrity_hash,
                "redaction_status": evidence.redaction_status.value,
            }
            for evidence in finding.evidence_links
        ),
        "remediation": finding.remediation,
        "owner_user_id": finding.owner_user_id,
        "correlation_key": duplicate_correlation_key(finding),
    }


def _normalize_text(value: str) -> str:
    return " ".join(value.strip().lower().split())


def _ensure_no_secret_like_text(value: str) -> None:
    try:
        assert_no_sensitive_output(value, RedactionArtifactClass.ISSUE_EXPORT)
    except ValueError as exc:
        raise ValueError("secret_like_text_forbidden") from exc


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
