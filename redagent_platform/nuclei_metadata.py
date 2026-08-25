"""Nuclei template metadata import and review contracts."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from redagent_platform.domain import TestRiskClass


class NucleiSeverity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class NucleiReviewStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    SANDBOX_ONLY_REQUIRED = "sandbox_only_required"


@dataclass(frozen=True, kw_only=True)
class NucleiClassification:
    cve_ids: tuple[str, ...] = ()
    cwe_ids: tuple[str, ...] = ()
    cvss_score: float | None = None
    cvss_metrics: str | None = None


@dataclass(frozen=True, kw_only=True)
class NucleiTemplateMetadata:
    template_id: str
    name: str
    severity: NucleiSeverity
    tags: tuple[str, ...]
    references: tuple[str, ...]
    classification: NucleiClassification
    protocol_types: tuple[str, ...]
    risk_class: TestRiskClass
    high_risk_reasons: tuple[str, ...]
    metadata_only: bool = True
    execution_enabled: bool = False


@dataclass(frozen=True, kw_only=True)
class NucleiTemplateReview:
    template: NucleiTemplateMetadata
    status: NucleiReviewStatus
    reviewer_user_id: str
    reason: str
    execution_enabled: bool = False


_PROTOCOL_KEYS = frozenset({"http", "dns", "ssl", "tcp", "udp", "file", "network", "headless", "code", "javascript", "workflow"})
_HIGH_RISK_PROTOCOLS = frozenset({"headless", "code", "javascript"})
_HIGH_RISK_TAGS = frozenset(
    {
        "destructive",
        "intrusive",
        "oast",
        "interactsh",
        "credential",
        "credentials",
        "bruteforce",
        "brute-force",
        "fuzz",
        "fuzzing",
        "rce",
        "ssrf",
    }
)


def import_nuclei_template_metadata(template: Mapping[str, object]) -> NucleiTemplateMetadata:
    """Import allowlisted Nuclei template metadata without executable content."""
    template_id = _require_string(template.get("id"), "missing_template_id")
    info = _require_mapping(template.get("info"), "missing_info")
    name = _require_string(info.get("name"), "missing_template_name")
    severity = _severity(info.get("severity"))
    tags = _tags(info.get("tags"))
    references = _references(info.get("reference") or info.get("references"))
    classification = _classification(info.get("classification"))
    protocol_types = tuple(sorted(key for key in template if isinstance(key, str) and key in _PROTOCOL_KEYS))
    if not protocol_types:
        raise ValueError("missing_protocol_type")
    high_risk_reasons = _high_risk_reasons(template, severity, tags, protocol_types)
    risk_class = TestRiskClass.ACTIVE_INTRUSIVE if high_risk_reasons else _risk_class_for_severity(severity)
    return NucleiTemplateMetadata(
        template_id=template_id,
        name=name,
        severity=severity,
        tags=tags,
        references=references,
        classification=classification,
        protocol_types=protocol_types,
        risk_class=risk_class,
        high_risk_reasons=high_risk_reasons,
    )


def review_nuclei_template(
    template: NucleiTemplateMetadata,
    *,
    reviewer_user_id: str,
    status: NucleiReviewStatus,
    reason: str,
) -> NucleiTemplateReview:
    _require_non_empty("reviewer_user_id", reviewer_user_id)
    _require_non_empty("reason", reason)
    if status is NucleiReviewStatus.APPROVED and template.high_risk_reasons:
        raise ValueError("high_risk_template_requires_sandbox_or_reject")
    if status is NucleiReviewStatus.SANDBOX_ONLY_REQUIRED and not template.high_risk_reasons:
        raise ValueError("sandbox_only_requires_high_risk_reason")
    if status is NucleiReviewStatus.PENDING:
        raise ValueError("review_status_must_be_terminal")
    return NucleiTemplateReview(
        template=template,
        status=status,
        reviewer_user_id=reviewer_user_id.strip(),
        reason=reason.strip(),
        execution_enabled=False,
    )


def _high_risk_reasons(
    template: Mapping[str, object],
    severity: NucleiSeverity,
    tags: tuple[str, ...],
    protocol_types: tuple[str, ...],
) -> tuple[str, ...]:
    reasons: set[str] = set()
    for protocol in protocol_types:
        if protocol in _HIGH_RISK_PROTOCOLS:
            reasons.add(f"protocol:{protocol}")
    for tag in tags:
        if tag in _HIGH_RISK_TAGS:
            reasons.add(f"tag:{tag}")
    if "self-contained" in template and bool(template["self-contained"]):
        reasons.add("self_contained")
    if severity in {NucleiSeverity.HIGH, NucleiSeverity.CRITICAL, NucleiSeverity.UNKNOWN}:
        reasons.add(f"severity:{severity.value}")
    if _has_unclear_behavior(template):
        reasons.add("unclear_behavior")
    return tuple(sorted(reasons))


def _has_unclear_behavior(template: Mapping[str, object]) -> bool:
    return any(key in template for key in ("payloads", "variables", "flow")) and not template.get("metadata")


def _risk_class_for_severity(severity: NucleiSeverity) -> TestRiskClass:
    if severity is NucleiSeverity.INFO:
        return TestRiskClass.METADATA_ONLY
    if severity is NucleiSeverity.LOW:
        return TestRiskClass.PASSIVE
    if severity is NucleiSeverity.MEDIUM:
        return TestRiskClass.ACTIVE_SAFE
    return TestRiskClass.ACTIVE_INTRUSIVE


def _severity(value: object) -> NucleiSeverity:
    if not isinstance(value, str):
        return NucleiSeverity.UNKNOWN
    normalized = value.strip().lower()
    return NucleiSeverity(normalized) if normalized in {item.value for item in NucleiSeverity} else NucleiSeverity.UNKNOWN


def _tags(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        raw = value.split(",")
    elif isinstance(value, tuple | list):
        raw = [str(item) for item in value]
    else:
        raise ValueError("invalid_tags")
    return tuple(sorted({tag.strip().lower() for tag in raw if tag.strip()}))


def _references(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value.strip(),) if value.strip() else ()
    if isinstance(value, tuple | list):
        return tuple(str(item).strip() for item in value if str(item).strip())
    raise ValueError("invalid_references")


def _classification(value: object) -> NucleiClassification:
    if value is None:
        return NucleiClassification()
    data = _require_mapping(value, "invalid_classification")
    cve_ids = _string_tuple(data.get("cve-id"))
    cwe_ids = _string_tuple(data.get("cwe-id"))
    cvss_score_raw = data.get("cvss-score")
    cvss_score = float(cvss_score_raw) if isinstance(cvss_score_raw, int | float | str) and str(cvss_score_raw).strip() else None
    cvss_metrics = data.get("cvss-metrics")
    return NucleiClassification(
        cve_ids=cve_ids,
        cwe_ids=cwe_ids,
        cvss_score=cvss_score,
        cvss_metrics=cvss_metrics if isinstance(cvss_metrics, str) else None,
    )


def _string_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value.strip(),) if value.strip() else ()
    if isinstance(value, tuple | list):
        return tuple(str(item).strip() for item in value if str(item).strip())
    return ()


def _require_mapping(value: object, error_code: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(error_code)
    return value


def _require_string(value: object, error_code: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(error_code)
    return value.strip()


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
