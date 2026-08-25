"""Passive reconnaissance planning and observation ingestion contracts.

This module does not execute network requests. It produces bounded passive
metadata request specifications and ingests observations supplied by a future
authorized runner.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from urllib.parse import urlparse

from redagent_platform.domain import EvidenceKind, FindingStatus, TargetType, TestMode
from redagent_platform.evidence_chain import (
    EvidenceAccessPolicy,
    EvidenceChain,
    EvidenceRecord,
    RedactionStatus,
    RetentionClass,
)
from redagent_platform.findings import (
    AssetCriticality,
    BusinessImpact,
    Confidence,
    EvidenceLink,
    ExploitLikelihood,
    FindingRecord,
    RiskFactors,
    Severity,
    VulnerabilityIntelligence,
    validate_finding,
)
from redagent_platform.scope_authorization import EngagementScope, JobScopeRequest, ScopeTarget, decide_scope


class PassiveCheckKind(str, Enum):
    DNS_METADATA = "dns_metadata"
    TLS_METADATA = "tls_metadata"
    HTTP_HEADERS = "http_headers"
    ROBOTS_TXT = "robots_txt"
    SECURITY_TXT = "security_txt"
    SITEMAP = "sitemap"
    TECH_FINGERPRINT = "tech_fingerprint"
    OPENAPI_METADATA = "openapi_metadata"


class PassiveTransport(str, Enum):
    DNS = "dns"
    TLS = "tls"
    HTTP = "http"
    DERIVED = "derived"


@dataclass(frozen=True, kw_only=True)
class PassiveReconProfile:
    include_dns: bool = True
    include_tls: bool = True
    include_http_headers: bool = True
    include_known_metadata_files: bool = True
    include_openapi_metadata: bool = True
    include_technology_fingerprint: bool = True
    max_metadata_body_bytes: int = 4096


@dataclass(frozen=True, kw_only=True)
class PassiveRequestSpec:
    spec_id: str
    kind: PassiveCheckKind
    target: ScopeTarget
    transport: PassiveTransport
    method: str | None
    reference: str
    max_response_body_bytes: int
    follow_redirects: bool = False
    payload_present: bool = False
    target_interaction: bool = True


@dataclass(frozen=True, kw_only=True)
class PassiveReconPlan:
    job_id: str
    organization_id: str
    engagement_id: str
    target: ScopeTarget
    specs: tuple[PassiveRequestSpec, ...]
    projected_interactions: int
    min_delay_seconds: float
    requested_at: datetime


@dataclass(frozen=True, kw_only=True)
class HeaderObservation:
    name: str
    value: str


@dataclass(frozen=True, kw_only=True)
class PassiveObservation:
    spec_id: str
    kind: PassiveCheckKind
    target: ScopeTarget
    captured_at: datetime
    status_code: int | None = None
    headers: tuple[HeaderObservation, ...] = ()
    dns_records: tuple[str, ...] = ()
    tls_metadata: tuple[tuple[str, str], ...] = ()
    body_excerpt: str | None = None
    openapi_metadata: tuple[tuple[str, str], ...] = ()
    technology: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class SanitizedPassiveObservation:
    observation: PassiveObservation
    redacted: bool
    content: dict[str, object]


@dataclass(frozen=True, kw_only=True)
class PassiveEvidenceResult:
    chain: EvidenceChain
    record: EvidenceRecord
    sanitized_observation: SanitizedPassiveObservation


_SENSITIVE_HEADER_NAMES = frozenset(
    {
        "authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "proxy-authorization",
    }
)
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_SECRET_TEXT = re.compile(r"(?i)(api[_-]?key|secret|token|password)\s*[:=]\s*\S+")


def build_passive_recon_plan(
    *,
    scope: EngagementScope,
    target: ScopeTarget,
    requested_at: datetime,
    job_id: str,
    profile: PassiveReconProfile | None = None,
) -> PassiveReconPlan:
    """Build a bounded passive plan after compat_006 scope authorization."""
    _require_non_empty("job_id", job_id)
    _require_timezone(requested_at)
    active_profile = profile or PassiveReconProfile()
    _validate_profile(active_profile)
    specs = _default_specs_for_target(target.normalized(), active_profile)
    projected_interactions = sum(1 for spec in specs if spec.target_interaction)
    decision = decide_scope(
        scope,
        JobScopeRequest(
            target=target,
            mode=TestMode.PASSIVE_SCAN,
            requested_at=requested_at,
            projected_interactions=projected_interactions,
        ),
    )
    if not decision.allowed:
        raise ValueError(f"passive_scope_denied:{decision.reason}")
    return PassiveReconPlan(
        job_id=job_id.strip(),
        organization_id=scope.organization_id,
        engagement_id=scope.engagement_id,
        target=target.normalized(),
        specs=specs,
        projected_interactions=projected_interactions,
        min_delay_seconds=1.0 / scope.max_rate_per_second,
        requested_at=requested_at,
    )


def validate_passive_request_spec(spec: PassiveRequestSpec) -> None:
    _require_non_empty("spec_id", spec.spec_id)
    _require_non_empty("reference", spec.reference)
    if spec.transport is PassiveTransport.HTTP and spec.method not in {"GET", "HEAD"}:
        raise ValueError("passive_http_method_required")
    if spec.transport is not PassiveTransport.HTTP and spec.method is not None:
        raise ValueError("non_http_spec_must_not_have_method")
    if spec.follow_redirects:
        raise ValueError("passive_redirect_following_forbidden")
    if spec.payload_present:
        raise ValueError("passive_payload_forbidden")
    if spec.max_response_body_bytes < 0 or spec.max_response_body_bytes > 4096:
        raise ValueError("passive_body_cap_invalid")


def sanitize_observation(observation: PassiveObservation) -> SanitizedPassiveObservation:
    _validate_observation(observation)
    redacted = False
    headers: list[dict[str, str]] = []
    for header in observation.headers:
        name = header.name.strip().lower()
        if name in _SENSITIVE_HEADER_NAMES:
            headers.append({"name": name, "value": "[redacted]"})
            redacted = True
        else:
            value, value_redacted = _sanitize_text(header.value)
            headers.append({"name": name, "value": value})
            redacted = redacted or value_redacted
    body_excerpt = None
    if observation.body_excerpt is not None:
        body_excerpt, body_redacted = _sanitize_text(observation.body_excerpt)
        redacted = redacted or body_redacted
    content: dict[str, object] = {
        "spec_id": observation.spec_id,
        "kind": observation.kind.value,
        "target_type": observation.target.target_type.value,
        "target_value": observation.target.normalized().value,
        "captured_at": observation.captured_at.isoformat(),
        "status_code": observation.status_code,
        "headers": tuple(headers),
        "dns_records": observation.dns_records,
        "tls_metadata": observation.tls_metadata,
        "body_excerpt": body_excerpt,
        "openapi_metadata": observation.openapi_metadata,
        "technology": observation.technology,
    }
    return SanitizedPassiveObservation(observation=observation, redacted=redacted, content=content)


def append_passive_observation_evidence(
    *,
    chain: EvidenceChain,
    observation: PassiveObservation,
    evidence_id: str,
    organization_id: str,
    source_job_id: str,
) -> PassiveEvidenceResult:
    sanitized = sanitize_observation(observation)
    next_chain = chain.append_evidence_record(
        evidence_id=evidence_id,
        organization_id=organization_id,
        source_job_id=source_job_id,
        kind=_evidence_kind_for_check(observation.kind),
        created_at=observation.captured_at,
        redaction_status=RedactionStatus.REDACTED if sanitized.redacted else RedactionStatus.NOT_APPLICABLE,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=json.dumps(sanitized.content, sort_keys=True, default=str).encode("utf-8"),
        contains_sensitive_capture=sanitized.redacted,
        metadata={
            "module": "passive_recon",
            "kind": observation.kind.value,
            "target": observation.target.normalized().value,
        },
    )
    return PassiveEvidenceResult(
        chain=next_chain,
        record=next_chain.evidence_records[-1],
        sanitized_observation=sanitized,
    )


def build_passive_metadata_finding(
    *,
    finding_id: str,
    observation: PassiveObservation,
    evidence_record: EvidenceRecord,
    owner_user_id: str | None = None,
) -> FindingRecord:
    """Create an informational reviewed-output candidate linked to evidence."""
    _require_non_empty("finding_id", finding_id)
    evidence_link = EvidenceLink(
        evidence_id=evidence_record.id,
        integrity_hash=evidence_record.integrity_hash,
        redaction_status=evidence_record.redaction_status,
        contains_sensitive_payload=evidence_record.redaction_status is RedactionStatus.REDACTED,
    )
    finding = FindingRecord(
        id=finding_id.strip(),
        title=f"Passive metadata observation: {observation.kind.value}",
        status=FindingStatus.NEEDS_REVIEW,
        affected_asset_id=observation.target.normalized().value,
        affected_asset_value=observation.target.normalized().value,
        confidence=Confidence.LOW,
        risk=RiskFactors(
            severity=Severity.INFO,
            exploit_likelihood=ExploitLikelihood.UNKNOWN,
            asset_criticality=AssetCriticality.UNKNOWN,
            business_impact=BusinessImpact.LOW,
            vulnerability_intelligence=VulnerabilityIntelligence(cve_ids=(), cwe_ids=()),
        ),
        reproduction_summary=f"Passive metadata was observed for {observation.target.normalized().value}.",
        evidence_links=(evidence_link,),
        remediation="Review metadata context and create a confirmed finding only if a policy gap is validated.",
        owner_user_id=owner_user_id,
        source="passive_recon",
        source_rule_id=observation.kind.value,
    )
    validate_finding(finding)
    return finding


def _default_specs_for_target(target: ScopeTarget, profile: PassiveReconProfile) -> tuple[PassiveRequestSpec, ...]:
    specs: list[PassiveRequestSpec] = []
    if target.target_type is TargetType.DOMAIN:
        host = target.value
        if profile.include_dns:
            specs.append(_spec("dns", PassiveCheckKind.DNS_METADATA, target, PassiveTransport.DNS, None, host, 0))
        if profile.include_tls:
            specs.append(_spec("tls-443", PassiveCheckKind.TLS_METADATA, target, PassiveTransport.TLS, None, f"{host}:443", 0))
    elif target.target_type is TargetType.WEB_ORIGIN:
        parsed = urlparse(target.value)
        host = parsed.hostname or target.value
        if profile.include_dns:
            specs.append(_spec("dns", PassiveCheckKind.DNS_METADATA, target, PassiveTransport.DNS, None, host, 0))
        if profile.include_tls and parsed.scheme == "https":
            port = parsed.port or 443
            specs.append(_spec("tls", PassiveCheckKind.TLS_METADATA, target, PassiveTransport.TLS, None, f"{host}:{port}", 0))
        if profile.include_http_headers:
            specs.append(_spec("headers", PassiveCheckKind.HTTP_HEADERS, target, PassiveTransport.HTTP, "HEAD", f"{target.value}/", 0))
        if profile.include_known_metadata_files:
            specs.extend(
                (
                    _spec("robots", PassiveCheckKind.ROBOTS_TXT, target, PassiveTransport.HTTP, "GET", f"{target.value}/robots.txt", profile.max_metadata_body_bytes),
                    _spec(
                        "security",
                        PassiveCheckKind.SECURITY_TXT,
                        target,
                        PassiveTransport.HTTP,
                        "GET",
                        f"{target.value}/.well-known/security.txt",
                        profile.max_metadata_body_bytes,
                    ),
                    _spec("sitemap", PassiveCheckKind.SITEMAP, target, PassiveTransport.HTTP, "GET", f"{target.value}/sitemap.xml", profile.max_metadata_body_bytes),
                )
            )
        if profile.include_openapi_metadata:
            specs.append(_spec("openapi", PassiveCheckKind.OPENAPI_METADATA, target, PassiveTransport.HTTP, "GET", f"{target.value}/openapi.json", profile.max_metadata_body_bytes))
        if profile.include_technology_fingerprint:
            specs.append(
                _spec(
                    "technology",
                    PassiveCheckKind.TECH_FINGERPRINT,
                    target,
                    PassiveTransport.DERIVED,
                    None,
                    "derived-from-http-and-tls-metadata",
                    0,
                    target_interaction=False,
                )
            )
    elif target.target_type is TargetType.API_SPEC:
        specs.append(_spec("openapi", PassiveCheckKind.OPENAPI_METADATA, target, PassiveTransport.HTTP, "GET", target.value, profile.max_metadata_body_bytes))
    else:
        raise ValueError("unsupported_passive_target_type")
    for spec in specs:
        validate_passive_request_spec(spec)
    return tuple(specs)


def _spec(
    suffix: str,
    kind: PassiveCheckKind,
    target: ScopeTarget,
    transport: PassiveTransport,
    method: str | None,
    reference: str,
    max_response_body_bytes: int,
    *,
    target_interaction: bool = True,
) -> PassiveRequestSpec:
    target_key = target.value.replace("://", "-").replace("/", "-").replace(":", "-")
    return PassiveRequestSpec(
        spec_id=f"{target.target_type.value}:{target_key}:{suffix}",
        kind=kind,
        target=target,
        transport=transport,
        method=method,
        reference=reference,
        max_response_body_bytes=max_response_body_bytes,
        target_interaction=target_interaction,
    )


def _evidence_kind_for_check(kind: PassiveCheckKind) -> EvidenceKind:
    if kind is PassiveCheckKind.DNS_METADATA:
        return EvidenceKind.DNS_METADATA
    if kind is PassiveCheckKind.TLS_METADATA:
        return EvidenceKind.TLS_METADATA
    if kind is PassiveCheckKind.OPENAPI_METADATA:
        return EvidenceKind.OPENAPI_METADATA
    if kind is PassiveCheckKind.TECH_FINGERPRINT:
        return EvidenceKind.TECH_FINGERPRINT
    return EvidenceKind.HTTP_METADATA


def _validate_profile(profile: PassiveReconProfile) -> None:
    if profile.max_metadata_body_bytes < 0 or profile.max_metadata_body_bytes > 4096:
        raise ValueError("passive_body_cap_invalid")


def _validate_observation(observation: PassiveObservation) -> None:
    _require_non_empty("spec_id", observation.spec_id)
    _require_timezone(observation.captured_at)
    if observation.status_code is not None and not (100 <= observation.status_code <= 599):
        raise ValueError("invalid_status_code")


def _sanitize_text(value: str) -> tuple[str, bool]:
    redacted = False
    sanitized = _EMAIL.sub("[redacted-email]", value)
    redacted = redacted or sanitized != value
    sanitized_secret = _SECRET_TEXT.sub(r"\1=[redacted]", sanitized)
    redacted = redacted or sanitized_secret != sanitized
    return sanitized_secret, redacted


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
