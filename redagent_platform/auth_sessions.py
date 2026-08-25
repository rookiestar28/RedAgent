"""Authenticated session test harness contracts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime

from redagent_platform.credentials import CredentialLease, assert_no_canary_markers
from redagent_platform.domain import EvidenceKind, TestMode
from redagent_platform.evidence_chain import (
    EvidenceAccessPolicy,
    EvidenceChain,
    EvidenceRecord,
    RedactionStatus,
    RetentionClass,
)
from redagent_platform.redaction import RedactionArtifactClass, sanitize_text
from redagent_platform.scope_authorization import ScopeTarget


@dataclass(frozen=True, kw_only=True)
class AuthenticatedSessionContext:
    session_id: str
    organization_id: str
    engagement_id: str
    target: ScopeTarget
    mode: TestMode
    credential_lease_id: str
    role_label: str
    created_at: datetime
    expires_at: datetime
    redaction_label: str

    @property
    def contains_secret_value(self) -> bool:
        return False


@dataclass(frozen=True, kw_only=True)
class HeaderPair:
    name: str
    value: str


@dataclass(frozen=True, kw_only=True)
class SessionExchangeCapture:
    session_id: str
    captured_at: datetime
    method: str
    url: str
    request_headers: tuple[HeaderPair, ...]
    response_status: int
    response_headers: tuple[HeaderPair, ...]
    body_excerpt: str | None = None


@dataclass(frozen=True, kw_only=True)
class SanitizedSessionCapture:
    content: dict[str, object]
    redacted: bool


@dataclass(frozen=True, kw_only=True)
class RoleAuthorizationCase:
    case_id: str
    target: ScopeTarget
    operation_label: str
    lower_privilege_role: str
    higher_privilege_role: str
    lower_session_id: str
    higher_session_id: str


@dataclass(frozen=True, kw_only=True)
class RoleAuthorizationComparison:
    case_id: str
    lower_status: int
    higher_status: int
    expected_difference_observed: bool
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class SessionEvidenceResult:
    chain: EvidenceChain
    record: EvidenceRecord
    sanitized_capture: SanitizedSessionCapture


_SENSITIVE_HEADER_NAMES = frozenset({"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token"})


def build_authenticated_session_context(
    *,
    session_id: str,
    organization_id: str,
    engagement_id: str,
    lease: CredentialLease,
    role_label: str,
    created_at: datetime,
) -> AuthenticatedSessionContext:
    _require_non_empty("session_id", session_id)
    _require_non_empty("organization_id", organization_id)
    _require_non_empty("engagement_id", engagement_id)
    _require_non_empty("role_label", role_label)
    _require_timezone(created_at)
    if created_at >= lease.expires_at:
        raise ValueError("credential_lease_expired")
    return AuthenticatedSessionContext(
        session_id=session_id.strip(),
        organization_id=organization_id.strip(),
        engagement_id=engagement_id.strip(),
        target=lease.target,
        mode=lease.mode,
        credential_lease_id=lease.id,
        role_label=role_label.strip(),
        created_at=created_at,
        expires_at=lease.expires_at,
        redaction_label=lease.redaction_label,
    )


def sanitize_session_capture(capture: SessionExchangeCapture) -> SanitizedSessionCapture:
    _validate_capture(capture)
    request_headers, request_redacted = _sanitize_headers(capture.request_headers)
    response_headers, response_redacted = _sanitize_headers(capture.response_headers)
    body_excerpt = None
    body_redacted = False
    if capture.body_excerpt is not None:
        body_excerpt, body_redacted = _sanitize_text(capture.body_excerpt)
    content: dict[str, object] = {
        "session_id": capture.session_id,
        "captured_at": capture.captured_at.isoformat(),
        "method": capture.method.upper(),
        "url": capture.url,
        "request_headers": request_headers,
        "response_status": capture.response_status,
        "response_headers": response_headers,
        "body_excerpt": body_excerpt,
    }
    return SanitizedSessionCapture(content=content, redacted=request_redacted or response_redacted or body_redacted)


def append_session_capture_evidence(
    *,
    chain: EvidenceChain,
    capture: SessionExchangeCapture,
    evidence_id: str,
    organization_id: str,
    source_job_id: str,
) -> SessionEvidenceResult:
    sanitized = sanitize_session_capture(capture)
    next_chain = chain.append_evidence_record(
        evidence_id=evidence_id,
        organization_id=organization_id,
        source_job_id=source_job_id,
        kind=EvidenceKind.HTTP_METADATA,
        created_at=capture.captured_at,
        redaction_status=RedactionStatus.REDACTED if sanitized.redacted else RedactionStatus.NOT_APPLICABLE,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=json.dumps(sanitized.content, sort_keys=True).encode("utf-8"),
        contains_sensitive_capture=sanitized.redacted,
        metadata={"module": "auth_sessions", "session_id": capture.session_id},
    )
    return SessionEvidenceResult(chain=next_chain, record=next_chain.evidence_records[-1], sanitized_capture=sanitized)


def build_role_authorization_case(
    *,
    case_id: str,
    target: ScopeTarget,
    operation_label: str,
    lower_session: AuthenticatedSessionContext,
    higher_session: AuthenticatedSessionContext,
) -> RoleAuthorizationCase:
    for field_name, value in (("case_id", case_id), ("operation_label", operation_label)):
        _require_non_empty(field_name, value)
    if lower_session.target.normalized() != target.normalized() or higher_session.target.normalized() != target.normalized():
        raise ValueError("role_case_target_mismatch")
    return RoleAuthorizationCase(
        case_id=case_id.strip(),
        target=target.normalized(),
        operation_label=operation_label.strip(),
        lower_privilege_role=lower_session.role_label,
        higher_privilege_role=higher_session.role_label,
        lower_session_id=lower_session.session_id,
        higher_session_id=higher_session.session_id,
    )


def compare_role_authorization(
    *,
    case: RoleAuthorizationCase,
    lower_status: int,
    higher_status: int,
    evidence_records: tuple[EvidenceRecord, ...],
) -> RoleAuthorizationComparison:
    if not evidence_records:
        raise ValueError("missing_evidence_records")
    expected = lower_status in {401, 403, 404} and 200 <= higher_status < 300
    return RoleAuthorizationComparison(
        case_id=case.case_id,
        lower_status=lower_status,
        higher_status=higher_status,
        expected_difference_observed=expected,
        evidence_ids=tuple(record.id for record in evidence_records),
    )


def assert_no_session_secret_leak(outputs: dict[str, str], canary_markers: tuple[str, ...]) -> None:
    assert_no_canary_markers(outputs, canary_markers)


def _sanitize_headers(headers: tuple[HeaderPair, ...]) -> tuple[tuple[dict[str, str], bool]]:
    values: list[dict[str, str]] = []
    redacted = False
    for header in headers:
        name = header.name.strip().lower()
        if name in _SENSITIVE_HEADER_NAMES:
            values.append({"name": name, "value": "[redacted]"})
            redacted = True
        else:
            value, value_redacted = _sanitize_text(header.value)
            values.append({"name": name, "value": value})
            redacted = redacted or value_redacted
    return tuple(values), redacted


def _sanitize_text(value: str) -> tuple[str, bool]:
    result = sanitize_text(value, RedactionArtifactClass.HTTP_METADATA)
    return result.sanitized_text, result.redacted


def _validate_capture(capture: SessionExchangeCapture) -> None:
    for field_name, value in (("session_id", capture.session_id), ("method", capture.method), ("url", capture.url)):
        _require_non_empty(field_name, value)
    _require_timezone(capture.captured_at)
    if not (100 <= capture.response_status <= 599):
        raise ValueError("invalid_response_status")


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
