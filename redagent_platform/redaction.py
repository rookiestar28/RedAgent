"""Central redaction pipeline for lower-trust RedAgent outputs."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Mapping

from redagent_platform.evidence_chain import RedactionStatus


class RedactionArtifactClass(str, Enum):
    COMMAND_LOG = "command_log"
    UI_LOG_PREVIEW = "ui_log_preview"
    HTTP_METADATA = "http_metadata"
    SCANNER_OUTPUT = "scanner_output"
    JSON_SARIF = "json_sarif"
    HAR_CAPTURE = "har_capture"
    SCREENSHOT_METADATA = "screenshot_metadata"
    REPORT = "report"
    ISSUE_EXPORT = "issue_export"
    EVIDENCE_ARTIFACT = "evidence_artifact"


class RedactionCategory(str, Enum):
    AUTH_HEADER = "auth_header"
    BEARER_AUTH = "bearer_auth"
    SENSITIVE_ASSIGNMENT = "sensitive_assignment"
    KEY_BLOCK = "key_block"
    EMAIL = "email"
    PHONE = "phone"
    SSN = "ssn"
    CANARY = "canary"


@dataclass(frozen=True, kw_only=True)
class RedactionConfig:
    canary_markers: tuple[str, ...] = ()
    block_private_keys: bool = True


@dataclass(frozen=True, kw_only=True)
class RedactionFinding:
    category: RedactionCategory
    replacement: str
    count: int


@dataclass(frozen=True, kw_only=True)
class RedactionResult:
    artifact_class: RedactionArtifactClass
    original_hash: str
    sanitized_hash: str
    redaction_status: RedactionStatus
    sanitized_text: str
    evidence: tuple[RedactionFinding, ...]
    blocked_reason: str | None = None

    @property
    def redacted(self) -> bool:
        return self.redaction_status in {RedactionStatus.REDACTED, RedactionStatus.BLOCKED}


_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
    re.DOTALL,
)
_SENSITIVE_HEADER = re.compile(
    r"(?im)^(\s*(?:authorization|cookie|set-cookie|x-api-key|x-auth-token)\s*:\s*)([^\r\n]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{6,}")
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)(?<![-\w])(api[_-]?key|secret|token|password|session[_-]?id|session)\s*[:=]\s*([^\s,;]+)"
)
_EMAIL = re.compile(r"(?i)\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b")
_PHONE = re.compile(r"\b(?:\+?\d{1,3}[-. ]?)?\(?\d{3}\)?[-. ]?\d{3}[-. ]?\d{4}\b")
_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")


def sanitize_text(
    value: str,
    artifact_class: RedactionArtifactClass,
    config: RedactionConfig | None = None,
) -> RedactionResult:
    config = config or RedactionConfig()
    sanitized = value
    findings: list[RedactionFinding] = []
    blocked_reason: str | None = None

    sanitized, count = _replace_exact_markers(sanitized, config.canary_markers, "[redacted-canary]")
    if count:
        findings.append(RedactionFinding(category=RedactionCategory.CANARY, replacement="[redacted-canary]", count=count))

    sanitized, count = _PRIVATE_KEY.subn("[blocked-private-key]", sanitized)
    if count:
        findings.append(
            RedactionFinding(category=RedactionCategory.KEY_BLOCK, replacement="[blocked-private-key]", count=count)
        )
        if config.block_private_keys:
            blocked_reason = "key_material_blocked"

    sanitized, count = _SENSITIVE_HEADER.subn(lambda match: match.group(1) + "[redacted]", sanitized)
    if count:
        findings.append(
            RedactionFinding(category=RedactionCategory.AUTH_HEADER, replacement="[redacted]", count=count)
        )

    sanitized, count = _BEARER.subn("Bearer [redacted]", sanitized)
    if count:
        findings.append(RedactionFinding(category=RedactionCategory.BEARER_AUTH, replacement="Bearer [redacted]", count=count))

    sanitized, count = _SECRET_ASSIGNMENT.subn(lambda match: f"{match.group(1)}=[redacted]", sanitized)
    if count:
        findings.append(
            RedactionFinding(category=RedactionCategory.SENSITIVE_ASSIGNMENT, replacement="[redacted]", count=count)
        )

    sanitized, count = _EMAIL.subn("[redacted-email]", sanitized)
    if count:
        findings.append(RedactionFinding(category=RedactionCategory.EMAIL, replacement="[redacted-email]", count=count))

    sanitized, count = _SSN.subn("[redacted-ssn]", sanitized)
    if count:
        findings.append(RedactionFinding(category=RedactionCategory.SSN, replacement="[redacted-ssn]", count=count))

    sanitized, count = _PHONE.subn("[redacted-phone]", sanitized)
    if count:
        findings.append(RedactionFinding(category=RedactionCategory.PHONE, replacement="[redacted-phone]", count=count))

    if blocked_reason:
        status = RedactionStatus.BLOCKED
    elif findings:
        status = RedactionStatus.REDACTED
    else:
        status = RedactionStatus.NOT_APPLICABLE
    return RedactionResult(
        artifact_class=artifact_class,
        original_hash=_sha256_text(value),
        sanitized_hash=_sha256_text(sanitized),
        redaction_status=status,
        sanitized_text=sanitized,
        evidence=tuple(findings),
        blocked_reason=blocked_reason,
    )


def sanitize_bytes(
    value: bytes,
    artifact_class: RedactionArtifactClass,
    config: RedactionConfig | None = None,
) -> RedactionResult:
    return sanitize_text(value.decode("utf-8", errors="replace"), artifact_class, config)


def sanitize_mapping(
    value: Mapping[str, object],
    artifact_class: RedactionArtifactClass,
    config: RedactionConfig | None = None,
) -> tuple[dict[str, object], RedactionResult]:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    result = sanitize_text(raw, artifact_class, config)
    sanitized_mapping = _sanitize_object(value, artifact_class, config or RedactionConfig())
    sanitized_raw = json.dumps(sanitized_mapping, sort_keys=True, separators=(",", ":"), default=str)
    return sanitized_mapping, RedactionResult(
        artifact_class=artifact_class,
        original_hash=result.original_hash,
        sanitized_hash=_sha256_text(sanitized_raw),
        redaction_status=result.redaction_status,
        sanitized_text=sanitized_raw,
        evidence=result.evidence,
        blocked_reason=result.blocked_reason,
    )


def assert_no_sensitive_output(
    value: str,
    artifact_class: RedactionArtifactClass,
    config: RedactionConfig | None = None,
) -> None:
    result = sanitize_text(value, artifact_class, config)
    if result.redacted:
        raise ValueError("sensitive_output_not_redacted")


def _sanitize_object(
    value: object,
    artifact_class: RedactionArtifactClass,
    config: RedactionConfig,
) -> object:
    if isinstance(value, str):
        return sanitize_text(value, artifact_class, config).sanitized_text
    if isinstance(value, Mapping):
        return {str(key): _sanitize_object(item, artifact_class, config) for key, item in value.items()}
    if isinstance(value, tuple):
        return tuple(_sanitize_object(item, artifact_class, config) for item in value)
    if isinstance(value, list):
        return [_sanitize_object(item, artifact_class, config) for item in value]
    return value


def _replace_exact_markers(value: str, markers: tuple[str, ...], replacement: str) -> tuple[str, int]:
    count = 0
    sanitized = value
    for marker in markers:
        if not marker:
            continue
        occurrences = sanitized.count(marker)
        if occurrences:
            sanitized = sanitized.replace(marker, replacement)
            count += occurrences
    return sanitized, count


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()
