"""Closed and bounded evidence storage contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


MAX_EVIDENCE_BYTES = 1_048_576
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")
_OBJECT_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,999}$")
_CONTENT_TYPES = frozenset({"text/plain", "application/json", "application/sarif+json", "application/octet-stream"})
_REDACTION_STATES = frozenset({"raw", "redacted", "report_safe", "export_safe", "blocked"})


class ArtifactClass(str, Enum):
    RAW = "raw"
    REDACTED = "redacted"
    REPORT_SAFE = "report_safe"
    EXPORT_SAFE = "export_safe"


class DataClassification(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


class RetentionMode(str, Enum):
    GOVERNANCE = "GOVERNANCE"
    COMPLIANCE = "COMPLIANCE"


class OperationState(str, Enum):
    RESERVED = "reserved"
    UPLOADED = "uploaded"
    VERIFIED = "verified"
    FINALIZED = "finalized"
    QUARANTINED = "quarantined"
    FAILED = "failed"


class EvidencePurpose(str, Enum):
    REVIEW = "review"
    REPORT = "report"
    EXPORT = "export"


@dataclass(frozen=True, slots=True)
class EvidenceDerivativeRequest:
    source_artifact_id: str
    artifact_id: str
    artifact_class: ArtifactClass
    transform_name: str
    transform_version: str
    quality_approved: bool
    idempotency_key: str

    def __post_init__(self) -> None:
        _identifier("source_artifact_id", self.source_artifact_id)
        _identifier("artifact_id", self.artifact_id)
        _identifier("idempotency_key", self.idempotency_key)
        if self.source_artifact_id == self.artifact_id:
            raise ValueError("derivative_source_cycle_forbidden")
        if self.artifact_class is ArtifactClass.RAW:
            raise ValueError("raw_derivative_forbidden")
        if self.transform_name != "central-redaction" or self.transform_version != "1":
            raise ValueError("derivative_transform_unsupported")
        if not isinstance(self.quality_approved, bool) or not self.quality_approved:
            raise ValueError("derivative_quality_approval_required")

    @property
    def transform_config_hash(self) -> str:
        canonical = json.dumps(
            {
                "artifact_class": self.artifact_class.value,
                "quality_approved": self.quality_approved,
                "transform_name": self.transform_name,
                "transform_version": self.transform_version,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass(frozen=True, slots=True)
class ArtifactWriteRequest:
    tenant_id: str
    artifact_id: str
    engagement_id: str
    job_id: str
    producer_id: str
    content: bytes
    content_type: str
    artifact_class: ArtifactClass
    classification: DataClassification
    redaction_state: str
    retention_mode: RetentionMode
    retain_until: datetime
    legal_hold: bool
    kms_reference: str
    policy_reference: str
    idempotency_key: str
    content_hash: str = field(init=False)

    def __post_init__(self) -> None:
        for name in ("tenant_id", "artifact_id", "engagement_id", "job_id", "producer_id", "idempotency_key"):
            _identifier(name, getattr(self, name))
        if not isinstance(self.content, bytes) or not 1 <= len(self.content) <= MAX_EVIDENCE_BYTES:
            raise ValueError("evidence_content_invalid")
        if self.content_type not in _CONTENT_TYPES:
            raise ValueError("evidence_content_type_unsupported")
        if not isinstance(self.artifact_class, ArtifactClass) or not isinstance(self.classification, DataClassification):
            raise ValueError("artifact_classification_invalid")
        if self.redaction_state not in _REDACTION_STATES:
            raise ValueError("redaction_state_invalid")
        if self.redaction_state != self.artifact_class.value:
            raise ValueError("artifact_redaction_class_mismatch")
        if self.artifact_class is ArtifactClass.RAW and self.classification is not DataClassification.RESTRICTED:
            raise ValueError("raw_artifact_must_be_restricted")
        if not isinstance(self.retention_mode, RetentionMode):
            raise ValueError("retention_mode_invalid")
        if self.retain_until.tzinfo is None or self.retain_until.utcoffset() is None:
            raise ValueError("retain_until_timezone_required")
        if not isinstance(self.legal_hold, bool):
            raise ValueError("legal_hold_invalid")
        _reference("kms_reference", self.kms_reference)
        _reference("policy_reference", self.policy_reference)
        object.__setattr__(self, "content_hash", content_sha256(self.content))


@dataclass(frozen=True, slots=True)
class ObjectPutRequest:
    object_key: str
    content: bytes
    content_type: str
    content_sha256: str
    retention_mode: str
    retain_until: str
    legal_hold: bool
    kms_reference: str
    operation_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.object_key, str) or not _OBJECT_KEY.fullmatch(self.object_key) or ".." in self.object_key.split("/"):
            raise ValueError("object_key_invalid")
        if not isinstance(self.content, bytes) or not 1 <= len(self.content) <= MAX_EVIDENCE_BYTES:
            raise ValueError("evidence_content_invalid")
        if self.content_sha256 != content_sha256(self.content):
            raise ValueError("content_hash_mismatch")
        if self.content_type not in _CONTENT_TYPES:
            raise ValueError("evidence_content_type_unsupported")
        if self.retention_mode not in {mode.value for mode in RetentionMode}:
            raise ValueError("retention_mode_invalid")
        try:
            retained = datetime.fromisoformat(self.retain_until)
        except ValueError as exc:
            raise ValueError("retain_until_invalid") from exc
        if retained.tzinfo is None or retained.utcoffset() is None:
            raise ValueError("retain_until_timezone_required")
        _reference("kms_reference", self.kms_reference)
        _identifier("operation_id", self.operation_id)


@dataclass(frozen=True, slots=True)
class StoredObjectVersion:
    object_key: str
    version_id: str
    storage_name: str
    content_sha256: str
    provider_checksum: str
    size_bytes: int
    content_type: str
    retention_mode: str
    retain_until: str
    legal_hold: bool
    kms_reference: str


@dataclass(frozen=True, slots=True)
class ObjectVerification:
    object_key: str
    version_id: str
    ok: bool
    reason: str


def content_sha256(content: bytes) -> str:
    if not isinstance(content, bytes):
        raise ValueError("evidence_content_invalid")
    return hashlib.sha256(content).hexdigest()


def deterministic_object_key(request: ArtifactWriteRequest) -> str:
    return (
        f"tenants/{request.tenant_id}/engagements/{request.engagement_id}/jobs/{request.job_id}"
        f"/artifacts/{request.artifact_id}/sha256/{request.content_hash}"
    )


def _identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")
    return value


def _reference(name: str, value: str) -> str:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ValueError(f"{name}_invalid")
    return value
