"""Durable immutable evidence artifact storage contracts."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Mapping

from redagent_platform.domain import EvidenceKind
from redagent_platform.evidence_chain import (
    AuditAction,
    EvidenceAccessPolicy,
    EvidenceChain,
    EvidenceOverwriteError,
    EvidenceRecord,
    RedactionStatus,
    RetentionClass,
    build_evidence_record,
)
from redagent_platform.reporting import RedactionReview, RedactionReviewStatus
from redagent_platform.redaction import RedactionArtifactClass, sanitize_bytes


class EvidenceArtifactStoreError(ValueError):
    """Base error for evidence artifact store policy failures."""


class EvidenceArtifactRetentionError(EvidenceArtifactStoreError):
    """Raised when retention policy forbids a requested operation."""


_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


@dataclass(frozen=True, kw_only=True)
class EvidenceArtifactWriteRequest:
    evidence_id: str
    organization_id: str
    source_job_id: str
    kind: EvidenceKind
    created_at: datetime
    redaction_status: RedactionStatus
    retention_class: RetentionClass
    access_policy: EvidenceAccessPolicy
    content: bytes | None
    contains_sensitive_capture: bool
    artifact_metadata: Mapping[str, object]
    operator_user_id: str
    runner_id: str
    manifest_id: str | None = None
    legal_hold: bool = False


@dataclass(frozen=True, kw_only=True)
class EvidenceArtifactManifest:
    manifest_id: str
    evidence_id: str
    organization_id: str
    source_job_id: str
    kind: EvidenceKind
    artifact_path: str | None
    artifact_size_bytes: int
    content_hash: str
    metadata_hash: str
    evidence_integrity_hash: str
    previous_evidence_hash: str | None
    retention_class: RetentionClass
    access_policy: EvidenceAccessPolicy
    redaction_status: RedactionStatus
    contains_sensitive_capture: bool
    artifact_metadata: Mapping[str, object]
    operator_user_id: str
    runner_id: str
    created_at: datetime
    legal_hold: bool
    manifest_hash: str

    def to_evidence_record(self) -> EvidenceRecord:
        return EvidenceRecord(
            id=self.evidence_id,
            organization_id=self.organization_id,
            source_job_id=self.source_job_id,
            kind=self.kind,
            created_at=self.created_at,
            redaction_status=self.redaction_status,
            retention_class=self.retention_class,
            access_policy=self.access_policy,
            content_hash=self.content_hash,
            metadata_hash=self.metadata_hash,
            previous_hash=self.previous_evidence_hash,
            integrity_hash=self.evidence_integrity_hash,
        )


@dataclass(frozen=True, kw_only=True)
class EvidenceArtifactVerification:
    evidence_id: str
    manifest_id: str
    ok: bool
    reason: str


@dataclass(frozen=True, kw_only=True)
class EvidenceArtifactExportRequest:
    export_id: str
    evidence_id: str
    requested_by_user_id: str
    requested_at: datetime
    redaction_review: RedactionReview
    destination_label: str


@dataclass(frozen=True, kw_only=True)
class EvidenceArtifactExportResult:
    export_id: str
    evidence_id: str
    approved: bool
    denied_reason: str | None
    content: bytes | None
    verification: EvidenceArtifactVerification
    audit_chain: EvidenceChain


@dataclass(frozen=True, kw_only=True)
class EvidenceArtifactWriteResult:
    manifest: EvidenceArtifactManifest
    evidence_record: EvidenceRecord
    evidence_chain: EvidenceChain


class LocalEvidenceArtifactStore:
    """Local immutable artifact store for sanitized RedAgent evidence."""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.artifact_dir = self.root / "artifacts"
        self.manifest_dir = self.root / "manifests"
        self.artifact_dir.mkdir(parents=True, exist_ok=True)
        self.manifest_dir.mkdir(parents=True, exist_ok=True)

    def write_artifact(
        self,
        request: EvidenceArtifactWriteRequest,
        evidence_chain: EvidenceChain,
    ) -> EvidenceArtifactWriteResult:
        request = _apply_redaction_pipeline(request)
        evidence_id = _safe_identifier("evidence_id", request.evidence_id)
        manifest_id = _safe_identifier("manifest_id", request.manifest_id or f"{evidence_id}:manifest")
        artifact_path = self._artifact_path(evidence_id)
        manifest_path = self._manifest_path(evidence_id)
        if artifact_path.exists() or manifest_path.exists():
            raise EvidenceOverwriteError("evidence_id_already_exists")

        next_chain = evidence_chain.append_evidence_record(
            evidence_id=evidence_id,
            organization_id=request.organization_id,
            source_job_id=request.source_job_id,
            kind=request.kind,
            created_at=request.created_at,
            redaction_status=request.redaction_status,
            retention_class=request.retention_class,
            access_policy=request.access_policy,
            content=request.content,
            contains_sensitive_capture=request.contains_sensitive_capture,
            metadata=request.artifact_metadata,
        )
        record = next_chain.evidence_records[-1]
        relative_artifact_path: str | None = None
        artifact_size = 0

        try:
            if request.redaction_status is not RedactionStatus.BLOCKED:
                if request.content is None:
                    raise ValueError("evidence_content_required_unless_blocked")
                with artifact_path.open("xb") as artifact_file:
                    artifact_file.write(request.content)
                relative_artifact_path = artifact_path.relative_to(self.root).as_posix()
                artifact_size = len(request.content)

            manifest = _build_manifest(
                manifest_id=manifest_id,
                request=request,
                record=record,
                artifact_path=relative_artifact_path,
                artifact_size_bytes=artifact_size,
            )
            with manifest_path.open("x", encoding="utf-8") as manifest_file:
                json.dump(_manifest_to_payload(manifest), manifest_file, sort_keys=True, indent=2)
                manifest_file.write("\n")
        except Exception:
            if artifact_path.exists() and relative_artifact_path is not None:
                artifact_path.unlink()
            if manifest_path.exists():
                manifest_path.unlink()
            raise

        return EvidenceArtifactWriteResult(manifest=manifest, evidence_record=record, evidence_chain=next_chain)

    def read_manifest(self, evidence_id: str) -> EvidenceArtifactManifest:
        manifest_path = self._manifest_path(_safe_identifier("evidence_id", evidence_id))
        if not manifest_path.exists():
            raise FileNotFoundError("missing_evidence_manifest")
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        return _manifest_from_payload(payload)

    def verify_artifact(self, evidence_id: str) -> EvidenceArtifactVerification:
        manifest = self.read_manifest(evidence_id)
        expected_manifest_hash = _manifest_hash(manifest)
        if expected_manifest_hash != manifest.manifest_hash:
            return _verification(manifest, False, "manifest_hash_mismatch")

        if manifest.redaction_status is RedactionStatus.BLOCKED:
            if manifest.artifact_path is not None:
                return _verification(manifest, False, "blocked_capture_has_artifact_path")
            content = None
        else:
            if manifest.artifact_path is None:
                return _verification(manifest, False, "missing_artifact_path")
            artifact_path = self._resolve_relative_artifact_path(manifest.artifact_path)
            if not artifact_path.exists():
                return _verification(manifest, False, "missing_artifact")
            content = artifact_path.read_bytes()
            if hashlib.sha256(content).hexdigest() != manifest.content_hash:
                return _verification(manifest, False, "content_hash_mismatch")
            if len(content) != manifest.artifact_size_bytes:
                return _verification(manifest, False, "artifact_size_mismatch")

        rebuilt = build_evidence_record(
            evidence_id=manifest.evidence_id,
            organization_id=manifest.organization_id,
            source_job_id=manifest.source_job_id,
            kind=manifest.kind,
            created_at=manifest.created_at,
            redaction_status=manifest.redaction_status,
            retention_class=manifest.retention_class,
            access_policy=manifest.access_policy,
            content=content,
            contains_sensitive_capture=manifest.contains_sensitive_capture,
            metadata=manifest.artifact_metadata,
            previous_hash=manifest.previous_evidence_hash,
        )
        if rebuilt.metadata_hash != manifest.metadata_hash:
            return _verification(manifest, False, "metadata_hash_mismatch")
        if rebuilt.integrity_hash != manifest.evidence_integrity_hash:
            return _verification(manifest, False, "evidence_integrity_hash_mismatch")
        return _verification(manifest, True, "verified")

    def export_artifact(
        self,
        request: EvidenceArtifactExportRequest,
        evidence_chain: EvidenceChain,
    ) -> EvidenceArtifactExportResult:
        export_id = _safe_identifier("export_id", request.export_id)
        manifest = self.read_manifest(request.evidence_id)
        denied_reason: str | None = None
        content: bytes | None = None
        verification = self.verify_artifact(manifest.evidence_id)

        if request.redaction_review.status is not RedactionReviewStatus.APPROVED:
            denied_reason = "redaction_review_required"
        elif not verification.ok:
            denied_reason = verification.reason
        elif manifest.redaction_status is RedactionStatus.BLOCKED:
            denied_reason = "artifact_content_blocked"
        else:
            if manifest.artifact_path is None:
                denied_reason = "missing_artifact_path"
            else:
                content = self._resolve_relative_artifact_path(manifest.artifact_path).read_bytes()

        next_chain = evidence_chain.append_audit_event(
            event_id=f"{manifest.evidence_id}:{export_id}",
            organization_id=manifest.organization_id,
            actor_user_id=request.requested_by_user_id,
            action=AuditAction.EXPORT,
            subject_type="evidence_artifact",
            subject_id=manifest.evidence_id,
            occurred_at=request.requested_at,
            details={
                "destination_label": request.destination_label,
                "approved": denied_reason is None,
                "denied_reason": denied_reason,
                "redaction_review_id": request.redaction_review.review_id,
                "redaction_review_status": request.redaction_review.status.value,
                "verification_reason": verification.reason,
            },
        )
        return EvidenceArtifactExportResult(
            export_id=export_id,
            evidence_id=manifest.evidence_id,
            approved=denied_reason is None,
            denied_reason=denied_reason,
            content=content,
            verification=verification,
            audit_chain=next_chain,
        )

    def assert_disposal_allowed(self, evidence_id: str) -> None:
        manifest = self.read_manifest(evidence_id)
        if manifest.legal_hold or manifest.retention_class is RetentionClass.LEGAL_HOLD:
            raise EvidenceArtifactRetentionError("legal_hold_prevents_disposal")

    def _artifact_path(self, evidence_id: str) -> Path:
        return self.artifact_dir / f"{evidence_id}.bin"

    def _manifest_path(self, evidence_id: str) -> Path:
        return self.manifest_dir / f"{evidence_id}.json"

    def _resolve_relative_artifact_path(self, relative_path: str) -> Path:
        candidate = (self.root / relative_path).resolve()
        root = self.root.resolve()
        try:
            candidate.relative_to(root)
        except ValueError as exc:
            raise EvidenceArtifactStoreError("artifact_path_outside_store_root") from exc
        return candidate


def _build_manifest(
    *,
    manifest_id: str,
    request: EvidenceArtifactWriteRequest,
    record: EvidenceRecord,
    artifact_path: str | None,
    artifact_size_bytes: int,
) -> EvidenceArtifactManifest:
    manifest = EvidenceArtifactManifest(
        manifest_id=manifest_id,
        evidence_id=record.id,
        organization_id=record.organization_id,
        source_job_id=record.source_job_id,
        kind=record.kind,
        artifact_path=artifact_path,
        artifact_size_bytes=artifact_size_bytes,
        content_hash=record.content_hash,
        metadata_hash=record.metadata_hash,
        evidence_integrity_hash=record.integrity_hash,
        previous_evidence_hash=record.previous_hash,
        retention_class=record.retention_class,
        access_policy=record.access_policy,
        redaction_status=record.redaction_status,
        contains_sensitive_capture=request.contains_sensitive_capture,
        artifact_metadata=dict(request.artifact_metadata),
        operator_user_id=request.operator_user_id.strip(),
        runner_id=request.runner_id.strip(),
        created_at=record.created_at,
        legal_hold=request.legal_hold or record.retention_class is RetentionClass.LEGAL_HOLD,
        manifest_hash="",
    )
    return EvidenceArtifactManifest(**{**manifest.__dict__, "manifest_hash": _manifest_hash(manifest)})


def _apply_redaction_pipeline(request: EvidenceArtifactWriteRequest) -> EvidenceArtifactWriteRequest:
    if request.content is None:
        return request
    result = sanitize_bytes(request.content, RedactionArtifactClass.EVIDENCE_ARTIFACT)
    if not result.redacted:
        return request

    metadata = dict(request.artifact_metadata)
    metadata["redaction_pipeline"] = {
        "status": result.redaction_status.value,
        "blocked_reason": result.blocked_reason,
        "original_hash": result.original_hash,
        "sanitized_hash": result.sanitized_hash,
        "evidence": tuple(
            {"category": finding.category.value, "replacement": finding.replacement, "count": finding.count}
            for finding in result.evidence
        ),
    }
    final_status = (
        RedactionStatus.BLOCKED
        if result.redaction_status is RedactionStatus.BLOCKED
        else RedactionStatus.REDACTED
    )
    final_content = None if final_status is RedactionStatus.BLOCKED else result.sanitized_text.encode("utf-8")
    return replace(
        request,
        content=final_content,
        redaction_status=final_status,
        contains_sensitive_capture=True,
        artifact_metadata=metadata,
    )


def _manifest_to_payload(manifest: EvidenceArtifactManifest) -> dict[str, object]:
    return {
        "manifest_id": manifest.manifest_id,
        "evidence_id": manifest.evidence_id,
        "organization_id": manifest.organization_id,
        "source_job_id": manifest.source_job_id,
        "kind": manifest.kind.value,
        "artifact_path": manifest.artifact_path,
        "artifact_size_bytes": manifest.artifact_size_bytes,
        "content_hash": manifest.content_hash,
        "metadata_hash": manifest.metadata_hash,
        "evidence_integrity_hash": manifest.evidence_integrity_hash,
        "previous_evidence_hash": manifest.previous_evidence_hash,
        "retention_class": manifest.retention_class.value,
        "access_policy": manifest.access_policy.value,
        "redaction_status": manifest.redaction_status.value,
        "contains_sensitive_capture": manifest.contains_sensitive_capture,
        "artifact_metadata": manifest.artifact_metadata,
        "operator_user_id": manifest.operator_user_id,
        "runner_id": manifest.runner_id,
        "created_at": manifest.created_at.isoformat(),
        "legal_hold": manifest.legal_hold,
        "manifest_hash": manifest.manifest_hash,
    }


def _manifest_from_payload(payload: Mapping[str, object]) -> EvidenceArtifactManifest:
    return EvidenceArtifactManifest(
        manifest_id=str(payload["manifest_id"]),
        evidence_id=str(payload["evidence_id"]),
        organization_id=str(payload["organization_id"]),
        source_job_id=str(payload["source_job_id"]),
        kind=EvidenceKind(str(payload["kind"])),
        artifact_path=str(payload["artifact_path"]) if payload["artifact_path"] is not None else None,
        artifact_size_bytes=int(payload["artifact_size_bytes"]),
        content_hash=str(payload["content_hash"]),
        metadata_hash=str(payload["metadata_hash"]),
        evidence_integrity_hash=str(payload["evidence_integrity_hash"]),
        previous_evidence_hash=str(payload["previous_evidence_hash"])
        if payload["previous_evidence_hash"] is not None
        else None,
        retention_class=RetentionClass(str(payload["retention_class"])),
        access_policy=EvidenceAccessPolicy(str(payload["access_policy"])),
        redaction_status=RedactionStatus(str(payload["redaction_status"])),
        contains_sensitive_capture=bool(payload["contains_sensitive_capture"]),
        artifact_metadata=dict(payload["artifact_metadata"]),  # type: ignore[arg-type]
        operator_user_id=str(payload["operator_user_id"]),
        runner_id=str(payload["runner_id"]),
        created_at=datetime.fromisoformat(str(payload["created_at"])),
        legal_hold=bool(payload["legal_hold"]),
        manifest_hash=str(payload["manifest_hash"]),
    )


def _manifest_hash(manifest: EvidenceArtifactManifest) -> str:
    payload = _manifest_to_payload(EvidenceArtifactManifest(**{**manifest.__dict__, "manifest_hash": ""}))
    payload.pop("manifest_hash")
    return _canonical_sha256(payload)


def _verification(manifest: EvidenceArtifactManifest, ok: bool, reason: str) -> EvidenceArtifactVerification:
    return EvidenceArtifactVerification(
        evidence_id=manifest.evidence_id,
        manifest_id=manifest.manifest_id,
        ok=ok,
        reason=reason,
    )


def _canonical_sha256(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _safe_identifier(field_name: str, value: str) -> str:
    value = value.strip()
    # IMPORTANT: identifiers become local path components; keep this deny-by-default.
    if not _SAFE_ID.fullmatch(value):
        raise EvidenceArtifactStoreError(f"invalid_{field_name}")
    return value
