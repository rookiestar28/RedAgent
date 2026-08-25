"""Issue tracker connector contracts with secret-safe export payloads."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Protocol

from redagent_platform.domain import FindingStatus
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.findings import FindingRecord, duplicate_correlation_key, export_sanitized_finding
from redagent_platform.redaction import RedactionArtifactClass, RedactionConfig, assert_no_sensitive_output


class ConnectorKind(str, Enum):
    GENERIC_ISSUE_TRACKER = "generic_issue_tracker"


class IssueExportAction(str, Enum):
    CREATED_NEW = "created_new"
    UPDATED_EXISTING = "updated_existing"


@dataclass(frozen=True, kw_only=True)
class IssueTrackerConnection:
    connector_id: str
    kind: ConnectorKind
    display_name: str
    project_key: str
    credential_reference_id: str
    redaction_label: str


@dataclass(frozen=True, kw_only=True)
class ExistingIssueExport:
    external_key: str
    issue_key: str
    finding_id: str
    connector_id: str


@dataclass(frozen=True, kw_only=True)
class IssueExportRequest:
    export_id: str
    organization_id: str
    actor_user_id: str
    connection: IssueTrackerConnection
    finding: FindingRecord
    requested_at: datetime
    audit_chain: EvidenceChain
    existing_exports: tuple[ExistingIssueExport, ...] = ()
    canary_markers: tuple[str, ...] = ()


@dataclass(frozen=True, kw_only=True)
class IssueEvidenceLink:
    evidence_id: str
    integrity_hash: str
    redaction_status: str


@dataclass(frozen=True, kw_only=True)
class IssueTaxonomy:
    source: str
    source_rule_id: str | None
    cve_ids: tuple[str, ...]
    cwe_ids: tuple[str, ...]
    correlation_key: str


@dataclass(frozen=True, kw_only=True)
class IssueExportPayload:
    external_key: str
    summary: str
    severity: str
    owner_user_id: str | None
    evidence_links: tuple[IssueEvidenceLink, ...]
    remediation: str
    taxonomy: IssueTaxonomy
    labels: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class IssueExportResult:
    action: IssueExportAction
    issue_key: str
    payload: IssueExportPayload
    audit_chain: EvidenceChain


class IssueConnector(Protocol):
    def export_finding(self, request: IssueExportRequest) -> IssueExportResult:
        """Plan a finding export without performing network I/O."""


@dataclass(frozen=True)
class GenericIssueTrackerConnector:
    """Deterministic issue tracker adapter that never performs network I/O."""

    def export_finding(self, request: IssueExportRequest) -> IssueExportResult:
        _validate_request(request)
        payload = build_issue_payload(request.connection, request.finding)
        _assert_no_canary_markers(payload, request.canary_markers)
        existing = _find_existing_export(request.existing_exports, payload.external_key, request.connection.connector_id)
        if existing is None:
            action = IssueExportAction.CREATED_NEW
            issue_key = _planned_issue_key(request.connection.project_key, payload.external_key)
        else:
            action = IssueExportAction.UPDATED_EXISTING
            issue_key = existing.issue_key

        next_chain = request.audit_chain.append_audit_event(
            event_id=request.export_id,
            organization_id=request.organization_id,
            actor_user_id=request.actor_user_id,
            action=AuditAction.EXPORT,
            subject_type="finding",
            subject_id=request.finding.id,
            occurred_at=request.requested_at,
            details={
                "connector_id": request.connection.connector_id,
                "connector_kind": request.connection.kind.value,
                "external_key": payload.external_key,
                "issue_key": issue_key,
                "export_action": action.value,
                "payload_hash": _payload_hash(payload),
            },
        )
        return IssueExportResult(action=action, issue_key=issue_key, payload=payload, audit_chain=next_chain)


def export_finding_to_issue(connector: IssueConnector, request: IssueExportRequest) -> IssueExportResult:
    return connector.export_finding(request)


def build_issue_payload(connection: IssueTrackerConnection, finding: FindingRecord) -> IssueExportPayload:
    _validate_connection(connection)
    if finding.status is not FindingStatus.CONFIRMED:
        raise ValueError("finding_must_be_confirmed")
    exported = export_sanitized_finding(finding)
    external_key = _external_key(connection, finding)
    payload = IssueExportPayload(
        external_key=external_key,
        summary=str(exported["title"]),
        severity=str(exported["severity"]),
        owner_user_id=finding.owner_user_id,
        evidence_links=tuple(
            IssueEvidenceLink(
                evidence_id=str(evidence["evidence_id"]),
                integrity_hash=str(evidence["integrity_hash"]),
                redaction_status=str(evidence["redaction_status"]),
            )
            for evidence in exported["evidence"]  # type: ignore[index]
        ),
        remediation=str(exported["remediation"]),
        taxonomy=IssueTaxonomy(
            source=finding.source,
            source_rule_id=finding.source_rule_id,
            cve_ids=tuple(finding.risk.vulnerability_intelligence.cve_ids),
            cwe_ids=tuple(finding.risk.vulnerability_intelligence.cwe_ids),
            correlation_key=str(exported["correlation_key"]),
        ),
        labels=_labels_for_export(connection, finding),
    )
    _ensure_payload_is_secret_free(payload)
    return payload


def _validate_request(request: IssueExportRequest) -> None:
    for field_name, value in (
        ("export_id", request.export_id),
        ("organization_id", request.organization_id),
        ("actor_user_id", request.actor_user_id),
    ):
        _require_non_empty(field_name, value)
    if request.requested_at.tzinfo is None or request.requested_at.utcoffset() is None:
        raise ValueError("timezone_required")


def _validate_connection(connection: IssueTrackerConnection) -> None:
    for field_name, value in (
        ("connector_id", connection.connector_id),
        ("display_name", connection.display_name),
        ("project_key", connection.project_key),
        ("credential_reference_id", connection.credential_reference_id),
        ("redaction_label", connection.redaction_label),
    ):
        _require_non_empty(field_name, value)
    _ensure_secret_free_text(connection.display_name)
    _ensure_secret_free_text(connection.project_key)
    _ensure_secret_free_text(connection.redaction_label)


def _external_key(connection: IssueTrackerConnection, finding: FindingRecord) -> str:
    payload = {
        "connector_id": connection.connector_id.strip().lower(),
        "project_key": connection.project_key.strip().lower(),
        "correlation_key": duplicate_correlation_key(finding),
    }
    return _canonical_sha256(payload)


def _find_existing_export(
    existing_exports: tuple[ExistingIssueExport, ...],
    external_key: str,
    connector_id: str,
) -> ExistingIssueExport | None:
    for existing in existing_exports:
        if existing.external_key == external_key and existing.connector_id == connector_id:
            return existing
    return None


def _planned_issue_key(project_key: str, external_key: str) -> str:
    normalized_project = "".join(character for character in project_key.upper() if character.isalnum() or character == "-")
    if not normalized_project:
        raise ValueError("invalid_project_key")
    return f"{normalized_project}-{int(external_key[:10], 16)}"


def _labels_for_export(connection: IssueTrackerConnection, finding: FindingRecord) -> tuple[str, ...]:
    labels = [
        "redteam",
        "security-finding",
        f"severity:{finding.severity.value}",
        f"source:{finding.source.strip().lower()}",
        f"connector:{connection.kind.value}",
    ]
    return tuple(labels)


def _payload_hash(payload: IssueExportPayload) -> str:
    return _canonical_sha256(_payload_to_dict(payload))


def _assert_no_canary_markers(payload: IssueExportPayload, canary_markers: tuple[str, ...]) -> None:
    encoded = json.dumps(_payload_to_dict(payload), sort_keys=True, default=str)
    try:
        assert_no_sensitive_output(
            encoded,
            RedactionArtifactClass.ISSUE_EXPORT,
            RedactionConfig(canary_markers=canary_markers),
        )
    except ValueError as exc:
        raise ValueError("canary_marker_leaked") from exc


def _ensure_payload_is_secret_free(payload: IssueExportPayload) -> None:
    encoded = json.dumps(_payload_to_dict(payload), sort_keys=True, default=str)
    _ensure_secret_free_text(encoded)


def _payload_to_dict(payload: IssueExportPayload) -> dict[str, object]:
    return {
        "external_key": payload.external_key,
        "summary": payload.summary,
        "severity": payload.severity,
        "owner_user_id": payload.owner_user_id,
        "evidence_links": tuple(
            {
                "evidence_id": evidence.evidence_id,
                "integrity_hash": evidence.integrity_hash,
                "redaction_status": evidence.redaction_status,
            }
            for evidence in payload.evidence_links
        ),
        "remediation": payload.remediation,
        "taxonomy": {
            "source": payload.taxonomy.source,
            "source_rule_id": payload.taxonomy.source_rule_id,
            "cve_ids": payload.taxonomy.cve_ids,
            "cwe_ids": payload.taxonomy.cwe_ids,
            "correlation_key": payload.taxonomy.correlation_key,
        },
        "labels": payload.labels,
    }


def _ensure_secret_free_text(value: str) -> None:
    try:
        assert_no_sensitive_output(value, RedactionArtifactClass.ISSUE_EXPORT)
    except ValueError as exc:
        raise ValueError("secret_like_text_forbidden") from exc


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
