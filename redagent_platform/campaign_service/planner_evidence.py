"""Closed campaign evidence bundles and bounded offline verification.

The retained bundle is intentionally data-only. It contains no callable names,
network locations, commands, plugins, credentials, or import-to-execution path.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
from typing import Mapping, cast

from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes
from redagent_platform.evidence_chain import EvidenceAccessPolicy, RedactionStatus, RetentionClass
from redagent_platform.redaction import RedactionArtifactClass, assert_no_sensitive_output


CAMPAIGN_EVIDENCE_ARTIFACT_SCHEMA_VERSION = "redagent.campaign-evidence-artifact/v2"
CAMPAIGN_EVIDENCE_MANIFEST_SCHEMA_VERSION = "redagent.campaign-evidence-manifest/v2"
CAMPAIGN_EVIDENCE_TERMINAL_SCHEMA_VERSION = "redagent.campaign-terminal-disposition/v2"
MAX_CAMPAIGN_EVIDENCE_ARTIFACTS = 64
MAX_CAMPAIGN_EVIDENCE_FILE_BYTES = 256 * 1024
MAX_CAMPAIGN_EVIDENCE_TOTAL_BYTES = 8 * 1024 * 1024
MAX_CAMPAIGN_EVIDENCE_JSON_DEPTH = 24
MAX_CAMPAIGN_EVIDENCE_JSON_NODES = 4096
MAX_CAMPAIGN_EVIDENCE_JSON_STRING_BYTES = 4096

_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SCHEMA = re.compile(r"^[a-z0-9][a-z0-9._/-]{0,127}$")
_REASON = re.compile(r"^[a-z0-9][a-z0-9._:-]{0,127}$")
_FILE_NAME = re.compile(r"^\d{4}-[a-z0-9-]+\.json$")
_REPARSE_POINT_ATTRIBUTE = 0x400
_RAW_IDENTIFIER_KEYS = {
    "actor",
    "actor_id",
    "campaign_id",
    "credential",
    "credential_id",
    "engagement_id",
    "evidence_id",
    "organization_id",
    "principal_id",
    "target_id",
    "tenant_id",
    "user_id",
}
_SENSITIVE_KEY_PARTS = ("password", "private_key", "secret", "token", "cookie", "authorization")


class LineageArtifactKind(str, Enum):
    AUTHORIZATION = "authorization"
    AUTHORITY_LIFECYCLE = "authority-lifecycle"
    PLANNING_DOMAIN = "planning-domain"
    TRUSTED_CONTEXT = "trusted-context"
    PLAN_REVISION = "plan-revision"
    PLANNER_RECEIPT = "planner-receipt"
    VALIDATION_CERTIFICATE = "validation-certificate"
    SUBSET_PROOF = "subset-proof"
    ADMISSION_POLICY = "admission-policy"
    ADMISSION_RECEIPT = "admission-receipt"
    BUDGET_RESERVATION = "budget-reservation"
    NODE_INTENT = "node-intent"
    EFFECT_POLICY_DECISION = "effect-policy-decision"
    CREDENTIAL_LEASE = "credential-lease"
    RUNNER_RESULT = "runner-result"
    EVIDENCE = "evidence"
    TRUSTED_OBSERVATION = "trusted-observation"
    REPLAN = "replan"
    CLEANUP = "cleanup"
    CONTAINMENT = "containment"
    BUDGET_RECONCILIATION = "budget-reconciliation"
    TERMINAL_DISPOSITION = "terminal-disposition"


REQUIRED_LINEAGE_ARTIFACT_KINDS = tuple(
    kind for kind in LineageArtifactKind if kind is not LineageArtifactKind.TERMINAL_DISPOSITION
)
_KIND_ORDER: dict[LineageArtifactKind, int] = {
    kind: index for index, kind in enumerate(REQUIRED_LINEAGE_ARTIFACT_KINDS)
}
_NOT_APPLICABLE_KINDS = frozenset(
    {
        LineageArtifactKind.CREDENTIAL_LEASE,
        LineageArtifactKind.TRUSTED_OBSERVATION,
        LineageArtifactKind.REPLAN,
        LineageArtifactKind.CONTAINMENT,
    }
)


class LineageArtifactState(str, Enum):
    COMPLETE = "complete"
    NOT_APPLICABLE = "not-applicable"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    LOST = "lost"


class CampaignTerminalDisposition(str, Enum):
    QUALIFIED = "qualified"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"
    LOST = "lost"


class CampaignEvidenceVerificationOutcome(str, Enum):
    VERIFIED = "verified"
    INCOMPLETE = "incomplete"
    AMBIGUOUS = "ambiguous"
    LOST = "lost"


class CampaignEvidenceVerificationError(ValueError):
    """Raised when retained evidence is malformed, tampered, or context-grafted."""


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignLineageArtifactInputV1:
    kind: LineageArtifactKind
    source_schema_version: str
    source_record_sha256: str
    source_parent_sha256s: tuple[str, ...]
    record_index: int
    record_count: int
    state: LineageArtifactState
    state_reason: str | None = None
    access_policy: EvidenceAccessPolicy = EvidenceAccessPolicy.REVIEWERS_ONLY
    retention_class: RetentionClass = RetentionClass.STANDARD
    redaction_status: RedactionStatus = RedactionStatus.REDACTED

    def __post_init__(self) -> None:
        if not isinstance(self.kind, LineageArtifactKind) or self.kind is LineageArtifactKind.TERMINAL_DISPOSITION:
            raise ValueError("campaign_evidence_artifact_kind_invalid")
        if self.source_schema_version != lineage_source_schema_version(self.kind):
            raise ValueError("campaign_evidence_source_schema_invalid")
        _sha256("source_record_sha256", self.source_record_sha256)
        if (
            not isinstance(self.source_parent_sha256s, tuple)
            or len(self.source_parent_sha256s) > MAX_CAMPAIGN_EVIDENCE_ARTIFACTS
            or len(set(self.source_parent_sha256s)) != len(self.source_parent_sha256s)
            or tuple(sorted(self.source_parent_sha256s)) != self.source_parent_sha256s
        ):
            raise ValueError("campaign_evidence_source_parents_invalid")
        for parent in self.source_parent_sha256s:
            _sha256("source_parent_sha256", parent)
        _bounded_int("record_index", self.record_index, 0, MAX_CAMPAIGN_EVIDENCE_ARTIFACTS - 1)
        _bounded_int("record_count", self.record_count, 1, MAX_CAMPAIGN_EVIDENCE_ARTIFACTS)
        if self.record_index >= self.record_count:
            raise ValueError("campaign_evidence_record_index_invalid")
        if not isinstance(self.state, LineageArtifactState):
            raise ValueError("campaign_evidence_artifact_state_invalid")
        if self.state is LineageArtifactState.NOT_APPLICABLE and self.kind not in _NOT_APPLICABLE_KINDS:
            raise ValueError("campaign_evidence_not_applicable_kind_invalid")
        if self.state in {LineageArtifactState.COMPLETE, LineageArtifactState.NOT_APPLICABLE}:
            if self.state_reason is not None:
                raise ValueError("campaign_evidence_state_reason_unexpected")
        elif not isinstance(self.state_reason, str) or not _REASON.fullmatch(self.state_reason):
            raise ValueError("campaign_evidence_state_reason_required")
        if self.access_policy not in {
            EvidenceAccessPolicy.REVIEWERS_ONLY,
            EvidenceAccessPolicy.SECURITY_LEADS_ONLY,
        }:
            raise ValueError("campaign_evidence_artifact_access_policy_invalid")
        if not isinstance(self.retention_class, RetentionClass):
            raise ValueError("campaign_evidence_artifact_retention_class_invalid")
        if self.redaction_status not in {RedactionStatus.REDACTED, RedactionStatus.NOT_APPLICABLE}:
            raise ValueError("campaign_evidence_artifact_redaction_status_invalid")


def lineage_source_schema_version(kind: LineageArtifactKind) -> str:
    if not isinstance(kind, LineageArtifactKind) or kind is LineageArtifactKind.TERMINAL_DISPOSITION:
        raise ValueError("campaign_evidence_source_kind_invalid")
    return f"redagent.campaign-lineage-source-{kind.value}/v1"


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignEvidenceTrustAnchorV1:
    expected_manifest_sha256: str
    expected_signed_authority_sha256: str
    expected_tenant_sha256: str
    expected_campaign_sha256: str

    def __post_init__(self) -> None:
        for name in (
            "expected_manifest_sha256",
            "expected_signed_authority_sha256",
            "expected_tenant_sha256",
            "expected_campaign_sha256",
        ):
            _sha256(name, getattr(self, name))


@dataclass(frozen=True, slots=True)
class CampaignEvidenceBundleV1:
    files: tuple[tuple[str, bytes], ...]
    manifest_bytes: bytes
    manifest_sha256: str

    def __post_init__(self) -> None:
        _sha256("manifest_sha256", self.manifest_sha256)
        if hashlib.sha256(self.manifest_bytes).hexdigest() != self.manifest_sha256:
            raise ValueError("campaign_evidence_manifest_digest_invalid")
        names = tuple(name for name, _ in self.files)
        if len(set(names)) != len(names) or len(names) > MAX_CAMPAIGN_EVIDENCE_ARTIFACTS:
            raise ValueError("campaign_evidence_bundle_file_inventory_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class VerifiedCampaignLineageArtifactV1:
    sequence: int
    kind: LineageArtifactKind
    source_schema_version: str
    state: LineageArtifactState
    access_policy: EvidenceAccessPolicy
    retention_class: RetentionClass
    redaction_status: RedactionStatus
    artifact_sha256: str
    payload_sha256: str
    parent_sha256s: tuple[str, ...]
    payload: Mapping[str, object]


@dataclass(frozen=True, slots=True, kw_only=True)
class CampaignEvidenceVerificationResultV1:
    outcome: CampaignEvidenceVerificationOutcome
    manifest_sha256: str
    signed_authority_sha256: str
    tenant_sha256: str
    campaign_sha256: str
    terminal_disposition: CampaignTerminalDisposition
    loss_reasons: tuple[str, ...]
    artifacts: tuple[VerifiedCampaignLineageArtifactV1, ...]


@dataclass(frozen=True, slots=True)
class _SourceRecordView:
    kind: LineageArtifactKind
    source_schema_version: str
    source_record_sha256: str
    source_parent_sha256s: tuple[str, ...]
    record_index: int
    record_count: int
    state: LineageArtifactState
    state_reason: str | None


def campaign_context_sha256(value: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise ValueError("campaign_evidence_context_invalid")
    return hashlib.sha256(canonical_planning_bytes({"context": value})).hexdigest()


def _validate_source_records(
    records: tuple[CampaignLineageArtifactInputV1, ...],
    *,
    error_type: type[ValueError],
) -> tuple[CampaignTerminalDisposition, tuple[str, ...]]:
    views = tuple(
        _SourceRecordView(
            item.kind,
            item.source_schema_version,
            item.source_record_sha256,
            item.source_parent_sha256s,
            item.record_index,
            item.record_count,
            item.state,
            item.state_reason,
        )
        for item in records
    )
    return _validate_source_record_views(views, error_type=error_type)


def _validate_source_record_views(
    records: tuple[_SourceRecordView, ...],
    *,
    error_type: type[ValueError],
) -> tuple[CampaignTerminalDisposition, tuple[str, ...]]:
    seen: set[str] = set()
    previous_order = -1
    grouped: dict[LineageArtifactKind, list[_SourceRecordView]] = {}
    for item in records:
        order = _KIND_ORDER[item.kind]
        if order < previous_order:
            raise error_type("campaign_evidence_kind_order_invalid")
        previous_order = order
        if item.source_schema_version != lineage_source_schema_version(item.kind):
            raise error_type("campaign_evidence_source_schema_invalid")
        if item.source_record_sha256 in seen:
            raise error_type("campaign_evidence_source_record_duplicate")
        if any(parent not in seen for parent in item.source_parent_sha256s):
            raise error_type("campaign_evidence_source_parent_invalid")
        if seen and not item.source_parent_sha256s:
            raise error_type("campaign_evidence_source_parent_required")
        if not seen and item.source_parent_sha256s:
            raise error_type("campaign_evidence_source_parent_invalid")
        seen.add(item.source_record_sha256)
        grouped.setdefault(item.kind, []).append(item)

    for kind, group in grouped.items():
        expected_count = len(group)
        if any(item.record_count != expected_count for item in group) or [
            item.record_index for item in group
        ] != list(range(expected_count)):
            raise error_type("campaign_evidence_record_cardinality_invalid")
        if any(
            item.state is LineageArtifactState.NOT_APPLICABLE and kind not in _NOT_APPLICABLE_KINDS
            for item in group
        ):
            raise error_type("campaign_evidence_not_applicable_kind_invalid")

    missing = tuple(kind for kind in REQUIRED_LINEAGE_ARTIFACT_KINDS if kind not in grouped)
    reasons = tuple(
        sorted(
            [f"{kind.value.replace('-', '_')}_missing" for kind in missing]
            + [
                str(item.state_reason)
                for item in records
                if item.state in {
                    LineageArtifactState.MISSING,
                    LineageArtifactState.AMBIGUOUS,
                    LineageArtifactState.LOST,
                }
            ]
        )
    )
    states = {item.state for item in records}
    if LineageArtifactState.LOST in states:
        disposition = CampaignTerminalDisposition.LOST
    elif LineageArtifactState.AMBIGUOUS in states:
        disposition = CampaignTerminalDisposition.AMBIGUOUS
    elif missing or LineageArtifactState.MISSING in states:
        disposition = CampaignTerminalDisposition.INCOMPLETE
    else:
        disposition = CampaignTerminalDisposition.QUALIFIED
    if disposition is CampaignTerminalDisposition.QUALIFIED and reasons:
        raise error_type("campaign_evidence_qualified_lineage_incomplete")
    if disposition is not CampaignTerminalDisposition.QUALIFIED and not reasons:
        raise error_type("campaign_evidence_loss_reason_missing")
    return disposition, reasons


def build_campaign_evidence_bundle(
    *,
    tenant_id: str,
    campaign_id: str,
    signed_authority_sha256: str,
    artifacts: tuple[CampaignLineageArtifactInputV1, ...],
) -> CampaignEvidenceBundleV1:
    """Build immutable canonical bytes; callers persist only the returned closed inventory."""

    tenant_sha256 = campaign_context_sha256(tenant_id)
    campaign_sha256 = campaign_context_sha256(campaign_id)
    _sha256("signed_authority_sha256", signed_authority_sha256)
    if (
        not isinstance(artifacts, tuple)
        or not artifacts
        or len(artifacts) + 1 > MAX_CAMPAIGN_EVIDENCE_ARTIFACTS
        or any(not isinstance(item, CampaignLineageArtifactInputV1) for item in artifacts)
    ):
        raise ValueError("campaign_evidence_artifacts_invalid")

    ordered = tuple(sorted(artifacts, key=lambda item: (_KIND_ORDER[item.kind], item.record_index)))
    terminal_disposition, reasons = _validate_source_records(ordered, error_type=ValueError)
    kinds = {item.kind for item in ordered}

    files: list[tuple[str, bytes]] = []
    entries: list[dict[str, object]] = []
    previous_sha256: str | None = None
    for sequence, item in enumerate(ordered):
        payload = {
            "source_record_sha256": item.source_record_sha256,
            "source_parent_sha256s": list(item.source_parent_sha256s),
            "record_index": item.record_index,
            "record_count": item.record_count,
            "state_reason": item.state_reason,
        }
        encoded, artifact_sha256, payload_sha256 = _artifact_bytes(
            sequence=sequence,
            kind=item.kind,
            source_schema_version=item.source_schema_version,
            state=item.state,
            access_policy=item.access_policy,
            retention_class=item.retention_class,
            redaction_status=item.redaction_status,
            tenant_sha256=tenant_sha256,
            campaign_sha256=campaign_sha256,
            parent_sha256s=() if previous_sha256 is None else (previous_sha256,),
            payload=payload,
        )
        file_name = f"{sequence:04d}-{item.kind.value}.json"
        files.append((file_name, encoded))
        entries.append(_manifest_entry(file_name, encoded, sequence, item.kind, artifact_sha256))
        previous_sha256 = artifact_sha256

    terminal_sequence = len(ordered)
    terminal_payload = {
        "disposition": terminal_disposition.value,
        "loss_reasons": list(reasons),
        "required_kind_count": len(REQUIRED_LINEAGE_ARTIFACT_KINDS),
        "observed_kind_count": len(kinds),
        "final_chain_sha256": previous_sha256,
    }
    terminal_bytes, terminal_sha256, _ = _artifact_bytes(
        sequence=terminal_sequence,
        kind=LineageArtifactKind.TERMINAL_DISPOSITION,
        source_schema_version=CAMPAIGN_EVIDENCE_TERMINAL_SCHEMA_VERSION,
        state={
            CampaignTerminalDisposition.QUALIFIED: LineageArtifactState.COMPLETE,
            CampaignTerminalDisposition.INCOMPLETE: LineageArtifactState.MISSING,
            CampaignTerminalDisposition.AMBIGUOUS: LineageArtifactState.AMBIGUOUS,
            CampaignTerminalDisposition.LOST: LineageArtifactState.LOST,
        }[terminal_disposition],
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        retention_class=RetentionClass.STANDARD,
        redaction_status=RedactionStatus.REDACTED,
        tenant_sha256=tenant_sha256,
        campaign_sha256=campaign_sha256,
        parent_sha256s=() if previous_sha256 is None else (previous_sha256,),
        payload=terminal_payload,
    )
    terminal_name = f"{terminal_sequence:04d}-{LineageArtifactKind.TERMINAL_DISPOSITION.value}.json"
    files.append((terminal_name, terminal_bytes))
    entries.append(
        _manifest_entry(
            terminal_name,
            terminal_bytes,
            terminal_sequence,
            LineageArtifactKind.TERMINAL_DISPOSITION,
            terminal_sha256,
        )
    )
    manifest = {
        "schema_version": CAMPAIGN_EVIDENCE_MANIFEST_SCHEMA_VERSION,
        "tenant_sha256": tenant_sha256,
        "campaign_sha256": campaign_sha256,
        "signed_authority_sha256": signed_authority_sha256,
        "artifact_count": len(entries),
        "artifacts": entries,
        "terminal_disposition": terminal_disposition.value,
        "loss_reasons": list(reasons),
        "terminal_artifact_sha256": terminal_sha256,
    }
    manifest_bytes = canonical_planning_bytes(manifest)
    if len(manifest_bytes) > MAX_CAMPAIGN_EVIDENCE_FILE_BYTES:
        raise ValueError("campaign_evidence_manifest_too_large")
    total = len(manifest_bytes) + sum(len(value) for _, value in files)
    if total > MAX_CAMPAIGN_EVIDENCE_TOTAL_BYTES:
        raise ValueError("campaign_evidence_bundle_too_large")
    return CampaignEvidenceBundleV1(
        files=tuple(files),
        manifest_bytes=manifest_bytes,
        manifest_sha256=hashlib.sha256(manifest_bytes).hexdigest(),
    )


def write_campaign_evidence_bundle(bundle: CampaignEvidenceBundleV1, destination: Path) -> None:
    if not isinstance(bundle, CampaignEvidenceBundleV1) or not isinstance(destination, Path):
        raise ValueError("campaign_evidence_write_input_invalid")
    if destination.exists() or destination.is_symlink():
        raise ValueError("campaign_evidence_destination_must_not_exist")
    if not destination.parent.is_dir() or destination.parent.is_symlink():
        raise ValueError("campaign_evidence_destination_parent_invalid")
    destination.mkdir()
    try:
        # CRITICAL: this fixed inventory is the offline trust boundary; never accept caller paths.
        for name, value in (*bundle.files, ("manifest.json", bundle.manifest_bytes)):
            if name != "manifest.json" and not _FILE_NAME.fullmatch(name):
                raise ValueError("campaign_evidence_file_name_invalid")
            with (destination / name).open("xb") as handle:
                handle.write(value)
    except (OSError, ValueError):
        for child in destination.iterdir():
            if child.is_file() and not child.is_symlink():
                child.unlink()
        destination.rmdir()
        raise


def verify_campaign_evidence_bundle(
    bundle_path: Path,
    *,
    trust_anchor: CampaignEvidenceTrustAnchorV1,
) -> CampaignEvidenceVerificationResultV1:
    if not isinstance(bundle_path, Path) or not isinstance(trust_anchor, CampaignEvidenceTrustAnchorV1):
        raise CampaignEvidenceVerificationError("campaign_evidence_verification_input_invalid")
    _assert_regular_directory(bundle_path)
    manifest_bytes = _read_bounded_regular_file(bundle_path / "manifest.json")
    manifest_sha256 = hashlib.sha256(manifest_bytes).hexdigest()
    # CRITICAL: never trust a digest declared only inside the same bundle; the caller pins it.
    if not hmac.compare_digest(manifest_sha256, trust_anchor.expected_manifest_sha256):
        raise CampaignEvidenceVerificationError("campaign_evidence_manifest_trust_mismatch")
    manifest = _json_object(manifest_bytes, "campaign_evidence_manifest_invalid")
    if set(manifest) != {
        "schema_version",
        "tenant_sha256",
        "campaign_sha256",
        "signed_authority_sha256",
        "artifact_count",
        "artifacts",
        "terminal_disposition",
        "loss_reasons",
        "terminal_artifact_sha256",
    }:
        raise CampaignEvidenceVerificationError("campaign_evidence_manifest_shape_invalid")
    if manifest["schema_version"] != CAMPAIGN_EVIDENCE_MANIFEST_SCHEMA_VERSION:
        raise CampaignEvidenceVerificationError("campaign_evidence_manifest_schema_invalid")
    _verify_trust_binding(manifest, trust_anchor)
    entries = manifest.get("artifacts")
    count = manifest.get("artifact_count")
    if (
        not isinstance(entries, list)
        or not isinstance(count, int)
        or isinstance(count, bool)
        or count != len(entries)
        or not 1 <= count <= MAX_CAMPAIGN_EVIDENCE_ARTIFACTS
    ):
        raise CampaignEvidenceVerificationError("campaign_evidence_manifest_inventory_invalid")
    names = []
    for entry in entries:
        if not isinstance(entry, dict) or set(entry) != {
            "name",
            "sequence",
            "kind",
            "size_bytes",
            "file_sha256",
            "artifact_sha256",
        }:
            raise CampaignEvidenceVerificationError("campaign_evidence_manifest_entry_invalid")
        name = entry.get("name")
        if not isinstance(name, str) or not _FILE_NAME.fullmatch(name):
            raise CampaignEvidenceVerificationError("campaign_evidence_manifest_name_invalid")
        if (
            type(entry.get("sequence")) is not int
            or type(entry.get("size_bytes")) is not int
            or not 0 <= entry["sequence"] < MAX_CAMPAIGN_EVIDENCE_ARTIFACTS
            or entry["size_bytes"] < 0
        ):
            raise CampaignEvidenceVerificationError("campaign_evidence_manifest_entry_number_invalid")
        if entry["size_bytes"] > MAX_CAMPAIGN_EVIDENCE_FILE_BYTES:
            raise CampaignEvidenceVerificationError("campaign_evidence_file_too_large")
        names.append(name)
    if len(set(names)) != len(names):
        raise CampaignEvidenceVerificationError("campaign_evidence_manifest_duplicate_name")
    actual_names: set[str] = set()
    try:
        for child in bundle_path.iterdir():
            actual_names.add(child.name)
            if len(actual_names) > MAX_CAMPAIGN_EVIDENCE_ARTIFACTS + 1:
                raise CampaignEvidenceVerificationError("campaign_evidence_bundle_inventory_too_large")
    except OSError as exc:
        raise CampaignEvidenceVerificationError("campaign_evidence_bundle_inventory_read_failed") from exc
    if actual_names != {"manifest.json", *names}:
        raise CampaignEvidenceVerificationError("campaign_evidence_bundle_inventory_mismatch")

    verified: list[VerifiedCampaignLineageArtifactV1] = []
    previous_sha256: str | None = None
    total_bytes = len(manifest_bytes)
    for expected_sequence, (entry, name) in enumerate(zip(entries, names, strict=True)):
        encoded = _read_bounded_regular_file(bundle_path / name)
        total_bytes += len(encoded)
        if total_bytes > MAX_CAMPAIGN_EVIDENCE_TOTAL_BYTES:
            raise CampaignEvidenceVerificationError("campaign_evidence_bundle_too_large")
        if entry["sequence"] != expected_sequence or entry["size_bytes"] != len(encoded):
            raise CampaignEvidenceVerificationError("campaign_evidence_manifest_order_or_size_invalid")
        file_sha256 = hashlib.sha256(encoded).hexdigest()
        if not isinstance(entry["file_sha256"], str) or not hmac.compare_digest(file_sha256, entry["file_sha256"]):
            raise CampaignEvidenceVerificationError("campaign_evidence_file_digest_mismatch")
        artifact = _verify_artifact(
            encoded,
            expected_sequence=expected_sequence,
            expected_name=name,
            expected_artifact_sha256=entry["artifact_sha256"],
            expected_kind=entry["kind"],
            tenant_sha256=str(manifest["tenant_sha256"]),
            campaign_sha256=str(manifest["campaign_sha256"]),
            previous_sha256=previous_sha256,
        )
        verified.append(artifact)
        previous_sha256 = artifact.artifact_sha256

    terminal = _terminal_disposition(manifest.get("terminal_disposition"))
    reasons = _verified_loss_reasons(manifest.get("loss_reasons"))
    derived_terminal, derived_reasons = _verify_lineage_completeness(verified)
    if terminal is not derived_terminal or reasons != derived_reasons:
        raise CampaignEvidenceVerificationError("campaign_evidence_terminal_truth_mismatch")
    _verify_terminal(verified, manifest, terminal, reasons)
    outcome = {
        CampaignTerminalDisposition.QUALIFIED: CampaignEvidenceVerificationOutcome.VERIFIED,
        CampaignTerminalDisposition.INCOMPLETE: CampaignEvidenceVerificationOutcome.INCOMPLETE,
        CampaignTerminalDisposition.AMBIGUOUS: CampaignEvidenceVerificationOutcome.AMBIGUOUS,
        CampaignTerminalDisposition.LOST: CampaignEvidenceVerificationOutcome.LOST,
    }[terminal]
    return CampaignEvidenceVerificationResultV1(
        outcome=outcome,
        manifest_sha256=manifest_sha256,
        signed_authority_sha256=str(manifest["signed_authority_sha256"]),
        tenant_sha256=str(manifest["tenant_sha256"]),
        campaign_sha256=str(manifest["campaign_sha256"]),
        terminal_disposition=terminal,
        loss_reasons=reasons,
        artifacts=tuple(verified),
    )


def _artifact_bytes(
    *,
    sequence: int,
    kind: LineageArtifactKind,
    source_schema_version: str,
    state: LineageArtifactState,
    access_policy: EvidenceAccessPolicy,
    retention_class: RetentionClass,
    redaction_status: RedactionStatus,
    tenant_sha256: str,
    campaign_sha256: str,
    parent_sha256s: tuple[str, ...],
    payload: Mapping[str, object],
) -> tuple[bytes, str, str]:
    safe_payload = _safe_payload(payload, kind=kind, state=state)
    payload_sha256 = hashlib.sha256(canonical_planning_bytes(safe_payload)).hexdigest()
    body = {
        "schema_version": CAMPAIGN_EVIDENCE_ARTIFACT_SCHEMA_VERSION,
        "sequence": sequence,
        "kind": kind.value,
        "source_schema_version": source_schema_version,
        "state": state.value,
        "access_policy": access_policy.value,
        "retention_class": retention_class.value,
        "redaction_status": redaction_status.value,
        "tenant_sha256": tenant_sha256,
        "campaign_sha256": campaign_sha256,
        "parent_sha256s": list(parent_sha256s),
        "payload_sha256": payload_sha256,
        "payload": safe_payload,
    }
    artifact_sha256 = hashlib.sha256(canonical_planning_bytes(body)).hexdigest()
    encoded = canonical_planning_bytes({**body, "artifact_sha256": artifact_sha256})
    if len(encoded) > MAX_CAMPAIGN_EVIDENCE_FILE_BYTES:
        raise ValueError("campaign_evidence_artifact_too_large")
    return encoded, artifact_sha256, payload_sha256


def _manifest_entry(
    name: str,
    encoded: bytes,
    sequence: int,
    kind: LineageArtifactKind,
    artifact_sha256: str,
) -> dict[str, object]:
    return {
        "name": name,
        "sequence": sequence,
        "kind": kind.value,
        "size_bytes": len(encoded),
        "file_sha256": hashlib.sha256(encoded).hexdigest(),
        "artifact_sha256": artifact_sha256,
    }


def _verify_artifact(
    encoded: bytes,
    *,
    expected_sequence: int,
    expected_name: str,
    expected_artifact_sha256: object,
    expected_kind: object,
    tenant_sha256: str,
    campaign_sha256: str,
    previous_sha256: str | None,
) -> VerifiedCampaignLineageArtifactV1:
    payload = _json_object(encoded, "campaign_evidence_artifact_invalid")
    if set(payload) != {
        "schema_version",
        "sequence",
        "kind",
        "source_schema_version",
        "state",
        "access_policy",
        "retention_class",
        "redaction_status",
        "tenant_sha256",
        "campaign_sha256",
        "parent_sha256s",
        "payload_sha256",
        "payload",
        "artifact_sha256",
    }:
        raise CampaignEvidenceVerificationError("campaign_evidence_artifact_shape_invalid")
    try:
        kind = LineageArtifactKind(payload["kind"])
        state = LineageArtifactState(payload["state"])
        access_policy = EvidenceAccessPolicy(payload["access_policy"])
        retention_class = RetentionClass(payload["retention_class"])
        redaction_status = RedactionStatus(payload["redaction_status"])
    except (TypeError, ValueError) as exc:
        raise CampaignEvidenceVerificationError("campaign_evidence_artifact_enum_invalid") from exc
    if access_policy not in {
        EvidenceAccessPolicy.REVIEWERS_ONLY,
        EvidenceAccessPolicy.SECURITY_LEADS_ONLY,
    } or redaction_status not in {RedactionStatus.REDACTED, RedactionStatus.NOT_APPLICABLE}:
        raise CampaignEvidenceVerificationError("campaign_evidence_artifact_disclosure_boundary_invalid")
    if (
        payload["schema_version"] != CAMPAIGN_EVIDENCE_ARTIFACT_SCHEMA_VERSION
        or type(payload["sequence"]) is not int
        or payload["sequence"] != expected_sequence
        or payload["kind"] != expected_kind
        or expected_name != f"{expected_sequence:04d}-{kind.value}.json"
    ):
        raise CampaignEvidenceVerificationError("campaign_evidence_artifact_identity_invalid")
    if payload["tenant_sha256"] != tenant_sha256 or payload["campaign_sha256"] != campaign_sha256:
        raise CampaignEvidenceVerificationError("campaign_evidence_artifact_context_invalid")
    parents = payload.get("parent_sha256s")
    expected_parents = [] if previous_sha256 is None else [previous_sha256]
    if parents != expected_parents:
        raise CampaignEvidenceVerificationError("campaign_evidence_artifact_parent_invalid")
    source_schema = payload.get("source_schema_version")
    expected_source_schema = (
        CAMPAIGN_EVIDENCE_TERMINAL_SCHEMA_VERSION
        if kind is LineageArtifactKind.TERMINAL_DISPOSITION
        else lineage_source_schema_version(kind)
    )
    if source_schema != expected_source_schema:
        raise CampaignEvidenceVerificationError("campaign_evidence_source_schema_invalid")
    safe_payload = _safe_payload_for_verification(payload.get("payload"), kind=kind, state=state)
    payload_sha256 = hashlib.sha256(canonical_planning_bytes(safe_payload)).hexdigest()
    if payload.get("payload_sha256") != payload_sha256:
        raise CampaignEvidenceVerificationError("campaign_evidence_payload_digest_mismatch")
    body = dict(payload)
    artifact_sha256 = body.pop("artifact_sha256", None)
    computed = hashlib.sha256(canonical_planning_bytes(body)).hexdigest()
    if (
        not isinstance(artifact_sha256, str)
        or not hmac.compare_digest(artifact_sha256, computed)
        or not isinstance(expected_artifact_sha256, str)
        or not hmac.compare_digest(artifact_sha256, expected_artifact_sha256)
    ):
        raise CampaignEvidenceVerificationError("campaign_evidence_artifact_digest_mismatch")
    return VerifiedCampaignLineageArtifactV1(
        sequence=expected_sequence,
        kind=kind,
        source_schema_version=source_schema,
        state=state,
        access_policy=access_policy,
        retention_class=retention_class,
        redaction_status=redaction_status,
        artifact_sha256=artifact_sha256,
        payload_sha256=payload_sha256,
        parent_sha256s=tuple(parents),
        payload=safe_payload,
    )


def _verify_trust_binding(manifest: Mapping[str, object], trust: CampaignEvidenceTrustAnchorV1) -> None:
    for key in ("tenant_sha256", "campaign_sha256", "signed_authority_sha256", "terminal_artifact_sha256"):
        value = manifest.get(key)
        if not isinstance(value, str) or not _SHA256.fullmatch(value):
            raise CampaignEvidenceVerificationError("campaign_evidence_manifest_digest_invalid")
    if not hmac.compare_digest(str(manifest["tenant_sha256"]), trust.expected_tenant_sha256):
        raise CampaignEvidenceVerificationError("campaign_evidence_tenant_binding_mismatch")
    if not hmac.compare_digest(str(manifest["campaign_sha256"]), trust.expected_campaign_sha256):
        raise CampaignEvidenceVerificationError("campaign_evidence_campaign_binding_mismatch")
    if not hmac.compare_digest(
        str(manifest["signed_authority_sha256"]), trust.expected_signed_authority_sha256
    ):
        raise CampaignEvidenceVerificationError("campaign_evidence_authority_binding_mismatch")


def _verify_terminal(
    artifacts: list[VerifiedCampaignLineageArtifactV1],
    manifest: Mapping[str, object],
    terminal: CampaignTerminalDisposition,
    reasons: tuple[str, ...],
) -> None:
    if not artifacts or artifacts[-1].kind is not LineageArtifactKind.TERMINAL_DISPOSITION:
        raise CampaignEvidenceVerificationError("campaign_evidence_terminal_missing")
    terminal_artifact = artifacts[-1]
    if terminal_artifact.artifact_sha256 != manifest["terminal_artifact_sha256"]:
        raise CampaignEvidenceVerificationError("campaign_evidence_terminal_digest_mismatch")
    expected_payload = {
        "disposition": terminal.value,
        "loss_reasons": list(reasons),
        "required_kind_count": len(REQUIRED_LINEAGE_ARTIFACT_KINDS),
        "observed_kind_count": len({item.kind for item in artifacts[:-1]}),
        "final_chain_sha256": artifacts[-2].artifact_sha256 if len(artifacts) > 1 else None,
    }
    if terminal_artifact.payload != expected_payload:
        raise CampaignEvidenceVerificationError("campaign_evidence_terminal_payload_mismatch")
    expected_state = {
        CampaignTerminalDisposition.QUALIFIED: LineageArtifactState.COMPLETE,
        CampaignTerminalDisposition.INCOMPLETE: LineageArtifactState.MISSING,
        CampaignTerminalDisposition.AMBIGUOUS: LineageArtifactState.AMBIGUOUS,
        CampaignTerminalDisposition.LOST: LineageArtifactState.LOST,
    }[terminal]
    if (
        terminal_artifact.state is not expected_state
        or terminal_artifact.access_policy is not EvidenceAccessPolicy.REVIEWERS_ONLY
        or terminal_artifact.retention_class is not RetentionClass.STANDARD
        or terminal_artifact.redaction_status is not RedactionStatus.REDACTED
    ):
        raise CampaignEvidenceVerificationError("campaign_evidence_terminal_contract_invalid")


def _verify_lineage_completeness(
    artifacts: list[VerifiedCampaignLineageArtifactV1],
) -> tuple[CampaignTerminalDisposition, tuple[str, ...]]:
    body = artifacts[:-1]
    views = []
    for item in body:
        payload = item.payload
        views.append(
            _SourceRecordView(
                item.kind,
                item.source_schema_version,
                cast(str, payload["source_record_sha256"]),
                tuple(cast(list[str], payload["source_parent_sha256s"])),
                cast(int, payload["record_index"]),
                cast(int, payload["record_count"]),
                item.state,
                None if payload["state_reason"] is None else cast(str, payload["state_reason"]),
            )
        )
    return _validate_source_record_views(
        tuple(views),
        error_type=CampaignEvidenceVerificationError,
    )


def _safe_payload(
    value: Mapping[str, object],
    *,
    kind: LineageArtifactKind,
    state: LineageArtifactState,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError("campaign_evidence_payload_invalid")
    try:
        normalized = json.loads(canonical_planning_bytes(dict(value)))
    except (TypeError, ValueError) as exc:
        raise ValueError("campaign_evidence_payload_invalid") from exc
    if not isinstance(normalized, dict):
        raise ValueError("campaign_evidence_payload_invalid")
    if kind is LineageArtifactKind.TERMINAL_DISPOSITION:
        if set(normalized) != {
            "disposition",
            "loss_reasons",
            "required_kind_count",
            "observed_kind_count",
            "final_chain_sha256",
        }:
            raise ValueError("campaign_evidence_terminal_payload_shape_invalid")
        _terminal_disposition(normalized["disposition"])
        _verified_loss_reasons(normalized["loss_reasons"])
        if normalized["required_kind_count"] != len(REQUIRED_LINEAGE_ARTIFACT_KINDS):
            raise ValueError("campaign_evidence_terminal_required_count_invalid")
        _bounded_int(
            "terminal_observed_kind_count",
            normalized["observed_kind_count"],
            0,
            len(REQUIRED_LINEAGE_ARTIFACT_KINDS),
        )
        if normalized["final_chain_sha256"] is not None:
            _sha256("terminal_final_chain_sha256", normalized["final_chain_sha256"])
    else:
        if set(normalized) != {
            "source_record_sha256",
            "source_parent_sha256s",
            "record_index",
            "record_count",
            "state_reason",
        }:
            raise ValueError("campaign_evidence_source_payload_shape_invalid")
        _sha256("source_record_sha256", normalized["source_record_sha256"])
        parents = normalized["source_parent_sha256s"]
        if (
            not isinstance(parents, list)
            or len(parents) > MAX_CAMPAIGN_EVIDENCE_ARTIFACTS
            or len(set(parents)) != len(parents)
            or sorted(parents) != parents
        ):
            raise ValueError("campaign_evidence_source_parents_invalid")
        for parent in parents:
            _sha256("source_parent_sha256", parent)
        _bounded_int("record_index", normalized["record_index"], 0, MAX_CAMPAIGN_EVIDENCE_ARTIFACTS - 1)
        _bounded_int("record_count", normalized["record_count"], 1, MAX_CAMPAIGN_EVIDENCE_ARTIFACTS)
        if normalized["record_index"] >= normalized["record_count"]:
            raise ValueError("campaign_evidence_record_index_invalid")
        reason = normalized["state_reason"]
        if state in {LineageArtifactState.COMPLETE, LineageArtifactState.NOT_APPLICABLE}:
            if reason is not None:
                raise ValueError("campaign_evidence_state_reason_unexpected")
        elif not isinstance(reason, str) or not _REASON.fullmatch(reason):
            raise ValueError("campaign_evidence_state_reason_required")
        if state is LineageArtifactState.NOT_APPLICABLE and kind not in _NOT_APPLICABLE_KINDS:
            raise ValueError("campaign_evidence_not_applicable_kind_invalid")
    _assert_json_bounds(normalized)
    encoded = canonical_planning_bytes(normalized)
    if len(encoded) > MAX_CAMPAIGN_EVIDENCE_FILE_BYTES // 2:
        raise ValueError("campaign_evidence_payload_too_large")
    try:
        assert_no_sensitive_output(encoded.decode("ascii"), RedactionArtifactClass.EVIDENCE_ARTIFACT)
    except ValueError as exc:
        raise ValueError("campaign_evidence_sensitive_payload_forbidden") from exc
    return normalized


def _safe_payload_for_verification(
    value: object,
    *,
    kind: LineageArtifactKind,
    state: LineageArtifactState,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise CampaignEvidenceVerificationError("campaign_evidence_payload_invalid")
    try:
        return _safe_payload(value, kind=kind, state=state)
    except ValueError as exc:
        raise CampaignEvidenceVerificationError(str(exc)) from exc


def _loss_reasons(value: tuple[str, ...]) -> tuple[str, ...]:
    if (
        not isinstance(value, tuple)
        or len(value) > 32
        or len(set(value)) != len(value)
        or tuple(sorted(value)) != value
        or any(not isinstance(item, str) or not _REASON.fullmatch(item) for item in value)
    ):
        raise ValueError("campaign_evidence_loss_reasons_invalid")
    return value


def _verified_loss_reasons(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise CampaignEvidenceVerificationError("campaign_evidence_loss_reasons_invalid")
    try:
        return _loss_reasons(tuple(value))
    except ValueError as exc:
        raise CampaignEvidenceVerificationError("campaign_evidence_loss_reasons_invalid") from exc


def _terminal_disposition(value: object) -> CampaignTerminalDisposition:
    try:
        return CampaignTerminalDisposition(value)
    except (TypeError, ValueError) as exc:
        raise CampaignEvidenceVerificationError("campaign_terminal_disposition_invalid") from exc


def _assert_regular_directory(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CampaignEvidenceVerificationError("campaign_evidence_bundle_directory_missing") from exc
    if not stat.S_ISDIR(metadata.st_mode) or _is_linklike(metadata):
        raise CampaignEvidenceVerificationError("campaign_evidence_bundle_directory_invalid")


def _read_bounded_regular_file(path: Path) -> bytes:
    try:
        before = path.lstat()
    except OSError as exc:
        raise CampaignEvidenceVerificationError("campaign_evidence_file_missing") from exc
    if not stat.S_ISREG(before.st_mode) or _is_linklike(before):
        raise CampaignEvidenceVerificationError("campaign_evidence_regular_file_required")
    if before.st_size > MAX_CAMPAIGN_EVIDENCE_FILE_BYTES:
        raise CampaignEvidenceVerificationError("campaign_evidence_file_too_large")
    try:
        value = path.read_bytes()
        after = path.lstat()
    except OSError as exc:
        raise CampaignEvidenceVerificationError("campaign_evidence_file_read_failed") from exc
    if _metadata_identity(before) != _metadata_identity(after) or len(value) != before.st_size:
        raise CampaignEvidenceVerificationError("campaign_evidence_file_changed_during_read")
    return value


def _metadata_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (
        int(value.st_dev),
        int(value.st_ino),
        int(value.st_size),
        int(getattr(value, "st_mtime_ns", 0)),
        int(getattr(value, "st_file_attributes", 0)),
    )


def _is_linklike(value: os.stat_result) -> bool:
    return stat.S_ISLNK(value.st_mode) or bool(
        getattr(value, "st_file_attributes", 0) & _REPARSE_POINT_ATTRIBUTE
    )


def _json_object(value: bytes, error: str) -> dict[str, object]:
    try:
        parsed = json.loads(value)
        _assert_json_bounds(parsed)
        canonical = canonical_planning_bytes(parsed)
    except ValueError as exc:
        if str(exc).startswith("campaign_evidence_json_"):
            raise CampaignEvidenceVerificationError(str(exc)) from exc
        raise CampaignEvidenceVerificationError(error) from exc
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError, TypeError) as exc:
        raise CampaignEvidenceVerificationError(error) from exc
    if not isinstance(parsed, dict) or canonical != value:
        raise CampaignEvidenceVerificationError(error)
    return parsed


def _assert_json_bounds(value: object) -> None:
    nodes = 0

    def visit(item: object, depth: int) -> None:
        nonlocal nodes
        nodes += 1
        if nodes > MAX_CAMPAIGN_EVIDENCE_JSON_NODES:
            raise ValueError("campaign_evidence_json_nodes_exceeded")
        if depth > MAX_CAMPAIGN_EVIDENCE_JSON_DEPTH:
            raise ValueError("campaign_evidence_json_depth_exceeded")
        if isinstance(item, dict):
            for key, nested in item.items():
                if not isinstance(key, str) or len(key.encode("utf-8")) > MAX_CAMPAIGN_EVIDENCE_JSON_STRING_BYTES:
                    raise ValueError("campaign_evidence_json_key_invalid")
                visit(nested, depth + 1)
        elif isinstance(item, list):
            for nested in item:
                visit(nested, depth + 1)
        elif isinstance(item, str):
            if len(item.encode("utf-8")) > MAX_CAMPAIGN_EVIDENCE_JSON_STRING_BYTES:
                raise ValueError("campaign_evidence_json_string_too_large")
        elif type(item) is int:
            if not -(2**63) <= item <= 2**63 - 1:
                raise ValueError("campaign_evidence_json_integer_out_of_range")
        elif item is not None and type(item) not in {bool, float}:
            raise ValueError("campaign_evidence_json_type_invalid")
        if isinstance(item, float):
            raise ValueError("campaign_evidence_json_float_forbidden")

    visit(value, 0)


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"campaign_evidence_{name}_invalid")


def _schema(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SCHEMA.fullmatch(value):
        raise ValueError(f"campaign_evidence_{name}_invalid")


def _bounded_int(name: str, value: object, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"campaign_evidence_{name}_invalid")
