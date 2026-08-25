"""Evidence package chain-of-custody attestation contracts.

compat_080 builds deterministic attestations over local evidence manifests. It does
not call external attestation services, dispatch runners, read target systems,
or export raw artifact bytes in package manifests.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from redagent_platform.evidence_chain import AuditAction, EvidenceChain, RetentionClass
from redagent_platform.evidence_store import (
    EvidenceArtifactManifest,
    EvidenceArtifactVerification,
    LocalEvidenceArtifactStore,
)
from redagent_platform.policy_simulator import PolicySimulationResult
from redagent_platform.redaction import RedactionArtifactClass, assert_no_sensitive_output
from redagent_platform.scope_roe_ledger import AuthorizationReplayProof


class CustodyEventKind(str, Enum):
    COLLECTION = "collection"
    REDACTION = "redaction"
    STORAGE = "storage"
    REVIEW = "review"
    EXPORT = "export"
    CUSTODY_TRANSFER = "custody_transfer"


class RetentionAction(str, Enum):
    DISPOSE = "dispose"
    EXPIRE = "expire"


class TamperReviewStatus(str, Enum):
    OPEN = "open"
    CONFIRMED_TAMPER = "confirmed_tamper"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_LOSS = "accepted_loss"
    REMEDIATED = "remediated"


REQUIRED_CUSTODY_EVENTS: frozenset[CustodyEventKind] = frozenset(CustodyEventKind)


@dataclass(frozen=True, kw_only=True)
class EvidenceCustodyEvent:
    event_id: str
    evidence_id: str
    organization_id: str
    kind: CustodyEventKind
    actor_user_id: str
    occurred_at: datetime
    details_hash: str
    previous_event_hash: str | None
    event_hash: str


@dataclass(frozen=True, kw_only=True)
class EvidencePackageAttestation:
    attestation_id: str
    organization_id: str
    generated_by_user_id: str
    generated_at: datetime
    evidence_ids: tuple[str, ...]
    custody_event_hashes: tuple[str, ...]
    artifact_manifest_hashes: tuple[str, ...]
    artifact_verification_hashes: tuple[str, ...]
    policy_simulation_hash: str | None
    scope_authorization_proof_hashes: tuple[str, ...]
    legal_hold_evidence_ids: tuple[str, ...]
    attestation_hash: str


@dataclass(frozen=True, kw_only=True)
class RehashVerificationEntry:
    evidence_id: str
    manifest_id: str | None
    ok: bool
    reason: str
    verification_hash: str


@dataclass(frozen=True, kw_only=True)
class RehashVerificationReport:
    verification_id: str
    organization_id: str
    verified_by_user_id: str
    verified_at: datetime
    entries: tuple[RehashVerificationEntry, ...]
    all_ok: bool
    audit_chain: EvidenceChain
    report_hash: str


@dataclass(frozen=True, kw_only=True)
class TamperReviewRecord:
    review_id: str
    verification_id: str
    evidence_id: str
    status: TamperReviewStatus
    opened_by_user_id: str
    opened_at: datetime
    reason: str
    source_verification_hash: str
    review_hash: str


@dataclass(frozen=True, kw_only=True)
class RetentionDispositionDecision:
    evidence_id: str
    action: RetentionAction
    allowed: bool
    reason: str
    requested_by_user_id: str
    requested_at: datetime
    decision_hash: str


@dataclass(frozen=True, kw_only=True)
class EvidencePackageExportManifest:
    export_manifest_id: str
    attestation_id: str
    organization_id: str
    destination_label: str
    generated_by_user_id: str
    generated_at: datetime
    evidence_ids: tuple[str, ...]
    custody_event_hashes: tuple[str, ...]
    artifact_manifest_hashes: tuple[str, ...]
    artifact_verification_hashes: tuple[str, ...]
    attestation_hash: str
    export_manifest_hash: str


def build_custody_event(
    *,
    event_id: str,
    evidence_id: str,
    organization_id: str,
    kind: CustodyEventKind,
    actor_user_id: str,
    occurred_at: datetime,
    details: Mapping[str, object],
    previous_event: EvidenceCustodyEvent | None = None,
) -> EvidenceCustodyEvent:
    for field_name, value in (
        ("event_id", event_id),
        ("evidence_id", evidence_id),
        ("organization_id", organization_id),
        ("actor_user_id", actor_user_id),
    ):
        _require_non_empty(field_name, value)
        _ensure_secret_free(value)
    _require_timezone(occurred_at)
    details_hash = _canonical_sha256(_fingerprinted_details(details))
    payload = {
        "event_id": event_id.strip(),
        "evidence_id": evidence_id.strip(),
        "organization_id": organization_id.strip(),
        "kind": kind.value,
        "actor_user_id": actor_user_id.strip(),
        "occurred_at": occurred_at.isoformat(),
        "details_hash": details_hash,
        "previous_event_hash": previous_event.event_hash if previous_event else None,
    }
    return EvidenceCustodyEvent(
        event_id=event_id.strip(),
        evidence_id=evidence_id.strip(),
        organization_id=organization_id.strip(),
        kind=kind,
        actor_user_id=actor_user_id.strip(),
        occurred_at=occurred_at,
        details_hash=details_hash,
        previous_event_hash=previous_event.event_hash if previous_event else None,
        event_hash=_canonical_sha256(payload),
    )


def build_evidence_package_attestation(
    *,
    attestation_id: str,
    organization_id: str,
    generated_by_user_id: str,
    generated_at: datetime,
    manifests: tuple[EvidenceArtifactManifest, ...],
    custody_events: tuple[EvidenceCustodyEvent, ...],
    artifact_verifications: tuple[EvidenceArtifactVerification, ...],
    policy_simulation: PolicySimulationResult | None = None,
    authorization_proofs: tuple[AuthorizationReplayProof, ...] = (),
) -> EvidencePackageAttestation:
    for field_name, value in (
        ("attestation_id", attestation_id),
        ("organization_id", organization_id),
        ("generated_by_user_id", generated_by_user_id),
    ):
        _require_non_empty(field_name, value)
        _ensure_secret_free(value)
    _require_timezone(generated_at)
    if not manifests:
        raise ValueError("attestation_manifests_required")
    evidence_ids = tuple(sorted(manifest.evidence_id for manifest in manifests))
    _validate_manifests(organization_id, manifests)
    _validate_custody_events(organization_id, evidence_ids, custody_events)
    _validate_verifications(evidence_ids, artifact_verifications)
    if policy_simulation is not None and not policy_simulation.allowed:
        raise ValueError("policy_simulation_not_allowed")

    custody_event_hashes = tuple(sorted(event.event_hash for event in custody_events))
    artifact_manifest_hashes = tuple(sorted(manifest.manifest_hash for manifest in manifests))
    artifact_verification_hashes = tuple(sorted(_verification_hash(verification) for verification in artifact_verifications))
    proof_hashes = tuple(sorted(proof.proof_hash for proof in authorization_proofs))
    legal_hold_ids = tuple(
        sorted(
            manifest.evidence_id
            for manifest in manifests
            if manifest.legal_hold or manifest.retention_class is RetentionClass.LEGAL_HOLD
        )
    )
    payload = {
        "attestation_id": attestation_id.strip(),
        "organization_id": organization_id.strip(),
        "generated_by_user_id": generated_by_user_id.strip(),
        "generated_at": generated_at.isoformat(),
        "evidence_ids": evidence_ids,
        "custody_event_hashes": custody_event_hashes,
        "artifact_manifest_hashes": artifact_manifest_hashes,
        "artifact_verification_hashes": artifact_verification_hashes,
        "policy_simulation_hash": policy_simulation.result_hash if policy_simulation else None,
        "scope_authorization_proof_hashes": proof_hashes,
        "legal_hold_evidence_ids": legal_hold_ids,
    }
    return EvidencePackageAttestation(
        attestation_id=attestation_id.strip(),
        organization_id=organization_id.strip(),
        generated_by_user_id=generated_by_user_id.strip(),
        generated_at=generated_at,
        evidence_ids=evidence_ids,
        custody_event_hashes=custody_event_hashes,
        artifact_manifest_hashes=artifact_manifest_hashes,
        artifact_verification_hashes=artifact_verification_hashes,
        policy_simulation_hash=policy_simulation.result_hash if policy_simulation else None,
        scope_authorization_proof_hashes=proof_hashes,
        legal_hold_evidence_ids=legal_hold_ids,
        attestation_hash=_canonical_sha256(payload),
    )


def run_rehash_verification(
    *,
    verification_id: str,
    organization_id: str,
    verified_by_user_id: str,
    verified_at: datetime,
    store: LocalEvidenceArtifactStore,
    evidence_ids: tuple[str, ...],
    evidence_chain: EvidenceChain,
) -> RehashVerificationReport:
    for field_name, value in (
        ("verification_id", verification_id),
        ("organization_id", organization_id),
        ("verified_by_user_id", verified_by_user_id),
    ):
        _require_non_empty(field_name, value)
        _ensure_secret_free(value)
    _require_timezone(verified_at)
    if not evidence_ids:
        raise ValueError("verification_evidence_ids_required")

    entries = tuple(_verify_one(store, evidence_id) for evidence_id in evidence_ids)
    all_ok = all(entry.ok for entry in entries)
    next_chain = evidence_chain.append_audit_event(
        event_id=f"{verification_id.strip()}:audit",
        organization_id=organization_id.strip(),
        actor_user_id=verified_by_user_id.strip(),
        action=AuditAction.EVIDENCE_CREATION,
        subject_type="evidence_rehash_verification",
        subject_id=verification_id.strip(),
        occurred_at=verified_at,
        details={
            "all_ok": all_ok,
            "entry_hashes": tuple(entry.verification_hash for entry in entries),
            "failed_evidence_ids": tuple(entry.evidence_id for entry in entries if not entry.ok),
        },
    )
    payload = {
        "verification_id": verification_id.strip(),
        "organization_id": organization_id.strip(),
        "verified_by_user_id": verified_by_user_id.strip(),
        "verified_at": verified_at.isoformat(),
        "entries": tuple(_rehash_entry_payload(entry) for entry in entries),
        "all_ok": all_ok,
        "audit_event_hash": next_chain.audit_events[-1].event_hash,
    }
    return RehashVerificationReport(
        verification_id=verification_id.strip(),
        organization_id=organization_id.strip(),
        verified_by_user_id=verified_by_user_id.strip(),
        verified_at=verified_at,
        entries=entries,
        all_ok=all_ok,
        audit_chain=next_chain,
        report_hash=_canonical_sha256(payload),
    )


def open_tamper_review(
    *,
    review_id: str,
    verification_id: str,
    entry: RehashVerificationEntry,
    opened_by_user_id: str,
    opened_at: datetime,
    reason: str,
) -> TamperReviewRecord:
    for field_name, value in (
        ("review_id", review_id),
        ("verification_id", verification_id),
        ("opened_by_user_id", opened_by_user_id),
        ("reason", reason),
    ):
        _require_non_empty(field_name, value)
        _ensure_secret_free(value)
    _require_timezone(opened_at)
    if entry.ok:
        raise ValueError("tamper_review_requires_failed_verification")
    payload = {
        "review_id": review_id.strip(),
        "verification_id": verification_id.strip(),
        "evidence_id": entry.evidence_id,
        "status": TamperReviewStatus.OPEN.value,
        "opened_by_user_id": opened_by_user_id.strip(),
        "opened_at": opened_at.isoformat(),
        "reason": reason.strip(),
        "source_verification_hash": entry.verification_hash,
    }
    return TamperReviewRecord(
        review_id=review_id.strip(),
        verification_id=verification_id.strip(),
        evidence_id=entry.evidence_id,
        status=TamperReviewStatus.OPEN,
        opened_by_user_id=opened_by_user_id.strip(),
        opened_at=opened_at,
        reason=reason.strip(),
        source_verification_hash=entry.verification_hash,
        review_hash=_canonical_sha256(payload),
    )


def decide_retention_disposition(
    *,
    manifest: EvidenceArtifactManifest,
    action: RetentionAction,
    requested_by_user_id: str,
    requested_at: datetime,
    reason: str,
) -> RetentionDispositionDecision:
    _require_non_empty("requested_by_user_id", requested_by_user_id)
    _require_non_empty("reason", reason)
    _ensure_secret_free(requested_by_user_id)
    _ensure_secret_free(reason)
    _require_timezone(requested_at)
    if manifest.legal_hold or manifest.retention_class is RetentionClass.LEGAL_HOLD:
        allowed = False
        decision_reason = "legal_hold_prevents_disposal"
    else:
        allowed = True
        decision_reason = "retention_disposition_allowed"
    payload = {
        "evidence_id": manifest.evidence_id,
        "action": action.value,
        "allowed": allowed,
        "reason": decision_reason,
        "requested_by_user_id": requested_by_user_id.strip(),
        "requested_at": requested_at.isoformat(),
    }
    return RetentionDispositionDecision(
        evidence_id=manifest.evidence_id,
        action=action,
        allowed=allowed,
        reason=decision_reason,
        requested_by_user_id=requested_by_user_id.strip(),
        requested_at=requested_at,
        decision_hash=_canonical_sha256(payload),
    )


def build_export_manifest(
    *,
    export_manifest_id: str,
    attestation: EvidencePackageAttestation,
    manifests: tuple[EvidenceArtifactManifest, ...],
    artifact_verifications: tuple[EvidenceArtifactVerification, ...],
    destination_label: str,
    generated_by_user_id: str,
    generated_at: datetime,
) -> EvidencePackageExportManifest:
    for field_name, value in (
        ("export_manifest_id", export_manifest_id),
        ("destination_label", destination_label),
        ("generated_by_user_id", generated_by_user_id),
    ):
        _require_non_empty(field_name, value)
        _ensure_secret_free(value)
    _require_timezone(generated_at)
    evidence_ids = tuple(sorted(manifest.evidence_id for manifest in manifests))
    if evidence_ids != attestation.evidence_ids:
        raise ValueError("export_manifest_evidence_mismatch")
    _validate_verifications(evidence_ids, artifact_verifications)
    artifact_manifest_hashes = tuple(sorted(manifest.manifest_hash for manifest in manifests))
    artifact_verification_hashes = tuple(sorted(_verification_hash(verification) for verification in artifact_verifications))
    if artifact_manifest_hashes != attestation.artifact_manifest_hashes:
        raise ValueError("export_manifest_attestation_mismatch")
    payload = {
        "export_manifest_id": export_manifest_id.strip(),
        "attestation_id": attestation.attestation_id,
        "organization_id": attestation.organization_id,
        "destination_label": destination_label.strip(),
        "generated_by_user_id": generated_by_user_id.strip(),
        "generated_at": generated_at.isoformat(),
        "evidence_ids": evidence_ids,
        "custody_event_hashes": attestation.custody_event_hashes,
        "artifact_manifest_hashes": artifact_manifest_hashes,
        "artifact_verification_hashes": artifact_verification_hashes,
        "attestation_hash": attestation.attestation_hash,
    }
    return EvidencePackageExportManifest(
        export_manifest_id=export_manifest_id.strip(),
        attestation_id=attestation.attestation_id,
        organization_id=attestation.organization_id,
        destination_label=destination_label.strip(),
        generated_by_user_id=generated_by_user_id.strip(),
        generated_at=generated_at,
        evidence_ids=evidence_ids,
        custody_event_hashes=attestation.custody_event_hashes,
        artifact_manifest_hashes=artifact_manifest_hashes,
        artifact_verification_hashes=artifact_verification_hashes,
        attestation_hash=attestation.attestation_hash,
        export_manifest_hash=_canonical_sha256(payload),
    )


def _verify_one(store: LocalEvidenceArtifactStore, evidence_id: str) -> RehashVerificationEntry:
    _require_non_empty("evidence_id", evidence_id)
    try:
        verification = store.verify_artifact(evidence_id)
        manifest_id: str | None = verification.manifest_id
        ok = verification.ok
        reason = verification.reason
    except FileNotFoundError:
        manifest_id = None
        ok = False
        reason = "missing_evidence_manifest"
    payload = {
        "evidence_id": evidence_id.strip(),
        "manifest_id": manifest_id,
        "ok": ok,
        "reason": reason,
    }
    return RehashVerificationEntry(
        evidence_id=evidence_id.strip(),
        manifest_id=manifest_id,
        ok=ok,
        reason=reason,
        verification_hash=_canonical_sha256(payload),
    )


def _validate_manifests(organization_id: str, manifests: tuple[EvidenceArtifactManifest, ...]) -> None:
    seen: set[str] = set()
    for manifest in manifests:
        if manifest.organization_id != organization_id.strip():
            raise ValueError("attestation_organization_mismatch")
        if manifest.evidence_id in seen:
            raise ValueError("duplicate_attestation_evidence_id")
        seen.add(manifest.evidence_id)


def _validate_custody_events(
    organization_id: str,
    evidence_ids: tuple[str, ...],
    custody_events: tuple[EvidenceCustodyEvent, ...],
) -> None:
    if not custody_events:
        raise ValueError("custody_events_required")
    events_by_evidence: dict[str, set[CustodyEventKind]] = {evidence_id: set() for evidence_id in evidence_ids}
    for event in custody_events:
        if event.organization_id != organization_id.strip():
            raise ValueError("custody_event_organization_mismatch")
        if event.evidence_id not in events_by_evidence:
            raise ValueError("custody_event_evidence_mismatch")
        events_by_evidence[event.evidence_id].add(event.kind)
    for evidence_id, kinds in events_by_evidence.items():
        missing = REQUIRED_CUSTODY_EVENTS - kinds
        if missing:
            missing_label = ",".join(sorted(kind.value for kind in missing))
            raise ValueError(f"missing_custody_event:{evidence_id}:{missing_label}")


def _validate_verifications(
    evidence_ids: tuple[str, ...],
    verifications: tuple[EvidenceArtifactVerification, ...],
) -> None:
    if not verifications:
        raise ValueError("artifact_verifications_required")
    verification_ids = tuple(sorted(verification.evidence_id for verification in verifications))
    if verification_ids != evidence_ids:
        raise ValueError("artifact_verification_evidence_mismatch")
    for verification in verifications:
        if not verification.ok:
            raise ValueError(f"artifact_verification_failed:{verification.evidence_id}:{verification.reason}")


def _verification_hash(verification: EvidenceArtifactVerification) -> str:
    return _canonical_sha256(
        {
            "evidence_id": verification.evidence_id,
            "manifest_id": verification.manifest_id,
            "ok": verification.ok,
            "reason": verification.reason,
        }
    )


def _rehash_entry_payload(entry: RehashVerificationEntry) -> dict[str, object]:
    return {
        "evidence_id": entry.evidence_id,
        "manifest_id": entry.manifest_id,
        "ok": entry.ok,
        "reason": entry.reason,
        "verification_hash": entry.verification_hash,
    }


def _fingerprinted_details(details: Mapping[str, object]) -> dict[str, object]:
    return {
        str(key): hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()
        for key, value in details.items()
    }


def _canonical_sha256(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")


def _ensure_secret_free(value: str) -> None:
    try:
        assert_no_sensitive_output(value, RedactionArtifactClass.COMMAND_LOG)
    except ValueError as exc:
        raise ValueError("sensitive_attestation_output_forbidden") from exc
