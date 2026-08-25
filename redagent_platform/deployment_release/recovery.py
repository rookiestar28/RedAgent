"""Component-aware backup catalog and deterministic recovery drills."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum
import hashlib


class RecoveryComponent(str, Enum):
    POSTGRESQL = "postgresql"
    TEMPORAL = "temporal"
    OPENBAO = "openbao"
    OBJECT_STORE = "object_store"
    IDENTITY = "identity"
    POLICY = "policy"
    APPLICATION_CONFIG = "application_config"


class DrillEvent(str, Enum):
    INTEGRITY_VERIFIED = "integrity_verified"
    ISOLATED_RESTORE_COMPLETED = "isolated_restore_completed"
    SEMANTIC_VERIFIED = "semantic_verified"
    AUDIT_VERIFIED = "audit_verified"
    CLEANUP_VERIFIED = "cleanup_verified"


@dataclass(frozen=True, kw_only=True)
class BackupArtifact:
    component: RecoveryComponent
    artifact_id: str
    expected_sha256: str
    observed_sha256: str
    encrypted: bool
    immutable: bool
    key_reference: str
    kind: str


@dataclass(frozen=True, kw_only=True)
class RecoveryCatalog:
    catalog_id: str
    created_at: datetime
    rpo_minutes: int
    rto_minutes: int
    artifacts: tuple[BackupArtifact, ...]


@dataclass(frozen=True, kw_only=True)
class RecoveryValidation:
    accepted: bool
    gaps: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class RestorePlan:
    catalog_id: str
    steps: tuple[RecoveryComponent, ...]
    isolated_environment_required: bool
    semantic_verification_required: bool
    audit_verification_required: bool
    cleanup_required: bool
    rpo_minutes: int
    rto_minutes: int
    production_qualified: bool = False


@dataclass(frozen=True, kw_only=True)
class RecoveryDrill:
    catalog_id: str
    expected_events: tuple[DrillEvent, ...]
    next_event_index: int
    evidence_sha256s: tuple[str, ...]
    started_at: datetime
    completed: bool
    production_qualified: bool = False


_ORDER = (
    RecoveryComponent.POSTGRESQL,
    RecoveryComponent.OPENBAO,
    RecoveryComponent.OBJECT_STORE,
    RecoveryComponent.IDENTITY,
    RecoveryComponent.POLICY,
    RecoveryComponent.APPLICATION_CONFIG,
    RecoveryComponent.TEMPORAL,
)
_EVENTS = tuple(DrillEvent)


def build_recovery_catalog(*, created_at: datetime) -> RecoveryCatalog:
    _aware(created_at)
    artifacts = tuple(
        BackupArtifact(
            component=component,
            artifact_id=f"r116-{component.value}-backup",
            expected_sha256=hashlib.sha256(f"r116:{component.value}".encode()).hexdigest(),
            observed_sha256=hashlib.sha256(f"r116:{component.value}".encode()).hexdigest(),
            encrypted=True,
            immutable=True,
            key_reference=f"opaque-kms://r116/{component.value}",
            kind=_kind(component),
        )
        for component in RecoveryComponent
    )
    return RecoveryCatalog(
        catalog_id="r116-synthetic-recovery-v1",
        created_at=created_at,
        rpo_minutes=60,
        rto_minutes=240,
        artifacts=artifacts,
    )


def validate_recovery_catalog(catalog: RecoveryCatalog, *, now: datetime) -> RecoveryValidation:
    _aware(now)
    _aware(catalog.created_at)
    gaps: list[str] = []
    observed = {item.component for item in catalog.artifacts}
    for component in RecoveryComponent:
        if component not in observed:
            gaps.append(f"missing_backup_component:{component.value}")
    if now < catalog.created_at or (now - catalog.created_at).total_seconds() > catalog.rpo_minutes * 60:
        gaps.append("backup_set_outside_rpo")
    if catalog.rpo_minutes <= 0 or catalog.rto_minutes <= 0:
        gaps.append("recovery_objective_invalid")
    seen: set[RecoveryComponent] = set()
    for artifact in catalog.artifacts:
        if artifact.component in seen:
            gaps.append(f"duplicate_backup_component:{artifact.component.value}")
        seen.add(artifact.component)
        if artifact.expected_sha256 != artifact.observed_sha256:
            gaps.append(f"backup_digest_mismatch:{artifact.component.value}")
        if not artifact.encrypted or not artifact.key_reference.startswith("opaque-kms://"):
            gaps.append(f"encrypted_backup_required:{artifact.component.value}")
        if not artifact.immutable:
            gaps.append(f"immutable_backup_required:{artifact.component.value}")
        if artifact.kind != _kind(artifact.component):
            gaps.append(f"backup_kind_invalid:{artifact.component.value}")
    return RecoveryValidation(accepted=not gaps, gaps=tuple(gaps))


def build_restore_plan(catalog: RecoveryCatalog, *, now: datetime) -> RestorePlan:
    validation = validate_recovery_catalog(catalog, now=now)
    if not validation.accepted:
        raise ValueError("recovery_catalog_invalid:" + ",".join(validation.gaps))
    return RestorePlan(
        catalog_id=catalog.catalog_id,
        steps=_ORDER,
        isolated_environment_required=True,
        semantic_verification_required=True,
        audit_verification_required=True,
        cleanup_required=True,
        rpo_minutes=catalog.rpo_minutes,
        rto_minutes=catalog.rto_minutes,
    )


def start_recovery_drill(plan: RestorePlan, *, started_at: datetime) -> RecoveryDrill:
    _aware(started_at)
    if not all(
        (
            plan.isolated_environment_required,
            plan.semantic_verification_required,
            plan.audit_verification_required,
            plan.cleanup_required,
        )
    ):
        raise ValueError("recovery_drill_controls_required")
    return RecoveryDrill(
        catalog_id=plan.catalog_id,
        expected_events=_EVENTS,
        next_event_index=0,
        evidence_sha256s=(),
        started_at=started_at,
        completed=False,
    )


def advance_recovery_drill(
    drill: RecoveryDrill,
    event: DrillEvent,
    *,
    evidence_sha256: str,
    occurred_at: datetime,
) -> RecoveryDrill:
    _aware(occurred_at)
    if occurred_at < drill.started_at:
        raise ValueError("recovery_drill_time_invalid")
    if len(evidence_sha256) != 64 or any(char not in "0123456789abcdef" for char in evidence_sha256):
        raise ValueError("recovery_drill_evidence_invalid")
    if drill.completed or drill.expected_events[drill.next_event_index] is not event:
        raise ValueError("recovery_drill_event_out_of_order")
    next_index = drill.next_event_index + 1
    return replace(
        drill,
        next_event_index=next_index,
        evidence_sha256s=(*drill.evidence_sha256s, evidence_sha256),
        completed=next_index == len(drill.expected_events),
    )


def _kind(component: RecoveryComponent) -> str:
    return {
        RecoveryComponent.POSTGRESQL: "base-backup-wal-manifest",
        RecoveryComponent.TEMPORAL: "application-consistent-persistence-backup",
        RecoveryComponent.OPENBAO: "raft-snapshot-unseal-custody-audit-config",
        RecoveryComponent.OBJECT_STORE: "versioned-retained-replicated-object-catalog",
        RecoveryComponent.IDENTITY: "encrypted-realm-and-client-configuration",
        RecoveryComponent.POLICY: "signed-policy-bundle",
        RecoveryComponent.APPLICATION_CONFIG: "encrypted-versioned-application-config",
    }[component]


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("recovery_time_timezone_required")
