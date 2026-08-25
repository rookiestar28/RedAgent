"""compat_110 immutable, separately approved VEX annotations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime


@dataclass(frozen=True, kw_only=True)
class VulnerabilityObservation:
    observation_id: str; component_id: str; advisory_id: str; passed: bool; observation_sha256: str


@dataclass(frozen=True, kw_only=True)
class VexAnnotation:
    annotation_id: str; observation_id: str; status: str; justification: str; requested_by: str; approved_by: str
    effective_at: datetime; expires_at: datetime; supersedes_annotation_id: str | None


@dataclass(frozen=True, kw_only=True)
class AnnotatedVulnerability:
    observation: VulnerabilityObservation; annotation: VexAnnotation; risk_state: str


def apply_vex(*, observation: VulnerabilityObservation, annotation: VexAnnotation, now: datetime) -> AnnotatedVulnerability:
    for value in (now, annotation.effective_at, annotation.expires_at):
        if value.tzinfo is None or value.utcoffset() is None: raise ValueError("artifact_time_invalid")
    if annotation.requested_by == annotation.approved_by: raise ValueError("artifact_vex_separation_required")
    if annotation.observation_id != observation.observation_id: raise ValueError("artifact_vex_scope_mismatch")
    if annotation.status not in {"not_affected", "affected", "fixed", "under_investigation"}: raise ValueError("artifact_vex_status_invalid")
    if not annotation.effective_at <= now < annotation.expires_at: raise ValueError("artifact_vex_inactive")
    if len(annotation.justification.strip()) < 20: raise ValueError("artifact_vex_justification_required")
    return AnnotatedVulnerability(observation=observation, annotation=annotation, risk_state=f"vex-{annotation.status.replace('_', '-')}")
