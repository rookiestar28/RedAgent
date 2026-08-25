"""Fail-closed canonical incident state transitions."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime
from enum import Enum


class IncidentState(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    CONTAINED = "contained"
    RECOVERED = "recovered"
    REVIEWED = "reviewed"
    CLOSED = "closed"


class IncidentAction(str, Enum):
    ASSIGN = "assign"
    ACKNOWLEDGE = "acknowledge"
    PRESERVE_EVIDENCE = "preserve_evidence"
    VERIFY_CONTAINMENT = "verify_containment"
    MARK_CONTAINED = "mark_contained"
    MARK_RECOVERED = "mark_recovered"
    COMPLETE_REVIEW = "complete_review"
    CLOSE = "close"


@dataclass(frozen=True, kw_only=True)
class IncidentSnapshot:
    incident_id: str
    tenant_id: str
    severity: str
    state: IncidentState
    opened_by: str
    assigned_to: str | None
    acknowledged_by: str | None
    contained_by: str | None
    recovered_by: str | None
    reviewed_by: str | None
    evidence_preserved: bool
    containment_verified: bool
    version: int


def apply_incident_action(
    incident: IncidentSnapshot,
    *,
    action: IncidentAction,
    actor_id: str,
    expected_version: int,
    occurred_at: datetime,
    assignee_id: str | None = None,
) -> IncidentSnapshot:
    if expected_version != incident.version:
        raise ValueError("incident_version_conflict")
    if not _safe_id(actor_id) or occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
        raise ValueError("incident_action_invalid")
    version = incident.version + 1
    if action is IncidentAction.ASSIGN and incident.state in {
        IncidentState.OPEN, IncidentState.ACKNOWLEDGED,
    }:
        if not _safe_id(assignee_id):
            raise ValueError("incident_assignee_invalid")
        return replace(incident, assigned_to=assignee_id, version=version)
    if action is IncidentAction.ACKNOWLEDGE and incident.state is IncidentState.OPEN:
        return replace(
            incident, state=IncidentState.ACKNOWLEDGED,
            acknowledged_by=actor_id, assigned_to=incident.assigned_to or actor_id,
            version=version,
        )
    if action is IncidentAction.PRESERVE_EVIDENCE and incident.state is IncidentState.ACKNOWLEDGED:
        return replace(incident, evidence_preserved=True, version=version)
    if action is IncidentAction.VERIFY_CONTAINMENT and incident.state is IncidentState.ACKNOWLEDGED:
        if not incident.evidence_preserved:
            raise ValueError("incident_evidence_preservation_required")
        return replace(incident, containment_verified=True, version=version)
    if action is IncidentAction.MARK_CONTAINED and incident.state is IncidentState.ACKNOWLEDGED:
        if not incident.evidence_preserved:
            raise ValueError("incident_evidence_preservation_required")
        if not incident.containment_verified:
            raise ValueError("incident_containment_receipt_required")
        return replace(incident, state=IncidentState.CONTAINED, contained_by=actor_id, version=version)
    if action is IncidentAction.MARK_RECOVERED and incident.state is IncidentState.CONTAINED:
        if actor_id in {incident.opened_by, incident.contained_by}:
            raise ValueError("incident_recovery_separation_required")
        return replace(incident, state=IncidentState.RECOVERED, recovered_by=actor_id, version=version)
    if action is IncidentAction.COMPLETE_REVIEW and incident.state is IncidentState.RECOVERED:
        if actor_id in {incident.opened_by, incident.contained_by, incident.recovered_by}:
            raise ValueError("incident_review_separation_required")
        return replace(incident, state=IncidentState.REVIEWED, reviewed_by=actor_id, version=version)
    if action is IncidentAction.CLOSE and incident.state is IncidentState.REVIEWED:
        if actor_id == incident.reviewed_by:
            raise ValueError("incident_close_separation_required")
        return replace(incident, state=IncidentState.CLOSED, version=version)
    raise ValueError("incident_transition_invalid")


def _safe_id(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128 and all(
        char.isalnum() or char in "._:-" for char in value
    )
