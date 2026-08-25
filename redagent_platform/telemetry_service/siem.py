"""Pinned minimal OCSF 1.8.0 incident translation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum
import hashlib
import json

from redagent_platform.telemetry_service.contracts import SignalKind, TelemetryEnvelope


class IncidentActivity(IntEnum):
    CREATE = 1
    UPDATE = 2
    CLOSE = 3


class IncidentSeverity(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5


class IncidentStatus(IntEnum):
    UNKNOWN = 0
    NEW = 1
    IN_PROGRESS = 2
    RESOLVED = 3
    CLOSED = 4


@dataclass(frozen=True, kw_only=True)
class OcsfDelivery:
    destination_alias: str
    event_id: str
    idempotency_key: str
    payload_sha256: str
    payload: dict[str, object]


def map_incident_to_ocsf(
    envelope: TelemetryEnvelope,
    *,
    severity: IncidentSeverity,
    activity: IncidentActivity,
    status: IncidentStatus,
    assignee_id: str | None,
) -> dict[str, object]:
    if envelope.kind is not SignalKind.EVENT:
        raise ValueError("ocsf_incident_event_required")
    if assignee_id is not None and not _safe_id(assignee_id):
        raise ValueError("ocsf_assignee_invalid")
    if not isinstance(severity, IncidentSeverity) or not isinstance(activity, IncidentActivity):
        raise ValueError("ocsf_incident_classification_invalid")
    if not isinstance(status, IncidentStatus):
        raise ValueError("ocsf_incident_status_invalid")
    payload: dict[str, object] = {
        "activity_id": int(activity),
        "category_uid": 2,
        "class_uid": 2005,
        "type_uid": 200500 + int(activity),
        "severity_id": int(severity),
        "status_id": int(status),
        "time": int(envelope.occurred_at.timestamp() * 1000),
        "metadata": {
            "version": "1.8.0",
            "profiles": ["incident"],
            "product": {
                "name": "RedAgent", "version": envelope.service_version,
                "uid": envelope.service_instance_id,
            },
            "original_event_uid": envelope.event_id,
            "correlation_uid": envelope.correlation_id,
        },
        "organization": {"uid": envelope.tenant_id},
        "trace": {"uid": envelope.trace_id},
        "finding_info_list": [{"uid": envelope.event_id, "title": envelope.reason_code}],
    }
    if assignee_id is not None:
        payload["assignee"] = {"uid": assignee_id}
    return payload


def build_ocsf_delivery(
    envelope: TelemetryEnvelope,
    *,
    destination_alias: str,
    severity: IncidentSeverity,
    activity: IncidentActivity,
    status: IncidentStatus,
    assignee_id: str | None,
) -> OcsfDelivery:
    if destination_alias not in {"local-siem", "enterprise-siem-primary"}:
        raise ValueError("siem_destination_alias_invalid")
    payload = map_incident_to_ocsf(
        envelope, severity=severity, activity=activity, status=status,
        assignee_id=assignee_id,
    )
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    if len(encoded) > 16 * 1024:
        raise ValueError("ocsf_payload_too_large")
    digest = hashlib.sha256(encoded).hexdigest()
    return OcsfDelivery(
        destination_alias=destination_alias, event_id=envelope.event_id,
        idempotency_key=f"ocsf:{envelope.event_id}:{digest[:16]}",
        payload_sha256=digest, payload=payload,
    )


def _safe_id(value: object) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 128 and all(
        char.isalnum() or char in "._:-" for char in value
    )
