"""Immutable compat_111 ability, approval, lab, and authorization contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class AbilityPhase(str, Enum):
    PREPARE = "prepare"
    EXECUTE = "execute"
    TELEMETRY = "telemetry"
    CLEANUP = "cleanup"
    VERIFY = "verify"


@dataclass(frozen=True, kw_only=True)
class DetectionExpectation:
    strategy_id: str
    analytic_id: str
    event_schema: str
    collector_id: str

    def __post_init__(self) -> None:
        for value in (self.strategy_id, self.analytic_id, self.event_schema, self.collector_id):
            _identifier(value)


@dataclass(frozen=True, kw_only=True)
class AbilityManifest:
    ability_id: str
    revision: int
    attack_version: str
    attack_technique_id: str
    adapter_id: str
    adapter_sha256: str
    content_sha256: str
    platform: str
    phases: tuple[AbilityPhase, ...]
    detection: DetectionExpectation
    marker_relative_path: str
    marker_sha256: str
    timeout_seconds: int
    required_privileges: tuple[str, ...] = ()
    expected_artifacts: tuple[str, ...] = ("owned_marker",)
    network_allowed: bool = False
    subprocess_allowed: bool = False
    external_content_allowed: bool = False

    def __post_init__(self) -> None:
        for value in (self.ability_id, self.attack_version, self.attack_technique_id, self.adapter_id, self.platform):
            _identifier(value)
        for value in (self.adapter_sha256, self.content_sha256, self.marker_sha256):
            _sha(value)
        expected = tuple(AbilityPhase)
        if self.revision != 1 or self.phases != expected:
            raise ValueError("purple_ability_phases_invalid")
        if self.platform != "redagent-disposable-filesystem-lab" or self.marker_relative_path != "r111-file-stage-marker-v1.marker":
            raise ValueError("purple_ability_boundary_invalid")
        if not 1 <= self.timeout_seconds <= 10 or self.required_privileges or self.expected_artifacts != ("owned_marker",):
            raise ValueError("purple_ability_limits_invalid")
        if self.network_allowed or self.subprocess_allowed or self.external_content_allowed:
            raise ValueError("purple_external_execution_boundary_invalid")


@dataclass(frozen=True, kw_only=True)
class AbilityApproval:
    approval_id: str
    ability_id: str
    ability_sha256: str
    adapter_sha256: str
    lab_binding_id: str
    lab_snapshot_sha256: str
    requester_id: str
    approver_id: str
    executor_id: str
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.approval_id, self.ability_id, self.lab_binding_id, self.requester_id, self.approver_id, self.executor_id):
            _identifier(value)
        for value in (self.ability_sha256, self.adapter_sha256, self.lab_snapshot_sha256):
            _sha(value)
        _window(self.approved_at, self.expires_at)
        if len({self.requester_id, self.approver_id, self.executor_id}) != 3:
            raise ValueError("purple_approval_separation_invalid")


@dataclass(frozen=True, kw_only=True)
class LabBinding:
    binding_id: str
    target_id: str
    runner_id: str
    snapshot_sha256: str
    telemetry_collector_id: str
    disposable: bool
    production: bool
    egress_allowed: bool
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.binding_id, self.target_id, self.runner_id, self.telemetry_collector_id):
            _identifier(value)
        _sha(self.snapshot_sha256)
        _aware(self.expires_at)


@dataclass(frozen=True, kw_only=True)
class AbilityAuthorization:
    authorization_id: str
    policy_decision_id: str
    policy_revision: str
    roe_revision: str
    reservation_id: str
    lease_id: str
    kill_switch_id: str
    quota_id: str
    ability_sha256: str
    lab_snapshot_sha256: str
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.authorization_id, self.policy_decision_id, self.policy_revision, self.roe_revision,
                      self.reservation_id, self.lease_id, self.kill_switch_id, self.quota_id):
            _identifier(value)
        _sha(self.ability_sha256); _sha(self.lab_snapshot_sha256)
        _window(self.approved_at, self.expires_at)


def manifest_sha256(manifest: AbilityManifest) -> str:
    payload = asdict(manifest)
    payload["phases"] = [item.value for item in manifest.phases]
    return _digest(payload)


def _digest(payload: object) -> str:
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("purple_identifier_invalid")


def _sha(value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError("purple_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("purple_time_invalid")


def _window(start: datetime, end: datetime) -> None:
    _aware(start); _aware(end)
    if not start < end:
        raise ValueError("purple_time_window_invalid")
