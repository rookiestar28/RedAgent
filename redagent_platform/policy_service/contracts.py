"""Closed canonical policy input and decision contracts for R099."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Mapping, Never, SupportsIndex
import unicodedata


POLICY_DECISION_CONTRACT_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,99}$")
_ALLOWED_ATTRIBUTES = frozenset(
    {
        "active_revision",
        "approver_id",
        "artifact_class",
        "artifact_status",
        "capability_status",
        "classification",
        "creator_id",
        "current_gate",
        "dispatch_blocked",
        "expected_version",
        "identity_generation",
        "job_status",
        "jit_status",
        "lease_state",
        "legal_hold",
        "membership_generation",
        "manifest_state",
        "orchestration_revision",
        "permission_count",
        "permission_digest",
        "purpose",
        "reference_status",
        "registration_state",
        "renewable",
        "resource_version",
        "revoke_pending",
        "roe_status",
        "runner_generation",
        "sandbox_status",
        "cleanup_required",
        "workload_client_status",
        # CRITICAL: keep authority inputs metadata-only; arbitrary values can bypass the policy schema boundary.
        "campaign_authority_sha256",
        "campaign_authority_version",
        "campaign_capability_id",
        "campaign_credential_class",
        "campaign_data_access_class",
        "campaign_effect_class",
        "campaign_environment_class",
        "campaign_kill_switch_epoch",
        "campaign_lifecycle_epoch",
        "campaign_lifecycle_state",
        "campaign_residual_budget_sha256",
        "campaign_target_id",
    }
)


class PolicyBoundary(str, Enum):
    API = "api"
    WORKFLOW = "workflow"
    EVIDENCE = "evidence"
    SECRET = "secret"  # pragma: allowlist secret
    RUNNER = "runner"


class PolicyObligation(str, Enum):
    AUDIT = "audit"
    REQUIRE_EXPECTED_VERSION = "require_expected_version"
    REQUIRE_DISTINCT_APPROVER = "require_distinct_approver"
    BLOCK_DISPATCH = "block_dispatch"
    EXACT_REVOKE = "exact_revoke"


@dataclass(frozen=True, slots=True)
class PolicyDecisionInput:
    boundary: PolicyBoundary
    action: str
    tenant_id: str
    subject_id: str
    roles: tuple[str, ...]
    permissions: tuple[str, ...]
    resource_type: str
    resource_id: str
    policy_reference: str
    roe_version_id: str | None
    correlation_id: str
    requested_at: datetime
    attributes: Mapping[str, object]

    def __post_init__(self) -> None:
        if not isinstance(self.boundary, PolicyBoundary):
            raise ValueError("policy_boundary_invalid")
        for value in (
            self.action,
            self.tenant_id,
            self.subject_id,
            self.resource_type,
            self.resource_id,
            self.correlation_id,
        ):
            _identifier(value)
        _reference(self.policy_reference)
        if self.roe_version_id is not None:
            _identifier(self.roe_version_id)
        _closed_identifiers("roles", self.roles)
        _closed_identifiers("permissions", self.permissions)
        _timezone(self.requested_at)
        if not isinstance(self.attributes, dict) or len(self.attributes) > 32:
            raise ValueError("policy_attributes_invalid")
        for key, value in self.attributes.items():
            if key not in _ALLOWED_ATTRIBUTES:
                raise ValueError("policy_attribute_unknown")
            _attribute_value(key, value)
        object.__setattr__(self, "attributes", MappingProxyType(dict(self.attributes)))


@dataclass(frozen=True, slots=True, repr=False)
class PolicyDecision:
    decision_id: str
    bundle_revision: str
    input_hash: str
    allowed: bool
    reason_code: str
    obligations: tuple[PolicyObligation, ...]
    issued_at: datetime
    valid_until: datetime

    def __post_init__(self) -> None:
        _identifier(self.decision_id)
        _identifier(self.bundle_revision)
        if not _HASH.fullmatch(self.input_hash):
            raise ValueError("policy_input_hash_invalid")
        if not isinstance(self.allowed, bool) or not _REASON.fullmatch(self.reason_code):
            raise ValueError("policy_decision_result_invalid")
        if (
            not isinstance(self.obligations, tuple)
            or not self.obligations
            or len(self.obligations) > len(PolicyObligation)
            or len(set(self.obligations)) != len(self.obligations)
            or any(not isinstance(item, PolicyObligation) for item in self.obligations)
        ):
            raise ValueError("policy_obligations_invalid")
        _timezone(self.issued_at)
        _timezone(self.valid_until)
        if not self.issued_at < self.valid_until <= self.issued_at + timedelta(minutes=5):
            raise ValueError("policy_decision_lifetime_invalid")

    def assert_current(self, request: PolicyDecisionInput, *, required_revision: str, now: datetime) -> None:
        _identifier(required_revision)
        _timezone(now)
        if self.bundle_revision != required_revision:
            raise ValueError("policy_bundle_revision_mismatch")
        if self.input_hash != policy_input_hash(request):
            raise ValueError("policy_input_hash_mismatch")
        if not self.issued_at <= now < self.valid_until:
            raise ValueError("policy_decision_expired")

    def __repr__(self) -> str:
        return (
            f"<PolicyDecision id={self.decision_id!r} revision={self.bundle_revision!r} "
            f"allowed={self.allowed} reason={self.reason_code!r}>"
        )

    def __reduce_ex__(self, protocol: SupportsIndex) -> Never:
        raise TypeError("policy_decision_serialization_forbidden")


def canonical_policy_input(request: PolicyDecisionInput) -> bytes:
    payload = {
        "schema_version": POLICY_DECISION_CONTRACT_VERSION,
        "boundary": request.boundary.value,
        "action": request.action,
        "tenant_id": request.tenant_id,
        "subject_id": request.subject_id,
        "roles": sorted(request.roles),
        "permissions": sorted(request.permissions),
        "resource_type": request.resource_type,
        "resource_id": request.resource_id,
        "policy_reference": request.policy_reference,
        "roe_version_id": request.roe_version_id,
        "correlation_id": request.correlation_id,
        "requested_at": request.requested_at.isoformat(),
        "attributes": dict(request.attributes),
    }
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode(
        "utf-8"
    )


def policy_input_hash(request: PolicyDecisionInput) -> str:
    return hashlib.sha256(canonical_policy_input(request)).hexdigest()


def _identifier(value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value) or unicodedata.normalize("NFC", value) != value:
        raise ValueError("policy_identifier_invalid")


def _reference(value: str) -> None:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ValueError("policy_reference_invalid")


def _closed_identifiers(name: str, values: tuple[str, ...]) -> None:
    if not isinstance(values, tuple) or not values or len(values) > 64 or len(set(values)) != len(values):
        raise ValueError(f"policy_{name}_invalid")
    for value in values:
        _identifier(value)


def _attribute_value(key: str, value: object) -> None:
    if isinstance(value, bool):
        return
    if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 2_147_483_647:
        return
    if isinstance(value, str) and len(value) <= 200 and _REFERENCE.fullmatch(value):
        return
    raise ValueError(f"policy_attribute_value_invalid:{key}")


def _timezone(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("policy_timezone_required")
