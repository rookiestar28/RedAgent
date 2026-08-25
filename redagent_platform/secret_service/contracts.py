"""Closed metadata and memory-only material contracts for R098."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
import re
from types import MappingProxyType
from typing import Iterator, Mapping


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_MATERIAL_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_MAX_MATERIAL_FIELDS = 8
_MAX_MATERIAL_FIELD_BYTES = 16_384
_MAX_MATERIAL_TOTAL_BYTES = 65_536


class SecretReferenceKind(str, Enum):
    DYNAMIC_DATABASE = "dynamic_database"
    DYNAMIC_CLOUD = "dynamic_cloud"
    OPAQUE_SESSION = "opaque_session"


class SecretReferenceStatus(str, Enum):
    ACTIVE = "active"
    ROTATION_DUE = "rotation_due"
    REVOKED = "revoked"
    EXPIRED = "expired"


@dataclass(frozen=True, slots=True)
class SecretReference:
    tenant_id: str
    reference_id: str
    engagement_id: str
    owner_user_id: str
    kind: SecretReferenceKind
    provider_alias: str
    role_reference: str
    allowed_capabilities: tuple[str, ...]
    allowed_permissions: tuple[str, ...]
    created_at: datetime
    expires_at: datetime
    rotation_due_at: datetime
    status: SecretReferenceStatus
    redaction_label: str

    def __post_init__(self) -> None:
        for name in ("tenant_id", "reference_id", "engagement_id", "owner_user_id", "provider_alias"):
            _identifier(name, getattr(self, name))
        _reference("role_reference", self.role_reference)
        _reference("redaction_label", self.redaction_label)
        _closed_values("allowed_capabilities", self.allowed_capabilities)
        _closed_values("allowed_permissions", self.allowed_permissions)
        for value in (self.created_at, self.expires_at, self.rotation_due_at):
            _timezone(value)
        if not isinstance(self.kind, SecretReferenceKind) or not isinstance(self.status, SecretReferenceStatus):
            raise ValueError("secret_reference_enum_invalid")
        if not self.created_at < self.rotation_due_at <= self.expires_at:
            raise ValueError("secret_reference_lifetime_invalid")


@dataclass(frozen=True, slots=True)
class WorkloadClient:
    tenant_id: str
    client_id: str
    job_id: str
    capability: str
    attestation_fingerprint: str
    expires_at: datetime
    revoked_at: datetime | None

    def __post_init__(self) -> None:
        for name in ("tenant_id", "client_id", "job_id", "capability"):
            _identifier(name, getattr(self, name))
        if not _FINGERPRINT.fullmatch(self.attestation_fingerprint):
            raise ValueError("workload_attestation_fingerprint_invalid")
        _timezone(self.expires_at)
        if self.revoked_at is not None:
            _timezone(self.revoked_at)


@dataclass(frozen=True, slots=True)
class LeaseIssueRequest:
    tenant_id: str
    lease_id: str
    reference_id: str
    engagement_id: str
    job_id: str
    workload_client_id: str
    capability: str
    requested_permissions: tuple[str, ...]
    requested_at: datetime
    ttl_seconds: int
    job_deadline: datetime
    policy_expires_at: datetime
    roe_expires_at: datetime
    policy_reference: str
    roe_version_id: str
    idempotency_key: str

    def __post_init__(self) -> None:
        for name in (
            "tenant_id", "lease_id", "reference_id", "engagement_id", "job_id",
            "workload_client_id", "capability", "roe_version_id", "idempotency_key",
        ):
            _identifier(name, getattr(self, name))
        _reference("policy_reference", self.policy_reference)
        if not self.requested_permissions:
            raise ValueError("lease_permissions_required")
        _closed_values("requested_permissions", self.requested_permissions)
        for value in (self.requested_at, self.job_deadline, self.policy_expires_at, self.roe_expires_at):
            _timezone(value)
        if isinstance(self.ttl_seconds, bool) or not 1 <= self.ttl_seconds <= 900:
            raise ValueError("lease_ttl_invalid")


def effective_lease_expiry(
    reference: SecretReference,
    workload: WorkloadClient,
    request: LeaseIssueRequest,
    *,
    provider_max_ttl_seconds: int,
) -> datetime:
    if request.tenant_id != reference.tenant_id or request.tenant_id != workload.tenant_id:
        raise ValueError("lease_tenant_mismatch")
    if request.reference_id != reference.reference_id or request.engagement_id != reference.engagement_id:
        raise ValueError("lease_reference_scope_mismatch")
    if request.workload_client_id != workload.client_id or request.job_id != workload.job_id:
        raise ValueError("lease_workload_scope_mismatch")
    if request.capability != workload.capability or request.capability not in reference.allowed_capabilities:
        raise ValueError("lease_capability_not_allowed")
    if not request.requested_permissions:
        raise ValueError("lease_permissions_required")
    if not set(request.requested_permissions).issubset(set(reference.allowed_permissions)):
        raise ValueError("lease_permission_not_allowed")
    if reference.status is not SecretReferenceStatus.ACTIVE:
        raise ValueError("secret_reference_not_active")
    if workload.revoked_at is not None:
        raise ValueError("workload_client_revoked")
    if isinstance(provider_max_ttl_seconds, bool) or not 1 <= provider_max_ttl_seconds <= 86_400:
        raise ValueError("provider_max_ttl_invalid")
    requested_expiry = request.requested_at + timedelta(seconds=request.ttl_seconds)
    provider_expiry = request.requested_at + timedelta(seconds=provider_max_ttl_seconds)
    expiry = min(
        requested_expiry,
        provider_expiry,
        reference.expires_at,
        reference.rotation_due_at,
        workload.expires_at,
        request.job_deadline,
        request.policy_expires_at,
        request.roe_expires_at,
    )
    if request.requested_at >= expiry:
        raise ValueError("lease_governing_deadline_expired")
    return expiry


class SecretMaterial:
    """Single-consumer bounded buffers; best-effort clearing, never serialization."""

    __slots__ = ("_buffers", "_cleared", "_consumed")

    def __init__(self, fields: Mapping[str, bytes | bytearray]) -> None:
        if not isinstance(fields, Mapping) or not 1 <= len(fields) <= _MAX_MATERIAL_FIELDS:
            raise ValueError("secret_material_fields_invalid")
        total = 0
        for name, value in fields.items():
            if not isinstance(name, str) or not _MATERIAL_NAME.fullmatch(name):
                raise ValueError("secret_material_field_name_invalid")
            if not isinstance(value, (bytes, bytearray)) or not 1 <= len(value) <= _MAX_MATERIAL_FIELD_BYTES:
                raise ValueError("secret_material_field_value_invalid")
            total += len(value)
        if total > _MAX_MATERIAL_TOTAL_BYTES:
            raise ValueError("secret_material_total_size_invalid")
        buffers = {
            name: value if isinstance(value, bytearray) else bytearray(value)
            for name, value in fields.items()
        }
        self._buffers = buffers
        self._cleared = False
        self._consumed = False

    @property
    def cleared(self) -> bool:
        return self._cleared

    @contextmanager
    def expose_once(self) -> Iterator[Mapping[str, memoryview]]:
        if self._consumed:
            raise RuntimeError("secret_material_already_consumed")
        self._consumed = True
        views = MappingProxyType({name: memoryview(value) for name, value in self._buffers.items()})
        try:
            yield views
        finally:
            for view in views.values():
                view.release()
            for buffer in self._buffers.values():
                buffer[:] = b"\x00" * len(buffer)
            self._cleared = True

    def __repr__(self) -> str:
        return f"<SecretMaterial redacted fields={len(self._buffers)} consumed={self._consumed}>"

    def __reduce_ex__(self, protocol: int):
        raise TypeError("secret_material_serialization_forbidden")


class ProviderLeaseEnvelope:
    __slots__ = ("provider_lease_reference", "duration_seconds", "renewable", "material")

    def __init__(
        self,
        *,
        provider_lease_reference: str,
        duration_seconds: int,
        renewable: bool,
        material: SecretMaterial,
    ) -> None:
        _reference("provider_lease_reference", provider_lease_reference)
        if isinstance(duration_seconds, bool) or not 1 <= duration_seconds <= 86_400:
            raise ValueError("provider_lease_duration_invalid")
        if not isinstance(renewable, bool) or not isinstance(material, SecretMaterial):
            raise ValueError("provider_lease_envelope_invalid")
        self.provider_lease_reference = provider_lease_reference
        self.duration_seconds = duration_seconds
        self.renewable = renewable
        self.material = material

    def __repr__(self) -> str:
        return (
            f"<ProviderLeaseEnvelope reference={self.provider_lease_reference!r} "
            f"duration_seconds={self.duration_seconds} renewable={self.renewable} material=<redacted>>"
        )

    def __reduce_ex__(self, protocol: int):
        raise TypeError("provider_lease_serialization_forbidden")


def _identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _reference(name: str, value: str) -> None:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _closed_values(name: str, values: tuple[str, ...]) -> None:
    if not isinstance(values, tuple) or not values or len(values) > 32 or len(set(values)) != len(values):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value)


def _timezone(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
