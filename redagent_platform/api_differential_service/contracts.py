"""Immutable compat_106 OpenAPI authorization-differential contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re
from types import MappingProxyType
from typing import Mapping


SCHEMATHESIS_VERSION = "4.22.4"
GATEWAY_ORIGIN = "http://redagent-r106-gateway:8080"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


class ApiDifferentialProfileId(str, Enum):
    STANDARD = "openapi-authorization-differential-v1"


class IdentityState(str, Enum):
    ANONYMOUS = "anonymous"
    OWNER = "owner"
    PEER = "peer"
    TENANT_ADMIN = "tenant_admin"
    OTHER_TENANT = "other_tenant"
    EXPIRED = "expired"
    REVOKED = "revoked"
    OWNERSHIP_TRANSFERRED = "ownership_transferred"


class IdentityRelation(str, Enum):
    CROSS_OWNER = "cross_owner"
    CROSS_TENANT = "cross_tenant"
    LOWER_ROLE = "lower_role"
    EXPIRED_SESSION = "expired_session"
    REVOKED_SESSION = "revoked_session"
    PROPERTY_RESTRICTED = "property_restricted"


class OperationRisk(str, Enum):
    READ = "read"
    ADMIN_READ = "admin_read"
    CREATE_OWNED = "create_owned"
    UPDATE_OWNED = "update_owned"
    DELETE_OWNED = "delete_owned"


@dataclass(frozen=True, kw_only=True)
class ApiDifferentialProfile:
    profile_id: ApiDifferentialProfileId
    engine_version: str
    phases: tuple[str, ...]
    max_examples: int
    max_stateful_steps: int
    max_requests: int
    request_rate_per_second: int
    concurrency: int
    timeout_seconds: int
    request_body_bytes: int
    response_body_bytes: int
    total_data_bytes: int
    unexpected_methods_allowed: bool
    callback_allowed: bool
    external_refs_allowed: bool


@dataclass(frozen=True, kw_only=True)
class ApiDifferentialAuthorization:
    tenant_id: str
    policy_decision_id: str
    policy_revision: str
    roe_version_id: str
    approved_profile_ids: tuple[ApiDifferentialProfileId, ...]
    approved_spec_sha256: str
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.tenant_id, self.policy_decision_id, self.policy_revision, self.roe_version_id):
            _identifier(value)
        _sha(self.approved_spec_sha256)
        _aware(self.approved_at)
        _aware(self.expires_at)
        if not self.approved_at < self.expires_at:
            raise ValueError("api_authorization_expiry_invalid")


@dataclass(frozen=True, kw_only=True)
class ApiDifferentialTargetBinding:
    target_id: str
    attestation_sha256: str
    fixture_sha256: str
    endpoint: str
    network_id: str
    non_production: bool
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.target_id)
        _sha(self.attestation_sha256)
        _sha(self.fixture_sha256)
        _aware(self.issued_at)
        _aware(self.expires_at)
        if (
            self.endpoint != GATEWAY_ORIGIN
            or self.network_id != "redagent-r106-gateway-target"
            or self.non_production is not True
            or not self.issued_at < self.expires_at
        ):
            raise ValueError("api_target_binding_invalid")


def certified_profiles() -> Mapping[ApiDifferentialProfileId, ApiDifferentialProfile]:
    return MappingProxyType({
        ApiDifferentialProfileId.STANDARD: ApiDifferentialProfile(
            profile_id=ApiDifferentialProfileId.STANDARD,
            engine_version=SCHEMATHESIS_VERSION,
            phases=("examples", "coverage", "fuzzing", "stateful"),
            max_examples=16,
            max_stateful_steps=8,
            max_requests=64,
            request_rate_per_second=2,
            concurrency=1,
            timeout_seconds=60,
            request_body_bytes=16 * 1024,
            response_body_bytes=64 * 1024,
            total_data_bytes=2 * 1024 * 1024,
            unexpected_methods_allowed=False,
            callback_allowed=False,
            external_refs_allowed=False,
        ),
    })


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("api_identifier_invalid")


def _sha(value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError("api_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("api_time_invalid")
