"""Immutable compat_108 provider identity, operation, profile, and authorization contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ProviderKind(str, Enum):
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"


class DataClass(str, Enum):
    RESOURCE_METADATA = "resource_metadata"
    SECURITY_CONFIGURATION = "security_configuration"
    IDENTITY_RELATIONSHIP = "identity_relationship"
    DATA_PLANE = "data_plane"
    SENSITIVE_VALUE = "sensitive_value"


@dataclass(frozen=True, kw_only=True)
class ProviderIdentity:
    provider: ProviderKind
    tenant: str
    parent: str | None = None

    def __post_init__(self) -> None:
        _identifier(self.tenant)
        if self.parent is not None:
            _identifier(self.parent)


@dataclass(frozen=True, kw_only=True)
class OperationManifest:
    operation_id: str
    action: str
    resource_scope: str
    data_class: DataClass
    mutation: bool
    paginated: bool
    page_cost: int

    def __post_init__(self) -> None:
        _identifier(self.operation_id)
        if not self.action.strip() or len(self.action) > 200 or not self.resource_scope.strip():
            raise ValueError("cloud_operation_invalid")
        if not isinstance(self.page_cost, int) or isinstance(self.page_cost, bool) or self.page_cost < 1:
            raise ValueError("cloud_operation_invalid")


@dataclass(frozen=True, kw_only=True)
class ProviderProfile:
    profile_id: str
    provider: ProviderKind
    enabled: bool
    emulator_only: bool
    expected_identity: ProviderIdentity
    operations: tuple[OperationManifest, ...]
    max_api_calls: int
    max_pages: int
    max_resources: int
    max_response_bytes: int
    timeout_seconds: int
    allow_redirects: bool
    allow_proxies: bool
    allow_ambient_credentials: bool

    def __post_init__(self) -> None:
        _identifier(self.profile_id)
        if self.expected_identity.provider is not self.provider or not self.operations:
            raise ValueError("cloud_profile_invalid")
        budgets = (
            self.max_api_calls,
            self.max_pages,
            self.max_resources,
            self.max_response_bytes,
            self.timeout_seconds,
        )
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in budgets):
            raise ValueError("cloud_budget_invalid")
        if self.max_pages > self.max_api_calls:
            raise ValueError("cloud_budget_invalid")
        # CRITICAL: redirects, ambient proxies, and SDK credential chains can escape the promoted provider boundary.
        if self.allow_redirects or self.allow_proxies or self.allow_ambient_credentials:
            raise ValueError("cloud_transport_not_closed")


@dataclass(frozen=True, kw_only=True)
class CollectionAuthorization:
    tenant_id: str
    policy_decision_id: str
    policy_revision: str
    reservation_id: str
    credential_lease_id: str
    profile_id: str
    effective_permissions: tuple[str, ...]
    approved_permissions: tuple[str, ...]
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (
            self.tenant_id,
            self.policy_decision_id,
            self.policy_revision,
            self.reservation_id,
            self.credential_lease_id,
            self.profile_id,
        ):
            _identifier(value)
        _aware(self.approved_at)
        _aware(self.expires_at)
        if not self.approved_at < self.expires_at:
            raise ValueError("cloud_authorization_invalid")
        for permission in self.effective_permissions + self.approved_permissions:
            if not permission.strip() or len(permission) > 200:
                raise ValueError("cloud_permission_invalid")


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("cloud_identifier_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("cloud_time_invalid")
