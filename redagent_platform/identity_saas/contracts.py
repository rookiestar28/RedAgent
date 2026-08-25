"""Immutable compat_109 provider operation, tenant, consent, and authorization contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class IdentityProvider(str, Enum):
    MICROSOFT_365 = "microsoft_365"
    GOOGLE_WORKSPACE = "google_workspace"
    OKTA = "okta"


class ConsentMode(str, Enum):
    APPLICATION = "application"
    DELEGATED = "delegated"
    DOMAIN_WIDE_DELEGATION = "domain_wide_delegation"


class IdentityDataClass(str, Enum):
    SECURITY_CONFIGURATION = "security_configuration"
    DIRECTORY_METADATA = "directory_metadata"
    RELATIONSHIP = "relationship"
    USER_CONTENT = "user_content"
    CREDENTIAL_METADATA = "credential_metadata"


@dataclass(frozen=True, kw_only=True)
class IdentityOperation:
    operation_id: str
    method: str
    api_version: str
    permission_scope: str
    effective_role_permission: str
    selected_fields: tuple[str, ...]
    data_class: IdentityDataClass
    paginated: bool
    graph_eligible: bool

    def __post_init__(self) -> None:
        _identifier(self.operation_id)
        if not self.method.strip() or not self.api_version.strip() or not self.permission_scope.strip() or not self.effective_role_permission.strip() or not self.selected_fields:
            raise ValueError("identity_operation_invalid")
        if any(not isinstance(field, str) or not field.strip() or len(field) > 100 for field in self.selected_fields):
            raise ValueError("identity_operation_invalid")


@dataclass(frozen=True, kw_only=True)
class IdentityProviderProfile:
    profile_id: str
    provider: IdentityProvider
    enabled: bool
    emulator_only: bool
    tenant_id: str
    audience: str
    consent_mode: ConsentMode
    operations: tuple[IdentityOperation, ...]
    max_calls: int
    max_pages: int
    max_resources: int
    max_bytes: int
    timeout_seconds: int
    snapshot_retention_days: int

    def __post_init__(self) -> None:
        for value in (self.profile_id, self.tenant_id, self.audience):
            _identifier(value)
        if not self.operations:
            raise ValueError("identity_profile_invalid")
        budgets = (self.max_calls, self.max_pages, self.max_resources, self.max_bytes, self.timeout_seconds, self.snapshot_retention_days)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in budgets) or self.max_pages > self.max_calls:
            raise ValueError("identity_budget_invalid")
        if self.snapshot_retention_days > 30:
            raise ValueError("identity_retention_excessive")


@dataclass(frozen=True, kw_only=True)
class IdentityAuthorization:
    authorization_id: str
    policy_decision_id: str
    policy_revision: str
    reservation_id: str
    credential_lease_id: str
    tenant_id: str
    audience: str
    consent_mode: ConsentMode
    granted_scopes: tuple[str, ...]
    effective_role_permissions: tuple[str, ...]
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.authorization_id, self.policy_decision_id, self.policy_revision, self.reservation_id, self.credential_lease_id, self.tenant_id, self.audience):
            _identifier(value)
        _aware(self.approved_at); _aware(self.expires_at)
        if not self.approved_at < self.expires_at:
            raise ValueError("identity_authorization_invalid")
        if any(not item.strip() or len(item) > 300 for item in self.granted_scopes + self.effective_role_permissions):
            raise ValueError("identity_permission_invalid")


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("identity_identifier_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("identity_time_invalid")
