"""Closed compat_109 compiler for exact tenant, consent, scope, role, field, and data boundaries."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

from redagent_platform.identity_saas.contracts import (
    IdentityAuthorization, IdentityDataClass, IdentityProvider, IdentityProviderProfile,
)


@dataclass(frozen=True, kw_only=True)
class CompiledIdentityPlan:
    profile_id: str
    provider: IdentityProvider
    tenant_id: str
    audience: str
    consent_mode: str
    credential_lease_id: str
    operation_ids: tuple[str, ...]
    scopes: tuple[str, ...]
    effective_role_permissions: tuple[str, ...]
    selected_fields: tuple[str, ...]
    data_classes: tuple[IdentityDataClass, ...]
    max_calls: int
    max_pages: int
    max_resources: int
    max_bytes: int
    timeout_seconds: int
    snapshot_retention_days: int
    plan_sha256: str


def compile_identity_plan(*, profile: IdentityProviderProfile, authorization: IdentityAuthorization, now: datetime) -> CompiledIdentityPlan:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("identity_time_invalid")
    if now < authorization.approved_at or now >= authorization.expires_at:
        raise ValueError("identity_authorization_inactive")
    if not profile.enabled:
        raise ValueError("identity_profile_disabled")
    if authorization.tenant_id != profile.tenant_id:
        raise ValueError("identity_tenant_mismatch")
    if authorization.audience != profile.audience:
        raise ValueError("identity_audience_mismatch")
    if authorization.consent_mode is not profile.consent_mode:
        raise ValueError("identity_consent_mode_mismatch")
    operations = tuple(sorted(profile.operations, key=lambda item: item.operation_id))
    if len({item.operation_id for item in operations}) != len(operations):
        raise ValueError("identity_duplicate_operation_denied")
    sensitive_fields = ("password", "token", "cookie", "session", "privatekey", "secret", "credential")
    for operation in operations:
        if operation.method.upper() != "GET":
            raise ValueError("identity_write_operation_denied")
        scope_lower = operation.permission_scope.lower()
        if "*" in operation.permission_scope or "*" in operation.effective_role_permission:
            raise ValueError("identity_wildcard_permission_denied")
        if any(marker in scope_lower for marker in ("readwrite", ".manage", ":manage", "write.all")):
            raise ValueError("identity_write_permission_denied")
        if operation.data_class in {IdentityDataClass.USER_CONTENT, IdentityDataClass.CREDENTIAL_METADATA}:
            raise ValueError("identity_sensitive_data_class_denied")
        if any(any(marker in field.lower() for marker in sensitive_fields) for field in operation.selected_fields):
            raise ValueError("identity_sensitive_field_denied")
    scopes = tuple(operation.permission_scope for operation in operations)
    roles = tuple(operation.effective_role_permission for operation in operations)
    granted = set(authorization.granted_scopes); required_scopes = set(scopes)
    effective = set(authorization.effective_role_permissions); required_roles = set(roles)
    if not required_scopes <= granted:
        raise ValueError("identity_scope_undergrant")
    if granted != required_scopes:
        raise ValueError("identity_scope_overgrant")
    if not required_roles <= effective:
        raise ValueError("identity_role_permission_undergrant")
    if effective != required_roles:
        raise ValueError("identity_role_permission_overgrant")
    fields = tuple(sorted({field for operation in operations for field in operation.selected_fields}))
    classes = tuple(dict.fromkeys(operation.data_class for operation in operations))
    material = {
        "schema": "redagent.r109-identity-plan/v1", "profile": profile.profile_id,
        "provider": profile.provider.value, "tenant": profile.tenant_id, "audience": profile.audience,
        "consent": profile.consent_mode.value, "lease": authorization.credential_lease_id,
        "operations": [[item.operation_id, item.method, item.api_version, item.permission_scope, item.effective_role_permission, list(item.selected_fields), item.data_class.value, item.paginated, item.graph_eligible] for item in operations],
        "limits": [profile.max_calls, profile.max_pages, profile.max_resources, profile.max_bytes, profile.timeout_seconds, profile.snapshot_retention_days],
    }
    digest = hashlib.sha256(json.dumps(material, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return CompiledIdentityPlan(
        profile_id=profile.profile_id, provider=profile.provider, tenant_id=profile.tenant_id,
        audience=profile.audience, consent_mode=profile.consent_mode.value,
        credential_lease_id=authorization.credential_lease_id,
        operation_ids=tuple(item.operation_id for item in operations), scopes=scopes,
        effective_role_permissions=roles, selected_fields=fields, data_classes=classes,
        max_calls=profile.max_calls, max_pages=profile.max_pages, max_resources=profile.max_resources,
        max_bytes=profile.max_bytes, timeout_seconds=profile.timeout_seconds,
        snapshot_retention_days=profile.snapshot_retention_days, plan_sha256=digest,
    )
