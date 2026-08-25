"""Closed compat_108 compiler from promoted provider metadata to immutable collection plans."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

from redagent_platform.cloud_connectors.contracts import (
    CollectionAuthorization,
    DataClass,
    ProviderIdentity,
    ProviderKind,
    ProviderProfile,
)


@dataclass(frozen=True, kw_only=True)
class CompiledCollectionPlan:
    profile_id: str
    provider: ProviderKind
    expected_identity: ProviderIdentity
    credential_lease_id: str
    operation_ids: tuple[str, ...]
    permissions: tuple[str, ...]
    data_classes: tuple[DataClass, ...]
    max_api_calls: int
    max_pages: int
    max_resources: int
    max_response_bytes: int
    timeout_seconds: int
    plan_sha256: str


def compile_collection_plan(
    *, profile: ProviderProfile, authorization: CollectionAuthorization, now: datetime
) -> CompiledCollectionPlan:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("cloud_time_invalid")
    if now < authorization.approved_at or now >= authorization.expires_at:
        raise ValueError("cloud_authorization_inactive")
    if not profile.enabled:
        raise ValueError("cloud_profile_disabled")
    if authorization.profile_id != profile.profile_id:
        raise ValueError("cloud_profile_not_authorized")

    operations = tuple(sorted(profile.operations, key=lambda item: item.operation_id))
    if len({item.operation_id for item in operations}) != len(operations):
        raise ValueError("cloud_duplicate_operation_denied")
    for item in operations:
        action = item.action.strip()
        if "*" in action or "*" in item.resource_scope.strip().removesuffix("/*"):
            raise ValueError("cloud_permission_wildcard_denied")
        if item.mutation:
            raise ValueError("cloud_mutating_operation_denied")
        if item.data_class in {DataClass.DATA_PLANE, DataClass.SENSITIVE_VALUE}:
            raise ValueError("cloud_sensitive_data_class_denied")

    required = {item.action for item in operations}
    approved = set(authorization.approved_permissions)
    effective = set(authorization.effective_permissions)
    if not required <= effective or not required <= approved:
        raise ValueError("cloud_permission_undergrant")
    # IMPORTANT: overgrant is a dispatch denial, not an advisory, because an adapter compromise could use it.
    if effective != approved or effective != required:
        raise ValueError("cloud_permission_overgrant")

    material = {
        "schema": "redagent.r108-collection-plan/v1",
        "profile_id": profile.profile_id,
        "provider": profile.provider.value,
        "identity": [profile.expected_identity.tenant, profile.expected_identity.parent],
        "lease": authorization.credential_lease_id,
        "operations": [
            [item.operation_id, item.action, item.resource_scope, item.data_class.value, item.paginated, item.page_cost]
            for item in operations
        ],
        "limits": [
            profile.max_api_calls,
            profile.max_pages,
            profile.max_resources,
            profile.max_response_bytes,
            profile.timeout_seconds,
        ],
    }
    digest = hashlib.sha256(
        json.dumps(material, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return CompiledCollectionPlan(
        profile_id=profile.profile_id,
        provider=profile.provider,
        expected_identity=profile.expected_identity,
        credential_lease_id=authorization.credential_lease_id,
        operation_ids=tuple(item.operation_id for item in operations),
        permissions=tuple(item.action for item in operations),
        data_classes=tuple(dict.fromkeys(item.data_class for item in operations)),
        max_api_calls=profile.max_api_calls,
        max_pages=profile.max_pages,
        max_resources=profile.max_resources,
        max_response_bytes=profile.max_response_bytes,
        timeout_seconds=profile.timeout_seconds,
        plan_sha256=digest,
    )
