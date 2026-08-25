from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.cloud_connectors.compiler import compile_collection_plan
from redagent_platform.cloud_connectors.contracts import (
    CollectionAuthorization,
    DataClass,
    OperationManifest,
    ProviderIdentity,
    ProviderKind,
    ProviderProfile,
)


NOW = datetime(2026, 7, 11, 14, 0, tzinfo=timezone.utc)


def operation(**overrides: object) -> OperationManifest:
    values = {
        "operation_id": "aws-iam-list-roles-v1",
        "action": "iam:ListRoles",
        "resource_scope": "arn:aws:iam::123456789012:role/*",
        "data_class": DataClass.SECURITY_CONFIGURATION,
        "mutation": False,
        "paginated": True,
        "page_cost": 1,
    }
    values.update(overrides)
    return OperationManifest(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> ProviderProfile:
    values = {
        "profile_id": "r108-aws-emulator-v1",
        "provider": ProviderKind.AWS,
        "enabled": True,
        "emulator_only": True,
        "expected_identity": ProviderIdentity(provider=ProviderKind.AWS, tenant="123456789012"),
        "operations": (operation(),),
        "max_api_calls": 6,
        "max_pages": 4,
        "max_resources": 20,
        "max_response_bytes": 16_384,
        "timeout_seconds": 20,
        "allow_redirects": False,
        "allow_proxies": False,
        "allow_ambient_credentials": False,
    }
    values.update(overrides)
    return ProviderProfile(**values)  # type: ignore[arg-type]


def authorization(**overrides: object) -> CollectionAuthorization:
    values = {
        "tenant_id": "tenant-r108",
        "policy_decision_id": "decision-r108",
        "policy_revision": "r099-v1",
        "reservation_id": "reservation-r108",
        "credential_lease_id": "lease-r108",
        "profile_id": "r108-aws-emulator-v1",
        "effective_permissions": ("iam:ListRoles",),
        "approved_permissions": ("iam:ListRoles",),
        "approved_at": NOW,
        "expires_at": NOW + timedelta(minutes=15),
    }
    values.update(overrides)
    return CollectionAuthorization(**values)  # type: ignore[arg-type]


def test_compiler_separates_identity_operations_data_classes_and_budgets() -> None:
    plan = compile_collection_plan(profile=profile(), authorization=authorization(), now=NOW)

    assert plan.provider is ProviderKind.AWS
    assert plan.expected_identity.tenant == "123456789012"
    assert plan.credential_lease_id == "lease-r108"
    assert plan.operation_ids == ("aws-iam-list-roles-v1",)
    assert plan.permissions == ("iam:ListRoles",)
    assert plan.data_classes == (DataClass.SECURITY_CONFIGURATION,)
    assert plan.max_api_calls == 6 and plan.max_pages == 4 and plan.max_resources == 20
    assert len(plan.plan_sha256) == 64


@pytest.mark.parametrize(
    ("changed_operation", "reason"),
    [
        (operation(action="iam:*"), "cloud_permission_wildcard_denied"),
        (operation(action="iam:CreateAccessKey", mutation=True), "cloud_mutating_operation_denied"),
        (operation(action="sensitive-store:GetValue", data_class=DataClass.SENSITIVE_VALUE), "cloud_sensitive_data_class_denied"),
        (operation(action="s3:GetObject", data_class=DataClass.DATA_PLANE), "cloud_sensitive_data_class_denied"),
    ],
)
def test_compiler_denies_wildcard_mutation_secret_and_data_plane(
    changed_operation: OperationManifest, reason: str
) -> None:
    changed = profile(operations=(changed_operation,))
    changed_auth = authorization(
        effective_permissions=(changed_operation.action,), approved_permissions=(changed_operation.action,)
    )
    with pytest.raises(ValueError, match=reason):
        compile_collection_plan(profile=changed, authorization=changed_auth, now=NOW)


def test_compiler_denies_undergrant_overgrant_profile_and_lease_time_drift() -> None:
    with pytest.raises(ValueError, match="cloud_permission_undergrant"):
        compile_collection_plan(
            profile=profile(), authorization=authorization(effective_permissions=()), now=NOW
        )
    with pytest.raises(ValueError, match="cloud_permission_overgrant"):
        compile_collection_plan(
            profile=profile(),
            authorization=authorization(
                effective_permissions=("iam:ListRoles", "iam:GetRole"),
                approved_permissions=("iam:ListRoles",),
            ),
            now=NOW,
        )
    with pytest.raises(ValueError, match="cloud_profile_not_authorized"):
        compile_collection_plan(
            profile=profile(), authorization=authorization(profile_id="other-profile"), now=NOW
        )
    with pytest.raises(ValueError, match="cloud_authorization_inactive"):
        compile_collection_plan(
            profile=profile(), authorization=authorization(), now=NOW + timedelta(minutes=16)
        )


def test_profile_rejects_unbounded_or_ambient_transport() -> None:
    with pytest.raises(ValueError, match="cloud_transport_not_closed"):
        profile(allow_redirects=True)
    with pytest.raises(ValueError, match="cloud_transport_not_closed"):
        profile(allow_proxies=True)
    with pytest.raises(ValueError, match="cloud_transport_not_closed"):
        profile(allow_ambient_credentials=True)
    with pytest.raises(ValueError, match="cloud_budget_invalid"):
        profile(max_resources=0)
