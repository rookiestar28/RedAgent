from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.identity_saas.compiler import compile_identity_plan
from redagent_platform.identity_saas.contracts import (
    ConsentMode, IdentityAuthorization, IdentityDataClass, IdentityOperation,
    IdentityProvider, IdentityProviderProfile,
)


NOW = datetime(2026, 7, 11, 18, 0, tzinfo=timezone.utc)


def operation(**overrides: object) -> IdentityOperation:
    values = {
        "operation_id": "m365-conditional-access-list-v1",
        "method": "GET",
        "api_version": "v1.0",
        "permission_scope": "Policy.Read.ConditionalAccess",
        "effective_role_permission": "microsoft.directory/conditionalAccessPolicies/read",
        "selected_fields": ("id", "displayName", "state", "conditions", "grantControls"),
        "data_class": IdentityDataClass.SECURITY_CONFIGURATION,
        "paginated": True,
        "graph_eligible": False,
    }
    values.update(overrides)
    return IdentityOperation(**values)  # type: ignore[arg-type]


def profile(**overrides: object) -> IdentityProviderProfile:
    values = {
        "profile_id": "r109-m365-emulator-v1",
        "provider": IdentityProvider.MICROSOFT_365,
        "enabled": True,
        "emulator_only": True,
        "tenant_id": "tenant-r109",
        "audience": "graph-microsoft",
        "consent_mode": ConsentMode.APPLICATION,
        "operations": (operation(),),
        "max_calls": 8,
        "max_pages": 6,
        "max_resources": 32,
        "max_bytes": 32_768,
        "timeout_seconds": 20,
        "snapshot_retention_days": 30,
    }
    values.update(overrides)
    return IdentityProviderProfile(**values)  # type: ignore[arg-type]


def authorization(**overrides: object) -> IdentityAuthorization:
    values = {
        "authorization_id": "auth-r109",
        "policy_decision_id": "decision-r109",
        "policy_revision": "r099-v1",
        "reservation_id": "reservation-r109",
        "credential_lease_id": "lease-r109",
        "tenant_id": "tenant-r109",
        "audience": "graph-microsoft",
        "consent_mode": ConsentMode.APPLICATION,
        "granted_scopes": ("Policy.Read.ConditionalAccess",),
        "effective_role_permissions": ("microsoft.directory/conditionalAccessPolicies/read",),
        "approved_at": NOW,
        "expires_at": NOW + timedelta(minutes=15),
    }
    values.update(overrides)
    return IdentityAuthorization(**values)  # type: ignore[arg-type]


def test_compiler_binds_tenant_audience_consent_scopes_roles_fields_and_data() -> None:
    plan = compile_identity_plan(profile=profile(), authorization=authorization(), now=NOW)
    assert plan.provider is IdentityProvider.MICROSOFT_365
    assert plan.tenant_id == "tenant-r109" and plan.audience == "graph-microsoft"
    assert plan.scopes == ("Policy.Read.ConditionalAccess",)
    assert plan.effective_role_permissions == ("microsoft.directory/conditionalAccessPolicies/read",)
    assert plan.selected_fields == ("conditions", "displayName", "grantControls", "id", "state")
    assert plan.data_classes == (IdentityDataClass.SECURITY_CONFIGURATION,)
    assert len(plan.plan_sha256) == 64


@pytest.mark.parametrize(
    ("changed", "reason"),
    [
        ({"method": "POST"}, "identity_write_operation_denied"),
        ({"permission_scope": "Directory.ReadWrite.All"}, "identity_write_permission_denied"),
        ({"permission_scope": "*"}, "identity_wildcard_permission_denied"),
        ({"selected_fields": ("id", "passwordProfile")}, "identity_sensitive_field_denied"),
        ({"selected_fields": ("id", "refreshTokensValidFromDateTime")}, "identity_sensitive_field_denied"),
        ({"data_class": IdentityDataClass.USER_CONTENT}, "identity_sensitive_data_class_denied"),
        ({"data_class": IdentityDataClass.CREDENTIAL_METADATA}, "identity_sensitive_data_class_denied"),
    ],
)
def test_compiler_denies_write_wildcard_credential_content_and_sensitive_fields(changed: dict[str, object], reason: str) -> None:
    changed_operation = operation(**changed)
    changed_profile = profile(operations=(changed_operation,))
    changed_auth = authorization(
        granted_scopes=(changed_operation.permission_scope,),
        effective_role_permissions=(changed_operation.effective_role_permission,),
    )
    with pytest.raises(ValueError, match=reason):
        compile_identity_plan(profile=changed_profile, authorization=changed_auth, now=NOW)


@pytest.mark.parametrize(
    ("auth_change", "reason"),
    [
        ({"tenant_id": "other-tenant"}, "identity_tenant_mismatch"),
        ({"audience": "wrong-audience"}, "identity_audience_mismatch"),
        ({"consent_mode": ConsentMode.DELEGATED}, "identity_consent_mode_mismatch"),
        ({"granted_scopes": ()}, "identity_scope_undergrant"),
        ({"granted_scopes": ("Policy.Read.ConditionalAccess", "Directory.Read.All")}, "identity_scope_overgrant"),
        ({"effective_role_permissions": ()}, "identity_role_permission_undergrant"),
        ({"effective_role_permissions": ("microsoft.directory/conditionalAccessPolicies/read", "microsoft.directory/users/allProperties/read")}, "identity_role_permission_overgrant"),
    ],
)
def test_compiler_denies_identity_consent_and_token_effective_permission_drift(auth_change: dict[str, object], reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        compile_identity_plan(profile=profile(), authorization=authorization(**auth_change), now=NOW)
