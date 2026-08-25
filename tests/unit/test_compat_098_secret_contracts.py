from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone
import pickle

import pytest

from redagent_platform.secret_service.contracts import (
    LeaseIssueRequest,
    ProviderLeaseEnvelope,
    SecretMaterial,
    SecretReference,
    SecretReferenceKind,
    SecretReferenceStatus,
    WorkloadClient,
    effective_lease_expiry,
)


NOW = datetime(2026, 7, 10, 21, 0, tzinfo=timezone.utc)


def reference(**overrides: object) -> SecretReference:
    values: dict[str, object] = {
        "tenant_id": "tenant-1",
        "reference_id": "secret-ref-1",
        "engagement_id": "engagement-1",
        "owner_user_id": "owner-1",
        "kind": SecretReferenceKind.DYNAMIC_DATABASE,
        "provider_alias": "openbao-primary",
        "role_reference": "role:database-readonly-v1",
        "allowed_capabilities": ("database-readonly",),
        "allowed_permissions": ("database:connect", "database:select"),
        "created_at": NOW - timedelta(days=1),
        "expires_at": NOW + timedelta(hours=1),
        "rotation_due_at": NOW + timedelta(minutes=30),
        "status": SecretReferenceStatus.ACTIVE,
        "redaction_label": "secret-reference:secret-ref-1",
    }
    values.update(overrides)
    return SecretReference(**values)  # type: ignore[arg-type]


def workload(**overrides: object) -> WorkloadClient:
    values: dict[str, object] = {
        "tenant_id": "tenant-1",
        "client_id": "workload-client-1",
        "job_id": "job-1",
        "capability": "database-readonly",
        "attestation_fingerprint": "a" * 64,
        "expires_at": NOW + timedelta(minutes=20),
        "revoked_at": None,
    }
    values.update(overrides)
    return WorkloadClient(**values)  # type: ignore[arg-type]


def issue_request(**overrides: object) -> LeaseIssueRequest:
    values: dict[str, object] = {
        "tenant_id": "tenant-1",
        "lease_id": "lease-1",
        "reference_id": "secret-ref-1",
        "engagement_id": "engagement-1",
        "job_id": "job-1",
        "workload_client_id": "workload-client-1",
        "capability": "database-readonly",
        "requested_permissions": ("database:connect", "database:select"),
        "requested_at": NOW,
        "ttl_seconds": 600,
        "job_deadline": NOW + timedelta(minutes=15),
        "policy_expires_at": NOW + timedelta(minutes=12),
        "roe_expires_at": NOW + timedelta(minutes=14),
        "policy_reference": "policy:compat_098:1",
        "roe_version_id": "roe-1",
        "idempotency_key": "issue-lease-1",
    }
    values.update(overrides)
    return LeaseIssueRequest(**values)  # type: ignore[arg-type]


def test_reference_workload_and_issue_contracts_are_closed_metadata_only() -> None:
    payloads = (asdict(reference()), asdict(workload()), asdict(issue_request()))
    for payload in payloads:
        rendered = str(payload).lower()
        for forbidden in (
            "secret_value", "password", "token", "secret_id", "unwrap", "provider_path",
            "mount", "endpoint", "root", "force_revoke", "revoke_prefix", "command",
        ):
            assert forbidden not in rendered
    assert effective_lease_expiry(reference(), workload(), issue_request(), provider_max_ttl_seconds=900) == NOW + timedelta(minutes=10)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"ttl_seconds": 901}, "lease_ttl_invalid"),
        ({"requested_permissions": ()}, "lease_permissions_required"),
        ({"requested_permissions": ("database:admin",)}, "lease_permission_not_allowed"),
        ({"capability": "database-admin"}, "lease_capability_not_allowed"),
        ({"tenant_id": "other-tenant"}, "lease_tenant_mismatch"),
        ({"requested_at": NOW.replace(tzinfo=None)}, "timezone_required"),
    ],
)
def test_issue_request_scope_and_ttl_fail_closed(override: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        effective_lease_expiry(reference(), workload(), issue_request(**override), provider_max_ttl_seconds=900)


def test_secret_material_is_single_use_redacted_nonserializable_and_cleared() -> None:
    first_value = bytearray(b"synthetic-credential-canary")
    material = SecretMaterial({"username": b"synthetic-user", "password": first_value})
    assert "synthetic" not in repr(material)
    with pytest.raises(TypeError, match="secret_material_serialization_forbidden"):
        pickle.dumps(material)

    observed: dict[str, bytes] = {}
    with material.expose_once() as fields:
        observed = {name: bytes(value) for name, value in fields.items()}
        assert observed["password"] == b"synthetic-credential-canary"
    assert material.cleared
    assert all(value == 0 for value in first_value)
    with pytest.raises(RuntimeError, match="secret_material_already_consumed"):
        with material.expose_once():
            pass


def test_provider_envelope_repr_and_serialization_never_expose_material() -> None:
    envelope = ProviderLeaseEnvelope(
        provider_lease_reference="provider-lease:opaque-1",
        duration_seconds=300,
        renewable=True,
        material=SecretMaterial({"password": b"synthetic-credential-canary"}),
    )
    assert "synthetic" not in repr(envelope)
    with pytest.raises(TypeError, match="provider_lease_serialization_forbidden"):
        pickle.dumps(envelope)
