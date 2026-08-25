from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.secret_service.broker import LeaseIssueResult, SecretLeaseBroker
from redagent_platform.secret_service.contracts import LeaseIssueRequest, ProviderLeaseEnvelope, SecretMaterial
from redagent_platform.secret_service.repository import LeaseReservation


NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)
CANARY = bytearray(b"R098-SYNTHETIC-CANARY")  # pragma: allowlist secret


@dataclass
class _Store:
    reservation: LeaseReservation
    issued: list[tuple[str, str]]
    finalized: list[str]
    compensated: list[tuple[str, str, bool]]
    fail_finalize: bool = False

    async def reserve_issue(self, request, *, actor_user_id, correlation_id, provider_max_ttl_seconds):
        return self.reservation

    async def mark_issued(self, operation_id, provider_lease_reference, *, tenant_id, occurred_at):
        self.issued.append((operation_id, provider_lease_reference))

    async def finalize_issue(self, operation_id, request, envelope, *, expires_at, actor_user_id, correlation_id, occurred_at):
        if self.fail_finalize:
            raise RuntimeError("synthetic_database_outage")
        self.finalized.append(operation_id)
        return {"id": request.lease_id, "lease_state": "active", "provider_lease_reference": envelope.provider_lease_reference}

    async def compensate_issue(self, operation_id, provider_lease_reference, *, tenant_id, revoke_confirmed, failure_code, actor_user_id, correlation_id, occurred_at):
        self.compensated.append((operation_id, failure_code, revoke_confirmed))


class _Provider:
    max_ttl_seconds = 300

    def __init__(self, *, revoke_fails: bool = False):
        self.material: SecretMaterial | None = None
        self.revoked: list[str] = []
        self.revoke_fails = revoke_fails

    async def issue(self, role_reference: str) -> ProviderLeaseEnvelope:
        self.material = SecretMaterial({"password": CANARY.copy()})
        return ProviderLeaseEnvelope(
            provider_lease_reference="database/creds/redagent/lease-1",
            duration_seconds=300,
            renewable=True,
            material=self.material,
        )

    async def revoke_sync(self, provider_lease_reference: str) -> None:
        self.revoked.append(provider_lease_reference)
        if self.revoke_fails:
            raise RuntimeError("synthetic_provider_outage")


class _Workload:
    def __init__(self, *, fail: bool = False):
        self.fail = fail
        self.observed = False

    async def deliver_once(self, *, client_id: str, attestation_fingerprint: str, material):
        assert client_id == "client-1"
        assert attestation_fingerprint == "a" * 64
        self.observed = bytes(material["password"]) == bytes(CANARY)
        if self.fail:
            raise RuntimeError("synthetic_workload_failure")


def test_broker_delivers_once_clears_material_and_returns_metadata_only() -> None:
    store = _store()
    provider = _Provider()
    workload = _Workload()
    result = asyncio.run(SecretLeaseBroker(store, provider, workload).issue(_request(), actor_user_id="operator-1", correlation_id="corr-1"))

    assert isinstance(result, LeaseIssueResult)
    assert result.lease["lease_state"] == "active"
    assert workload.observed
    assert provider.material is not None and provider.material.cleared
    assert store.issued == [("operation-1", "database/creds/redagent/lease-1")]
    assert store.finalized == ["operation-1"]
    assert bytes(CANARY) not in repr(result).encode()


@pytest.mark.parametrize("revoke_fails,confirmed", [(False, True), (True, False)])
def test_broker_compensates_delivery_failure_and_preserves_revoke_pending(revoke_fails: bool, confirmed: bool) -> None:
    store = _store()
    provider = _Provider(revoke_fails=revoke_fails)
    with pytest.raises(RuntimeError, match="secret_delivery_failed"):
        asyncio.run(
            SecretLeaseBroker(store, provider, _Workload(fail=True)).issue(
                _request(), actor_user_id="operator-1", correlation_id="corr-1"
            )
        )
    assert provider.material is not None and provider.material.cleared
    assert store.compensated == [("operation-1", "secret_delivery_failed", confirmed)]


def test_broker_revokes_when_database_finalize_fails_after_delivery() -> None:
    store = _store()
    store.fail_finalize = True
    provider = _Provider()
    with pytest.raises(RuntimeError, match="secret_finalize_failed"):
        asyncio.run(
            SecretLeaseBroker(store, provider, _Workload()).issue(
                _request(), actor_user_id="operator-1", correlation_id="corr-1"
            )
        )
    assert provider.revoked == ["database/creds/redagent/lease-1"]
    assert store.compensated == [("operation-1", "secret_finalize_failed", True)]


def _store() -> _Store:
    return _Store(
        LeaseReservation(
            operation_id="operation-1",
            role_reference="database-role-1",
            workload_client_id="client-1",
            attestation_fingerprint="a" * 64,
            effective_expires_at=NOW + timedelta(seconds=300),
            replayed=False,
            lease=None,
        ),
        [], [], [],
    )


def _request() -> LeaseIssueRequest:
    deadline = NOW + timedelta(hours=1)
    return LeaseIssueRequest(
        tenant_id="tenant-1", lease_id="lease-1", reference_id="reference-1",
        engagement_id="engagement-1", job_id="job-1", workload_client_id="client-1",
        capability="synthetic-db", requested_permissions=("read",), requested_at=NOW,
        ttl_seconds=300, job_deadline=deadline, policy_expires_at=deadline,
        roe_expires_at=deadline, policy_reference="policy:compat_098:1", roe_version_id="roe-1",
        idempotency_key="issue-1",
    )
