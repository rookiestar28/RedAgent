"""Last-responsible-moment secret issuance and one-shot workload delivery."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any

from redagent_platform.secret_service.contracts import LeaseIssueRequest


@dataclass(frozen=True, slots=True)
class LeaseIssueResult:
    lease: dict[str, object]
    replayed: bool


@dataclass(frozen=True, slots=True)
class LeaseMutationResult:
    lease: dict[str, object]
    replayed: bool


class SecretLeaseBroker:
    def __init__(self, store: Any, provider: Any, workload: Any, policy_sdk: Any | None = None) -> None:
        self.store = store
        self.provider = provider
        self.workload = workload
        self.policy_sdk = policy_sdk

    async def issue(
        self,
        request: LeaseIssueRequest,
        *,
        actor_user_id: str,
        correlation_id: str,
    ) -> LeaseIssueResult:
        if self.policy_sdk is not None:
            facts = await self.store.current_issue_policy_facts(request, actor_user_id=actor_user_id)
            await self.policy_sdk.enforce_secret(
                tenant_id=request.tenant_id,
                subject_id=actor_user_id,
                action="secret.lease",
                lease_id=request.lease_id,
                reference_status=str(facts["reference_status"]),
                lease_state=str(facts["lease_state"]),
                renewable=bool(facts["renewable"]),
                revoke_pending=bool(facts["revoke_pending"]),
                permission_digest=str(facts["permission_digest"]),
                permission_count=int(facts["permission_count"]),
                workload_client_status=str(facts["workload_client_status"]),
                policy_reference=request.policy_reference,
                roe_version_id=request.roe_version_id,
                correlation_id=correlation_id,
                requested_at=request.requested_at,
            )
        provider_max_ttl = getattr(self.provider, "max_ttl_seconds", 900)
        reservation = await self.store.reserve_issue(
            request,
            actor_user_id=actor_user_id,
            correlation_id=correlation_id,
            provider_max_ttl_seconds=provider_max_ttl,
        )
        if reservation.lease is not None:
            return LeaseIssueResult(reservation.lease, True)

        envelope = await self.provider.issue(reservation.role_reference)
        provider_expiry = request.requested_at + timedelta(seconds=envelope.duration_seconds)
        expires_at = min(reservation.effective_expires_at, provider_expiry)
        delivered = False
        try:
            await self.store.mark_issued(
                reservation.operation_id,
                envelope.provider_lease_reference,
                tenant_id=request.tenant_id,
                occurred_at=request.requested_at,
            )
            with envelope.material.expose_once() as material:
                await self.workload.deliver_once(
                    client_id=reservation.workload_client_id,
                    attestation_fingerprint=reservation.attestation_fingerprint,
                    material=material,
                )
            delivered = True
            lease = await self.store.finalize_issue(
                reservation.operation_id,
                request,
                envelope,
                expires_at=expires_at,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
                occurred_at=request.requested_at,
            )
        except Exception as exc:
            revoke_confirmed = False
            try:
                await self.provider.revoke_sync(envelope.provider_lease_reference)
                revoke_confirmed = True
            except Exception:  # noqa: BLE001
                # IMPORTANT: an unconfirmed exact revoke remains persisted as revoke_pending.
                pass
            failure_code = "secret_finalize_failed" if delivered else "secret_delivery_failed"
            try:
                await self.store.compensate_issue(
                    reservation.operation_id,
                    envelope.provider_lease_reference,
                    tenant_id=request.tenant_id,
                    revoke_confirmed=revoke_confirmed,
                    failure_code=failure_code,
                    actor_user_id=actor_user_id,
                    correlation_id=correlation_id,
                    occurred_at=request.requested_at,
                )
            except Exception:  # noqa: BLE001
                # IMPORTANT: exact provider revoke was attempted; reconciliation owns ambiguous metadata failure.
                pass
            raise RuntimeError(failure_code) from exc
        return LeaseIssueResult(lease, reservation.replayed)

    async def renew(
        self,
        request: LeaseIssueRequest,
        *,
        expected_version: int,
        actor_user_id: str,
        correlation_id: str,
    ) -> LeaseMutationResult:
        if self.policy_sdk is not None:
            facts = await self.store.current_lease_policy_facts(
                tenant_id=request.tenant_id, lease_id=request.lease_id,
            )
            await self._enforce_lease_facts(
                tenant_id=request.tenant_id, lease_id=request.lease_id,
                actor_user_id=actor_user_id, correlation_id=correlation_id,
                occurred_at=request.requested_at, facts=facts,
            )
        provider_max_ttl = getattr(self.provider, "max_ttl_seconds", 900)
        reservation = await self.store.prepare_renew(
            request, expected_version=expected_version, actor_user_id=actor_user_id,
            provider_max_ttl_seconds=provider_max_ttl,
        )
        remaining = max(1, int((reservation.effective_expires_at - request.requested_at).total_seconds()))
        renewal = await self.provider.renew(
            reservation.provider_lease_reference,
            increment_seconds=min(request.ttl_seconds, remaining, 900),
        )
        expires_at = min(
            reservation.effective_expires_at,
            request.requested_at + timedelta(seconds=renewal.duration_seconds),
        )
        lease = await self.store.finalize_renew(
            tenant_id=request.tenant_id, lease_id=request.lease_id, expected_version=expected_version,
            expires_at=expires_at, renewable=renewal.renewable, actor_user_id=actor_user_id,
            correlation_id=correlation_id, occurred_at=request.requested_at,
        )
        return LeaseMutationResult(lease, False)

    async def revoke(
        self,
        *,
        tenant_id: str,
        lease_id: str,
        expected_version: int,
        actor_user_id: str,
        correlation_id: str,
        occurred_at,
    ) -> LeaseMutationResult:
        if self.policy_sdk is not None:
            facts = await self.store.current_lease_policy_facts(tenant_id=tenant_id, lease_id=lease_id)
            await self._enforce_lease_facts(
                tenant_id=tenant_id, lease_id=lease_id, actor_user_id=actor_user_id,
                correlation_id=correlation_id, occurred_at=occurred_at, facts=facts,
            )
        reservation = await self.store.prepare_revoke(
            tenant_id=tenant_id, lease_id=lease_id, expected_version=expected_version
        )
        if reservation.already_terminal:
            status = await self.provider.lookup_status(reservation.provider_lease_reference)
            if status.active:
                raise RuntimeError("secret_terminal_lease_provider_mismatch")
            return LeaseMutationResult(reservation.lease, True)
        try:
            await self.provider.revoke_sync(reservation.provider_lease_reference)
        except Exception as exc:
            lease = await self.store.finalize_revoke(
                tenant_id=tenant_id, lease_id=lease_id, expected_version=expected_version,
                state="revoke_pending", failure_code="provider_revoke_unconfirmed",
                actor_user_id=actor_user_id, correlation_id=correlation_id, occurred_at=occurred_at,
            )
            raise RuntimeError("provider_revoke_unconfirmed") from exc
        lease = await self.store.finalize_revoke(
            tenant_id=tenant_id, lease_id=lease_id, expected_version=expected_version,
            state="revoked", failure_code=None, actor_user_id=actor_user_id,
            correlation_id=correlation_id, occurred_at=occurred_at,
        )
        return LeaseMutationResult(lease, False)

    async def reconcile(
        self,
        *,
        tenant_id: str,
        lease_id: str,
        actor_user_id: str,
        correlation_id: str,
        occurred_at,
    ) -> LeaseMutationResult:
        if self.policy_sdk is not None:
            facts = await self.store.current_lease_policy_facts(tenant_id=tenant_id, lease_id=lease_id)
            await self._enforce_lease_facts(
                tenant_id=tenant_id, lease_id=lease_id, actor_user_id=actor_user_id,
                correlation_id=correlation_id, occurred_at=occurred_at, facts=facts,
            )
        lease = await self.store.get_lease(tenant_id=tenant_id, lease_id=lease_id)
        if lease is None:
            raise RuntimeError("secret_lease_not_found")
        status = await self.provider.lookup_status(str(lease["provider_lease_reference"]))
        if lease["lease_state"] == "revoke_pending" and not status.active:
            reconciled = await self.store.finalize_revoke(
                tenant_id=tenant_id, lease_id=lease_id, expected_version=int(lease["version"]),
                state="revoked", failure_code=None, actor_user_id=actor_user_id,
                correlation_id=correlation_id, occurred_at=occurred_at,
            )
            return LeaseMutationResult(reconciled, False)
        if lease["lease_state"] == "active" and not status.active:
            reconciled = await self.store.finalize_revoke(
                tenant_id=tenant_id, lease_id=lease_id, expected_version=int(lease["version"]),
                state="expired", failure_code="provider_lease_absent", actor_user_id=actor_user_id,
                correlation_id=correlation_id, occurred_at=occurred_at,
            )
            return LeaseMutationResult(reconciled, False)
        return LeaseMutationResult(lease, True)

    async def _enforce_lease_facts(
        self, *, tenant_id: str, lease_id: str, actor_user_id: str,
        correlation_id: str, occurred_at, facts: dict[str, object],
    ) -> None:
        await self.policy_sdk.enforce_secret(
            tenant_id=tenant_id, subject_id=actor_user_id, action="secret.lease",
            lease_id=lease_id, reference_status=str(facts["reference_status"]),
            lease_state=str(facts["lease_state"]), renewable=bool(facts["renewable"]),
            revoke_pending=bool(facts["revoke_pending"]),
            permission_digest=str(facts["permission_digest"]),
            permission_count=int(facts["permission_count"]),
            workload_client_status=str(facts["workload_client_status"]),
            policy_reference=str(facts["policy_reference"]),
            roe_version_id=str(facts["roe_version_id"]),
            correlation_id=correlation_id, requested_at=occurred_at,
        )
