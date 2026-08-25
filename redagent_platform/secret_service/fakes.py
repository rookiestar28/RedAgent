"""Synthetic-only compat_098 provider and attested workload conformance doubles."""

from __future__ import annotations

import hashlib
from typing import Mapping

from redagent_platform.secret_service.contracts import ProviderLeaseEnvelope, SecretMaterial
from redagent_platform.secret_service.providers import ProviderLeaseStatus, ProviderRenewal


class DeterministicFakeSecretProvider:
    max_ttl_seconds = 300

    def __init__(self, *, seed: str = "r098-local-conformance") -> None:
        if not seed:
            raise ValueError("fake_secret_seed_required")
        self._seed = seed
        self._counter = 0
        self._leases: dict[str, bool] = {}
        self.last_material: SecretMaterial | None = None
        self.fail_revoke = False

    async def issue(self, role_reference: str) -> ProviderLeaseEnvelope:
        self._counter += 1
        suffix = hashlib.sha256(f"{self._seed}:{role_reference}:{self._counter}".encode()).hexdigest()
        lease_reference = f"database/creds/synthetic/{suffix[:24]}"
        # CRITICAL: this provider is explicit synthetic-only conformance behavior.
        canary = bytearray(f"R098-SYNTHETIC-{suffix}".encode())  # pragma: allowlist secret
        self.last_material = SecretMaterial({"password": canary})
        self._leases[lease_reference] = True
        return ProviderLeaseEnvelope(
            provider_lease_reference=lease_reference,
            duration_seconds=self.max_ttl_seconds,
            renewable=True,
            material=self.last_material,
        )

    async def renew(self, provider_lease_reference: str, *, increment_seconds: int) -> ProviderRenewal:
        if not self._leases.get(provider_lease_reference):
            raise RuntimeError("synthetic_lease_inactive")
        return ProviderRenewal(min(increment_seconds, self.max_ttl_seconds), True)

    async def lookup_status(self, provider_lease_reference: str) -> ProviderLeaseStatus:
        active = self._leases.get(provider_lease_reference, False)
        return ProviderLeaseStatus(active, self.max_ttl_seconds if active else 0, active)

    async def revoke_sync(self, provider_lease_reference: str) -> None:
        if self.fail_revoke:
            raise RuntimeError("synthetic_revoke_outage")
        self._leases[provider_lease_reference] = False


class AttestedFakeWorkload:
    """Consumes a canary once and retains only a one-way observation digest."""

    def __init__(self, *, client_id: str, attestation_fingerprint: str) -> None:
        self.client_id = client_id
        self.attestation_fingerprint = attestation_fingerprint
        self.delivery_count = 0
        self.observation_digest: str | None = None

    async def deliver_once(
        self,
        *,
        client_id: str,
        attestation_fingerprint: str,
        material: Mapping[str, memoryview],
    ) -> None:
        if client_id != self.client_id or attestation_fingerprint != self.attestation_fingerprint:
            raise RuntimeError("fake_workload_attestation_mismatch")
        if self.delivery_count:
            raise RuntimeError("fake_workload_duplicate_delivery")
        value = material.get("password")
        if value is None:
            raise RuntimeError("fake_workload_material_shape_invalid")
        self.observation_digest = hashlib.sha256(value).hexdigest()
        self.delivery_count = 1
