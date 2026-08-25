"""Immutable resource ledger and ordered cancellation/cleanup state for R106."""

from __future__ import annotations

from dataclasses import dataclass, replace
import re


_SHA = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, kw_only=True)
class ResourceEntry:
    resource_id: str
    resource_lineage_sha256: str
    owner_identity_handle: str
    tenant_handle: str
    idempotency_key: str
    compensation_operation: str
    depends_on: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class ResourceLedger:
    entries: tuple[ResourceEntry, ...] = ()

    def record_created(
        self, *, resource_id: str, resource_lineage_sha256: str,
        owner_identity_handle: str, tenant_handle: str, idempotency_key: str,
        compensation_operation: str, depends_on: tuple[str, ...] = (),
    ) -> "ResourceLedger":
        if not _SHA.fullmatch(resource_lineage_sha256):
            raise ValueError("api_resource_lineage_invalid")
        entry = ResourceEntry(
            resource_id=resource_id, resource_lineage_sha256=resource_lineage_sha256,
            owner_identity_handle=owner_identity_handle, tenant_handle=tenant_handle,
            idempotency_key=idempotency_key, compensation_operation=compensation_operation,
            depends_on=depends_on,
        )
        for existing in self.entries:
            if existing.idempotency_key == idempotency_key or existing.resource_id == resource_id:
                if existing == entry:
                    return self
                raise ValueError("api_resource_replay_mismatch")
        known = {item.resource_id for item in self.entries}
        if any(dependency not in known for dependency in depends_on):
            raise ValueError("api_resource_dependency_missing")
        return ResourceLedger(entries=self.entries + (entry,))

    def compensation_order(self) -> tuple[ResourceEntry, ...]:
        # Dependencies are admitted before dependants, so exact reverse creation order is safe and deterministic.
        return tuple(reversed(self.entries))


@dataclass(frozen=True, kw_only=True)
class RuntimeLifecycle:
    gateway_blocked: bool
    native_stop_attempted: bool
    native_stop_acknowledged: bool
    forced_termination: bool
    leases_revoked: bool
    cleanup_complete: bool

    @classmethod
    def initial(cls) -> "RuntimeLifecycle":
        return cls(
            gateway_blocked=False, native_stop_attempted=False,
            native_stop_acknowledged=False, forced_termination=False,
            leases_revoked=False, cleanup_complete=False,
        )

    def block_gateway(self) -> "RuntimeLifecycle":
        return replace(self, gateway_blocked=True)

    def attempt_native_stop(self) -> "RuntimeLifecycle":
        if not self.gateway_blocked:
            raise ValueError("api_cancel_gateway_block_required")
        return replace(self, native_stop_attempted=True)

    def acknowledge_native_stop(self) -> "RuntimeLifecycle":
        if not self.gateway_blocked:
            raise ValueError("api_cancel_gateway_block_required")
        if not self.native_stop_attempted:
            raise ValueError("api_cancel_native_stop_attempt_required")
        return replace(self, native_stop_acknowledged=True)

    def force_terminate(self) -> "RuntimeLifecycle":
        if not self.gateway_blocked or not self.native_stop_attempted:
            raise ValueError("api_cancel_native_stop_attempt_required")
        return replace(self, forced_termination=True)

    def revoke_leases(self) -> "RuntimeLifecycle":
        if not self.gateway_blocked:
            raise ValueError("api_cancel_gateway_block_required")
        return replace(self, leases_revoked=True)

    def complete_cleanup(self, *, compensation_complete: bool, residual_resource_count: int) -> "RuntimeLifecycle":
        if not self.leases_revoked:
            raise ValueError("api_cleanup_lease_revocation_required")
        if not (self.native_stop_acknowledged or self.forced_termination):
            raise ValueError("api_cleanup_workload_containment_required")
        if not compensation_complete or residual_resource_count != 0:
            raise ValueError("api_cleanup_residual_state")
        return replace(self, cleanup_complete=True)
