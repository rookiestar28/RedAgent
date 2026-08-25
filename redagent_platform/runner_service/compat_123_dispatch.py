"""Closed two-adapter dispatcher for compat_123 manifest-v2 execution."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
import re
from typing import Callable, Protocol

from redagent_platform.campaign_service.registry import (
    ClosedExecutionBinding,
    closed_execution_registry,
)


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


@dataclass(frozen=True, slots=True)
class R123AdapterRequest:
    tenant_id: str
    capability_id: str
    capability_revision: int
    adapter_id: str
    adapter_version: str
    profile_id: str
    profile_revision: int
    profile_sha256: str
    bundle_id: str | None
    bundle_revision: int | None
    bundle_sha256: str | None
    invocation_id: str
    effect_id: str
    envelope_sha256: str
    manifest_v2_sha256: str

    def __post_init__(self) -> None:
        _identifier64("tenant_id", self.tenant_id)
        for name in (
            "capability_id",
            "adapter_id",
            "adapter_version",
            "profile_id",
            "invocation_id",
            "effect_id",
        ):
            _identifier(name, getattr(self, name))
        for name, value in (
            ("capability_revision", self.capability_revision),
            ("profile_revision", self.profile_revision),
        ):
            if isinstance(value, bool) or value < 1:
                raise ValueError(f"{name}_invalid")
        for name, value in (
            ("profile_sha256", self.profile_sha256),
            ("envelope_sha256", self.envelope_sha256),
            ("manifest_v2_sha256", self.manifest_v2_sha256),
        ):
            _sha256(name, value)
        bundle = (self.bundle_id, self.bundle_revision, self.bundle_sha256)
        if any(value is None for value in bundle) and any(value is not None for value in bundle):
            raise ValueError("r123_bundle_binding_mismatch")
        if self.bundle_id is not None:
            _identifier("bundle_id", self.bundle_id)
            if isinstance(self.bundle_revision, bool) or not isinstance(self.bundle_revision, int) or self.bundle_revision < 1:
                raise ValueError("r123_bundle_binding_mismatch")
            _sha256("bundle_sha256", self.bundle_sha256)

    @property
    def capability_key(self) -> str:
        return f"{self.capability_id}@{self.capability_revision}"


@dataclass(frozen=True, slots=True)
class AdapterTerminalReceipt:
    invocation_id: str
    effect_id: str
    state: str
    external_receipt_id: str | None
    evidence_ids: tuple[str, ...]
    cleanup_receipt_id: str | None
    output_complete: bool
    external_contact_count: int
    failure_code: str | None

    def __post_init__(self) -> None:
        _identifier("invocation_id", self.invocation_id)
        _identifier("effect_id", self.effect_id)
        if self.state not in {
            "confirmed",
            "not_applied",
            "reconciliation_required",
            "compensated",
            "manual_review_required",
            "failed",
        }:
            raise ValueError("r123_adapter_receipt_state_invalid")
        if not isinstance(self.output_complete, bool):
            raise ValueError("r123_adapter_output_complete_invalid")
        if (
            isinstance(self.external_contact_count, bool)
            or not 0 <= self.external_contact_count <= 1000
        ):
            raise ValueError("r123_external_contact_count_invalid")
        if self.external_contact_count != 0:
            raise ValueError("r123_external_contact_forbidden")
        if not isinstance(self.evidence_ids, tuple) or len(self.evidence_ids) > 32:
            raise ValueError("r123_adapter_evidence_invalid")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("r123_adapter_evidence_invalid")
        for evidence_id in self.evidence_ids:
            _identifier("evidence_id", evidence_id)
        for name, value in (
            ("external_receipt_id", self.external_receipt_id),
            ("cleanup_receipt_id", self.cleanup_receipt_id),
            ("failure_code", self.failure_code),
        ):
            if value is not None:
                _identifier(name, value)
        if self.state == "confirmed" and (
            not self.output_complete
            or self.external_receipt_id is None
            or not self.evidence_ids
            or self.cleanup_receipt_id is None
            or self.failure_code is not None
        ):
            raise ValueError("r123_confirmed_receipt_incomplete")
        if self.state == "not_applied" and (
            not self.output_complete
            or self.external_receipt_id is None
            or not self.evidence_ids
            or self.cleanup_receipt_id is None
            or self.failure_code is not None
        ):
            # CRITICAL: NOT_APPLIED is retry authority only with status and cleanup proof.
            raise ValueError("r123_not_applied_receipt_incomplete")
        if self.state == "failed" and self.failure_code is None:
            raise ValueError("r123_failed_receipt_reason_required")


class ClosedAdapter(Protocol):
    adapter_id: str
    adapter_version: str

    async def dispatch(self, request: R123AdapterRequest) -> AdapterTerminalReceipt: ...

    async def lookup(self, request: R123AdapterRequest) -> AdapterTerminalReceipt | None: ...


class ClosedR123Dispatcher:
    def __init__(self, adapters: tuple[ClosedAdapter, ...]) -> None:
        if not isinstance(adapters, tuple):
            raise ValueError("r123_adapters_invalid")
        indexed = {(item.adapter_id, item.adapter_version): item for item in adapters}
        expected = {
            ("zap-service", "2.17.0-r104.2"),
            ("nuclei-service", "3.11.1-r105.2"),
        }
        if set(indexed) != expected or len(adapters) != 2:
            raise ValueError("r123_adapters_invalid")
        self._adapters = indexed

    async def dispatch(self, request: R123AdapterRequest) -> AdapterTerminalReceipt:
        binding, adapter = self._resolve(request)
        result = await adapter.dispatch(request)
        if result.invocation_id != request.invocation_id or result.effect_id != request.effect_id:
            raise ValueError("r123_adapter_receipt_binding_mismatch")
        return result

    async def lookup(self, request: R123AdapterRequest) -> AdapterTerminalReceipt | None:
        _, adapter = self._resolve(request)
        result = await adapter.lookup(request)
        if result is not None and (
            result.invocation_id != request.invocation_id or result.effect_id != request.effect_id
        ):
            raise ValueError("r123_adapter_receipt_binding_mismatch")
        return result

    def _resolve(self, request: R123AdapterRequest) -> tuple[ClosedExecutionBinding, ClosedAdapter]:
        binding = _closed_binding(request)
        return binding, self._adapters[(binding.adapter_id, binding.adapter_version)]


class RunnerLifecycleOwner(Protocol):
    async def begin(
        self,
        request: R123AdapterRequest,
        *,
        occurred_at: datetime,
    ) -> object: ...

    async def complete(
        self,
        request: R123AdapterRequest,
        handle: object,
        receipt: AdapterTerminalReceipt,
        *,
        occurred_at: datetime,
    ) -> AdapterTerminalReceipt: ...

    async def ambiguity(
        self,
        request: R123AdapterRequest,
        handle: object,
        *,
        failure_code: str,
        occurred_at: datetime,
    ) -> None: ...


class ClosedDispatcherPort(Protocol):
    async def dispatch(self, request: R123AdapterRequest) -> AdapterTerminalReceipt: ...

    async def lookup(self, request: R123AdapterRequest) -> AdapterTerminalReceipt | None: ...


class RunnerAmbiguityPersistenceError(RuntimeError):
    """Runner ambiguity persistence failed; campaign ownership must persist fallback state."""


class RunnerOwnedR123Dispatcher:
    """Require canonical runner lifecycle ownership around the exact closed adapter."""

    def __init__(
        self,
        dispatcher: ClosedDispatcherPort,
        lifecycle: RunnerLifecycleOwner,
        *,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._dispatcher = dispatcher
        self._lifecycle = lifecycle
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    async def dispatch(self, request: R123AdapterRequest) -> AdapterTerminalReceipt:
        _closed_binding(request)
        occurred_at = self._clock()
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise ValueError("r123_runner_lifecycle_time_invalid")
        handle = await self._lifecycle.begin(request, occurred_at=occurred_at)
        lifecycle_terminal = False
        try:
            receipt = await self._dispatcher.dispatch(request)
            # CRITICAL: never terminalize the canonical runner lifecycle with an
            # adapter receipt that is not bound to this exact invocation/effect.
            _validate_owned_receipt(request, receipt)
            completed_at = self._clock()
            owned = await self._lifecycle.complete(
                request,
                handle,
                receipt,
                occurred_at=completed_at,
            )
            lifecycle_terminal = True
            if _validate_owned_receipt(request, owned) != receipt:
                raise ValueError("r123_runner_owned_receipt_invalid")
            return owned
        except BaseException as original_error:
            # CRITICAL: once the runner lifecycle begins, adapter acceptance may be
            # ambiguous; record that boundary and never turn the exception into a resend.
            if not lifecycle_terminal:
                try:
                    await self._lifecycle.ambiguity(
                        request,
                        handle,
                        failure_code="adapter_result_unknown",
                        occurred_at=self._clock(),
                    )
                except BaseException as persistence_error:
                    # CRITICAL: cancellation remains observable; all other persistence
                    # loss is explicit so the campaign owner can durably fail closed.
                    if isinstance(original_error, asyncio.CancelledError):
                        original_error.add_note(
                            "r123_runner_ambiguity_persistence_failed"
                        )
                    else:
                        raise RunnerAmbiguityPersistenceError(
                            "r123_runner_ambiguity_persistence_failed"
                        ) from persistence_error
            raise

    async def lookup(
        self, request: R123AdapterRequest
    ) -> AdapterTerminalReceipt | None:
        # Read-only reconciliation must not claim a runner lease or advance lifecycle state.
        return await self._dispatcher.lookup(request)


def _closed_binding(request: R123AdapterRequest) -> ClosedExecutionBinding:
    if not isinstance(request, R123AdapterRequest):
        raise ValueError("r123_adapter_request_invalid")
    binding = closed_execution_registry().get(request.capability_key)
    if binding is None:
        raise ValueError("r123_capability_binding_unknown")
    if (request.adapter_id, request.adapter_version) != (
        binding.adapter_id,
        binding.adapter_version,
    ):
        raise ValueError("r123_adapter_binding_mismatch")
    if (
        request.profile_id,
        request.profile_revision,
        request.profile_sha256,
    ) != (
        binding.profile_id,
        binding.profile_revision,
        binding.profile_sha256,
    ):
        raise ValueError("r123_profile_binding_mismatch")
    if (
        request.bundle_id,
        request.bundle_revision,
        request.bundle_sha256,
    ) != (
        binding.bundle_id,
        binding.bundle_revision,
        binding.bundle_sha256,
    ):
        raise ValueError("r123_bundle_binding_mismatch")
    return binding


def _validate_owned_receipt(
    request: R123AdapterRequest,
    receipt: object,
) -> AdapterTerminalReceipt:
    if (
        not isinstance(receipt, AdapterTerminalReceipt)
        or receipt.state != "confirmed"
        or receipt.invocation_id != request.invocation_id
        or receipt.effect_id != request.effect_id
    ):
        raise ValueError("r123_runner_owned_receipt_invalid")
    return receipt


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _identifier64(name: str, value: object) -> None:
    if (
        not isinstance(value, str)
        or len(value) > 64
        or not _ID.fullmatch(value)
    ):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{name}_invalid")
