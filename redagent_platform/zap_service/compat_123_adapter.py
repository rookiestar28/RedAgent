"""Exact passive ZAP product adapter for the compat_123 closed dispatcher."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import json
from typing import Protocol

from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.finding_operations.contracts import CoverageState
from redagent_platform.runner_service.compat_123_dispatch import (
    AdapterTerminalReceipt,
    R123AdapterRequest,
)
from redagent_platform.runner_service.compat_123_result import (
    AdapterResultMaterialV1,
    AdapterResultWriter,
    NormalizedAdapterFindingV1,
)
from redagent_platform.zap_service.contracts import (
    ZAP_ADDON_INVENTORY_COUNT,
    ZAP_ADDON_INVENTORY_SHA256,
)


@dataclass(frozen=True, slots=True)
class ZapFixedInvocation:
    invocation_id: str
    effect_id: str
    profile_id: str
    allowed_paths: tuple[str, ...]
    argv: tuple[str, ...]
    envelope_sha256: str
    manifest_v2_sha256: str


@dataclass(frozen=True, slots=True)
class ZapRuntimeReceipt:
    invocation_id: str
    effect_id: str
    terminal_state: str
    automation_plan_complete: bool
    addon_inventory_count: int
    addon_inventory_sha256: str
    output_complete: bool
    active_request_count: int
    external_contact_count: int
    evidence_ids: tuple[str, ...]
    cleanup_receipt_id: str | None
    external_receipt_id: str | None
    report_safe_payload: dict[str, object] | None = None
    normalized_findings: tuple[NormalizedAdapterFindingV1, ...] = ()
    observed_at: datetime | None = None
    coverage_state: str = "complete"


class ZapR123Transport(Protocol):
    async def execute(self, invocation: ZapFixedInvocation) -> ZapRuntimeReceipt: ...

    async def lookup(self, invocation_id: str) -> ZapRuntimeReceipt | None: ...


class ZapR123Adapter:
    adapter_id = "zap-service"
    adapter_version = "2.17.0-r104.2"

    def __init__(self, transport: ZapR123Transport, result_writer: AdapterResultWriter) -> None:
        self._transport = transport
        self._result_writer = result_writer

    async def dispatch(self, request: R123AdapterRequest) -> AdapterTerminalReceipt:
        _validate_request(request)
        invocation = ZapFixedInvocation(
            invocation_id=request.invocation_id,
            effect_id=request.effect_id,
            profile_id="zap-passive-v1",
            allowed_paths=("/passive/missing-header",),
            argv=(
                "/zap/zap.sh",
                "-cmd",
                "-autorun",
                "/run/redagent/r123-zap-passive.yaml",
            ),
            envelope_sha256=request.envelope_sha256,
            manifest_v2_sha256=request.manifest_v2_sha256,
        )
        runtime = _validate_runtime(
            await self._transport.execute(invocation), request=request
        )
        if runtime.report_safe_payload is None or runtime.observed_at is None:
            raise ValueError("r123_zap_canonical_result_missing")
        return await self._result_writer.persist(
            AdapterResultMaterialV1(
                request=request,
                report_safe_content=json.dumps(
                    runtime.report_safe_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8"),
                findings=runtime.normalized_findings,
                coverage_state=CoverageState(runtime.coverage_state),
                cleanup_receipt_id=runtime.cleanup_receipt_id or "",
                observed_at=runtime.observed_at,
            )
        )

    async def lookup(self, request: R123AdapterRequest) -> AdapterTerminalReceipt | None:
        _validate_request(request)
        result = await self._transport.lookup(request.invocation_id)
        if result is None:
            return None
        runtime = _validate_runtime(result, request=request)
        if runtime.terminal_state == "not_applied":
            return AdapterTerminalReceipt(
                invocation_id=request.invocation_id,
                effect_id=request.effect_id,
                state="not_applied",
                external_receipt_id=runtime.external_receipt_id,
                evidence_ids=runtime.evidence_ids,
                cleanup_receipt_id=runtime.cleanup_receipt_id,
                output_complete=runtime.output_complete,
                external_contact_count=runtime.external_contact_count,
                failure_code=None,
            )
        owned = await self._result_writer.lookup(
            request,
            cleanup_receipt_id=runtime.cleanup_receipt_id or "",
        )
        if owned is not None:
            return owned
        return AdapterTerminalReceipt(
            invocation_id=request.invocation_id,
            effect_id=request.effect_id,
            state="reconciliation_required",
            external_receipt_id=runtime.external_receipt_id,
            evidence_ids=(),
            cleanup_receipt_id=runtime.cleanup_receipt_id,
            output_complete=runtime.output_complete,
            external_contact_count=runtime.external_contact_count,
            failure_code="canonical_result_not_committed",
        )


def _validate_request(request: R123AdapterRequest) -> None:
    expected = closed_execution_registry()["zap-controlled-runtime@2"]
    if request.capability_key != expected.capability_key:
        raise ValueError("r123_zap_capability_mismatch")
    if (request.adapter_id, request.adapter_version) != (
        expected.adapter_id,
        expected.adapter_version,
    ):
        raise ValueError("r123_zap_adapter_mismatch")
    if (
        request.profile_id,
        request.profile_revision,
        request.profile_sha256,
    ) != (
        expected.profile_id,
        expected.profile_revision,
        expected.profile_sha256,
    ):
        raise ValueError("r123_zap_profile_mismatch")
    if any(value is not None for value in (request.bundle_id, request.bundle_revision, request.bundle_sha256)):
        raise ValueError("r123_zap_bundle_forbidden")


def _validate_runtime(
    receipt: ZapRuntimeReceipt,
    *,
    request: R123AdapterRequest,
) -> ZapRuntimeReceipt:
    if not isinstance(receipt, ZapRuntimeReceipt):
        raise ValueError("r123_zap_receipt_invalid")
    if (
        receipt.invocation_id != request.invocation_id
        or receipt.effect_id != request.effect_id
    ):
        # CRITICAL: canonical persistence must not rewrite mismatched runtime lineage.
        raise ValueError("r123_zap_runtime_binding_mismatch")
    if (
        isinstance(receipt.external_contact_count, bool)
        or receipt.external_contact_count != 0
    ):
        # CRITICAL: the product path is owned-loopback only; never rewrite contact truth to zero.
        raise ValueError("r123_zap_external_contact_forbidden")
    if receipt.terminal_state == "not_applied":
        if (
            receipt.automation_plan_complete is not False
            or receipt.output_complete is not True
            or receipt.active_request_count != 0
            or receipt.normalized_findings != ()
            or receipt.report_safe_payload is not None
            or receipt.observed_at is None
            or not receipt.evidence_ids
            or receipt.cleanup_receipt_id is None
            or receipt.external_receipt_id is None
        ):
            raise ValueError("r123_zap_not_applied_receipt_incomplete")
        return receipt
    if (
        not isinstance(receipt.normalized_findings, tuple)
        or not all(
            isinstance(item, NormalizedAdapterFindingV1)
            for item in receipt.normalized_findings
        )
        or receipt.report_safe_payload
        != {
            "schema": "redagent.r123-result/v1",
            "adapter_id": "zap-service",
            "output_complete": True,
            "findings": [asdict(item) for item in receipt.normalized_findings],
        }
    ):
        # CRITICAL: evidence bytes and imported findings must describe the same result.
        raise ValueError("r123_zap_report_safe_payload_invalid")
    if (
        receipt.terminal_state != "completed"
        or receipt.automation_plan_complete is not True
    ):
        raise ValueError("r123_zap_terminal_incomplete")
    if receipt.coverage_state not in {"complete", "partial", "unknown"}:
        raise ValueError("r123_zap_coverage_invalid")
    if (
        receipt.addon_inventory_count != ZAP_ADDON_INVENTORY_COUNT
        or receipt.addon_inventory_sha256 != ZAP_ADDON_INVENTORY_SHA256
    ):
        raise ValueError("r123_zap_addon_inventory_mismatch")
    if (
        receipt.output_complete is not True
        or isinstance(receipt.active_request_count, bool)
        or receipt.active_request_count != 0
        or not receipt.evidence_ids
        or receipt.cleanup_receipt_id is None
        or receipt.external_receipt_id is None
    ):
        raise ValueError("r123_zap_terminal_incomplete")
    return receipt
