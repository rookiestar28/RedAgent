"""Exact signed-bundle Nuclei product adapter for the compat_123 closed dispatcher."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import json
from typing import Protocol

from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.finding_operations.contracts import CoverageState
from redagent_platform.nuclei_service.contracts import GATEWAY_ENDPOINT
from redagent_platform.runner_service.campaign_dispatch import (
    AdapterTerminalReceipt,
    CampaignAdapterRequest,
)
from redagent_platform.runner_service.campaign_result import (
    AdapterResultMaterialV1,
    AdapterResultWriter,
    NormalizedAdapterFindingV1,
)


NUCLEI_FIXED_ARGV = (
    "-target",
    GATEWAY_ENDPOINT,
    "-templates",
    "/opt/redagent/bundle/templates/redagent-r105-missing-header.yaml",
    "-template-id",
    "redagent-r105-missing-header",
    "-disable-unsigned-templates",
    "-disable-update-check",
    "-no-interactsh",
    "-no-stdin",
    "-jsonl-export",
    "/work/results.jsonl",
    "-omit-raw",
    "-omit-template",
    "-rate-limit",
    "2",
    "-concurrency",
    "1",
    "-bulk-size",
    "1",
    "-timeout",
    "5",
    "-retries",
    "0",
    "-response-size-read",
    "1048576",
    "-response-size-save",
    "0",
    "-silent",
    "-no-color",
)


@dataclass(frozen=True, slots=True)
class NucleiFixedInvocation:
    invocation_id: str
    effect_id: str
    profile_id: str
    bundle_id: str
    bundle_revision: int
    bundle_sha256: str
    argv: tuple[str, ...]
    envelope_sha256: str
    manifest_v2_sha256: str


@dataclass(frozen=True, slots=True)
class NucleiRuntimeReceipt:
    invocation_id: str
    effect_id: str
    terminal_state: str
    bundle_id: str | None
    bundle_revision: int | None
    bundle_sha256: str | None
    signed_bundle_verified: bool
    output_complete: bool
    result_count: int
    external_contact_count: int
    evidence_ids: tuple[str, ...]
    cleanup_receipt_id: str | None
    external_receipt_id: str | None
    report_safe_payload: dict[str, object] | None = None
    normalized_findings: tuple[NormalizedAdapterFindingV1, ...] = ()
    observed_at: datetime | None = None
    coverage_state: str = "complete"


class NucleiCampaignTransport(Protocol):
    async def execute(self, invocation: NucleiFixedInvocation) -> NucleiRuntimeReceipt: ...

    async def lookup(self, invocation_id: str) -> NucleiRuntimeReceipt | None: ...


class NucleiCampaignAdapter:
    adapter_id = "nuclei-service"
    adapter_version = "3.11.1-r105.2"

    def __init__(self, transport: NucleiCampaignTransport, result_writer: AdapterResultWriter) -> None:
        self._transport = transport
        self._result_writer = result_writer

    async def dispatch(self, request: CampaignAdapterRequest) -> AdapterTerminalReceipt:
        binding = _validate_request(request)
        invocation = NucleiFixedInvocation(
            invocation_id=request.invocation_id,
            effect_id=request.effect_id,
            profile_id=binding.profile_id,
            bundle_id=binding.bundle_id or "",
            bundle_revision=binding.bundle_revision or 0,
            bundle_sha256=binding.bundle_sha256 or "",
            argv=NUCLEI_FIXED_ARGV,
            envelope_sha256=request.envelope_sha256,
            manifest_v2_sha256=request.manifest_v2_sha256,
        )
        runtime = _validate_runtime(
            await self._transport.execute(invocation), request=request
        )
        if runtime.report_safe_payload is None or runtime.observed_at is None:
            raise ValueError("r123_nuclei_canonical_result_missing")
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

    async def lookup(self, request: CampaignAdapterRequest) -> AdapterTerminalReceipt | None:
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


def _validate_request(request: CampaignAdapterRequest):
    expected = closed_execution_registry()["nuclei-trusted-runtime@2"]
    if request.capability_key != expected.capability_key:
        raise ValueError("r123_nuclei_capability_mismatch")
    if (request.adapter_id, request.adapter_version) != (
        expected.adapter_id,
        expected.adapter_version,
    ):
        raise ValueError("r123_nuclei_adapter_mismatch")
    if (
        request.profile_id,
        request.profile_revision,
        request.profile_sha256,
    ) != (
        expected.profile_id,
        expected.profile_revision,
        expected.profile_sha256,
    ):
        raise ValueError("r123_nuclei_profile_mismatch")
    if (
        request.bundle_id,
        request.bundle_revision,
        request.bundle_sha256,
    ) != (
        expected.bundle_id,
        expected.bundle_revision,
        expected.bundle_sha256,
    ):
        raise ValueError("r123_nuclei_bundle_mismatch")
    return expected


def _validate_runtime(
    receipt: NucleiRuntimeReceipt,
    *,
    request: CampaignAdapterRequest,
) -> NucleiRuntimeReceipt:
    if not isinstance(receipt, NucleiRuntimeReceipt):
        raise ValueError("r123_nuclei_receipt_invalid")
    if (
        receipt.invocation_id != request.invocation_id
        or receipt.effect_id != request.effect_id
    ):
        # CRITICAL: canonical persistence must not rewrite mismatched runtime lineage.
        raise ValueError("r123_nuclei_runtime_binding_mismatch")
    if (
        isinstance(receipt.external_contact_count, bool)
        or receipt.external_contact_count != 0
    ):
        # CRITICAL: the product path is owned-loopback only; never rewrite contact truth to zero.
        raise ValueError("r123_nuclei_external_contact_forbidden")
    expected = closed_execution_registry()["nuclei-trusted-runtime@2"]
    if receipt.terminal_state == "not_applied":
        if (
            (receipt.bundle_id, receipt.bundle_revision, receipt.bundle_sha256)
            != (expected.bundle_id, expected.bundle_revision, expected.bundle_sha256)
            or receipt.signed_bundle_verified is not False
            or receipt.output_complete is not True
            or receipt.result_count != 0
            or receipt.normalized_findings != ()
            or receipt.report_safe_payload is not None
            or receipt.observed_at is None
            or not receipt.evidence_ids
            or receipt.cleanup_receipt_id is None
            or receipt.external_receipt_id is None
        ):
            raise ValueError("r123_nuclei_not_applied_receipt_incomplete")
        return receipt
    if (
        not isinstance(receipt.normalized_findings, tuple)
        or not all(
            isinstance(item, NormalizedAdapterFindingV1)
            for item in receipt.normalized_findings
        )
        or receipt.result_count != len(receipt.normalized_findings)
        or receipt.report_safe_payload
        != {
            "schema": "redagent.r123-result/v1",
            "adapter_id": "nuclei-service",
            "output_complete": True,
            "findings": [asdict(item) for item in receipt.normalized_findings],
        }
    ):
        # CRITICAL: evidence bytes and imported findings must describe the same result.
        raise ValueError("r123_nuclei_report_safe_payload_invalid")
    if receipt.coverage_state not in {"complete", "partial", "unknown"}:
        raise ValueError("r123_nuclei_coverage_invalid")
    if (
        receipt.bundle_id,
        receipt.bundle_revision,
        receipt.bundle_sha256,
    ) != (
        expected.bundle_id,
        expected.bundle_revision,
        expected.bundle_sha256,
    ) or not receipt.signed_bundle_verified:
        raise ValueError("r123_nuclei_bundle_mismatch")
    if (
        receipt.terminal_state != "completed"
        or receipt.output_complete is not True
        or isinstance(receipt.result_count, bool)
        or not 0 <= receipt.result_count <= 10
        or not receipt.evidence_ids
        or receipt.cleanup_receipt_id is None
        or receipt.external_receipt_id is None
    ):
        raise ValueError("r123_nuclei_terminal_incomplete")
    return receipt
