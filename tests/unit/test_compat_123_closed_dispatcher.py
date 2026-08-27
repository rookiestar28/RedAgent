from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timezone

import pytest

from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.runner_service.campaign_dispatch import (
    AdapterTerminalReceipt,
    ClosedCampaignDispatcher,
    CampaignAdapterRequest,
    RunnerOwnedCampaignDispatcher,
    RunnerAmbiguityPersistenceError,
)


NOW = datetime(2026, 8, 24, 3, tzinfo=timezone.utc)


class Adapter:
    def __init__(self, adapter_id: str, adapter_version: str) -> None:
        self.adapter_id = adapter_id
        self.adapter_version = adapter_version
        self.requests: list[CampaignAdapterRequest] = []
        self.lookups: list[str] = []

    async def dispatch(self, request: CampaignAdapterRequest) -> AdapterTerminalReceipt:
        self.requests.append(request)
        return AdapterTerminalReceipt(
            invocation_id=request.invocation_id,
            effect_id=request.effect_id,
            state="confirmed",
            external_receipt_id=f"receipt-{request.invocation_id}",
            evidence_ids=(f"evidence-{request.invocation_id}",),
            cleanup_receipt_id=f"cleanup-{request.invocation_id}",
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )

    async def lookup(self, request: CampaignAdapterRequest) -> AdapterTerminalReceipt | None:
        self.lookups.append(request.invocation_id)
        return None


def _request(capability_key: str) -> CampaignAdapterRequest:
    binding = closed_execution_registry()[capability_key]
    return CampaignAdapterRequest(
        tenant_id="tenant-r123",
        capability_id=binding.capability_id,
        capability_revision=binding.capability_revision,
        adapter_id=binding.adapter_id,
        adapter_version=binding.adapter_version,
        profile_id=binding.profile_id,
        profile_revision=binding.profile_revision,
        profile_sha256=binding.profile_sha256,
        bundle_id=binding.bundle_id,
        bundle_revision=binding.bundle_revision,
        bundle_sha256=binding.bundle_sha256,
        invocation_id=f"invocation-{binding.capability_id}",
        effect_id=f"effect-{binding.capability_id}",
        envelope_sha256="a" * 64,
        manifest_v2_sha256="b" * 64,
    )


def _dispatcher() -> tuple[ClosedCampaignDispatcher, Adapter, Adapter]:
    zap = Adapter("zap-service", "2.17.0-r104.2")
    nuclei = Adapter("nuclei-service", "3.11.1-r105.2")
    return ClosedCampaignDispatcher((zap, nuclei)), zap, nuclei


def test_dispatcher_routes_only_exact_two_noninterchangeable_bindings() -> None:
    dispatcher, zap, nuclei = _dispatcher()

    zap_result = asyncio.run(dispatcher.dispatch(_request("zap-controlled-runtime@2")))
    nuclei_result = asyncio.run(dispatcher.dispatch(_request("nuclei-trusted-runtime@2")))

    assert zap_result.state == "confirmed"
    assert nuclei_result.state == "confirmed"
    assert len(zap.requests) == 1
    assert len(nuclei.requests) == 1


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    [
        ("adapter_id", "nuclei-service", "r123_adapter_binding_mismatch"),
        ("adapter_version", "latest", "r123_adapter_binding_mismatch"),
        ("profile_id", "zap-active-xss-lab-v1", "r123_profile_binding_mismatch"),
        ("profile_sha256", "f" * 64, "r123_profile_binding_mismatch"),
        ("bundle_id", "community-templates", "r123_bundle_binding_mismatch"),
        ("bundle_sha256", "f" * 64, "r123_bundle_binding_mismatch"),
    ],
)
def test_dispatcher_rejects_adapter_profile_or_bundle_substitution(
    field: str, value: object, reason: str
) -> None:
    dispatcher, zap, nuclei = _dispatcher()

    with pytest.raises(ValueError, match=reason):
        request = replace(_request("zap-controlled-runtime@2"), **{field: value})
        asyncio.run(dispatcher.dispatch(request))
    assert zap.requests == [] and nuclei.requests == []


def test_dispatcher_status_lookup_is_read_only_and_requires_exact_binding() -> None:
    dispatcher, zap, nuclei = _dispatcher()
    request = _request("zap-controlled-runtime@2")

    result = asyncio.run(dispatcher.lookup(request))

    assert result is None
    assert zap.lookups == [request.invocation_id]
    assert nuclei.lookups == []


def test_terminal_receipt_rejects_incomplete_or_contacting_confirmed_result() -> None:
    with pytest.raises(ValueError, match="r123_confirmed_receipt_incomplete"):
        AdapterTerminalReceipt(
            invocation_id="invocation-r123",
            effect_id="effect-r123",
            state="confirmed",
            external_receipt_id="receipt-r123",
            evidence_ids=("evidence-r123",),
            cleanup_receipt_id="cleanup-r123",
            output_complete=False,
            external_contact_count=0,
            failure_code=None,
        )


@pytest.mark.parametrize(
    "overrides",
    (
        {"external_receipt_id": None},
        {"evidence_ids": ()},
        {"cleanup_receipt_id": None},
        {"output_complete": False},
        {"failure_code": "status-proof-incomplete"},
    ),
)
def test_terminal_receipt_requires_complete_not_applied_status_and_cleanup_proof(
    overrides,
) -> None:
    fields = {
        "invocation_id": "invocation-r123",
        "effect_id": "effect-r123",
        "state": "not_applied",
        "external_receipt_id": "status-receipt-r123",
        "evidence_ids": ("status-evidence-r123",),
        "cleanup_receipt_id": "cleanup-r123",
        "output_complete": True,
        "external_contact_count": 0,
        "failure_code": None,
    }
    fields.update(overrides)

    with pytest.raises(ValueError, match="r123_not_applied_receipt_incomplete"):
        AdapterTerminalReceipt(**fields)


def test_adapter_request_rejects_tenant_identifier_that_cannot_fit_canonical_owners() -> None:
    request = _request("zap-controlled-runtime@2")

    with pytest.raises(ValueError, match="tenant_id_invalid"):
        replace(request, tenant_id="t" * 65)
    with pytest.raises(ValueError, match="r123_external_contact_forbidden"):
        AdapterTerminalReceipt(
            invocation_id="invocation-r123",
            effect_id="effect-r123",
            state="confirmed",
            external_receipt_id="receipt-r123",
            evidence_ids=("evidence-r123",),
            cleanup_receipt_id="cleanup-r123",
            output_complete=True,
            external_contact_count=1,
            failure_code=None,
        )


class LifecycleOwner:
    def __init__(self, *, ambiguity_fail: bool = False) -> None:
        self.events = []
        self.ambiguity_fail = ambiguity_fail

    async def begin(self, request, *, occurred_at):
        self.events.append(("begin", request.effect_id, occurred_at))
        return f"runner-handle-{request.effect_id}"

    async def complete(self, request, handle, receipt, *, occurred_at):
        self.events.append(("complete", handle, receipt.external_receipt_id, occurred_at))
        return receipt

    async def ambiguity(self, request, handle, *, failure_code, occurred_at):
        self.events.append(("ambiguity", handle, failure_code, occurred_at))
        if self.ambiguity_fail:
            raise RuntimeError("synthetic-runner-ambiguity-write-failed")


def test_runner_owned_dispatcher_wraps_adapter_with_canonical_lifecycle() -> None:
    closed, _, _ = _dispatcher()
    lifecycle = LifecycleOwner()
    dispatcher = RunnerOwnedCampaignDispatcher(closed, lifecycle, clock=lambda: NOW)
    request = _request("zap-controlled-runtime@2")

    receipt = asyncio.run(dispatcher.dispatch(request))

    assert receipt.state == "confirmed"
    assert lifecycle.events == [
        ("begin", request.effect_id, NOW),
        (
            "complete",
            f"runner-handle-{request.effect_id}",
            f"receipt-{request.invocation_id}",
            NOW,
        ),
    ]


class FailingClosedDispatcher:
    async def dispatch(self, request):
        raise RuntimeError("accepted_then_connection_lost")

    async def lookup(self, request):
        return None


class CancelledClosedDispatcher:
    async def dispatch(self, request):
        raise asyncio.CancelledError

    async def lookup(self, request):
        return None


class WrongReceiptDispatcher:
    async def dispatch(self, request):
        return AdapterTerminalReceipt(
            invocation_id="invocation-wrong",
            effect_id=request.effect_id,
            state="confirmed",
            external_receipt_id="receipt-wrong",
            evidence_ids=("evidence-wrong",),
            cleanup_receipt_id="cleanup-wrong",
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )

    async def lookup(self, request):
        return None


def test_runner_owned_dispatcher_records_ambiguity_after_possible_adapter_acceptance() -> None:
    lifecycle = LifecycleOwner()
    dispatcher = RunnerOwnedCampaignDispatcher(
        FailingClosedDispatcher(), lifecycle, clock=lambda: NOW
    )
    request = _request("nuclei-trusted-runtime@2")

    with pytest.raises(RuntimeError, match="accepted_then_connection_lost"):
        asyncio.run(dispatcher.dispatch(request))

    assert lifecycle.events == [
        ("begin", request.effect_id, NOW),
        (
            "ambiguity",
            f"runner-handle-{request.effect_id}",
            "adapter_result_unknown",
            NOW,
        ),
    ]


@pytest.mark.parametrize(
    ("closed", "expected_exception", "expected_message"),
    (
        (
            FailingClosedDispatcher(),
            RunnerAmbiguityPersistenceError,
            "r123_runner_ambiguity_persistence_failed",
        ),
        (CancelledClosedDispatcher(), asyncio.CancelledError, None),
    ),
)
def test_runner_owned_dispatcher_preserves_original_failure_when_ambiguity_write_fails(
    closed,
    expected_exception,
    expected_message,
) -> None:
    lifecycle = LifecycleOwner(ambiguity_fail=True)
    dispatcher = RunnerOwnedCampaignDispatcher(closed, lifecycle, clock=lambda: NOW)
    request = _request("nuclei-trusted-runtime@2")

    if expected_message is None:
        with pytest.raises(expected_exception):
            asyncio.run(dispatcher.dispatch(request))
    else:
        with pytest.raises(expected_exception, match=expected_message):
            asyncio.run(dispatcher.dispatch(request))

    assert lifecycle.events[-1][0:3] == (
        "ambiguity",
        f"runner-handle-{request.effect_id}",
        "adapter_result_unknown",
    )


def test_runner_owned_dispatcher_rejects_unbound_receipt_before_terminalizing_lifecycle() -> None:
    lifecycle = LifecycleOwner()
    dispatcher = RunnerOwnedCampaignDispatcher(
        WrongReceiptDispatcher(), lifecycle, clock=lambda: NOW
    )
    request = _request("zap-controlled-runtime@2")

    with pytest.raises(ValueError, match="r123_runner_owned_receipt_invalid"):
        asyncio.run(dispatcher.dispatch(request))

    assert lifecycle.events == [
        ("begin", request.effect_id, NOW),
        (
            "ambiguity",
            f"runner-handle-{request.effect_id}",
            "adapter_result_unknown",
            NOW,
        ),
    ]


def test_runner_owned_lookup_does_not_mutate_runner_lifecycle() -> None:
    closed, zap, _ = _dispatcher()
    lifecycle = LifecycleOwner()
    dispatcher = RunnerOwnedCampaignDispatcher(closed, lifecycle, clock=lambda: NOW)
    request = _request("zap-controlled-runtime@2")

    assert asyncio.run(dispatcher.lookup(request)) is None
    assert lifecycle.events == []
    assert zap.lookups == [request.invocation_id]
