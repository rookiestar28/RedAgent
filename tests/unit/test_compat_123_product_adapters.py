from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import json

import pytest

from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.finding_operations.contracts import CoverageState
from redagent_platform.nuclei_service.campaign_adapter import (
    NucleiCampaignAdapter,
    NucleiRuntimeReceipt,
)
from redagent_platform.runner_service.campaign_dispatch import CampaignAdapterRequest
from redagent_platform.runner_service.campaign_dispatch import AdapterTerminalReceipt
from redagent_platform.zap_service.contracts import (
    ZAP_ADDON_INVENTORY_COUNT,
    ZAP_ADDON_INVENTORY_SHA256,
)
from redagent_platform.zap_service.campaign_adapter import ZapCampaignAdapter, ZapRuntimeReceipt


class ZapTransport:
    def __init__(self, receipt: ZapRuntimeReceipt) -> None:
        self.receipt = receipt
        self.invocations = []
        self.lookups: list[str] = []

    async def execute(self, invocation):
        self.invocations.append(invocation)
        return self.receipt

    async def lookup(self, invocation_id: str):
        self.lookups.append(invocation_id)
        return self.receipt


class NucleiTransport:
    def __init__(self, receipt: NucleiRuntimeReceipt) -> None:
        self.receipt = receipt
        self.invocations = []
        self.lookups: list[str] = []

    async def execute(self, invocation):
        self.invocations.append(invocation)
        return self.receipt

    async def lookup(self, invocation_id: str):
        self.lookups.append(invocation_id)
        return self.receipt


NOW = datetime(2026, 8, 24, 3, tzinfo=timezone.utc)


class ResultWriter:
    def __init__(self) -> None:
        self.materials = []
        self.lookups = []

    async def persist(self, material):
        self.materials.append(material)
        return AdapterTerminalReceipt(
            invocation_id=material.request.invocation_id,
            effect_id=material.request.effect_id,
            state="confirmed",
            external_receipt_id=f"execution-{material.request.invocation_id}",
            evidence_ids=(f"evidence-{material.request.invocation_id}",),
            cleanup_receipt_id=material.cleanup_receipt_id,
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )

    async def lookup(self, request, *, cleanup_receipt_id):
        self.lookups.append((request, cleanup_receipt_id))
        return AdapterTerminalReceipt(
            invocation_id=request.invocation_id,
            effect_id=request.effect_id,
            state="confirmed",
            external_receipt_id=f"execution-{request.invocation_id}",
            evidence_ids=(f"evidence-{request.invocation_id}",),
            cleanup_receipt_id=cleanup_receipt_id,
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )

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


def _zap_receipt(**overrides: object) -> ZapRuntimeReceipt:
    values: dict[str, object] = {
        "invocation_id": "invocation-zap-controlled-runtime",
        "effect_id": "effect-zap-controlled-runtime",
        "terminal_state": "completed",
        "automation_plan_complete": True,
        "addon_inventory_count": ZAP_ADDON_INVENTORY_COUNT,
        "addon_inventory_sha256": ZAP_ADDON_INVENTORY_SHA256,
        "output_complete": True,
        "active_request_count": 0,
        "external_contact_count": 0,
        "evidence_ids": ("evidence-zap",),
        "cleanup_receipt_id": "cleanup-zap",
        "external_receipt_id": "receipt-zap",
        "report_safe_payload": {
            "schema": "redagent.r123-result/v1",
            "adapter_id": "zap-service",
            "output_complete": True,
            "findings": [],
        },
        "normalized_findings": (),
        "observed_at": NOW,
    }
    values.update(overrides)
    return ZapRuntimeReceipt(**values)  # type: ignore[arg-type]


def _nuclei_receipt(**overrides: object) -> NucleiRuntimeReceipt:
    binding = closed_execution_registry()["nuclei-trusted-runtime@2"]
    values: dict[str, object] = {
        "invocation_id": "invocation-nuclei-trusted-runtime",
        "effect_id": "effect-nuclei-trusted-runtime",
        "terminal_state": "completed",
        "bundle_id": binding.bundle_id,
        "bundle_revision": binding.bundle_revision,
        "bundle_sha256": binding.bundle_sha256,
        "signed_bundle_verified": True,
        "output_complete": True,
        "result_count": 0,
        "external_contact_count": 0,
        "evidence_ids": ("evidence-nuclei",),
        "cleanup_receipt_id": "cleanup-nuclei",
        "external_receipt_id": "receipt-nuclei",
        "report_safe_payload": {
            "schema": "redagent.r123-result/v1",
            "adapter_id": "nuclei-service",
            "output_complete": True,
            "findings": [],
        },
        "normalized_findings": (),
        "observed_at": NOW,
    }
    values.update(overrides)
    return NucleiRuntimeReceipt(**values)  # type: ignore[arg-type]


def test_zap_adapter_uses_fixed_passive_command_and_requires_terminal_completeness() -> None:
    transport = ZapTransport(_zap_receipt())
    writer = ResultWriter()
    adapter = ZapCampaignAdapter(transport, writer)

    result = asyncio.run(adapter.dispatch(_request("zap-controlled-runtime@2")))

    assert result.state == "confirmed"
    invocation = transport.invocations[0]
    assert invocation.argv == (
        "/zap/zap.sh",
        "-cmd",
        "-autorun",
        "/run/redagent/r123-zap-passive.yaml",
    )
    assert invocation.profile_id == "zap-passive-v1"
    assert invocation.allowed_paths == ("/passive/missing-header",)
    assert json.loads(writer.materials[0].report_safe_content) == _zap_receipt().report_safe_payload

    with pytest.raises(ValueError, match="r123_zap_terminal_incomplete"):
        asyncio.run(ZapCampaignAdapter(ZapTransport(_zap_receipt(output_complete=False)), ResultWriter()).dispatch(
            _request("zap-controlled-runtime@2")
        ))
    with pytest.raises(ValueError, match="r123_zap_addon_inventory_mismatch"):
        asyncio.run(ZapCampaignAdapter(ZapTransport(_zap_receipt(addon_inventory_count=1)), ResultWriter()).dispatch(
            _request("zap-controlled-runtime@2")
        ))


def test_nuclei_adapter_uses_fixed_signed_bundle_command_and_forbids_dynamic_features() -> None:
    transport = NucleiTransport(_nuclei_receipt())
    adapter = NucleiCampaignAdapter(transport, ResultWriter())

    result = asyncio.run(adapter.dispatch(_request("nuclei-trusted-runtime@2")))

    assert result.state == "confirmed"
    argv = transport.invocations[0].argv
    assert argv[:4] == (
        "-target",
        "http://redagent-r105-gateway:8080",
        "-templates",
        "/opt/redagent/bundle/templates/redagent-r105-missing-header.yaml",
    )
    for forbidden in ("-headless", "-code", "-oast", "-update-templates", "-list"):
        assert forbidden not in argv
    assert "-disable-unsigned-templates" in argv
    assert "-no-interactsh" in argv

    with pytest.raises(ValueError, match="r123_nuclei_bundle_mismatch"):
        asyncio.run(NucleiCampaignAdapter(NucleiTransport(_nuclei_receipt(bundle_sha256="f" * 64)), ResultWriter()).dispatch(
            _request("nuclei-trusted-runtime@2")
        ))
    with pytest.raises(ValueError, match="r123_nuclei_terminal_incomplete"):
        asyncio.run(NucleiCampaignAdapter(NucleiTransport(_nuclei_receipt(output_complete=False)), ResultWriter()).dispatch(
            _request("nuclei-trusted-runtime@2")
        ))


def test_adapter_lookup_is_read_only_and_normalizes_same_terminal_contract() -> None:
    zap_transport = ZapTransport(_zap_receipt())
    nuclei_transport = NucleiTransport(_nuclei_receipt())

    zap = asyncio.run(ZapCampaignAdapter(zap_transport, ResultWriter()).lookup(
        _request("zap-controlled-runtime@2")
    ))
    nuclei = asyncio.run(
        NucleiCampaignAdapter(nuclei_transport, ResultWriter()).lookup(
            _request("nuclei-trusted-runtime@2")
        )
    )

    assert zap is not None and zap.state == "confirmed"
    assert nuclei is not None and nuclei.state == "confirmed"
    assert zap_transport.invocations == [] and nuclei_transport.invocations == []


def test_adapter_lookup_accepts_only_complete_not_applied_status_proof() -> None:
    zap_writer = ResultWriter()
    nuclei_writer = ResultWriter()
    zap = asyncio.run(
        ZapCampaignAdapter(
            ZapTransport(
                _zap_receipt(
                    terminal_state="not_applied",
                    automation_plan_complete=False,
                    addon_inventory_count=0,
                    addon_inventory_sha256="0" * 64,
                    report_safe_payload=None,
                    evidence_ids=("evidence-zap-not-applied",),
                    external_receipt_id="status-zap-not-applied",
                )
            ),
            zap_writer,
        ).lookup(_request("zap-controlled-runtime@2"))
    )
    nuclei = asyncio.run(
        NucleiCampaignAdapter(
            NucleiTransport(
                _nuclei_receipt(
                    terminal_state="not_applied",
                    signed_bundle_verified=False,
                    report_safe_payload=None,
                    evidence_ids=("evidence-nuclei-not-applied",),
                    external_receipt_id="status-nuclei-not-applied",
                )
            ),
            nuclei_writer,
        ).lookup(_request("nuclei-trusted-runtime@2"))
    )

    assert zap is not None and zap.state == "not_applied"
    assert nuclei is not None and nuclei.state == "not_applied"
    assert zap_writer.lookups == [] and nuclei_writer.lookups == []


def test_adapter_preserves_closed_observation_coverage_for_successor_policy() -> None:
    writer = ResultWriter()

    asyncio.run(
        ZapCampaignAdapter(
            ZapTransport(_zap_receipt(coverage_state="partial")), writer
        ).dispatch(_request("zap-controlled-runtime@2"))
    )

    assert writer.materials[0].coverage_state is CoverageState.PARTIAL
    with pytest.raises(ValueError, match="r123_zap_coverage_invalid"):
        asyncio.run(
            ZapCampaignAdapter(
                ZapTransport(_zap_receipt(coverage_state="unbounded")), ResultWriter()
            ).dispatch(_request("zap-controlled-runtime@2"))
        )


@pytest.mark.parametrize(
    ("adapter", "request_key", "error"),
    (
        (
            ZapCampaignAdapter(ZapTransport(_zap_receipt(external_contact_count=1)), ResultWriter()),
            "zap-controlled-runtime@2",
            "r123_zap_external_contact_forbidden",
        ),
        (
            NucleiCampaignAdapter(
                NucleiTransport(_nuclei_receipt(external_contact_count=1)), ResultWriter()
            ),
            "nuclei-trusted-runtime@2",
            "r123_nuclei_external_contact_forbidden",
        ),
    ),
)
def test_adapter_rejects_any_runtime_receipt_reporting_external_contact(
    adapter,
    request_key,
    error,
) -> None:
    with pytest.raises(ValueError, match=error):
        asyncio.run(adapter.dispatch(_request(request_key)))


@pytest.mark.parametrize(
    ("adapter", "request_key", "error"),
    (
        (
            ZapCampaignAdapter(
                ZapTransport(_zap_receipt(effect_id="effect-other")), ResultWriter()
            ),
            "zap-controlled-runtime@2",
            "r123_zap_runtime_binding_mismatch",
        ),
        (
            NucleiCampaignAdapter(
                NucleiTransport(_nuclei_receipt(invocation_id="invocation-other")),
                ResultWriter(),
            ),
            "nuclei-trusted-runtime@2",
            "r123_nuclei_runtime_binding_mismatch",
        ),
    ),
)
def test_adapter_rejects_runtime_receipt_lineage_mismatch(
    adapter,
    request_key,
    error,
) -> None:
    request = _request(request_key)
    with pytest.raises(ValueError, match=error):
        asyncio.run(adapter.dispatch(request))
    with pytest.raises(ValueError, match=error):
        asyncio.run(adapter.lookup(request))


@pytest.mark.parametrize(
    ("adapter", "request_key", "error"),
    (
        (
            ZapCampaignAdapter(
                ZapTransport(
                    _zap_receipt(
                        report_safe_payload={
                            "schema": "redagent.r123-result/v1",
                            "adapter_id": "nuclei-service",
                            "output_complete": True,
                            "findings": [],
                        }
                    )
                ),
                ResultWriter(),
            ),
            "zap-controlled-runtime@2",
            "r123_zap_report_safe_payload_invalid",
        ),
        (
            NucleiCampaignAdapter(
                NucleiTransport(
                    _nuclei_receipt(
                        report_safe_payload={
                            "schema": "redagent.r123-result/v1",
                            "adapter_id": "zap-service",
                            "output_complete": True,
                            "findings": [],
                        }
                    )
                ),
                ResultWriter(),
            ),
            "nuclei-trusted-runtime@2",
            "r123_nuclei_report_safe_payload_invalid",
        ),
    ),
)
def test_adapter_rejects_report_safe_evidence_identity_mismatch(
    adapter,
    request_key,
    error,
) -> None:
    with pytest.raises(ValueError, match=error):
        asyncio.run(adapter.dispatch(_request(request_key)))
