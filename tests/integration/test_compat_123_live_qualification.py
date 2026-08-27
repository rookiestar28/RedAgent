from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
from uuid import uuid4

import pytest

from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.nuclei_service.campaign_adapter import NucleiCampaignAdapter
from redagent_platform.nuclei_service.campaign_transport import NucleiDockerTransport
from redagent_platform.runner_service.campaign_dispatch import (
    AdapterTerminalReceipt,
    ClosedCampaignDispatcher,
    CampaignAdapterRequest,
)
from redagent_platform.runner_service.campaign_result import AdapterResultMaterialV1
from redagent_platform.zap_service.campaign_adapter import ZapCampaignAdapter
from redagent_platform.zap_service.campaign_transport import ZapDockerTransport


ROOT = Path(__file__).resolve().parents[2]
LIVE = os.environ.get("REDAGENT_R123_LIVE_QUALIFICATION") == "owned-loopback-v2"


class _QualificationResultWriter:
    """Observe the canonical adapter handoff without replacing the real runtime path."""

    def __init__(self) -> None:
        self.materials: list[AdapterResultMaterialV1] = []

    async def persist(self, material: AdapterResultMaterialV1) -> AdapterTerminalReceipt:
        self.materials.append(material)
        digest = hashlib.sha256(material.report_safe_content).hexdigest()[:24]
        return AdapterTerminalReceipt(
            invocation_id=material.request.invocation_id,
            effect_id=material.request.effect_id,
            state="confirmed",
            external_receipt_id=f"qualification-result-{digest}",
            evidence_ids=(f"qualification-evidence-{digest}",),
            cleanup_receipt_id=material.cleanup_receipt_id,
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )

    async def lookup(
        self,
        request: CampaignAdapterRequest,
        *,
        cleanup_receipt_id: str,
    ) -> AdapterTerminalReceipt | None:
        del request, cleanup_receipt_id
        return None


def _request(capability_key: str, *, suffix: str) -> CampaignAdapterRequest:
    binding = closed_execution_registry()[capability_key]
    return CampaignAdapterRequest(
        tenant_id="r123-live-qualification",
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
        invocation_id=f"invocation-r123-{suffix}",
        effect_id=f"effect-r123-{suffix}",
        envelope_sha256=hashlib.sha256(f"envelope-{suffix}".encode()).hexdigest(),
        manifest_v2_sha256=hashlib.sha256(f"manifest-{suffix}".encode()).hexdigest(),
    )


@pytest.mark.skipif(
    not LIVE,
    reason="requires explicit owned-loopback R123 live qualification authority",
)
def test_r123_real_closed_dispatcher_executes_both_current_owned_loopback_profiles() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    zap_writer = _QualificationResultWriter()
    nuclei_writer = _QualificationResultWriter()
    dispatcher = ClosedCampaignDispatcher((
        ZapCampaignAdapter(ZapDockerTransport(ROOT), zap_writer),
        NucleiCampaignAdapter(NucleiDockerTransport(ROOT), nuclei_writer),
    ))
    unique = uuid4().hex[:12]

    zap = await dispatcher.dispatch(_request("zap-controlled-runtime@2", suffix=f"zap-{unique}"))
    nuclei = await dispatcher.dispatch(
        _request("nuclei-trusted-runtime@2", suffix=f"nuclei-{unique}")
    )

    assert zap.state == nuclei.state == "confirmed"
    assert zap.external_contact_count == nuclei.external_contact_count == 0
    assert zap.output_complete is nuclei.output_complete is True
    assert zap.cleanup_receipt_id and nuclei.cleanup_receipt_id
    assert len(zap_writer.materials) == len(nuclei_writer.materials) == 1
    assert len(zap_writer.materials[0].findings) >= 1
    assert len(nuclei_writer.materials[0].findings) == 1
    assert nuclei_writer.materials[0].findings[0].tool_version == "3.11.1"
    assert nuclei_writer.materials[0].findings[0].database_version == (
        "r105-http-header-bundle:2"
    )
