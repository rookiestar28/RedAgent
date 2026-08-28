from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timezone
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redagent_platform.artifact_pipeline.campaign_adapter import ArtifactCampaignAdapter
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.resolver import CanonicalAuthoritySnapshot
from redagent_platform.campaign_service.runtime import (
    LocalCampaignPlanningFactsOwner,
    PolicyBoundCampaignAuthorizationOwner,
)
from redagent_platform.campaign_service.service import (
    CampaignStartRequest,
    DeterministicCampaignStartPlanner,
    binding_from_campaign_context,
)
from redagent_platform.finding_operations.contracts import CoverageState
from redagent_platform.runner_service.campaign_dispatch import (
    AdapterTerminalReceipt,
    CampaignAdapterRequest,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 28, 12, tzinfo=timezone.utc)


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
            external_receipt_id="execution-artifact-r129",
            evidence_ids=("evidence-artifact-r129",),
            cleanup_receipt_id=material.cleanup_receipt_id,
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )

    async def lookup(self, request, *, cleanup_receipt_id):
        self.lookups.append((request, cleanup_receipt_id))
        return None


def _request() -> CampaignAdapterRequest:
    binding = closed_execution_registry()["artifact-posture@1"]
    return CampaignAdapterRequest(
        tenant_id="tenant-r129",
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
        invocation_id="invocation-artifact-r129",
        effect_id="effect-artifact-r129",
        envelope_sha256="a" * 64,
        manifest_v2_sha256="b" * 64,
    )


def _start_request() -> CampaignStartRequest:
    return CampaignStartRequest(
        tenant_id="tenant-r129",
        principal_id="principal-r129",
        engagement_id="engagement-r129",
        target_id="artifact-binding-r129",
        name="Assess repository snapshot posture",
        objective_kind="repository_snapshot_posture",
        header_code=None,
        require_corroboration=False,
        risk_profile="tier1_passive",
    )


def _authority() -> CanonicalAuthoritySnapshot:
    return CanonicalAuthoritySnapshot(
        tenant_id="tenant-r129",
        principal_id="principal-r129",
        engagement_id="engagement-r129",
        engagement_version=1,
        roe_version_id="roe-r129",
        roe_revision=1,
        roe_sha256="1" * 64,
        roe_status="approved",
        roe_revocation_epoch=1,
        policy_decision_id="policy-r129",
        policy_revision="artifact-posture-policy-v2",
        policy_sha256="2" * 64,
        policy_status="allowed",
        policy_revocation_epoch=1,
        target_id="artifact-binding-r129",
        target_revision=1,
        target_sha256="3" * 64,
        target_value="artifact-binding-r129",
        target_resolution_mode="canonical-artifact-binding",
        credential_class="none",
        credential_reference=None,
        quota_reference="quota-r129",
        quota_available=True,
        runner_id="runner-r129",
        runner_workload_identity="spiffe://redagent.test/runner/r129",
        runner_ready=True,
        reservation_id="reservation-r129",
        lease_id="artifact-binding-r129",
        lease_expires_at=datetime(2026, 8, 29, tzinfo=timezone.utc),
        stop_requested=False,
        observed_at=datetime(2026, 8, 28, 11, 59, tzinfo=timezone.utc),
        expires_at=datetime(2026, 8, 29, tzinfo=timezone.utc),
    )


def test_artifact_campaign_adapter_runs_real_r110_zero_execution_path() -> None:
    writer = ResultWriter()
    adapter = ArtifactCampaignAdapter(ROOT, writer, clock=lambda: NOW)

    receipt = asyncio.run(adapter.dispatch(_request()))

    assert receipt.state == "confirmed"
    assert len(writer.materials) == 1
    material = writer.materials[0]
    report = json.loads(material.report_safe_content)
    assert material.coverage_state is CoverageState.COMPLETE
    assert report["profile_id"] == "r110-repository-snapshot-v1"
    assert report["untrusted_execution_count"] == 0
    assert report["external_contact_count"] == 0
    assert report["cleanup"]["residual_resource_count"] == 0
    assert report["findings"]
    assert all(item.tool == "redagent-canonical-artifact" for item in material.findings)


def test_artifact_campaign_adapter_rejects_cross_capability_binding_and_lookup_is_read_only() -> None:
    writer = ResultWriter()
    adapter = ArtifactCampaignAdapter(ROOT, writer, clock=lambda: NOW)
    request = _request()

    assert asyncio.run(adapter.lookup(request)) is None
    assert len(writer.lookups) == 1
    with pytest.raises(ValueError, match="artifact_campaign_binding_mismatch"):
        asyncio.run(adapter.dispatch(replace(
            request,
            capability_id="zap-controlled-runtime",
            capability_revision=2,
        )))


def test_artifact_campaign_planner_resolves_receipt_server_side_and_emits_three_bindings() -> None:
    facts_owner = LocalCampaignPlanningFactsOwner(ROOT)
    request = _start_request()
    authority = _authority()

    facts = asyncio.run(facts_owner.read(request, authority, now=NOW))
    planner = DeterministicCampaignStartPlanner(
        facts_owner,
        PolicyBoundCampaignAuthorizationOwner(
            Ed25519PrivateKey.generate(),
            signing_key_id="r129-test-signing-key",
        ),
    )
    material = asyncio.run(
        planner.prepare(
            request,
            authority,
            campaign_id="campaign-r129",
            now=NOW,
        )
    )

    assert facts.artifact_receipt is not None
    assert facts.snapshot.schema_version == "redagent.artifact-posture-decision-context/v2"
    assert material.decision_schema == "redagent.artifact-posture-strategy-receipt/v2"
    assert material.plan_payload["primary"]["capability_id"] == "artifact-posture"
    assert len(material.context_payload["bindings"]) == 3
    binding = binding_from_campaign_context(material.context_payload, "artifact-posture")
    assert binding.capability_revision == 1
    assert "artifact_receipt" not in {field for field in request.__dataclass_fields__}
