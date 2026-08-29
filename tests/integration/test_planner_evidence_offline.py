from __future__ import annotations

import hashlib
import shutil

from redagent_platform.campaign_service.planner_evidence import (
    CampaignEvidenceTrustAnchorV1,
    CampaignEvidenceVerificationOutcome,
    CampaignLineageArtifactInputV1,
    CampaignTerminalDisposition,
    LineageArtifactState,
    REQUIRED_LINEAGE_ARTIFACT_KINDS,
    build_campaign_evidence_bundle,
    campaign_context_sha256,
    verify_campaign_evidence_bundle,
    write_campaign_evidence_bundle,
)


def test_retained_bundle_verifies_after_runtime_fixture_and_cache_cleanup(tmp_path) -> None:
    runtime = tmp_path / "runtime"
    fixture = tmp_path / "fixture"
    cache = tmp_path / "cache"
    for path in (runtime, fixture, cache):
        path.mkdir()
        (path / "ephemeral.txt").write_text("ephemeral", encoding="utf-8")

    signed = "a" * 64
    bundle = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=signed,
        artifacts=tuple(
            CampaignLineageArtifactInputV1(
                kind=kind,
                source_schema_version=f"redagent.{kind.value}/v1",
                state=LineageArtifactState.COMPLETE,
                payload={
                    "source_sha256": hashlib.sha256(kind.value.encode("ascii")).hexdigest(),
                    "complete": True,
                },
            )
            for kind in REQUIRED_LINEAGE_ARTIFACT_KINDS
        ),
        terminal_disposition=CampaignTerminalDisposition.QUALIFIED,
        loss_reasons=(),
    )
    retained = tmp_path / "retained"
    write_campaign_evidence_bundle(bundle, retained)
    for path in (runtime, fixture, cache):
        shutil.rmtree(path)

    result = verify_campaign_evidence_bundle(
        retained,
        trust_anchor=CampaignEvidenceTrustAnchorV1(
            expected_manifest_sha256=bundle.manifest_sha256,
            expected_signed_authority_sha256=signed,
            expected_tenant_sha256=campaign_context_sha256("tenant-alpha"),
            expected_campaign_sha256=campaign_context_sha256("campaign-alpha"),
        ),
    )

    assert result.outcome is CampaignEvidenceVerificationOutcome.VERIFIED
    assert not runtime.exists() and not fixture.exists() and not cache.exists()
