from __future__ import annotations

import hashlib
import shutil

from redagent_platform.campaign_service.planner_evidence import (
    CampaignEvidenceTrustAnchorV1,
    CampaignEvidenceVerificationOutcome,
    CampaignLineageArtifactInputV1,
    LineageArtifactState,
    REQUIRED_LINEAGE_ARTIFACT_KINDS,
    build_campaign_evidence_bundle,
    campaign_context_sha256,
    lineage_source_schema_version,
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
    records = []
    previous = None
    for kind in REQUIRED_LINEAGE_ARTIFACT_KINDS:
        source_sha256 = hashlib.sha256(kind.value.encode("ascii")).hexdigest()
        records.append(
            CampaignLineageArtifactInputV1(
                kind=kind,
                source_schema_version=lineage_source_schema_version(kind),
                source_record_sha256=source_sha256,
                source_parent_sha256s=() if previous is None else (previous,),
                record_index=0,
                record_count=1,
                state=LineageArtifactState.COMPLETE,
            )
        )
        previous = source_sha256
    bundle = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=signed,
        artifacts=tuple(records),
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
