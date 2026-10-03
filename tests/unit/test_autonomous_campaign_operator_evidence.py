from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.campaign_service.operator_evidence import (
    RetainedOperatorBundleV1, verify_operator_bundle,
)
from redagent_platform.campaign_service.planner_evidence import (
    LineageArtifactKind, build_campaign_evidence_bundle, write_campaign_evidence_bundle,
    CampaignEvidenceTrustAnchorV1, campaign_context_sha256,
)
from tests.unit.test_planner_evidence import _inputs


NOW = datetime(2026, 10, 3, tzinfo=timezone.utc)


def retained(tmp_path):
    records = _inputs()
    fingerprint = next(record.source_record_sha256 for record in records if record.kind is LineageArtifactKind.EVIDENCE)
    bundle = build_campaign_evidence_bundle(tenant_id="tenant-alpha", campaign_id="campaign-alpha",
        signed_authority_sha256="a" * 64, artifacts=records)
    path = tmp_path / "retained"
    write_campaign_evidence_bundle(bundle, path)
    anchor = CampaignEvidenceTrustAnchorV1(expected_manifest_sha256=bundle.manifest_sha256,
        expected_signed_authority_sha256="a" * 64, expected_tenant_sha256=campaign_context_sha256("tenant-alpha"),
        expected_campaign_sha256=campaign_context_sha256("campaign-alpha"))
    reference = RetainedOperatorBundleV1(path, anchor, fingerprint, NOW + timedelta(days=1))
    subject = dict(tenant_id="tenant-alpha", campaign_id="campaign-alpha", signed_authority_sha256="a" * 64,
        native_result_sha256=fingerprint, now=NOW)
    return reference, subject


def test_operator_bundle_requires_independent_anchor_exact_native_result_and_retention(tmp_path):
    reference, subject = retained(tmp_path)
    assert verify_operator_bundle(reference, **subject) == reference.trust_anchor.expected_manifest_sha256
    for overrides in ({"tenant_id": "other-tenant"}, {"campaign_id": "other-campaign"},
                      {"signed_authority_sha256": "b" * 64}, {"native_result_sha256": "b" * 64},
                      {"now": reference.retain_until}):
        with pytest.raises(ValueError):
            verify_operator_bundle(reference, **{**subject, **overrides})
    with pytest.raises(ValueError):
        verify_operator_bundle(replace(reference, native_result_sha256="b" * 64), **{**subject, "native_result_sha256": "b" * 64})
    with pytest.raises(ValueError):
        verify_operator_bundle(replace(reference, trust_anchor=replace(reference.trust_anchor,
            expected_manifest_sha256="b" * 64)), **subject)


def test_operator_bundle_cannot_self_pin_or_hide_changed_retained_bytes(tmp_path):
    reference, subject = retained(tmp_path)
    (reference.directory / "manifest.json").write_bytes((reference.directory / "manifest.json").read_bytes() + b" ")
    with pytest.raises(ValueError):
        verify_operator_bundle(reference, **subject)
