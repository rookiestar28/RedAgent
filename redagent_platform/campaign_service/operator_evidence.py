"""Read-only retained bundle binding; paths and anchors never come from HTTP."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hmac
from pathlib import Path

from redagent_platform.campaign_service.planner_evidence import (
    CampaignEvidenceTrustAnchorV1, CampaignEvidenceVerificationOutcome, LineageArtifactKind,
    campaign_context_sha256, verify_campaign_evidence_bundle,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256


@dataclass(frozen=True, slots=True)
class RetainedOperatorBundleV1:
    directory: Path
    trust_anchor: CampaignEvidenceTrustAnchorV1
    native_result_sha256: str
    retain_until: datetime

    def __post_init__(self):
        if not isinstance(self.directory, Path) or not isinstance(self.trust_anchor, CampaignEvidenceTrustAnchorV1):
            raise ValueError("operator_bundle_configuration_invalid")
        if (not isinstance(self.native_result_sha256, str) or len(self.native_result_sha256) != 64
            or any(value not in "0123456789abcdef" for value in self.native_result_sha256)):
            raise ValueError("operator_bundle_native_digest_invalid")
        if not isinstance(self.retain_until, datetime) or self.retain_until.utcoffset() is None:
            raise ValueError("operator_bundle_retention_invalid")


def native_operator_result_sha256(*, execution_run_id, preview_sha256, effects, owners):
    if len(effects) > 100 or len(owners) > 100:
        raise ValueError("operator_bundle_native_result_unbounded")
    return canonical_planning_sha256({"schema": "redagent.operator-native-result/v1",
        "execution_run_id": execution_run_id, "preview_sha256": preview_sha256,
        "effects": sorted((dict(item) for item in effects), key=lambda item: item["effect_id"]),
        "owners": sorted((dict(item) for item in owners), key=lambda item: item["effect_id"])})


def verify_operator_bundle(reference, *, tenant_id, campaign_id, signed_authority_sha256, native_result_sha256, now):
    if not isinstance(reference, RetainedOperatorBundleV1) or not isinstance(now, datetime) or now.utcoffset() is None:
        raise ValueError("operator_bundle_reference_invalid")
    anchor = reference.trust_anchor
    if now >= reference.retain_until or not all(hmac.compare_digest(expected, actual) for expected, actual in (
        (anchor.expected_tenant_sha256, campaign_context_sha256(tenant_id)),
        (anchor.expected_campaign_sha256, campaign_context_sha256(campaign_id)),
        (anchor.expected_signed_authority_sha256, signed_authority_sha256),
        (reference.native_result_sha256, native_result_sha256),
    )):
        raise ValueError("operator_bundle_current_binding_invalid")
    # CRITICAL: an independently pinned manifest is insufficient if it belongs to an older run.
    # Its evidence source must also bind the exact current preview and retained native result owners.
    verified = verify_campaign_evidence_bundle(reference.directory, trust_anchor=anchor)
    fingerprints = tuple(item.payload["source_record_sha256"] for item in verified.artifacts
                         if item.kind is LineageArtifactKind.EVIDENCE)
    if verified.outcome is not CampaignEvidenceVerificationOutcome.VERIFIED or fingerprints != (native_result_sha256,):
        raise ValueError("operator_bundle_native_lineage_invalid")
    return verified.manifest_sha256
