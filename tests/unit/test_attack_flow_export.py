from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json

import pytest

from redagent_platform.campaign_service.attack_flow_export import (
    AttackFlowExportRequestV1,
    export_verified_campaign_attack_flow,
)
from redagent_platform.campaign_service.planner_evidence import (
    CampaignEvidenceTrustAnchorV1,
    CampaignEvidenceVerificationOutcome,
    CampaignEvidenceVerificationResultV1,
    CampaignLineageArtifactInputV1,
    CampaignTerminalDisposition,
    LineageArtifactState,
    REQUIRED_LINEAGE_ARTIFACT_KINDS,
    build_campaign_evidence_bundle,
    campaign_context_sha256,
    lineage_source_schema_version,
    verify_campaign_evidence_bundle,
    write_campaign_evidence_bundle,
)
from redagent_platform.evidence_chain import EvidenceAccessPolicy


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _verified(tmp_path, *, access_policy: EvidenceAccessPolicy = EvidenceAccessPolicy.REVIEWERS_ONLY):
    signed = "a" * 64
    records = []
    previous = None
    for kind in REQUIRED_LINEAGE_ARTIFACT_KINDS:
        source_sha256 = _digest(kind.value)
        records.append(
            CampaignLineageArtifactInputV1(
                kind=kind,
                source_schema_version=lineage_source_schema_version(kind),
                source_record_sha256=source_sha256,
                source_parent_sha256s=() if previous is None else (previous,),
                record_index=0,
                record_count=1,
                state=LineageArtifactState.COMPLETE,
                access_policy=access_policy,
            )
        )
        previous = source_sha256
    bundle = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=signed,
        artifacts=tuple(records),
    )
    path = tmp_path / "bundle"
    write_campaign_evidence_bundle(bundle, path)
    anchor = CampaignEvidenceTrustAnchorV1(
        expected_manifest_sha256=bundle.manifest_sha256,
        expected_signed_authority_sha256=signed,
        expected_tenant_sha256=campaign_context_sha256("tenant-alpha"),
        expected_campaign_sha256=campaign_context_sha256("campaign-alpha"),
    )
    return path, anchor, verify_campaign_evidence_bundle(path, trust_anchor=anchor)


def test_attack_flow_export_is_permission_gated_deterministic_and_sanitized(tmp_path) -> None:
    path, anchor, verified = _verified(tmp_path)
    request = AttackFlowExportRequestV1(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        roles=("reviewer",),
        exported_at=datetime(2026, 8, 29, tzinfo=timezone.utc),
    )

    first = export_verified_campaign_attack_flow(path, trust_anchor=anchor, request=request)
    second = export_verified_campaign_attack_flow(path, trust_anchor=anchor, request=request)

    assert first == second
    assert first["type"] == "bundle"
    assert first["x_redagent_non_executable"] is True
    assert first["x_redagent_source_manifest_sha256"] == verified.manifest_sha256
    assert first["x_redagent_semantic_loss"]
    encoded = json.dumps(first, sort_keys=True)
    for raw in ("tenant-alpha", "campaign-alpha", "Bearer", "secret"):
        assert raw not in encoded
    assert any(item["type"] == "attack-flow" for item in first["objects"])
    assert any(item["type"] == "attack-action" for item in first["objects"])
    assert all("command" not in item and "payload" not in item for item in first["objects"])


def test_operator_and_cross_tenant_export_are_denied(tmp_path) -> None:
    path, anchor, _ = _verified(tmp_path)
    now = datetime(2026, 8, 29, tzinfo=timezone.utc)
    with pytest.raises(PermissionError, match="permission"):
        export_verified_campaign_attack_flow(
            path,
            trust_anchor=anchor,
            request=AttackFlowExportRequestV1(
                tenant_id="tenant-alpha",
                campaign_id="campaign-alpha",
                roles=("operator",),
                exported_at=now,
            ),
        )
    with pytest.raises(PermissionError, match="binding"):
        export_verified_campaign_attack_flow(
            path,
            trust_anchor=anchor,
            request=AttackFlowExportRequestV1(
                tenant_id="tenant-other",
                campaign_id="campaign-alpha",
                roles=("reviewer",),
                exported_at=now,
            ),
        )


def test_export_module_has_no_import_or_execution_surface() -> None:
    from redagent_platform.campaign_service import attack_flow_export

    public_names = {name for name in dir(attack_flow_export) if not name.startswith("_")}
    assert not {name for name in public_names if "import" in name.casefold()}
    assert not {name for name in public_names if "execute" in name.casefold() or "dispatch" in name.casefold()}


def test_forged_verified_result_is_not_an_export_input(tmp_path) -> None:
    _, _, verified = _verified(tmp_path)
    forged = CampaignEvidenceVerificationResultV1(
        outcome=CampaignEvidenceVerificationOutcome.VERIFIED,
        manifest_sha256=verified.manifest_sha256,
        signed_authority_sha256=verified.signed_authority_sha256,
        tenant_sha256=verified.tenant_sha256,
        campaign_sha256=verified.campaign_sha256,
        terminal_disposition=CampaignTerminalDisposition.QUALIFIED,
        loss_reasons=(),
        artifacts=(),
    )
    with pytest.raises(ValueError, match="input"):
        export_verified_campaign_attack_flow(
            forged,  # type: ignore[arg-type]
            trust_anchor=CampaignEvidenceTrustAnchorV1(
                expected_manifest_sha256=forged.manifest_sha256,
                expected_signed_authority_sha256=forged.signed_authority_sha256,
                expected_tenant_sha256=forged.tenant_sha256,
                expected_campaign_sha256=forged.campaign_sha256,
            ),
            request=AttackFlowExportRequestV1(
                tenant_id="tenant-alpha",
                campaign_id="campaign-alpha",
                roles=("reviewer",),
                exported_at=datetime(2026, 8, 29, tzinfo=timezone.utc),
            ),
        )


def test_security_lead_only_bundle_requires_tenant_admin_role(tmp_path) -> None:
    path, anchor, _ = _verified(tmp_path, access_policy=EvidenceAccessPolicy.SECURITY_LEADS_ONLY)
    now = datetime(2026, 8, 29, tzinfo=timezone.utc)
    with pytest.raises(PermissionError, match="security_lead"):
        export_verified_campaign_attack_flow(
            path,
            trust_anchor=anchor,
            request=AttackFlowExportRequestV1(
                tenant_id="tenant-alpha",
                campaign_id="campaign-alpha",
                roles=("reviewer",),
                exported_at=now,
            ),
        )
    export = export_verified_campaign_attack_flow(
        path,
        trust_anchor=anchor,
        request=AttackFlowExportRequestV1(
            tenant_id="tenant-alpha",
            campaign_id="campaign-alpha",
            roles=("tenant_admin",),
            exported_at=now,
        ),
    )
    assert export["x_redagent_non_executable"] is True
