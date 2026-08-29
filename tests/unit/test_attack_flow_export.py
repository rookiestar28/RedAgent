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
    CampaignLineageArtifactInputV1,
    CampaignTerminalDisposition,
    LineageArtifactState,
    REQUIRED_LINEAGE_ARTIFACT_KINDS,
    build_campaign_evidence_bundle,
    campaign_context_sha256,
    verify_campaign_evidence_bundle,
    write_campaign_evidence_bundle,
)
from redagent_platform.evidence_chain import EvidenceAccessPolicy


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _verified(tmp_path, *, access_policy: EvidenceAccessPolicy = EvidenceAccessPolicy.REVIEWERS_ONLY):
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
                payload={"source_sha256": _digest(kind.value), "complete": True},
                access_policy=access_policy,
            )
            for kind in REQUIRED_LINEAGE_ARTIFACT_KINDS
        ),
        terminal_disposition=CampaignTerminalDisposition.QUALIFIED,
        loss_reasons=(),
    )
    path = tmp_path / "bundle"
    write_campaign_evidence_bundle(bundle, path)
    return verify_campaign_evidence_bundle(
        path,
        trust_anchor=CampaignEvidenceTrustAnchorV1(
            expected_manifest_sha256=bundle.manifest_sha256,
            expected_signed_authority_sha256=signed,
            expected_tenant_sha256=campaign_context_sha256("tenant-alpha"),
            expected_campaign_sha256=campaign_context_sha256("campaign-alpha"),
        ),
    )


def test_attack_flow_export_is_permission_gated_deterministic_and_sanitized(tmp_path) -> None:
    verified = _verified(tmp_path)
    request = AttackFlowExportRequestV1(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        roles=("reviewer",),
        exported_at=datetime(2026, 8, 29, tzinfo=timezone.utc),
    )

    first = export_verified_campaign_attack_flow(verified, request=request)
    second = export_verified_campaign_attack_flow(verified, request=request)

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
    verified = _verified(tmp_path)
    now = datetime(2026, 8, 29, tzinfo=timezone.utc)
    with pytest.raises(PermissionError, match="permission"):
        export_verified_campaign_attack_flow(
            verified,
            request=AttackFlowExportRequestV1(
                tenant_id="tenant-alpha",
                campaign_id="campaign-alpha",
                roles=("operator",),
                exported_at=now,
            ),
        )
    with pytest.raises(PermissionError, match="binding"):
        export_verified_campaign_attack_flow(
            verified,
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


def test_security_lead_only_bundle_requires_tenant_admin_role(tmp_path) -> None:
    verified = _verified(tmp_path, access_policy=EvidenceAccessPolicy.SECURITY_LEADS_ONLY)
    now = datetime(2026, 8, 29, tzinfo=timezone.utc)
    with pytest.raises(PermissionError, match="security_lead"):
        export_verified_campaign_attack_flow(
            verified,
            request=AttackFlowExportRequestV1(
                tenant_id="tenant-alpha",
                campaign_id="campaign-alpha",
                roles=("reviewer",),
                exported_at=now,
            ),
        )
    export = export_verified_campaign_attack_flow(
        verified,
        request=AttackFlowExportRequestV1(
            tenant_id="tenant-alpha",
            campaign_id="campaign-alpha",
            roles=("tenant_admin",),
            exported_at=now,
        ),
    )
    assert export["x_redagent_non_executable"] is True
