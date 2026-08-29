from __future__ import annotations

from dataclasses import replace
import hashlib
import json
import stat
from types import SimpleNamespace

import pytest

from redagent_platform.campaign_service.planner_evidence import (
    CampaignEvidenceTrustAnchorV1,
    CampaignEvidenceVerificationError,
    CampaignEvidenceVerificationOutcome,
    CampaignLineageArtifactInputV1,
    CampaignTerminalDisposition,
    LineageArtifactKind,
    LineageArtifactState,
    MAX_CAMPAIGN_EVIDENCE_FILE_BYTES,
    REQUIRED_LINEAGE_ARTIFACT_KINDS,
    build_campaign_evidence_bundle,
    campaign_context_sha256,
    verify_campaign_evidence_bundle,
    write_campaign_evidence_bundle,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes


SHA = "a" * 64


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _inputs() -> tuple[CampaignLineageArtifactInputV1, ...]:
    return tuple(
        CampaignLineageArtifactInputV1(
            kind=kind,
            source_schema_version=f"redagent.{kind.value}/v1",
            state=LineageArtifactState.COMPLETE,
            payload={"source_sha256": _digest(kind.value), "complete": True},
        )
        for kind in REQUIRED_LINEAGE_ARTIFACT_KINDS
    )


def _bundle(tmp_path):
    bundle = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=SHA,
        artifacts=_inputs(),
        terminal_disposition=CampaignTerminalDisposition.QUALIFIED,
        loss_reasons=(),
    )
    path = tmp_path / "bundle"
    write_campaign_evidence_bundle(bundle, path)
    anchor = CampaignEvidenceTrustAnchorV1(
        expected_manifest_sha256=bundle.manifest_sha256,
        expected_signed_authority_sha256=SHA,
        expected_tenant_sha256=campaign_context_sha256("tenant-alpha"),
        expected_campaign_sha256=campaign_context_sha256("campaign-alpha"),
    )
    return bundle, path, anchor


def _rewrite_manifest(path, payload, anchor):
    encoded = canonical_planning_bytes(payload)
    (path / "manifest.json").write_bytes(encoded)
    return replace(anchor, expected_manifest_sha256=hashlib.sha256(encoded).hexdigest())


def test_complete_bundle_round_trips_with_exact_pinned_context(tmp_path) -> None:
    bundle, path, anchor = _bundle(tmp_path)

    first = verify_campaign_evidence_bundle(path, trust_anchor=anchor)
    second = verify_campaign_evidence_bundle(path, trust_anchor=anchor)

    assert first == second
    assert first.outcome is CampaignEvidenceVerificationOutcome.VERIFIED
    assert first.manifest_sha256 == bundle.manifest_sha256
    assert first.terminal_disposition is CampaignTerminalDisposition.QUALIFIED
    assert first.loss_reasons == ()
    assert tuple(item.sequence for item in first.artifacts) == tuple(range(len(first.artifacts)))
    assert first.artifacts[-1].kind is LineageArtifactKind.TERMINAL_DISPOSITION
    retained_bytes = b"".join(child.read_bytes() for child in path.iterdir())
    assert b"tenant-alpha" not in retained_bytes
    assert b"campaign-alpha" not in retained_bytes


@pytest.mark.parametrize("attack", ["tamper", "missing", "reorder", "duplicate"])
def test_bundle_file_attacks_fail_closed(tmp_path, attack: str) -> None:
    _, path, anchor = _bundle(tmp_path)
    artifact_paths = sorted(path.glob("[0-9][0-9][0-9][0-9]-*.json"))
    if attack == "tamper":
        payload = json.loads(artifact_paths[3].read_text(encoding="utf-8"))
        payload["payload"]["source_sha256"] = "b" * 64
        artifact_paths[3].write_text(json.dumps(payload), encoding="utf-8")
    elif attack == "missing":
        artifact_paths[3].unlink()
    elif attack == "reorder":
        first = artifact_paths[2].read_bytes()
        second = artifact_paths[3].read_bytes()
        artifact_paths[2].write_bytes(second)
        artifact_paths[3].write_bytes(first)
    else:
        (path / "unexpected.json").write_bytes(artifact_paths[3].read_bytes())

    with pytest.raises(CampaignEvidenceVerificationError):
        verify_campaign_evidence_bundle(path, trust_anchor=anchor)


def test_cross_context_and_coherent_replacement_fail_against_external_pin(tmp_path) -> None:
    bundle, path, anchor = _bundle(tmp_path)
    cross_tenant = replace(
        anchor,
        expected_tenant_sha256=campaign_context_sha256("tenant-other"),
    )
    with pytest.raises(CampaignEvidenceVerificationError, match="tenant_binding"):
        verify_campaign_evidence_bundle(path, trust_anchor=cross_tenant)
    cross_campaign = replace(
        anchor,
        expected_campaign_sha256=campaign_context_sha256("campaign-other"),
    )
    with pytest.raises(CampaignEvidenceVerificationError, match="campaign_binding"):
        verify_campaign_evidence_bundle(path, trust_anchor=cross_campaign)

    replacement = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=SHA,
        artifacts=tuple(
            replace(item, payload={"source_sha256": _digest(f"replacement-{item.kind.value}"), "complete": True})
            for item in _inputs()
        ),
        terminal_disposition=CampaignTerminalDisposition.QUALIFIED,
        loss_reasons=(),
    )
    replacement_path = tmp_path / "replacement"
    write_campaign_evidence_bundle(replacement, replacement_path)
    assert replacement.manifest_sha256 != bundle.manifest_sha256
    with pytest.raises(CampaignEvidenceVerificationError, match="manifest"):
        verify_campaign_evidence_bundle(replacement_path, trust_anchor=anchor)


def test_truthful_incomplete_bundle_is_deterministic_non_pass(tmp_path) -> None:
    inputs = tuple(item for item in _inputs() if item.kind is not LineageArtifactKind.CLEANUP)
    bundle = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=SHA,
        artifacts=inputs,
        terminal_disposition=CampaignTerminalDisposition.INCOMPLETE,
        loss_reasons=("cleanup_evidence_missing",),
    )
    path = tmp_path / "incomplete"
    write_campaign_evidence_bundle(bundle, path)
    result = verify_campaign_evidence_bundle(
        path,
        trust_anchor=CampaignEvidenceTrustAnchorV1(
            expected_manifest_sha256=bundle.manifest_sha256,
            expected_signed_authority_sha256=SHA,
            expected_tenant_sha256=campaign_context_sha256("tenant-alpha"),
            expected_campaign_sha256=campaign_context_sha256("campaign-alpha"),
        ),
    )

    assert result.outcome is CampaignEvidenceVerificationOutcome.INCOMPLETE
    assert result.loss_reasons == ("cleanup_evidence_missing",)


def test_secret_bearing_or_raw_identifier_payload_is_rejected() -> None:
    with pytest.raises(ValueError, match="sensitive|identifier"):
        CampaignLineageArtifactInputV1(
            kind=LineageArtifactKind.EVIDENCE,
            source_schema_version="redagent.evidence/v1",
            state=LineageArtifactState.COMPLETE,
            payload={"target_id": "raw-target", "authorization": "Bearer secret"},
        )
    with pytest.raises(ValueError, match="identifier_value"):
        CampaignLineageArtifactInputV1(
            kind=LineageArtifactKind.EVIDENCE,
            source_schema_version="redagent.evidence/v1",
            state=LineageArtifactState.COMPLETE,
            payload={"label": "raw-target"},
        )


@pytest.mark.parametrize("attack", ["schema", "size", "duplicate-name", "path", "malformed"])
def test_manifest_and_parser_attacks_fail_closed(tmp_path, attack: str) -> None:
    _, path, anchor = _bundle(tmp_path)
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    if attack == "schema":
        manifest["schema_version"] = "redagent.campaign-evidence-manifest/v999"
    elif attack == "size":
        manifest["artifacts"][0]["size_bytes"] += 1
    elif attack == "duplicate-name":
        manifest["artifacts"].append(dict(manifest["artifacts"][0]))
        manifest["artifact_count"] += 1
    elif attack == "path":
        manifest["artifacts"][0]["name"] = "../outside.json"
    else:
        artifact = sorted(path.glob("[0-9][0-9][0-9][0-9]-*.json"))[2]
        malformed = b"{"
        artifact.write_bytes(malformed)
        entry = manifest["artifacts"][2]
        entry["size_bytes"] = len(malformed)
        entry["file_sha256"] = hashlib.sha256(malformed).hexdigest()
    anchor = _rewrite_manifest(path, manifest, anchor)

    with pytest.raises(CampaignEvidenceVerificationError):
        verify_campaign_evidence_bundle(path, trust_anchor=anchor)


def test_oversized_and_linklike_artifacts_fail_before_parsing(tmp_path) -> None:
    _, oversized_path, oversized_anchor = _bundle(tmp_path)
    manifest = json.loads((oversized_path / "manifest.json").read_text(encoding="utf-8"))
    artifact = sorted(oversized_path.glob("[0-9][0-9][0-9][0-9]-*.json"))[1]
    oversized = b"x" * (MAX_CAMPAIGN_EVIDENCE_FILE_BYTES + 1)
    artifact.write_bytes(oversized)
    manifest["artifacts"][1]["size_bytes"] = len(oversized)
    manifest["artifacts"][1]["file_sha256"] = hashlib.sha256(oversized).hexdigest()
    oversized_anchor = _rewrite_manifest(oversized_path, manifest, oversized_anchor)
    with pytest.raises(CampaignEvidenceVerificationError, match="too_large"):
        verify_campaign_evidence_bundle(oversized_path, trust_anchor=oversized_anchor)

    link_root = tmp_path / "link-case"
    link_root.mkdir()
    _, link_path, link_anchor = _bundle(link_root)
    linked = sorted(link_path.glob("[0-9][0-9][0-9][0-9]-*.json"))[1]
    outside = tmp_path / "outside-artifact.json"
    outside.write_bytes(linked.read_bytes())
    linked.unlink()
    try:
        linked.symlink_to(outside)
    except OSError as exc:
        pytest.skip(f"host cannot create a test symlink: {exc}")
    with pytest.raises(CampaignEvidenceVerificationError, match="regular_file"):
        verify_campaign_evidence_bundle(link_path, trust_anchor=link_anchor)


def test_windows_reparse_metadata_is_treated_as_linklike() -> None:
    from redagent_platform.campaign_service import planner_evidence

    metadata = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
    assert planner_evidence._is_linklike(metadata)
