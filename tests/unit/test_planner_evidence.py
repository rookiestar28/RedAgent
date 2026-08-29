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
    MAX_CAMPAIGN_EVIDENCE_ARTIFACTS,
    REQUIRED_LINEAGE_ARTIFACT_KINDS,
    build_campaign_evidence_bundle,
    campaign_context_sha256,
    lineage_source_schema_version,
    verify_campaign_evidence_bundle,
    write_campaign_evidence_bundle,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes


SHA = "a" * 64


def _digest(label: str) -> str:
    return hashlib.sha256(label.encode("ascii")).hexdigest()


def _inputs(
    *,
    excluded: frozenset[LineageArtifactKind] = frozenset(),
    states: dict[LineageArtifactKind, LineageArtifactState] | None = None,
    counts: dict[LineageArtifactKind, int] | None = None,
) -> tuple[CampaignLineageArtifactInputV1, ...]:
    records = []
    previous: str | None = None
    for kind in REQUIRED_LINEAGE_ARTIFACT_KINDS:
        if kind in excluded:
            continue
        count = (counts or {}).get(kind, 1)
        for record_index in range(count):
            source_sha256 = _digest(kind.value if count == 1 else f"{kind.value}-{record_index}")
            state = (states or {}).get(kind, LineageArtifactState.COMPLETE)
            records.append(
                CampaignLineageArtifactInputV1(
                    kind=kind,
                    source_schema_version=lineage_source_schema_version(kind),
                    source_record_sha256=source_sha256,
                    source_parent_sha256s=() if previous is None else (previous,),
                    record_index=record_index,
                    record_count=count,
                    state=state,
                    state_reason=(
                        None
                        if state in {LineageArtifactState.COMPLETE, LineageArtifactState.NOT_APPLICABLE}
                        else f"{kind.value.replace('-', '_')}_{state.value.replace('-', '_')}"
                    ),
                )
            )
            previous = source_sha256
    return tuple(records)


def _bundle(tmp_path):
    bundle = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=SHA,
        artifacts=_inputs(),
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


def _coherently_rewrite_artifacts(
    path,
    anchor,
    mutate,
    *,
    sequence_overrides=None,
    mutate_manifest=None,
):
    manifest = json.loads((path / "manifest.json").read_text(encoding="utf-8"))
    artifacts = [
        json.loads((path / entry["name"]).read_text(encoding="utf-8"))
        for entry in manifest["artifacts"]
    ]
    mutate(artifacts)
    if mutate_manifest is not None:
        mutate_manifest(manifest)
    for artifact_path in path.glob("[0-9][0-9][0-9][0-9]-*.json"):
        artifact_path.unlink()

    entries = []
    previous = None
    for index, artifact in enumerate(artifacts):
        artifact["sequence"] = (sequence_overrides or {}).get(index, index)
        artifact["parent_sha256s"] = [] if previous is None else [previous]
        if artifact["kind"] == LineageArtifactKind.TERMINAL_DISPOSITION.value:
            artifact["payload"]["final_chain_sha256"] = previous
            artifact["payload"]["observed_kind_count"] = len(
                {item["kind"] for item in artifacts[:-1]}
            )
        if "payload_sha256" in artifact:
            normalized = artifact["payload"] if isinstance(artifact["payload"], dict) else {}
            artifact["payload_sha256"] = hashlib.sha256(canonical_planning_bytes(normalized)).hexdigest()
        body = dict(artifact)
        body.pop("artifact_sha256", None)
        artifact_sha256 = hashlib.sha256(canonical_planning_bytes(body)).hexdigest()
        artifact["artifact_sha256"] = artifact_sha256
        encoded = canonical_planning_bytes(artifact)
        name = f"{index:04d}-{artifact['kind']}.json"
        (path / name).write_bytes(encoded)
        entries.append(
            {
                "name": name,
                "sequence": (sequence_overrides or {}).get(index, index),
                "kind": artifact["kind"],
                "size_bytes": len(encoded),
                "file_sha256": hashlib.sha256(encoded).hexdigest(),
                "artifact_sha256": artifact_sha256,
            }
        )
        previous = artifact_sha256

    manifest["artifacts"] = entries
    manifest["artifact_count"] = len(entries)
    manifest["terminal_artifact_sha256"] = entries[-1]["artifact_sha256"]
    return _rewrite_manifest(path, manifest, anchor)


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


def test_multiple_source_records_have_contiguous_cardinality_and_optional_na_is_truthful(tmp_path) -> None:
    bundle = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=SHA,
        artifacts=_inputs(
            counts={LineageArtifactKind.EVIDENCE: 2},
            states={
                LineageArtifactKind.CREDENTIAL_LEASE: LineageArtifactState.NOT_APPLICABLE,
                LineageArtifactKind.TRUSTED_OBSERVATION: LineageArtifactState.NOT_APPLICABLE,
                LineageArtifactKind.REPLAN: LineageArtifactState.NOT_APPLICABLE,
                LineageArtifactKind.CONTAINMENT: LineageArtifactState.NOT_APPLICABLE,
            },
        ),
    )
    path = tmp_path / "multiple"
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
    evidence = [item for item in result.artifacts if item.kind is LineageArtifactKind.EVIDENCE]
    assert result.outcome is CampaignEvidenceVerificationOutcome.VERIFIED
    assert [(item.payload["record_index"], item.payload["record_count"]) for item in evidence] == [
        (0, 2),
        (1, 2),
    ]


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

    replacement_records = []
    replacement_parent = None
    for item in _inputs():
        replacement_sha256 = _digest(f"replacement-{item.kind.value}")
        replacement_records.append(
            replace(
                item,
                source_record_sha256=replacement_sha256,
                source_parent_sha256s=() if replacement_parent is None else (replacement_parent,),
            )
        )
        replacement_parent = replacement_sha256
    replacement = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=SHA,
        artifacts=tuple(replacement_records),
    )
    replacement_path = tmp_path / "replacement"
    write_campaign_evidence_bundle(replacement, replacement_path)
    assert replacement.manifest_sha256 != bundle.manifest_sha256
    with pytest.raises(CampaignEvidenceVerificationError, match="manifest"):
        verify_campaign_evidence_bundle(replacement_path, trust_anchor=anchor)


def test_truthful_incomplete_bundle_is_deterministic_non_pass(tmp_path) -> None:
    inputs = _inputs(excluded=frozenset({LineageArtifactKind.CLEANUP}))
    bundle = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=SHA,
        artifacts=inputs,
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
    assert result.loss_reasons == ("cleanup_missing",)


def test_source_record_contract_rejects_arbitrary_payload_and_unknown_schema() -> None:
    with pytest.raises(TypeError):
        CampaignLineageArtifactInputV1(
            kind=LineageArtifactKind.EVIDENCE,
            source_schema_version=lineage_source_schema_version(LineageArtifactKind.EVIDENCE),
            source_record_sha256=SHA,
            source_parent_sha256s=("b" * 64,),
            record_index=0,
            record_count=1,
            state=LineageArtifactState.COMPLETE,
            payload={"value": 123},  # type: ignore[call-arg]
        )
    with pytest.raises(ValueError, match="source_schema"):
        CampaignLineageArtifactInputV1(
            kind=LineageArtifactKind.EVIDENCE,
            source_schema_version="redagent.unapproved/v1",
            source_record_sha256=SHA,
            source_parent_sha256s=("b" * 64,),
            record_index=0,
            record_count=1,
            state=LineageArtifactState.COMPLETE,
        )


def test_semantic_cardinality_parent_and_required_state_are_fail_closed() -> None:
    base = list(_inputs())
    evidence_index = next(index for index, item in enumerate(base) if item.kind is LineageArtifactKind.EVIDENCE)
    duplicate = replace(
        base[evidence_index],
        source_record_sha256=_digest("second-evidence"),
        record_index=0,
        record_count=1,
    )
    base.insert(evidence_index + 1, duplicate)
    with pytest.raises(ValueError, match="cardinality|record_index"):
        build_campaign_evidence_bundle(
            tenant_id="tenant-alpha",
            campaign_id="campaign-alpha",
            signed_authority_sha256=SHA,
            artifacts=tuple(base),
        )

    orphaned = list(_inputs())
    orphaned[4] = replace(orphaned[4], source_parent_sha256s=("f" * 64,))
    with pytest.raises(ValueError, match="parent"):
        build_campaign_evidence_bundle(
            tenant_id="tenant-alpha",
            campaign_id="campaign-alpha",
            signed_authority_sha256=SHA,
            artifacts=tuple(orphaned),
        )

    with pytest.raises(ValueError, match="not_applicable"):
        _inputs(states={LineageArtifactKind.AUTHORIZATION: LineageArtifactState.NOT_APPLICABLE})


@pytest.mark.parametrize(
    ("kind", "state", "expected_outcome"),
    [
        (LineageArtifactKind.CLEANUP, LineageArtifactState.MISSING, CampaignEvidenceVerificationOutcome.INCOMPLETE),
        (LineageArtifactKind.EVIDENCE, LineageArtifactState.AMBIGUOUS, CampaignEvidenceVerificationOutcome.AMBIGUOUS),
        (LineageArtifactKind.RUNNER_RESULT, LineageArtifactState.LOST, CampaignEvidenceVerificationOutcome.LOST),
    ],
)
def test_terminal_loss_is_derived_from_matching_source_state(tmp_path, kind, state, expected_outcome) -> None:
    bundle = build_campaign_evidence_bundle(
        tenant_id="tenant-alpha",
        campaign_id="campaign-alpha",
        signed_authority_sha256=SHA,
        artifacts=_inputs(states={kind: state}),
    )
    path = tmp_path / state.value
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
    assert result.outcome is expected_outcome
    assert result.loss_reasons == (f"{kind.value.replace('-', '_')}_{state.value.replace('-', '_')}",)


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


@pytest.mark.parametrize("attack", ["non-object-payload", "boolean-sequence", "coherent-reorder"])
def test_coherently_repinned_malformed_or_reordered_bundle_fails_closed(tmp_path, attack: str) -> None:
    _, path, anchor = _bundle(tmp_path)
    sequence_overrides = {1: True} if attack == "boolean-sequence" else None

    def mutate(artifacts):
        if attack == "non-object-payload":
            artifacts[1]["payload"] = []
        elif attack == "coherent-reorder":
            artifacts[2], artifacts[3] = artifacts[3], artifacts[2]

    anchor = _coherently_rewrite_artifacts(
        path,
        anchor,
        mutate,
        sequence_overrides=sequence_overrides,
    )
    with pytest.raises(CampaignEvidenceVerificationError):
        verify_campaign_evidence_bundle(path, trust_anchor=anchor)


@pytest.mark.parametrize(
    ("attack", "malformed_value"),
    [
        ("heterogeneous-parents", [0, "b" * 64]),
        ("unhashable-parents", [["b" * 64]]),
        ("heterogeneous-loss", [0, "fabricated_loss"]),
        ("unhashable-loss", [["fabricated_loss"]]),
    ],
)
def test_coherently_repinned_container_types_raise_typed_verification_error(
    tmp_path,
    attack: str,
    malformed_value: list[object],
) -> None:
    _, path, anchor = _bundle(tmp_path)

    def mutate(artifacts):
        if attack.endswith("parents"):
            artifacts[2]["payload"]["source_parent_sha256s"] = malformed_value
        else:
            artifacts[-1]["payload"]["loss_reasons"] = malformed_value

    anchor = _coherently_rewrite_artifacts(path, anchor, mutate)
    with pytest.raises(CampaignEvidenceVerificationError):
        verify_campaign_evidence_bundle(path, trust_anchor=anchor)


@pytest.mark.parametrize("attack", ["cardinality", "duplicate-source", "terminal-lie"])
def test_coherently_repinned_semantic_lineage_lies_fail_closed(tmp_path, attack: str) -> None:
    _, path, anchor = _bundle(tmp_path)

    def mutate(artifacts):
        if attack == "cardinality":
            artifacts[4]["payload"]["record_count"] = 2
        elif attack == "duplicate-source":
            artifacts[4]["payload"]["source_record_sha256"] = artifacts[3]["payload"][
                "source_record_sha256"
            ]
        else:
            terminal = artifacts[-1]
            terminal["state"] = LineageArtifactState.AMBIGUOUS.value
            terminal["payload"]["disposition"] = CampaignTerminalDisposition.AMBIGUOUS.value
            terminal["payload"]["loss_reasons"] = ["fabricated_ambiguity"]

    def mutate_manifest(manifest):
        if attack == "terminal-lie":
            manifest["terminal_disposition"] = CampaignTerminalDisposition.AMBIGUOUS.value
            manifest["loss_reasons"] = ["fabricated_ambiguity"]

    anchor = _coherently_rewrite_artifacts(
        path,
        anchor,
        mutate,
        mutate_manifest=mutate_manifest,
    )
    with pytest.raises(CampaignEvidenceVerificationError):
        verify_campaign_evidence_bundle(path, trust_anchor=anchor)


def test_json_depth_and_directory_inventory_are_bounded(tmp_path) -> None:
    _, deep_path, deep_anchor = _bundle(tmp_path)

    def deepen(artifacts):
        nested: object = 1
        for _ in range(40):
            nested = [nested]
        artifacts[1]["payload"]["nested"] = nested

    deep_anchor = _coherently_rewrite_artifacts(deep_path, deep_anchor, deepen)
    with pytest.raises(CampaignEvidenceVerificationError, match="depth"):
        verify_campaign_evidence_bundle(deep_path, trust_anchor=deep_anchor)

    inventory_root = tmp_path / "inventory"
    inventory_root.mkdir()
    _, inventory_path, inventory_anchor = _bundle(inventory_root)
    for index in range(MAX_CAMPAIGN_EVIDENCE_ARTIFACTS + 2):
        (inventory_path / f"extra-{index:03d}.json").write_text("{}", encoding="ascii")
    with pytest.raises(CampaignEvidenceVerificationError, match="inventory_too_large"):
        verify_campaign_evidence_bundle(inventory_path, trust_anchor=inventory_anchor)


def test_oversized_artifact_fails_before_parsing(tmp_path) -> None:
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


def test_file_symlink_artifact_fails_before_parsing(tmp_path) -> None:
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
