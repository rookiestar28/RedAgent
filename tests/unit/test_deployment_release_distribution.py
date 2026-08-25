from __future__ import annotations

from dataclasses import replace
import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ec

from redagent_platform.deployment_release.distribution import (
    ArtifactClass,
    BundlePolicy,
    create_signed_bundle,
    stage_verified_bundle_files,
    verify_signed_bundle,
)


def _contents() -> dict[str, tuple[ArtifactClass, bytes]]:
    return {
        f"artifacts/{kind.value}.json": (kind, (kind.value + "\n").encode())
        for kind in ArtifactClass
    }


def _policy() -> BundlePolicy:
    return BundlePolicy(
        trusted_signer="release@example.invalid",
        expected_builder="https://github.com/example/redagent/.github/workflows/release.yml",
        expected_source_revision="a" * 40,
        max_artifacts=64,
        max_total_bytes=1_000_000,
    )


def test_complete_signed_airgap_bundle_verifies_offline_without_execution() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    bundle = create_signed_bundle(
        _contents(),
        signer_identity=_policy().trusted_signer,
        builder_id=_policy().expected_builder,
        source_revision=_policy().expected_source_revision,
        private_key=private_key,
    )
    receipt = verify_signed_bundle(bundle, _contents(), policy=_policy(), public_key=private_key.public_key())

    assert receipt.accepted
    assert receipt.network_contact_count == 0
    assert receipt.executed_artifact_count == 0
    assert receipt.artifact_count == len(ArtifactClass)
    assert receipt.production_qualified is False
    image_digest = next(item.sha256 for item in bundle.descriptors if item.artifact_class is ArtifactClass.IMAGE)
    assert all(
        item.subject_sha256 == image_digest
        for item in bundle.descriptors
        if item.artifact_class in {ArtifactClass.SBOM, ArtifactClass.SIGNATURE, ArtifactClass.ATTESTATION}
    )


def test_missing_tampered_unreferenced_or_wrong_provenance_bundle_fails_closed() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    contents = _contents()
    bundle = create_signed_bundle(
        contents,
        signer_identity=_policy().trusted_signer,
        builder_id=_policy().expected_builder,
        source_revision=_policy().expected_source_revision,
        private_key=private_key,
    )

    missing = dict(contents); missing.pop(next(iter(missing)))
    with pytest.raises(ValueError, match="bundle_content_set_mismatch"):
        verify_signed_bundle(bundle, missing, policy=_policy(), public_key=private_key.public_key())

    tampered = dict(contents); path = next(iter(tampered)); tampered[path] = (tampered[path][0], b"altered")
    with pytest.raises(ValueError, match="bundle_artifact_digest_mismatch"):
        verify_signed_bundle(bundle, tampered, policy=_policy(), public_key=private_key.public_key())

    wrong_source = replace(_policy(), expected_source_revision="b" * 40)
    with pytest.raises(ValueError, match="bundle_provenance_expectation_mismatch"):
        verify_signed_bundle(bundle, contents, policy=wrong_source, public_key=private_key.public_key())


def test_bundle_creation_rejects_path_escape_and_case_collision() -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    with pytest.raises(ValueError, match="bundle_artifact_path_invalid"):
        create_signed_bundle(
            {"../escape": (ArtifactClass.IMAGE, b"x")},
            signer_identity="release@example.invalid", builder_id="builder", source_revision="a" * 40,
            private_key=private_key,
        )
    with pytest.raises(ValueError, match="bundle_artifact_path_collision"):
        create_signed_bundle(
            {"A/file": (ArtifactClass.IMAGE, b"x"), "a/FILE": (ArtifactClass.CHART, b"y")},
            signer_identity="release@example.invalid", builder_id="builder", source_revision="a" * 40,
            private_key=private_key,
        )


def test_verified_bundle_stages_atomically_idempotently_and_without_execution(tmp_path: Path) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    contents = _contents()
    bundle = create_signed_bundle(
        contents,
        signer_identity=_policy().trusted_signer,
        builder_id=_policy().expected_builder,
        source_revision=_policy().expected_source_revision,
        private_key=private_key,
    )
    staging_root = tmp_path / "staged"
    content_root = tmp_path / "content"
    for relative, (_, content) in contents.items():
        target = content_root / Path(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    receipt = stage_verified_bundle_files(
        bundle,
        content_root,
        policy=_policy(),
        public_key=private_key.public_key(),
        staging_root=staging_root,
    )

    destination = staging_root / receipt.staged_directory
    assert receipt.accepted
    assert receipt.staged_file_count == len(contents)
    assert receipt.network_contact_count == 0
    assert receipt.executed_artifact_count == 0
    assert destination.is_dir()
    for relative, (_, expected) in contents.items():
        path = destination / Path(*relative.split("/"))
        assert path.read_bytes() == expected
        if os.name != "nt":
            assert path.stat().st_mode & 0o111 == 0
    repeated = stage_verified_bundle_files(
        bundle,
        content_root,
        policy=_policy(),
        public_key=private_key.public_key(),
        staging_root=staging_root,
    )
    assert repeated == receipt

    extra = content_root / "unreferenced.bin"
    extra.write_bytes(b"unexpected")
    with pytest.raises(ValueError, match="bundle_content_set_mismatch"):
        stage_verified_bundle_files(
            bundle,
            content_root,
            policy=_policy(),
            public_key=private_key.public_key(),
            staging_root=staging_root,
        )
    extra.unlink()

    first = destination / Path(*next(iter(contents)).split("/"))
    first.write_bytes(b"altered")
    with pytest.raises(ValueError, match="bundle_staging_artifact_mismatch"):
        stage_verified_bundle_files(
            bundle,
            content_root,
            policy=_policy(),
            public_key=private_key.public_key(),
            staging_root=staging_root,
        )


def test_invalid_bundle_never_creates_staging_root(tmp_path: Path) -> None:
    private_key = ec.generate_private_key(ec.SECP256R1())
    contents = _contents()
    bundle = create_signed_bundle(
        contents,
        signer_identity=_policy().trusted_signer,
        builder_id=_policy().expected_builder,
        source_revision=_policy().expected_source_revision,
        private_key=private_key,
    )
    tampered = dict(contents)
    path = next(iter(tampered))
    tampered[path] = (tampered[path][0], b"altered")
    staging_root = tmp_path / "must-not-exist"
    content_root = tmp_path / "content"
    for relative, (_, content) in tampered.items():
        target = content_root / Path(*relative.split("/"))
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)

    with pytest.raises(ValueError, match="bundle_artifact_digest_mismatch"):
        stage_verified_bundle_files(
            bundle,
            content_root,
            policy=_policy(),
            public_key=private_key.public_key(),
            staging_root=staging_root,
        )
    assert not staging_root.exists()
