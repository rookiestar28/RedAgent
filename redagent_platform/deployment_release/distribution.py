"""Signed, closed, content-addressed disconnected bundle verification."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import base64
import binascii
import hashlib
import json
import os
from pathlib import Path
from pathlib import PurePosixPath
import re
import shutil
from typing import Mapping
import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec


class ArtifactClass(str, Enum):
    IMAGE = "image"
    CHART = "chart"
    MIGRATION = "migration"
    POLICY = "policy"
    COVERAGE = "coverage"
    ADAPTER = "adapter"
    TEMPLATE = "template"
    VULNERABILITY_DATABASE = "vulnerability_database"
    SBOM = "sbom"
    SIGNATURE = "signature"
    ATTESTATION = "attestation"


@dataclass(frozen=True, kw_only=True)
class ArtifactDescriptor:
    path: str
    artifact_class: ArtifactClass
    sha256: str
    size: int
    subject_sha256: str | None = None


@dataclass(frozen=True, kw_only=True)
class SignedBundle:
    schema: str
    descriptors: tuple[ArtifactDescriptor, ...]
    signer_identity: str
    builder_id: str
    source_revision: str
    manifest_sha256: str
    signature: bytes


@dataclass(frozen=True, kw_only=True)
class BundlePolicy:
    trusted_signer: str
    expected_builder: str
    expected_source_revision: str
    max_artifacts: int
    max_total_bytes: int


@dataclass(frozen=True, kw_only=True)
class BundleVerificationReceipt:
    accepted: bool
    manifest_sha256: str
    artifact_count: int
    total_bytes: int
    network_contact_count: int
    executed_artifact_count: int
    production_qualified: bool = False


@dataclass(frozen=True, kw_only=True)
class BundleStagingReceipt:
    accepted: bool
    manifest_sha256: str
    staged_directory: str
    staged_file_count: int
    staged_bytes: int
    network_contact_count: int
    executed_artifact_count: int
    production_qualified: bool = False


_REVISION = re.compile(r"^[0-9a-f]{40,64}$")


def create_signed_bundle(
    contents: Mapping[str, tuple[ArtifactClass, bytes]],
    *,
    signer_identity: str,
    builder_id: str,
    source_revision: str,
    private_key: ec.EllipticCurvePrivateKey,
) -> SignedBundle:
    if not signer_identity or not builder_id or not _REVISION.fullmatch(source_revision):
        raise ValueError("bundle_provenance_invalid")
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise ValueError("bundle_signing_key_invalid")
    descriptors = _descriptors(contents)
    manifest = _manifest(descriptors, signer_identity, builder_id, source_revision)
    encoded = _canonical(manifest)
    return SignedBundle(
        schema="redagent.airgap-bundle/v1",
        descriptors=descriptors,
        signer_identity=signer_identity,
        builder_id=builder_id,
        source_revision=source_revision,
        manifest_sha256=hashlib.sha256(encoded).hexdigest(),
        signature=private_key.sign(encoded, ec.ECDSA(hashes.SHA256())),
    )


def verify_signed_bundle(
    bundle: SignedBundle,
    contents: Mapping[str, tuple[ArtifactClass, bytes]],
    *,
    policy: BundlePolicy,
    public_key: ec.EllipticCurvePublicKey,
) -> BundleVerificationReceipt:
    digest = _verify_bundle_envelope(bundle, policy=policy, public_key=public_key)
    expected_paths = {item.path for item in bundle.descriptors}
    if expected_paths != set(contents):
        raise ValueError("bundle_content_set_mismatch")
    total_bytes = 0
    for descriptor in bundle.descriptors:
        kind, content = contents[descriptor.path]
        total_bytes += len(content)
        if kind is not descriptor.artifact_class:
            raise ValueError("bundle_artifact_class_mismatch")
        if hashlib.sha256(content).hexdigest() != descriptor.sha256 or len(content) != descriptor.size:
            raise ValueError("bundle_artifact_digest_mismatch")
    if total_bytes > policy.max_total_bytes or policy.max_total_bytes <= 0:
        raise ValueError("bundle_total_size_exceeded")
    return BundleVerificationReceipt(
        accepted=True,
        manifest_sha256=digest,
        artifact_count=len(bundle.descriptors),
        total_bytes=total_bytes,
        network_contact_count=0,
        executed_artifact_count=0,
    )


def verify_signed_bundle_files(
    bundle: SignedBundle,
    content_root: Path,
    *,
    policy: BundlePolicy,
    public_key: ec.EllipticCurvePublicKey,
) -> tuple[BundleVerificationReceipt, dict[str, Path]]:
    digest = _verify_bundle_envelope(bundle, policy=policy, public_key=public_key)
    paths = _closed_content_paths(content_root, bundle.descriptors)
    total_bytes = 0
    for descriptor in bundle.descriptors:
        path = paths[descriptor.path]
        size, observed = _file_digest(path)
        total_bytes += size
        if size != descriptor.size or observed != descriptor.sha256:
            raise ValueError("bundle_artifact_digest_mismatch")
        if total_bytes > policy.max_total_bytes or policy.max_total_bytes <= 0:
            raise ValueError("bundle_total_size_exceeded")
    return (
        BundleVerificationReceipt(
            accepted=True,
            manifest_sha256=digest,
            artifact_count=len(bundle.descriptors),
            total_bytes=total_bytes,
            network_contact_count=0,
            executed_artifact_count=0,
        ),
        paths,
    )


def _verify_bundle_envelope(
    bundle: SignedBundle,
    *,
    policy: BundlePolicy,
    public_key: ec.EllipticCurvePublicKey,
) -> str:
    _validate_bundle_descriptors(bundle.descriptors)
    if bundle.schema != "redagent.airgap-bundle/v1":
        raise ValueError("bundle_schema_invalid")
    if (
        bundle.signer_identity != policy.trusted_signer
        or bundle.builder_id != policy.expected_builder
        or bundle.source_revision != policy.expected_source_revision
    ):
        raise ValueError("bundle_provenance_expectation_mismatch")
    if len(bundle.descriptors) > policy.max_artifacts or policy.max_artifacts <= 0:
        raise ValueError("bundle_artifact_limit_exceeded")
    if not set(ArtifactClass).issubset({item.artifact_class for item in bundle.descriptors}):
        raise ValueError("bundle_required_artifact_class_missing")
    manifest = _manifest(bundle.descriptors, bundle.signer_identity, bundle.builder_id, bundle.source_revision)
    encoded = _canonical(manifest)
    digest = hashlib.sha256(encoded).hexdigest()
    if digest != bundle.manifest_sha256:
        raise ValueError("bundle_manifest_digest_mismatch")
    try:
        if not isinstance(public_key.curve, ec.SECP256R1):
            raise InvalidSignature
        public_key.verify(bundle.signature, encoded, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature as exc:
        raise ValueError("bundle_signature_invalid") from exc
    return digest


def _closed_content_paths(
    content_root: Path,
    descriptors: tuple[ArtifactDescriptor, ...],
) -> dict[str, Path]:
    if not content_root.is_dir() or content_root.is_symlink():
        raise ValueError("bundle_content_root_invalid")
    entries = tuple(content_root.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise ValueError("bundle_content_symlink_forbidden")
    paths = {
        path.relative_to(content_root).as_posix(): path
        for path in entries
        if path.is_file()
    }
    if set(paths) != {descriptor.path for descriptor in descriptors}:
        raise ValueError("bundle_content_set_mismatch")
    return paths


def _file_digest(path: Path) -> tuple[int, str]:
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            size += len(chunk)
            digest.update(chunk)
    return size, digest.hexdigest()


def stage_verified_bundle_files(
    bundle: SignedBundle,
    content_root: Path,
    *,
    policy: BundlePolicy,
    public_key: ec.EllipticCurvePublicKey,
    staging_root: Path,
) -> BundleStagingReceipt:
    verification, sources = verify_signed_bundle_files(
        bundle,
        content_root,
        policy=policy,
        public_key=public_key,
    )
    staging_root.mkdir(parents=True, exist_ok=True)
    if not staging_root.is_dir() or staging_root.is_symlink():
        raise ValueError("bundle_staging_root_invalid")
    final = staging_root / verification.manifest_sha256
    if final.exists():
        _verify_staged_directory_files(final, bundle.descriptors, verification)
        return _staging_receipt(verification, final.name)
    temporary = staging_root / f".{verification.manifest_sha256}.tmp-{uuid.uuid4().hex}"
    temporary.mkdir(mode=0o700)
    try:
        for descriptor in bundle.descriptors:
            target = temporary.joinpath(*PurePosixPath(descriptor.path).parts)
            target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            digest = hashlib.sha256()
            size = 0
            with sources[descriptor.path].open("rb") as source, target.open("xb") as output:
                while chunk := source.read(1024 * 1024):
                    size += len(chunk)
                    digest.update(chunk)
                    output.write(chunk)
            if size != descriptor.size or digest.hexdigest() != descriptor.sha256:
                raise ValueError("bundle_artifact_changed_during_staging")
            target.chmod(0o600)
        (temporary / "staging-receipt.json").write_bytes(
            _canonical(_staging_receipt_document(verification)) + b"\n"
        )
        try:
            os.replace(temporary, final)
        except OSError:
            if not final.is_dir():
                raise
            _verify_staged_directory_files(final, bundle.descriptors, verification)
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)
    _verify_staged_directory_files(final, bundle.descriptors, verification)
    return _staging_receipt(verification, final.name)


def _verify_staged_directory_files(
    directory: Path,
    descriptors: tuple[ArtifactDescriptor, ...],
    verification: BundleVerificationReceipt,
) -> None:
    if not directory.is_dir() or directory.is_symlink():
        raise ValueError("bundle_staging_destination_invalid")
    entries = tuple(directory.rglob("*"))
    if any(path.is_symlink() for path in entries):
        raise ValueError("bundle_staging_symlink_forbidden")
    paths = {
        path.relative_to(directory).as_posix(): path
        for path in entries
        if path.is_file()
    }
    expected = {descriptor.path for descriptor in descriptors} | {"staging-receipt.json"}
    if set(paths) != expected:
        raise ValueError("bundle_staging_content_set_mismatch")
    for descriptor in descriptors:
        size, digest = _file_digest(paths[descriptor.path])
        if size != descriptor.size or digest != descriptor.sha256:
            raise ValueError("bundle_staging_artifact_mismatch")
    expected_receipt = _canonical(_staging_receipt_document(verification)) + b"\n"
    if paths["staging-receipt.json"].read_bytes() != expected_receipt:
        raise ValueError("bundle_staging_receipt_mismatch")


def _staging_receipt_document(verification: BundleVerificationReceipt) -> dict[str, object]:
    return {
        "schema": "redagent.airgap-staging-receipt/v1",
        "manifest_sha256": verification.manifest_sha256,
        "artifact_count": verification.artifact_count,
        "total_bytes": verification.total_bytes,
        "network_contact_count": 0,
        "executed_artifact_count": 0,
        "production_qualified": False,
    }


def _staging_receipt(
    verification: BundleVerificationReceipt,
    directory_name: str,
) -> BundleStagingReceipt:
    return BundleStagingReceipt(
        accepted=True,
        manifest_sha256=verification.manifest_sha256,
        staged_directory=directory_name,
        staged_file_count=verification.artifact_count,
        staged_bytes=verification.total_bytes,
        network_contact_count=0,
        executed_artifact_count=0,
    )


def signed_bundle_to_dict(bundle: SignedBundle) -> dict[str, object]:
    return {
        "schema": bundle.schema,
        "descriptors": [
            {**asdict(item), "artifact_class": item.artifact_class.value}
            for item in bundle.descriptors
        ],
        "signer_identity": bundle.signer_identity,
        "builder_id": bundle.builder_id,
        "source_revision": bundle.source_revision,
        "manifest_sha256": bundle.manifest_sha256,
        "signature_base64": base64.b64encode(bundle.signature).decode("ascii"),
    }


def signed_bundle_from_dict(value: object) -> SignedBundle:
    if not isinstance(value, dict) or not isinstance(value.get("descriptors"), list):
        raise ValueError("bundle_document_invalid")
    try:
        descriptors = tuple(
            ArtifactDescriptor(
                path=str(item["path"]),
                artifact_class=ArtifactClass(str(item["artifact_class"])),
                sha256=str(item["sha256"]),
                size=int(item["size"]),
                subject_sha256=str(item["subject_sha256"]) if item.get("subject_sha256") is not None else None,
            )
            for item in value["descriptors"]
            if isinstance(item, dict)
        )
        signature = base64.b64decode(str(value["signature_base64"]), validate=True)
        bundle = SignedBundle(
            schema=str(value["schema"]),
            descriptors=descriptors,
            signer_identity=str(value["signer_identity"]),
            builder_id=str(value["builder_id"]),
            source_revision=str(value["source_revision"]),
            manifest_sha256=str(value["manifest_sha256"]),
            signature=signature,
        )
    except (KeyError, TypeError, ValueError, binascii.Error) as exc:
        raise ValueError("bundle_document_invalid") from exc
    if len(descriptors) != len(value["descriptors"]):
        raise ValueError("bundle_document_invalid")
    _validate_bundle_descriptors(descriptors)
    return bundle


def _descriptors(contents: Mapping[str, tuple[ArtifactClass, bytes]]) -> tuple[ArtifactDescriptor, ...]:
    collisions: set[str] = set()
    descriptors: list[ArtifactDescriptor] = []
    for path, (artifact_class, content) in contents.items():
        _validate_path(path)
        folded = path.casefold()
        if folded in collisions:
            raise ValueError("bundle_artifact_path_collision")
        collisions.add(folded)
        if not isinstance(content, bytes):
            raise ValueError("bundle_artifact_content_invalid")
        descriptors.append(
            ArtifactDescriptor(
                path=path,
                artifact_class=artifact_class,
                sha256=hashlib.sha256(content).hexdigest(),
                size=len(content),
            )
        )
    image_subject = next(
        (item.sha256 for item in sorted(descriptors, key=lambda value: value.path) if item.artifact_class is ArtifactClass.IMAGE),
        None,
    )
    with_subjects = tuple(
        ArtifactDescriptor(
            path=item.path,
            artifact_class=item.artifact_class,
            sha256=item.sha256,
            size=item.size,
            subject_sha256=(
                image_subject
                if item.artifact_class in {ArtifactClass.SBOM, ArtifactClass.SIGNATURE, ArtifactClass.ATTESTATION}
                else None
            ),
        )
        for item in sorted(descriptors, key=lambda value: value.path)
    )
    _validate_bundle_descriptors(with_subjects)
    return with_subjects


def _validate_bundle_descriptors(descriptors: tuple[ArtifactDescriptor, ...]) -> None:
    paths: set[str] = set()
    folded_paths: set[str] = set()
    primary_digests = {
        item.sha256
        for item in descriptors
        if item.artifact_class not in {ArtifactClass.SBOM, ArtifactClass.SIGNATURE, ArtifactClass.ATTESTATION}
    }
    for item in descriptors:
        _validate_path(item.path)
        if item.path in paths or item.path.casefold() in folded_paths:
            raise ValueError("bundle_artifact_path_collision")
        paths.add(item.path)
        folded_paths.add(item.path.casefold())
        if len(item.sha256) != 64 or any(char not in "0123456789abcdef" for char in item.sha256) or item.size < 0:
            raise ValueError("bundle_artifact_descriptor_invalid")
        if item.subject_sha256 is not None and item.subject_sha256 not in primary_digests:
            raise ValueError("bundle_artifact_subject_missing")
    for required_referrer in (ArtifactClass.SBOM, ArtifactClass.SIGNATURE, ArtifactClass.ATTESTATION):
        matching = [item for item in descriptors if item.artifact_class is required_referrer]
        if matching and any(item.subject_sha256 is None for item in matching):
            raise ValueError("bundle_artifact_subject_required")


def _validate_path(path: str) -> None:
    candidate = PurePosixPath(path)
    if not path or "\\" in path or candidate.is_absolute() or ".." in candidate.parts or "." in candidate.parts:
        raise ValueError("bundle_artifact_path_invalid")


def _manifest(
    descriptors: tuple[ArtifactDescriptor, ...],
    signer_identity: str,
    builder_id: str,
    source_revision: str,
) -> dict[str, object]:
    return {
        "schema": "redagent.airgap-bundle/v1",
        "signer_identity": signer_identity,
        "provenance": {
            "predicate_type": "https://slsa.dev/provenance/v1",
            "builder_id": builder_id,
            "source_revision": source_revision,
        },
        "descriptors": [
            {**asdict(item), "artifact_class": item.artifact_class.value}
            for item in sorted(descriptors, key=lambda value: value.path)
        ],
    }


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
