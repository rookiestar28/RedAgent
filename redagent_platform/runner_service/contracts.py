"""Closed immutable compat_100 runner and signed-job contracts."""

from __future__ import annotations

import base64
from dataclasses import asdict, dataclass, fields
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
import re
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


CONTRACT_SCHEMA_VERSION = "1.0"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,99}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_IMAGE_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SPIFFE_ID = re.compile(r"^spiffe://[a-z0-9.-]+/[A-Za-z0-9._/-]+$")
_PHASES = ("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup")
_REQUIRED_UNSUPPORTED = frozenset({"arbitrary_command", "native_template", "plugin_loading"})
_EXECUTABLE_FIELD_NAMES = frozenset(
    {"command", "argv", "shell", "script", "code", "url", "flags", "environment", "mounts", "image", "plugin", "template"}
)


class IsolationTier(str, Enum):
    CONTAINER = "container"
    GVISOR = "gvisor"


class NetworkMode(str, Enum):
    NONE = "none"
    TARGET_ALLOWLIST = "target_allowlist"
    HOST = "host"


class CredentialClass(str, Enum):
    NONE = "none"
    DYNAMIC_DATABASE = "dynamic_database"
    HTTP_HEADER = "http_header"
    CLOUD_READ_ONLY = "cloud_read_only"


@dataclass(frozen=True, kw_only=True)
class ResourceLimits:
    cpu_millis: int
    memory_mib: int
    pids: int
    timeout_seconds: int
    evidence_bytes: int

    def __post_init__(self) -> None:
        _bounded_int("resource_cpu_millis", self.cpu_millis, 50, 4_000)
        _bounded_int("resource_memory_mib", self.memory_mib, 32, 4_096)
        _bounded_int("resource_pids", self.pids, 4, 256)
        _bounded_int("resource_timeout_seconds", self.timeout_seconds, 1, 60)
        _bounded_int("resource_evidence_bytes", self.evidence_bytes, 1, 10 * 1024 * 1024)


@dataclass(frozen=True, kw_only=True)
class SandboxProfile:
    profile_id: str
    isolation_tier: IsolationTier
    runtime_name: str
    run_as_user: int
    read_only_root: bool
    privileged: bool
    host_socket: bool
    host_namespaces: bool
    capabilities: tuple[str, ...]
    no_new_privileges: bool
    seccomp_profile: str
    network_mode: NetworkMode
    writable_mounts: tuple[str, ...]
    limits: ResourceLimits

    def __post_init__(self) -> None:
        _identifier("sandbox_profile_id", self.profile_id)
        _identifier("sandbox_runtime_name", self.runtime_name)
        if isinstance(self.run_as_user, bool) or not 1 <= self.run_as_user <= 2_147_483_647:
            raise ValueError("sandbox_run_as_user_invalid")
        if self.privileged:
            raise ValueError("sandbox_privileged_forbidden")
        if self.host_socket:
            raise ValueError("sandbox_host_socket_forbidden")
        if self.host_namespaces:
            raise ValueError("sandbox_host_namespaces_forbidden")
        if self.capabilities:
            raise ValueError("sandbox_capabilities_forbidden")
        if not self.no_new_privileges:
            raise ValueError("sandbox_no_new_privileges_required")
        if not self.read_only_root:
            raise ValueError("sandbox_read_only_root_required")
        if self.seccomp_profile == "unconfined" or not _IDENTIFIER.fullmatch(self.seccomp_profile):
            raise ValueError("sandbox_seccomp_profile_invalid")
        if self.network_mode is NetworkMode.HOST:
            raise ValueError("sandbox_host_network_forbidden")
        if self.writable_mounts != ("/work",):
            raise ValueError("sandbox_writable_mounts_invalid")
        if self.isolation_tier is IsolationTier.GVISOR and self.runtime_name != "runsc":
            raise ValueError("sandbox_gvisor_runtime_required")
        if self.isolation_tier is IsolationTier.CONTAINER and self.runtime_name == "runsc":
            raise ValueError("sandbox_isolation_runtime_mismatch")


@dataclass(frozen=True, kw_only=True)
class ArtifactVerificationReceipt:
    receipt_id: str
    image_digest: str
    signature_verified: bool
    signer_identity: str
    provenance_sha256: str
    sbom_sha256: str
    vulnerability_review: str
    verifier: str
    verified_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _identifier("artifact_receipt_id", self.receipt_id)
        _image_digest("artifact_image_digest", self.image_digest)
        if not self.signature_verified:
            raise ValueError("artifact_signature_required")
        _reference("artifact_signer_identity", self.signer_identity)
        _sha256("artifact_provenance_sha256", self.provenance_sha256)
        _sha256("artifact_sbom_sha256", self.sbom_sha256)
        if self.vulnerability_review != "accepted_no_critical":
            raise ValueError("artifact_vulnerability_review_invalid")
        _reference("artifact_verifier", self.verifier)
        _aware(self.verified_at)
        _aware(self.expires_at)
        if not self.verified_at < self.expires_at <= self.verified_at + timedelta(days=30):
            raise ValueError("artifact_receipt_expiry_invalid")


@dataclass(frozen=True, kw_only=True)
class ExecutionCapabilityManifest:
    schema_version: str
    capability_id: str
    revision: int
    adapter_id: str
    adapter_version: str
    image_digest: str
    input_schema_id: str
    supported_modes: tuple[str, ...]
    phases: tuple[str, ...]
    sandbox_profile_id: str
    network_mode: NetworkMode
    credential_class: CredentialClass
    evidence_schema: tuple[str, ...]
    unsupported_features: tuple[str, ...]
    limits: ResourceLimits
    artifact_receipt_id: str
    reviewed_by: str
    status: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name, value in (
            ("capability_id", self.capability_id),
            ("capability_adapter_id", self.adapter_id),
            ("capability_adapter_version", self.adapter_version),
            ("capability_input_schema_id", self.input_schema_id),
            ("capability_sandbox_profile_id", self.sandbox_profile_id),
            ("capability_artifact_receipt_id", self.artifact_receipt_id),
            ("capability_reviewed_by", self.reviewed_by),
        ):
            _identifier(name, value)
        _bounded_int("capability_revision", self.revision, 1, 2_147_483_647)
        _image_digest("capability_image_digest", self.image_digest)
        _closed_identifiers("capability_supported_modes", self.supported_modes, maximum=16)
        if self.phases != _PHASES:
            raise ValueError("capability_phases_invalid")
        _closed_identifiers("capability_evidence_schema", self.evidence_schema, maximum=16)
        _closed_identifiers("capability_unsupported_features", self.unsupported_features, maximum=32, allow_empty=True)
        if not _REQUIRED_UNSUPPORTED.issubset(self.unsupported_features):
            raise ValueError("capability_unsupported_features_required")
        if self.status != "certified":
            raise ValueError("capability_status_invalid")
        if self.network_mode is NetworkMode.HOST:
            raise ValueError("capability_network_mode_invalid")


@dataclass(frozen=True, kw_only=True)
class RunnerRegistration:
    runner_id: str
    tenant_id: str
    environment: str
    runner_class_id: str
    network_plane: str
    spiffe_id: str
    certificate_fingerprint: str
    certificate_serial: str
    adapter_allowlist: tuple[str, ...]
    image_allowlist: tuple[str, ...]
    required_policy_revision: str
    generation: int
    registered_at: datetime
    expires_at: datetime
    revoked_at: datetime | None

    def __post_init__(self) -> None:
        for name, value in (
            ("runner_id", self.runner_id),
            ("runner_tenant_id", self.tenant_id),
            ("runner_environment", self.environment),
            ("runner_class_id", self.runner_class_id),
            ("runner_network_plane", self.network_plane),
            ("runner_certificate_serial", self.certificate_serial),
            ("runner_required_policy_revision", self.required_policy_revision),
        ):
            _identifier(name, value)
        if not _SPIFFE_ID.fullmatch(self.spiffe_id):
            raise ValueError("runner_spiffe_id_invalid")
        _sha256("runner_certificate_fingerprint", self.certificate_fingerprint)
        _closed_references("runner_adapter_allowlist", self.adapter_allowlist, maximum=64)
        if not self.image_allowlist or len(self.image_allowlist) > 64 or len(set(self.image_allowlist)) != len(self.image_allowlist):
            raise ValueError("runner_image_allowlist_invalid")
        for value in self.image_allowlist:
            _image_digest("runner_image_allowlist", value)
        _bounded_int("runner_generation", self.generation, 1, 2_147_483_647)
        _aware(self.registered_at)
        _aware(self.expires_at)
        if not self.registered_at < self.expires_at <= self.registered_at + timedelta(hours=24):
            raise ValueError("runner_expiry_invalid")
        if self.revoked_at is not None:
            _aware(self.revoked_at)
            if self.revoked_at < self.registered_at:
                raise ValueError("runner_revoked_at_invalid")


@dataclass(frozen=True, kw_only=True)
class RunnerClassDefinition:
    schema_version: str
    class_id: str
    revision: int
    environment: str
    network_plane: str
    policy_revision: str
    sandbox: SandboxProfile
    credential_classes: tuple[CredentialClass, ...]
    evidence_schemas: tuple[str, ...]
    status: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name, value in (
            ("runner_class_id", self.class_id),
            ("runner_class_environment", self.environment),
            ("runner_class_network_plane", self.network_plane),
            ("runner_class_policy_revision", self.policy_revision),
        ):
            _identifier(name, value)
        _bounded_int("runner_class_revision", self.revision, 1, 2_147_483_647)
        if not isinstance(self.credential_classes, tuple) or not self.credential_classes:
            raise ValueError("runner_class_credential_classes_invalid")
        if len(set(self.credential_classes)) != len(self.credential_classes):
            raise ValueError("runner_class_credential_classes_invalid")
        _closed_identifiers("runner_class_evidence_schemas", self.evidence_schemas, maximum=16)
        if self.status != "certified":
            raise ValueError("runner_class_status_invalid")
        if self.sandbox.network_mode is NetworkMode.NONE and self.network_plane != "isolated-none":
            raise ValueError("runner_class_network_plane_invalid")


@dataclass(frozen=True, kw_only=True)
class JobManifestDraft:
    schema_version: str
    manifest_id: str
    job_id: str
    tenant_id: str
    engagement_id: str
    roe_version_id: str
    environment: str
    runner_class_id: str
    network_plane: str
    adapter_id: str
    adapter_version: str
    capability_digest: str
    image_digest: str
    artifact_receipt_id: str
    policy_revision: str
    policy_decision_id: str
    target_ids: tuple[str, ...]
    target_hashes: tuple[str, ...]
    limits: ResourceLimits
    egress_profile: str
    evidence_schema: tuple[str, ...]
    secret_reference_ids: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    nonce: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name, value in (
            ("manifest_id", self.manifest_id),
            ("manifest_job_id", self.job_id),
            ("manifest_tenant_id", self.tenant_id),
            ("manifest_engagement_id", self.engagement_id),
            ("manifest_roe_version_id", self.roe_version_id),
            ("manifest_environment", self.environment),
            ("manifest_runner_class_id", self.runner_class_id),
            ("manifest_network_plane", self.network_plane),
            ("manifest_adapter_id", self.adapter_id),
            ("manifest_adapter_version", self.adapter_version),
            ("manifest_artifact_receipt_id", self.artifact_receipt_id),
            ("manifest_policy_revision", self.policy_revision),
            ("manifest_policy_decision_id", self.policy_decision_id),
            ("manifest_egress_profile", self.egress_profile),
            ("manifest_nonce", self.nonce),
        ):
            _identifier(name, value)
        _sha256("manifest_capability_digest", self.capability_digest)
        _image_digest("manifest_image_digest", self.image_digest)
        _closed_identifiers("manifest_target_ids", self.target_ids, maximum=100)
        if len(self.target_hashes) != len(self.target_ids) or len(set(self.target_hashes)) != len(self.target_hashes):
            raise ValueError("manifest_target_hashes_invalid")
        for value in self.target_hashes:
            _sha256("manifest_target_hash", value)
        _closed_identifiers("manifest_evidence_schema", self.evidence_schema, maximum=16)
        _closed_identifiers("manifest_secret_reference_ids", self.secret_reference_ids, maximum=16, allow_empty=True)
        _aware(self.issued_at)
        _aware(self.expires_at)
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=5):
            raise ValueError("manifest_ttl_invalid")
        if self.egress_profile == "none" and self.network_plane != "isolated-none":
            raise ValueError("manifest_network_plane_invalid")


@dataclass(frozen=True, kw_only=True)
class SignedJobManifest:
    manifest: JobManifestDraft
    manifest_sha256: str
    signature: str
    key_id: str

    def __post_init__(self) -> None:
        _sha256("manifest_sha256", self.manifest_sha256)
        _identifier("manifest_key_id", self.key_id)
        try:
            decoded = base64.urlsafe_b64decode(self.signature.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("manifest_signature_invalid") from exc
        if len(decoded) != 64:
            raise ValueError("manifest_signature_invalid")

    def to_public_dict(self) -> dict[str, object]:
        payload = _manifest_payload(self.manifest)
        payload.update(
            {
                "manifest_sha256": self.manifest_sha256,
                "signature": self.signature,
                "key_id": self.key_id,
            }
        )
        return payload


@dataclass(frozen=True, kw_only=True)
class JobManifestDraftV2:
    """Add exact capability/profile/bundle identity without changing v1 canonical bytes."""

    v1: JobManifestDraft
    capability_id: str
    capability_revision: int
    execution_manifest_sha256: str
    profile_id: str
    profile_revision: int
    profile_sha256: str
    bundle_id: str | None
    bundle_revision: int | None
    bundle_sha256: str | None

    def __post_init__(self) -> None:
        if not isinstance(self.v1, JobManifestDraft):
            raise ValueError("manifest_v2_v1_contract_invalid")
        _identifier("manifest_v2_capability_id", self.capability_id)
        _bounded_int("manifest_v2_capability_revision", self.capability_revision, 1, 9999)
        _sha256("manifest_v2_execution_manifest_sha256", self.execution_manifest_sha256)
        if self.v1.capability_digest != self.execution_manifest_sha256:
            raise ValueError("manifest_v2_capability_digest_mismatch")
        _identifier("manifest_v2_profile_id", self.profile_id)
        _bounded_int("manifest_v2_profile_revision", self.profile_revision, 1, 9999)
        _sha256("manifest_v2_profile_sha256", self.profile_sha256)
        bundle = (self.bundle_id, self.bundle_revision, self.bundle_sha256)
        if any(value is None for value in bundle) and any(value is not None for value in bundle):
            raise ValueError("manifest_v2_bundle_identity_incomplete")
        if self.bundle_id is not None:
            _identifier("manifest_v2_bundle_id", self.bundle_id)
            _bounded_int("manifest_v2_bundle_revision", self.bundle_revision, 1, 9999)
            _sha256("manifest_v2_bundle_sha256", self.bundle_sha256)


@dataclass(frozen=True, kw_only=True)
class SignedJobManifestV2:
    manifest: JobManifestDraftV2
    manifest_sha256: str
    signature: str
    key_id: str

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, JobManifestDraftV2):
            raise ValueError("manifest_v2_contract_invalid")
        _sha256("manifest_v2_sha256", self.manifest_sha256)
        _identifier("manifest_v2_key_id", self.key_id)
        try:
            decoded = base64.urlsafe_b64decode(self.signature.encode("ascii"))
        except (ValueError, UnicodeEncodeError) as exc:
            raise ValueError("manifest_v2_signature_invalid") from exc
        if len(decoded) != 64:
            raise ValueError("manifest_v2_signature_invalid")

    def to_public_dict(self) -> dict[str, object]:
        return {
            **_manifest_v2_payload(self.manifest),
            "manifest_sha256": self.manifest_sha256,
            "signature": self.signature,
            "key_id": self.key_id,
        }


@dataclass(frozen=True, kw_only=True)
class PullLeaseGrant:
    lease_id: str
    manifest_record_id: str
    claim_id: str
    expires_at: datetime
    lease_token: bytearray | None = None

    def __post_init__(self) -> None:
        _identifier("runner_lease_id", self.lease_id)
        _identifier("runner_manifest_record_id", self.manifest_record_id)
        _identifier("runner_claim_id", self.claim_id)
        _aware(self.expires_at)
        if self.lease_token is not None and (not isinstance(self.lease_token, bytearray) or not 16 <= len(self.lease_token) <= 256):
            raise ValueError("runner_lease_token_invalid")

    def __repr__(self) -> str:
        return (
            f"PullLeaseGrant(lease_id={self.lease_id!r}, manifest_record_id={self.manifest_record_id!r}, "
            f"claim_id={self.claim_id!r}, expires_at={self.expires_at!r}, lease_token=<redacted>)"
        )


def canonical_job_manifest_sha256(manifest: JobManifestDraft) -> str:
    return hashlib.sha256(_canonical_manifest_bytes(manifest)).hexdigest()


def canonical_job_manifest_v2_sha256(manifest: JobManifestDraftV2) -> str:
    if not isinstance(manifest, JobManifestDraftV2):
        raise ValueError("manifest_v2_contract_invalid")
    return hashlib.sha256(_canonical_manifest_v2_bytes(manifest)).hexdigest()


def canonical_capability_sha256(capability: ExecutionCapabilityManifest) -> str:
    payload = _normalize(asdict(capability))
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def sign_job_manifest(manifest: JobManifestDraft, private_key: Ed25519PrivateKey, *, key_id: str) -> SignedJobManifest:
    if not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("manifest_signing_key_invalid")
    _identifier("manifest_key_id", key_id)
    encoded = _canonical_manifest_bytes(manifest)
    signature = base64.urlsafe_b64encode(private_key.sign(encoded)).decode("ascii")
    return SignedJobManifest(
        manifest=manifest,
        manifest_sha256=hashlib.sha256(encoded).hexdigest(),
        signature=signature,
        key_id=key_id,
    )


def sign_job_manifest_v2(
    manifest: JobManifestDraftV2,
    private_key: Ed25519PrivateKey,
    *,
    key_id: str,
) -> SignedJobManifestV2:
    if not isinstance(manifest, JobManifestDraftV2) or not isinstance(private_key, Ed25519PrivateKey):
        raise ValueError("manifest_v2_signing_input_invalid")
    _identifier("manifest_v2_key_id", key_id)
    encoded = _canonical_manifest_v2_bytes(manifest)
    return SignedJobManifestV2(
        manifest=manifest,
        manifest_sha256=hashlib.sha256(encoded).hexdigest(),
        signature=base64.urlsafe_b64encode(private_key.sign(encoded)).decode("ascii"),
        key_id=key_id,
    )


def verify_signed_job_manifest(
    signed: SignedJobManifest,
    public_key: Ed25519PublicKey,
    *,
    now: datetime,
) -> JobManifestDraft:
    _aware(now)
    encoded = _canonical_manifest_bytes(signed.manifest)
    if hashlib.sha256(encoded).hexdigest() != signed.manifest_sha256:
        raise ValueError("manifest_hash_mismatch")
    try:
        public_key.verify(base64.urlsafe_b64decode(signed.signature.encode("ascii")), encoded)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("manifest_signature_invalid") from exc
    if not signed.manifest.issued_at <= now < signed.manifest.expires_at:
        raise ValueError("manifest_expired")
    return signed.manifest


def verify_signed_job_manifest_v2(
    signed: SignedJobManifestV2,
    public_key: Ed25519PublicKey,
    *,
    now: datetime,
) -> JobManifestDraftV2:
    if not isinstance(signed, SignedJobManifestV2):
        raise ValueError("manifest_v2_contract_invalid")
    _aware(now)
    encoded = _canonical_manifest_v2_bytes(signed.manifest)
    if hashlib.sha256(encoded).hexdigest() != signed.manifest_sha256:
        raise ValueError("manifest_v2_hash_mismatch")
    try:
        public_key.verify(base64.urlsafe_b64decode(signed.signature.encode("ascii")), encoded)
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError("manifest_v2_signature_invalid") from exc
    if not signed.manifest.v1.issued_at <= now < signed.manifest.v1.expires_at:
        raise ValueError("manifest_v2_expired")
    return signed.manifest


def verify_job_manifest_v2_binding(manifest: JobManifestDraftV2, binding: object) -> None:
    """Verify the executable identity against an accepted compat_119 binding without importing it here."""
    required = (
        "capability_id", "capability_revision", "execution_manifest_sha256", "adapter_id",
        "adapter_version", "profile_id", "profile_revision", "profile_sha256", "bundle_id",
        "bundle_revision", "bundle_sha256",
    )
    if not isinstance(manifest, JobManifestDraftV2) or any(not hasattr(binding, name) for name in required):
        raise ValueError("manifest_v2_binding_invalid")
    if (
        manifest.capability_id,
        manifest.capability_revision,
        manifest.execution_manifest_sha256,
    ) != (
        getattr(binding, "capability_id"),
        getattr(binding, "capability_revision"),
        getattr(binding, "execution_manifest_sha256"),
    ):
        raise ValueError("manifest_v2_capability_mismatch")
    if (manifest.v1.adapter_id, manifest.v1.adapter_version) != (
        getattr(binding, "adapter_id"),
        getattr(binding, "adapter_version"),
    ):
        raise ValueError("manifest_v2_adapter_mismatch")
    if (manifest.profile_id, manifest.profile_revision, manifest.profile_sha256) != (
        getattr(binding, "profile_id"),
        getattr(binding, "profile_revision"),
        getattr(binding, "profile_sha256"),
    ):
        raise ValueError("manifest_v2_profile_mismatch")
    if (manifest.bundle_id, manifest.bundle_revision, manifest.bundle_sha256) != (
        getattr(binding, "bundle_id"),
        getattr(binding, "bundle_revision"),
        getattr(binding, "bundle_sha256"),
    ):
        raise ValueError("manifest_v2_bundle_mismatch")


def parse_signed_job_manifest(payload: Mapping[str, object]) -> SignedJobManifest:
    expected = {field.name for field in fields(JobManifestDraft)} | {"manifest_sha256", "signature", "key_id"}
    if set(payload) != expected or set(payload).intersection(_EXECUTABLE_FIELD_NAMES):
        raise ValueError("manifest_fields_invalid")
    values: dict[str, Any] = dict(payload)
    limits = values.get("limits")
    if not isinstance(limits, Mapping) or set(limits) != {field.name for field in fields(ResourceLimits)}:
        raise ValueError("manifest_limits_invalid")
    values["limits"] = ResourceLimits(**dict(limits))
    for name in ("target_ids", "target_hashes", "evidence_schema", "secret_reference_ids"):
        item = values.get(name)
        if not isinstance(item, list):
            raise ValueError(f"manifest_{name}_invalid")
        values[name] = tuple(item)
    for name in ("issued_at", "expires_at"):
        item = values.get(name)
        if not isinstance(item, str):
            raise ValueError("manifest_datetime_invalid")
        try:
            values[name] = datetime.fromisoformat(item.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("manifest_datetime_invalid") from exc
    metadata = {name: values.pop(name) for name in ("manifest_sha256", "signature", "key_id")}
    return SignedJobManifest(manifest=JobManifestDraft(**values), **metadata)


def parse_signed_job_manifest_v2(payload: Mapping[str, object]) -> SignedJobManifestV2:
    manifest_fields = {
        "manifest_contract_version",
        "v1",
        "capability_id",
        "capability_revision",
        "execution_manifest_sha256",
        "profile_id",
        "profile_revision",
        "profile_sha256",
        "bundle_id",
        "bundle_revision",
        "bundle_sha256",
    }
    expected = manifest_fields | {"manifest_sha256", "signature", "key_id"}
    if not isinstance(payload, Mapping) or set(payload) != expected:
        raise ValueError("manifest_v2_fields_invalid")
    if payload.get("manifest_contract_version") != "redagent.r123-job-manifest/v2":
        raise ValueError("manifest_v2_contract_version_invalid")
    nested = payload.get("v1")
    if not isinstance(nested, Mapping) or set(nested) != {field.name for field in fields(JobManifestDraft)}:
        raise ValueError("manifest_v2_v1_fields_invalid")
    values: dict[str, Any] = dict(nested)
    limits = values.get("limits")
    if not isinstance(limits, Mapping) or set(limits) != {field.name for field in fields(ResourceLimits)}:
        raise ValueError("manifest_v2_limits_invalid")
    values["limits"] = ResourceLimits(**dict(limits))
    for name in ("target_ids", "target_hashes", "evidence_schema", "secret_reference_ids"):
        item = values.get(name)
        if not isinstance(item, list):
            raise ValueError(f"manifest_v2_{name}_invalid")
        values[name] = tuple(item)
    for name in ("issued_at", "expires_at"):
        item = values.get(name)
        if not isinstance(item, str):
            raise ValueError("manifest_v2_datetime_invalid")
        try:
            values[name] = datetime.fromisoformat(item.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValueError("manifest_v2_datetime_invalid") from exc
    manifest_values = {name: payload[name] for name in manifest_fields - {"manifest_contract_version", "v1"}}
    manifest = JobManifestDraftV2(v1=JobManifestDraft(**values), **manifest_values)
    return SignedJobManifestV2(
        manifest=manifest,
        manifest_sha256=payload["manifest_sha256"],
        signature=payload["signature"],
        key_id=payload["key_id"],
    )


def _manifest_payload(manifest: JobManifestDraft) -> dict[str, object]:
    payload = asdict(manifest)
    payload["issued_at"] = _iso(manifest.issued_at)
    payload["expires_at"] = _iso(manifest.expires_at)
    payload["target_ids"] = list(manifest.target_ids)
    payload["target_hashes"] = list(manifest.target_hashes)
    payload["evidence_schema"] = list(manifest.evidence_schema)
    payload["secret_reference_ids"] = list(manifest.secret_reference_ids)
    return payload


def _canonical_manifest_bytes(manifest: JobManifestDraft) -> bytes:
    return json.dumps(_manifest_payload(manifest), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def _manifest_v2_payload(manifest: JobManifestDraftV2) -> dict[str, object]:
    return {
        "manifest_contract_version": "redagent.r123-job-manifest/v2",
        "v1": _manifest_payload(manifest.v1),
        "capability_id": manifest.capability_id,
        "capability_revision": manifest.capability_revision,
        "execution_manifest_sha256": manifest.execution_manifest_sha256,
        "profile_id": manifest.profile_id,
        "profile_revision": manifest.profile_revision,
        "profile_sha256": manifest.profile_sha256,
        "bundle_id": manifest.bundle_id,
        "bundle_revision": manifest.bundle_revision,
        "bundle_sha256": manifest.bundle_sha256,
    }


def _canonical_manifest_v2_bytes(manifest: JobManifestDraftV2) -> bytes:
    return json.dumps(
        _manifest_v2_payload(manifest),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _iso(value: datetime) -> str:
    _aware(value)
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _normalize(value: object) -> object:
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_normalize(item) for item in value]
    return value


def _schema(value: str) -> None:
    if value != CONTRACT_SCHEMA_VERSION:
        raise ValueError("contract_schema_version_unsupported")


def _identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _reference(name: str, value: str) -> None:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _image_digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IMAGE_DIGEST.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")


def _closed_identifiers(name: str, values: tuple[str, ...], *, maximum: int, allow_empty: bool = False) -> None:
    if not isinstance(values, tuple) or (not values and not allow_empty) or len(values) > maximum or len(set(values)) != len(values):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _identifier(name, value)


def _closed_references(name: str, values: tuple[str, ...], *, maximum: int) -> None:
    if not isinstance(values, tuple) or not values or len(values) > maximum or len(set(values)) != len(values):
        raise ValueError(f"{name}_invalid")
    for value in values:
        _reference(name, value)
