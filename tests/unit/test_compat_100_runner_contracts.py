from __future__ import annotations

from dataclasses import FrozenInstanceError, replace
from datetime import datetime, timedelta, timezone

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redagent_platform.runner_service.contracts import (
    ArtifactVerificationReceipt,
    CredentialClass,
    ExecutionCapabilityManifest,
    IsolationTier,
    JobManifestDraft,
    NetworkMode,
    ResourceLimits,
    RunnerRegistration,
    SandboxProfile,
    canonical_job_manifest_sha256,
    parse_signed_job_manifest,
    sign_job_manifest,
    verify_signed_job_manifest,
)


NOW = datetime(2026, 7, 10, 15, 0, tzinfo=timezone.utc)
DIGEST_A = "sha256:" + "a" * 64
DIGEST_B = "sha256:" + "b" * 64


def limits() -> ResourceLimits:
    return ResourceLimits(cpu_millis=500, memory_mib=128, pids=32, timeout_seconds=30, evidence_bytes=65_536)


def sandbox(**overrides: object) -> SandboxProfile:
    values: dict[str, object] = {
        "profile_id": "synthetic-standard-v1",
        "isolation_tier": IsolationTier.CONTAINER,
        "runtime_name": "runc",
        "run_as_user": 65532,
        "read_only_root": True,
        "privileged": False,
        "host_socket": False,
        "host_namespaces": False,
        "capabilities": (),
        "no_new_privileges": True,
        "seccomp_profile": "runtime-default",
        "network_mode": NetworkMode.NONE,
        "writable_mounts": ("/work",),
        "limits": limits(),
    }
    values.update(overrides)
    return SandboxProfile(**values)  # type: ignore[arg-type]


def receipt(**overrides: object) -> ArtifactVerificationReceipt:
    values: dict[str, object] = {
        "receipt_id": "artifact-receipt-1",
        "image_digest": DIGEST_A,
        "signature_verified": True,
        "signer_identity": "redagent-release-r100",
        "provenance_sha256": "1" * 64,
        "sbom_sha256": "2" * 64,
        "vulnerability_review": "accepted_no_critical",
        "verifier": "redagent-offline-v1",
        "verified_at": NOW,
        "expires_at": NOW + timedelta(days=7),
    }
    values.update(overrides)
    return ArtifactVerificationReceipt(**values)  # type: ignore[arg-type]


def capability(**overrides: object) -> ExecutionCapabilityManifest:
    values: dict[str, object] = {
        "schema_version": "1.0",
        "capability_id": "synthetic-conformance",
        "revision": 1,
        "adapter_id": "synthetic-conformance",
        "adapter_version": "1.0.0",
        "image_digest": DIGEST_A,
        "input_schema_id": "redagent.synthetic-job.v1",
        "supported_modes": ("synthetic",),
        "phases": ("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        "sandbox_profile_id": "synthetic-standard-v1",
        "network_mode": NetworkMode.NONE,
        "credential_class": CredentialClass.DYNAMIC_DATABASE,
        "evidence_schema": ("synthetic-result-v1",),
        "unsupported_features": ("arbitrary_command", "native_template", "plugin_loading"),
        "limits": limits(),
        "artifact_receipt_id": "artifact-receipt-1",
        "reviewed_by": "reviewer-r100",
        "status": "certified",
    }
    values.update(overrides)
    return ExecutionCapabilityManifest(**values)  # type: ignore[arg-type]


def registration(**overrides: object) -> RunnerRegistration:
    values: dict[str, object] = {
        "runner_id": "runner-local-1",
        "tenant_id": "tenant-a",
        "environment": "local-conformance",
        "runner_class_id": "synthetic-standard",
        "network_plane": "isolated-none",
        "spiffe_id": "spiffe://redagent.test/runner/runner-local-1",
        "certificate_fingerprint": "3" * 64,
        "certificate_serial": "1001",
        "adapter_allowlist": ("synthetic-conformance:1.0.0",),
        "image_allowlist": (DIGEST_A,),
        "required_policy_revision": "r099-v1",
        "generation": 1,
        "registered_at": NOW,
        "expires_at": NOW + timedelta(minutes=10),
        "revoked_at": None,
    }
    values.update(overrides)
    return RunnerRegistration(**values)  # type: ignore[arg-type]


def draft(**overrides: object) -> JobManifestDraft:
    values: dict[str, object] = {
        "schema_version": "1.0",
        "manifest_id": "manifest-1",
        "job_id": "job-1",
        "tenant_id": "tenant-a",
        "engagement_id": "engagement-1",
        "roe_version_id": "roe-1",
        "environment": "local-conformance",
        "runner_class_id": "synthetic-standard",
        "network_plane": "isolated-none",
        "adapter_id": "synthetic-conformance",
        "adapter_version": "1.0.0",
        "capability_digest": "4" * 64,
        "image_digest": DIGEST_A,
        "artifact_receipt_id": "artifact-receipt-1",
        "policy_revision": "r099-v1",
        "policy_decision_id": "decision-1",
        "target_ids": ("target-synthetic-1",),
        "target_hashes": ("5" * 64,),
        "limits": limits(),
        "egress_profile": "none",
        "evidence_schema": ("synthetic-result-v1",),
        "secret_reference_ids": ("secret-ref-1",),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=2),
        "nonce": "nonce-1",
    }
    values.update(overrides)
    return JobManifestDraft(**values)  # type: ignore[arg-type]


def test_closed_registration_capability_artifact_and_sandbox_contracts_are_immutable() -> None:
    values = (registration(), capability(), receipt(), sandbox())
    for value in values:
        with pytest.raises(FrozenInstanceError):
            setattr(value, "runner_id", "mutated")
        assert "private" not in repr(value).lower() and "credential_material" not in repr(value).lower()


def test_sandbox_rejects_privilege_host_access_unconfined_or_isolation_downgrade() -> None:
    for change in (
        {"privileged": True},
        {"host_socket": True},
        {"host_namespaces": True},
        {"capabilities": ("CAP_SYS_ADMIN",)},
        {"no_new_privileges": False},
        {"read_only_root": False},
        {"seccomp_profile": "unconfined"},
        {"network_mode": NetworkMode.HOST},
        {"writable_mounts": ("/work", "/var/run/docker.sock")},
    ):
        with pytest.raises(ValueError, match="sandbox_"):
            sandbox(**change)


def test_gvisor_profile_cannot_silently_run_under_runc() -> None:
    with pytest.raises(ValueError, match="sandbox_gvisor_runtime_required"):
        sandbox(isolation_tier=IsolationTier.GVISOR, runtime_name="runc")


def test_artifact_receipt_requires_exact_digest_signature_sbom_provenance_review_and_freshness() -> None:
    for change in (
        {"image_digest": "latest"},
        {"signature_verified": False},
        {"provenance_sha256": "missing"},
        {"sbom_sha256": "missing"},
        {"vulnerability_review": "critical_open"},
        {"expires_at": NOW},
    ):
        with pytest.raises(ValueError, match="artifact_"):
            receipt(**change)


def test_capability_requires_exact_lifecycle_closed_features_and_matching_artifact() -> None:
    with pytest.raises(ValueError, match="capability_phases_invalid"):
        capability(phases=("execute", "cleanup"))
    with pytest.raises(ValueError, match="capability_unsupported_features_required"):
        capability(unsupported_features=())
    with pytest.raises(ValueError, match="capability_status_invalid"):
        capability(status="draft")


def test_runner_registration_rejects_mutable_scope_duplicates_expiry_and_revocation_confusion() -> None:
    for change in (
        {"adapter_allowlist": ("synthetic-conformance:1.0.0", "synthetic-conformance:1.0.0")},
        {"image_allowlist": (DIGEST_A, DIGEST_B, DIGEST_A)},
        {"required_policy_revision": ""},
        {"generation": 0},
        {"expires_at": NOW},
        {"spiffe_id": "https://runner.example"},
    ):
        with pytest.raises(ValueError, match="runner_"):
            registration(**change)


def test_signed_job_manifest_is_deterministic_verifiable_and_metadata_only() -> None:
    key = Ed25519PrivateKey.generate()
    first = sign_job_manifest(draft(), key, key_id="r100-local-signing-v1")
    second = sign_job_manifest(draft(), key, key_id="r100-local-signing-v1")
    assert first == second
    assert canonical_job_manifest_sha256(first.manifest) == first.manifest_sha256
    verified = verify_signed_job_manifest(first, key.public_key(), now=NOW + timedelta(seconds=1))
    assert verified.job_id == "job-1" and verified.image_digest == DIGEST_A
    rendered = repr(first).lower()
    for forbidden in ("password", "credential_material", "private_key", "authorization"):
        assert forbidden not in rendered


def test_manifest_mutation_wrong_key_expiry_and_artifact_mismatch_fail_closed() -> None:
    key = Ed25519PrivateKey.generate()
    signed = sign_job_manifest(draft(), key, key_id="r100-local-signing-v1")
    with pytest.raises(ValueError, match="manifest_signature_invalid"):
        verify_signed_job_manifest(signed, Ed25519PrivateKey.generate().public_key(), now=NOW)
    with pytest.raises(ValueError, match="manifest_expired"):
        verify_signed_job_manifest(signed, key.public_key(), now=NOW + timedelta(minutes=3))
    tampered = replace(signed, manifest=replace(signed.manifest, image_digest=DIGEST_B))
    with pytest.raises(ValueError, match="manifest_hash_mismatch"):
        verify_signed_job_manifest(tampered, key.public_key(), now=NOW)


def test_manifest_parser_rejects_unknown_or_executable_fields_and_noncanonical_collections() -> None:
    key = Ed25519PrivateKey.generate()
    signed = sign_job_manifest(draft(), key, key_id="r100-local-signing-v1")
    payload = signed.to_public_dict()
    for field in ("command", "argv", "shell", "url", "flags", "environment", "mounts", "image"):
        with pytest.raises(ValueError, match="manifest_fields_invalid"):
            parse_signed_job_manifest({**payload, field: "forbidden"})
    with pytest.raises(ValueError, match="manifest_target_ids_invalid"):
        JobManifestDraft(**{**draft().__dict__, "target_ids": ("target-synthetic-1", "target-synthetic-1")})


def test_manifest_ttl_is_bounded_by_five_minutes_and_datetime_must_be_aware() -> None:
    with pytest.raises(ValueError, match="manifest_ttl_invalid"):
        draft(expires_at=NOW + timedelta(minutes=6))
    with pytest.raises(ValueError, match="timezone_required"):
        draft(issued_at=NOW.replace(tzinfo=None))
