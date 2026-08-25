from __future__ import annotations

from dataclasses import replace
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.runner_service.contracts import (
    JobManifestDraftV2,
    canonical_job_manifest_sha256,
    canonical_job_manifest_v2_sha256,
    parse_signed_job_manifest_v2,
    sign_job_manifest_v2,
    verify_job_manifest_v2_binding,
    verify_signed_job_manifest_v2,
)
from tests.unit.test_compat_100_runner_contracts import NOW, draft


SHA_A = "a" * 64
SHA_B = "b" * 64
SHA_C = "c" * 64


def binding(**overrides: object) -> CapabilityBindingKeyV1:
    values: dict[str, object] = {
        "schema_version": "redagent.r119-capability-binding/v1",
        "capability_id": "nuclei-trusted-runtime",
        "capability_revision": 1,
        "execution_manifest_sha256": SHA_A,
        "adapter_id": "nuclei-service",
        "adapter_version": "3.11.1-r105.2",
        "profile_id": "nuclei-http-header-v1",
        "profile_revision": 1,
        "profile_sha256": SHA_B,
        "bundle_id": "r105-http-header-bundle",
        "bundle_revision": 1,
        "bundle_sha256": SHA_C,
        "semantics_revision": 1,
        "semantics_sha256": SHA_A,
        "normalized_output_sha256": SHA_B,
        "projection_revision": 1,
        "projection_sha256": SHA_C,
    }
    values.update(overrides)
    return CapabilityBindingKeyV1(**values)  # type: ignore[arg-type]


def v2(**overrides: object) -> JobManifestDraftV2:
    values: dict[str, object] = {
        "v1": draft(
            adapter_id="nuclei-service",
            adapter_version="3.11.1-r105.2",
            capability_digest=SHA_A,
            secret_reference_ids=(),
        ),
        "capability_id": "nuclei-trusted-runtime",
        "capability_revision": 1,
        "execution_manifest_sha256": SHA_A,
        "profile_id": "nuclei-http-header-v1",
        "profile_revision": 1,
        "profile_sha256": SHA_B,
        "bundle_id": "r105-http-header-bundle",
        "bundle_revision": 1,
        "bundle_sha256": SHA_C,
    }
    values.update(overrides)
    return JobManifestDraftV2(**values)  # type: ignore[arg-type]


def test_v1_canonical_bytes_and_hash_are_unchanged_by_v2_addition() -> None:
    assert canonical_job_manifest_sha256(draft()) == (
        "4f1ed52da5c69a693ad23e49221217771a480163b87b8a499a09408e6fdf233c"  # pragma: allowlist secret
    )


def test_v2_sign_parse_verify_and_exact_binding_are_deterministic() -> None:
    key = Ed25519PrivateKey.generate()
    signed = sign_job_manifest_v2(v2(), key, key_id="r123-local-signing-v1")
    assert signed.manifest_sha256 == canonical_job_manifest_v2_sha256(v2())
    parsed = parse_signed_job_manifest_v2(signed.to_public_dict())
    verified = verify_signed_job_manifest_v2(
        parsed, key.public_key(), now=NOW + timedelta(seconds=1)
    )
    assert verified == v2()
    verify_job_manifest_v2_binding(verified, binding())


@pytest.mark.parametrize(
    ("field", "value", "reason"),
    (
        ("capability_id", "zap-controlled-runtime", "manifest_v2_capability_mismatch"),
        ("capability_revision", 2, "manifest_v2_capability_mismatch"),
        ("execution_manifest_sha256", SHA_B, "manifest_v2_capability_digest_mismatch"),
        ("profile_id", "zap-passive-v1", "manifest_v2_profile_mismatch"),
        ("profile_revision", 2, "manifest_v2_profile_mismatch"),
        ("profile_sha256", SHA_C, "manifest_v2_profile_mismatch"),
        ("bundle_id", "different-bundle", "manifest_v2_bundle_mismatch"),
        ("bundle_revision", 2, "manifest_v2_bundle_mismatch"),
        ("bundle_sha256", SHA_A, "manifest_v2_bundle_mismatch"),
    ),
)
def test_v2_rejects_capability_profile_and_bundle_substitution(
    field: str, value: object, reason: str
) -> None:
    with pytest.raises(ValueError, match=reason):
        verify_job_manifest_v2_binding(replace(v2(), **{field: value}), binding())


def test_v2_rejects_adapter_substitution_and_partial_bundle_identity() -> None:
    wrong_adapter = replace(v2(), v1=replace(v2().v1, adapter_id="zap-service"))
    with pytest.raises(ValueError, match="manifest_v2_adapter_mismatch"):
        verify_job_manifest_v2_binding(wrong_adapter, binding())

    with pytest.raises(ValueError, match="manifest_v2_bundle_identity_incomplete"):
        v2(bundle_sha256=None)


def test_v2_parser_rejects_executable_or_unknown_fields() -> None:
    key = Ed25519PrivateKey.generate()
    payload = sign_job_manifest_v2(v2(), key, key_id="r123-local-signing-v1").to_public_dict()
    for field in ("command", "argv", "shell", "url", "flags", "mounts", "image"):
        with pytest.raises(ValueError, match="manifest_v2_fields_invalid"):
            parse_signed_job_manifest_v2({**payload, field: "forbidden"})
