from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils

from redagent_platform.nuclei_service.artifact_promotion import (
    NucleiArtifactPromotionError,
    verify_current_nuclei_artifact_promotion,
)
from redagent_platform.nuclei_service.authority import (
    CURRENT_NUCLEI_ARTIFACT_PROMOTION,
    CURRENT_NUCLEI_BUNDLE_MANIFEST,
    CURRENT_NUCLEI_BUNDLE_PROMOTION,
    CURRENT_NUCLEI_RUNTIME_LOCK,
)
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.nuclei_service.promotion import (
    NucleiPromotionError,
    verify_current_nuclei_bundle_promotion,
)
from redagent_platform.zap_service.authority import (
    CURRENT_ZAP_ARTIFACT_PROMOTION,
    CURRENT_ZAP_RUNTIME_LOCK,
)
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from redagent_platform.zap_service.promotion import (
    ZapPromotionError,
    verify_current_zap_promotion,
)


ROOT = Path(__file__).resolve().parents[2]

V1_AUTHORITY_SHA256 = {
    "config/r104-zap-runtime.json": "db21fcf4f69ff91ecdcc10c3b80c8053eb270996a0df160006a52480f3e4c8df",  # pragma: allowlist secret
    "config/r105-nuclei-runtime.json": "decb436f2e608e6f3c702ef865f3bfae7f2220b5a3e4df54bb6d81dbf3cb335d",  # pragma: allowlist secret
    "runtime-assets/attestations/260711-R104_ZAP_ARTIFACT_PROMOTION.json": "ab13748873833cb6aebfc97e56b62dffed7e61bfec4a53bccefece91eca27b8b",  # pragma: allowlist secret
    "runtime-assets/attestations/260711-R104_ZAP_ARTIFACT_PROMOTION.sigstore.json": "2c344cb4bf35e06536b5a6ba64695e1484fe45ebd2297388ffe317553eb61327",  # pragma: allowlist secret
    "runtime-assets/attestations/260711-R104_ZAP_ARTIFACT_PROMOTION.pub": "7476c78bfef45906affd2ae7070ee5f498a573689870437493b7bad43825e506",  # pragma: allowlist secret
    "runtime-assets/attestations/260711-R105_NUCLEI_ARTIFACT_PROMOTION.json": "ff86b687a3ca3a0fc7b6a132ac9cad2c7a0ad546fc69169ba73bf2de44a6d95f",  # pragma: allowlist secret
    "runtime-assets/attestations/260711-R105_NUCLEI_ARTIFACT_PROMOTION.sigstore.json": "2033efe25e3bd01814600cf3e2d394a1e39e329b8010f1fc9ba6e92e47e8a750",  # pragma: allowlist secret
    "runtime-assets/attestations/260711-R105_NUCLEI_ARTIFACT_PROMOTION.pub": "88eed1a742e62d25e975736536172eebc8ecb34766e261174e77e8d922cf3b95",  # pragma: allowlist secret
    "bundles/r105-nuclei/bundle-manifest.json": "6c16355c64475bbea0b647f5a0c8571a461a7382ec9acb9a0aff9800108bc768",  # pragma: allowlist secret
    "runtime-assets/attestations/260711-R105_NUCLEI_BUNDLE_PROMOTION.sigstore.json": "16dca316c8c649fd8627dd5835cf07a70e7cf69abb55fed5f169dd7764434cc6",  # pragma: allowlist secret
    "runtime-assets/attestations/260711-R105_NUCLEI_BUNDLE_PROMOTION.pub": "78227538d9b1f310480c169ae6388bc51ab9d9caac712f157b8063620bba9435",  # pragma: allowlist secret
}


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_revision_one_authority_files_remain_byte_stable() -> None:
    assert {relative: _sha256(ROOT / relative) for relative in V1_AUTHORITY_SHA256} == (
        V1_AUTHORITY_SHA256
    )


def test_revision_two_authority_paths_are_additive_and_explicit() -> None:
    assert CURRENT_ZAP_RUNTIME_LOCK == ROOT / "config/r104-zap-runtime-v2.json"
    assert CURRENT_ZAP_ARTIFACT_PROMOTION.document == (
        ROOT / "runtime-assets/attestations/260824-R104_ZAP_ARTIFACT_PROMOTION_V2.json"
    )
    assert CURRENT_NUCLEI_RUNTIME_LOCK == ROOT / "config/r105-nuclei-runtime-v2.json"
    assert CURRENT_NUCLEI_ARTIFACT_PROMOTION.document == (
        ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.json"
    )
    assert CURRENT_NUCLEI_BUNDLE_MANIFEST == (
        ROOT / "bundles/r105-nuclei/bundle-manifest-v2.json"
    )
    assert CURRENT_NUCLEI_BUNDLE_PROMOTION.signature == (
        ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_BUNDLE_PROMOTION_V2.sigstore.json"
    )


def test_revision_two_locks_bind_reproducible_build_contract() -> None:
    for relative, schema in (
        ("config/r104-zap-runtime-v2.json", "redagent.r104-runtime-lock/v2"),
        ("config/r105-nuclei-runtime-v2.json", "redagent.r105-runtime-lock/v2"),
    ):
        value = json.loads((ROOT / relative).read_text(encoding="utf-8"))
        assert value["schema"] == schema
        assert value["source_date_epoch"] == 1787529600
        assert value["buildkit_compatibility_version"] == "20"
        assert value["rewrite_timestamp"] is True
        assert value["production_qualified"] is False
        for key in ("engine_image_id", "target_image_id", "gateway_image_id"):
            assert value[key].startswith("sha256:") and len(value[key]) == 71


def test_revision_two_capability_identity_is_additive() -> None:
    zap = build_zap_capability_manifest(
        platform="linux/amd64", artifact_receipt_id="artifact-r104-v2"
    )
    nuclei = build_nuclei_capability_manifest(
        platform="linux/amd64", artifact_receipt_id="artifact-r105-v2"
    )
    assert (zap.revision, zap.adapter_version) == (2, "2.17.0-r104.2")
    assert (nuclei.revision, nuclei.adapter_version) == (2, "3.11.1-r105.2")


def test_revision_two_build_controllers_are_closed_and_reproducible() -> None:
    for relative, confirmation in (
        ("scripts/compat_104_requalify.py", "--confirm-r104-local-lab"),
        ("scripts/compat_105_requalify.py", "--confirm-r105-local-lab"),
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        for token in (
            confirmation,
            'choices=("build", "sign", "validate")',
            '"buildx", "build"',
            '"--no-cache"',
            '"--provenance=false"',
            '"SOURCE_DATE_EPOCH=1787529600"',
            '"rewrite-timestamp=true"',
            '"unpack=false"',
            '"compatibility-version=20"',
            "requalification_build_not_reproducible",
        ):
            assert token in source
        for forbidden in ("--target", "--url", "--template", "--image", "--flags"):
            assert forbidden not in source


def test_engine_layers_remove_apk_wall_clock_log_before_identity_export() -> None:
    for relative in (
        "containers/r104-zap/Dockerfile",
        "containers/r105-nuclei/Dockerfile",
    ):
        source = (ROOT / relative).read_text(encoding="utf-8")
        assert "rm -f /var/log/apk.log" in source


def test_zap_engine_removes_nondeterministic_fontconfig_cache() -> None:
    source = (ROOT / "containers/r104-zap/Dockerfile").read_text(encoding="utf-8")
    assert "rm -rf /var/cache/fontconfig/*" in source


def test_revision_two_signed_promotions_bind_locks_qualification_and_bundle() -> None:
    now = datetime(2026, 8, 24, 9, 30, tzinfo=timezone.utc)
    zap, _ = verify_current_zap_promotion(
        promotion_bytes=CURRENT_ZAP_ARTIFACT_PROMOTION.document.read_bytes(),
        bundle_bytes=CURRENT_ZAP_ARTIFACT_PROMOTION.signature.read_bytes(),
        public_key_bytes=CURRENT_ZAP_ARTIFACT_PROMOTION.public_key.read_bytes(),
        runtime_lock_bytes=CURRENT_ZAP_RUNTIME_LOCK.read_bytes(),
        qualification_bytes=(
            ROOT / "runtime-assets/attestations/260824-R104_ZAP_RUNTIME_QUALIFICATION_V2.json"
        ).read_bytes(),
        now=now,
    )
    nuclei, _ = verify_current_nuclei_artifact_promotion(
        promotion_bytes=CURRENT_NUCLEI_ARTIFACT_PROMOTION.document.read_bytes(),
        signature_bundle_bytes=CURRENT_NUCLEI_ARTIFACT_PROMOTION.signature.read_bytes(),
        public_key_bytes=CURRENT_NUCLEI_ARTIFACT_PROMOTION.public_key.read_bytes(),
        runtime_lock_bytes=CURRENT_NUCLEI_RUNTIME_LOCK.read_bytes(),
        qualification_bytes=(
            ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_RUNTIME_QUALIFICATION_V2.json"
        ).read_bytes(),
        now=now,
    )
    bundle = verify_current_nuclei_bundle_promotion(
        manifest_bytes=CURRENT_NUCLEI_BUNDLE_MANIFEST.read_bytes(),
        signature_bundle_bytes=CURRENT_NUCLEI_BUNDLE_PROMOTION.signature.read_bytes(),
        public_key_bytes=CURRENT_NUCLEI_BUNDLE_PROMOTION.public_key.read_bytes(),
        template_bytes=(
            ROOT / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml"
        ).read_bytes(),
        certificate_bytes=(ROOT / "config/trust/r105-nuclei-user.crt").read_bytes(),
        qualification_bytes=(
            ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_RUNTIME_QUALIFICATION_V2.json"
        ).read_bytes(),
        now=now,
    )
    assert zap.receipt_id == "artifact-r104-zap-2170-r104-2"
    assert nuclei.receipt_id == "artifact-r105-nuclei-3111-r105-2"
    assert bundle.revision == 2


def test_revision_two_promotion_documents_claim_every_locked_helper_and_source() -> None:
    for promotion_path, lock_path in (
        (CURRENT_ZAP_ARTIFACT_PROMOTION.document, CURRENT_ZAP_RUNTIME_LOCK),
        (CURRENT_NUCLEI_ARTIFACT_PROMOTION.document, CURRENT_NUCLEI_RUNTIME_LOCK),
    ):
        promotion = json.loads(promotion_path.read_text(encoding="utf-8"))
        lock = json.loads(lock_path.read_text(encoding="utf-8"))
        assert promotion["artifact"]["local_tag"] == lock["engine_local_tag"]
        assert promotion["artifact"]["dockerfile_sha256"] == lock["engine_dockerfile_sha256"]
        helpers = promotion["owned_helpers"]
        assert helpers == {
            "target_local_tag": lock["target_local_tag"],
            "target_image_id": lock["target_image_id"],
            "target_source_sha256": lock["target_source_sha256"],
            "target_dockerfile_sha256": lock["target_dockerfile_sha256"],
            "gateway_local_tag": lock["gateway_local_tag"],
            "gateway_image_id": lock["gateway_image_id"],
            "gateway_source_sha256": lock["gateway_source_sha256"],
            "gateway_dockerfile_sha256": lock["gateway_dockerfile_sha256"],
        }


def _signed_test_promotion(document: dict[str, object]) -> tuple[bytes, bytes, bytes]:
    payload = (
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")
    key = ec.generate_private_key(ec.SECP256R1())
    digest = hashlib.sha256(payload).digest()
    signature = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "messageSignature": {
            "messageDigest": {
                "algorithm": "SHA2_256",
                "digest": base64.b64encode(digest).decode("ascii"),
            },
            "signature": base64.b64encode(signature).decode("ascii"),
        },
    }
    public_key = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return payload, json.dumps(bundle).encode("utf-8"), public_key


@pytest.mark.parametrize("family", ("zap", "nuclei"))
@pytest.mark.parametrize(
    ("section", "field", "replacement"),
    (
        ("runtime_lock", "path", "config/wrong-runtime-lock.json"),
        ("artifact", "local_tag", "redagent/wrong:latest"),
        ("artifact", "dockerfile_sha256", "0" * 64),
        ("artifact", "configured_user", "0:0"),
        ("owned_helpers", "target_local_tag", "redagent/wrong-target:latest"),
        ("owned_helpers", "target_image_id", "sha256:" + "0" * 64),
        ("owned_helpers", "target_source_sha256", "0" * 64),
        ("owned_helpers", "target_dockerfile_sha256", "0" * 64),
        ("owned_helpers", "gateway_local_tag", "redagent/wrong-gateway:latest"),
        ("owned_helpers", "gateway_image_id", "sha256:" + "0" * 64),
        ("owned_helpers", "gateway_source_sha256", "0" * 64),
        ("owned_helpers", "gateway_dockerfile_sha256", "0" * 64),
    ),
)
def test_revision_two_promotion_denies_validly_signed_lock_identity_drift(
    family: str,
    section: str,
    field: str,
    replacement: str,
) -> None:
    now = datetime(2026, 8, 24, 9, 30, tzinfo=timezone.utc)
    if family == "zap":
        authority = CURRENT_ZAP_ARTIFACT_PROMOTION
        lock = CURRENT_ZAP_RUNTIME_LOCK
        qualification = ROOT / "runtime-assets/attestations/260824-R104_ZAP_RUNTIME_QUALIFICATION_V2.json"
    else:
        authority = CURRENT_NUCLEI_ARTIFACT_PROMOTION
        lock = CURRENT_NUCLEI_RUNTIME_LOCK
        qualification = ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_RUNTIME_QUALIFICATION_V2.json"
    document = json.loads(authority.document.read_text(encoding="utf-8"))
    document[section][field] = replacement
    payload, bundle, public_key = _signed_test_promotion(document)

    if family == "zap":
        with pytest.raises(ZapPromotionError, match="zap_current_promotion_claim_invalid"):
            verify_current_zap_promotion(
                promotion_bytes=payload,
                bundle_bytes=bundle,
                public_key_bytes=public_key,
                runtime_lock_bytes=lock.read_bytes(),
                qualification_bytes=qualification.read_bytes(),
                now=now,
            )
    else:
        with pytest.raises(
            NucleiArtifactPromotionError,
            match="nuclei_current_artifact_claim_invalid",
        ):
            verify_current_nuclei_artifact_promotion(
                promotion_bytes=payload,
                signature_bundle_bytes=bundle,
                public_key_bytes=public_key,
                runtime_lock_bytes=lock.read_bytes(),
                qualification_bytes=qualification.read_bytes(),
                now=now,
            )


def test_revision_two_promotions_deny_tamper_and_expiry() -> None:
    now = datetime(2026, 8, 24, 9, 30, tzinfo=timezone.utc)
    qualification = (
        ROOT / "runtime-assets/attestations/260824-R104_ZAP_RUNTIME_QUALIFICATION_V2.json"
    ).read_bytes()
    with pytest.raises(ZapPromotionError, match="zap_promotion_digest_mismatch"):
        verify_current_zap_promotion(
            promotion_bytes=CURRENT_ZAP_ARTIFACT_PROMOTION.document.read_bytes() + b" ",
            bundle_bytes=CURRENT_ZAP_ARTIFACT_PROMOTION.signature.read_bytes(),
            public_key_bytes=CURRENT_ZAP_ARTIFACT_PROMOTION.public_key.read_bytes(),
            runtime_lock_bytes=CURRENT_ZAP_RUNTIME_LOCK.read_bytes(),
            qualification_bytes=qualification,
            now=now,
        )
    with pytest.raises(
        NucleiArtifactPromotionError, match="nuclei_artifact_digest_mismatch"
    ):
        verify_current_nuclei_artifact_promotion(
            promotion_bytes=CURRENT_NUCLEI_ARTIFACT_PROMOTION.document.read_bytes() + b" ",
            signature_bundle_bytes=CURRENT_NUCLEI_ARTIFACT_PROMOTION.signature.read_bytes(),
            public_key_bytes=CURRENT_NUCLEI_ARTIFACT_PROMOTION.public_key.read_bytes(),
            runtime_lock_bytes=CURRENT_NUCLEI_RUNTIME_LOCK.read_bytes(),
            qualification_bytes=(
                ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_RUNTIME_QUALIFICATION_V2.json"
            ).read_bytes(),
            now=now,
        )
    with pytest.raises(NucleiPromotionError, match="nuclei_current_promotion_expired"):
        verify_current_nuclei_bundle_promotion(
            manifest_bytes=CURRENT_NUCLEI_BUNDLE_MANIFEST.read_bytes(),
            signature_bundle_bytes=CURRENT_NUCLEI_BUNDLE_PROMOTION.signature.read_bytes(),
            public_key_bytes=CURRENT_NUCLEI_BUNDLE_PROMOTION.public_key.read_bytes(),
            template_bytes=(
                ROOT / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml"
            ).read_bytes(),
            certificate_bytes=(ROOT / "config/trust/r105-nuclei-user.crt").read_bytes(),
            qualification_bytes=(
                ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_RUNTIME_QUALIFICATION_V2.json"
            ).read_bytes(),
            now=datetime(2026, 9, 23, 9, 4, tzinfo=timezone.utc),
        )
