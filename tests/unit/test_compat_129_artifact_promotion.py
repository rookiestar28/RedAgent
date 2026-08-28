from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import shutil

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from redagent_platform.artifact_pipeline import promotion


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 28, 12, 0, tzinfo=timezone.utc)


def test_historical_artifact_promotion_is_expired_but_current_v2_is_accepted() -> None:
    with pytest.raises(ValueError, match="artifact_promotion_inactive"):
        promotion.verify_artifact_promotion(ROOT, now=NOW)

    current = promotion.verify_current_artifact_promotion(ROOT, now=NOW)

    assert current.receipt.signature_verified is True
    assert current.receipt.verified_at <= NOW < current.receipt.expires_at
    assert current.receipt.vulnerability_review == "accepted_no_critical"


def test_current_promotion_binds_current_source_and_rejects_anchor_tamper(
    tmp_path: Path,
) -> None:
    current = promotion.verify_current_artifact_promotion(ROOT, now=NOW)
    assert current.receipt.image_digest.removeprefix("sha256:") == promotion.artifact_source_sha256(
        ROOT
    )

    for relative in (
        "config/artifact-posture-promotion-anchor-v2.json",
        "config/artifact-posture-runtime-v2.json",
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_QUALIFICATION_V2.json",
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.json",
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.pub",
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.signature.json",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    source = tmp_path / "redagent_platform" / "artifact_pipeline"
    shutil.copytree(ROOT / "redagent_platform" / "artifact_pipeline", source)

    public_key = tmp_path / (
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.pub"
    )
    public_key.write_bytes(public_key.read_bytes() + b"\n")

    with pytest.raises(ValueError, match="artifact_promotion_anchor_invalid"):
        promotion.verify_current_artifact_promotion(tmp_path, now=NOW)


def test_current_promotion_rejects_coherent_fresh_key_replacement(
    tmp_path: Path,
) -> None:
    for relative in (
        "config/artifact-posture-promotion-anchor-v2.json",
        "config/artifact-posture-runtime-v2.json",
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_QUALIFICATION_V2.json",
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.json",
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.pub",
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.signature.json",
    ):
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(ROOT / relative, target)
    source = tmp_path / "redagent_platform" / "artifact_pipeline"
    shutil.copytree(ROOT / "redagent_platform" / "artifact_pipeline", source)

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_bytes = private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    public_sha256 = hashlib.sha256(public_bytes).hexdigest()
    public_path = tmp_path / (
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.pub"
    )
    manifest_path = tmp_path / (
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.json"
    )
    signature_path = tmp_path / (
        "runtime-assets/attestations/260828-ARTIFACT_POSTURE_PROMOTION_V2.signature.json"
    )
    anchor_path = tmp_path / "config/artifact-posture-promotion-anchor-v2.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["public_key_sha256"] = public_sha256
    content = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    signature = private_key.sign(content, ec.ECDSA(hashes.SHA256()))
    public_path.write_bytes(public_bytes)
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    anchor_path.write_text(
        json.dumps(
            {
                "algorithm": "ECDSA_P256_SHA256",
                "public_key_sha256": public_sha256,
                "schema": "redagent.artifact-posture-promotion-anchor/v1",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )
    signature_path.write_text(
        json.dumps(
            {
                "algorithm": "ECDSA_P256_SHA256",
                "manifest_sha256": hashlib.sha256(content).hexdigest(),
                "schema": "redagent.ecdsa-p256-signature/v1",
                "signature_bytes": list(signature),
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    with pytest.raises(ValueError, match="artifact_promotion_anchor_invalid"):
        promotion.verify_current_artifact_promotion(tmp_path, now=NOW)
