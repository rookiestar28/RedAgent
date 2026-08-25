from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
import shutil

import pytest

from redagent_platform.deployment_release.promotion import verify_deployment_release_promotion


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 12, 12, tzinfo=UTC)


def test_repository_r116_promotion_is_signed_safe_and_not_production_qualified() -> None:
    receipt = verify_deployment_release_promotion(ROOT, now=NOW)
    assert receipt.signature_verified
    assert receipt.profile_count == 2
    assert receipt.bundled_image_count == 1
    assert receipt.production_qualified is False


def test_promotion_rejects_runtime_lock_tamper(tmp_path: Path) -> None:
    for relative in (
        "runtime-assets/attestations/260712-R116_DEPLOYMENT_RELEASE_PROMOTION.json",
        "runtime-assets/attestations/260712-R116_DEPLOYMENT_RELEASE_PROMOTION.signature.json",
        "runtime-assets/attestations/260712-R116_DEPLOYMENT_RELEASE_PROMOTION.pub",
        "runtime-assets/attestations/260712-R116_DEPLOYMENT_RELEASE_QUALIFICATION.json",
        "config/r116-deployment-release-runtime.json",
        "runtime-assets/attestations/260712-R116_APP_IMAGE_SBOM.spdx.json.gz",
        "runtime-assets/attestations/public-source-relocations.json",
        "runtime-assets/attestations/260712-R116_APP_IMAGE_SBOM.cdx.json.gz",
    ):
        source = ROOT / relative
        target = tmp_path / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    lock_path = tmp_path / "config/r116-deployment-release-runtime.json"
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    lock["network_enabled"] = True
    lock_path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(ValueError, match="deployment_release_promotion_safety_invalid"):
        verify_deployment_release_promotion(tmp_path, now=NOW)


def test_promotion_rejects_sbom_tamper_even_when_manifest_signature_is_valid(tmp_path: Path) -> None:
    lock = json.loads((ROOT / "config/r116-deployment-release-runtime.json").read_text(encoding="utf-8"))
    relatives = {
        "runtime-assets/attestations/260712-R116_DEPLOYMENT_RELEASE_PROMOTION.json",
        "runtime-assets/attestations/260712-R116_DEPLOYMENT_RELEASE_PROMOTION.signature.json",
        "runtime-assets/attestations/260712-R116_DEPLOYMENT_RELEASE_PROMOTION.pub",
        "runtime-assets/attestations/260712-R116_DEPLOYMENT_RELEASE_QUALIFICATION.json",
        "config/r116-deployment-release-runtime.json",
        "runtime-assets/attestations/260712-R116_APP_IMAGE_SBOM.spdx.json.gz",
        "runtime-assets/attestations/public-source-relocations.json",
        *(f"deploy/profiles/{item['path']}" for item in lock["profile_sha256s"]),
        *(item["path"] for item in lock["source_sha256s"]),
    }
    for relative in relatives:
        public_relative = {
            "scripts/r116_deployment_release.py": "scripts/compat_116_deployment_release.py",
            "scripts/r116_sign_promotion.py": "scripts/compat_116_sign_promotion.py",
        }.get(relative, relative)
        source = ROOT / public_relative
        target = tmp_path / public_relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    sbom = tmp_path / "runtime-assets/attestations/260712-R116_APP_IMAGE_SBOM.spdx.json.gz"
    sbom.write_bytes(sbom.read_bytes() + b"tamper")

    with pytest.raises(ValueError, match="deployment_release_promotion_sbom_invalid"):
        verify_deployment_release_promotion(tmp_path, now=NOW)
