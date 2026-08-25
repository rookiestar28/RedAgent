from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from redagent_platform.nuclei_service.promotion import NucleiPromotionError, verify_nuclei_bundle_promotion


ROOT = Path(__file__).resolve().parents[2]


def _inputs() -> dict[str, object]:
    return {
        "manifest_bytes": (ROOT / "bundles/r105-nuclei/bundle-manifest.json").read_bytes(),
        "signature_bundle_bytes": (ROOT / "runtime-assets/attestations/260711-R105_NUCLEI_BUNDLE_PROMOTION.sigstore.json").read_bytes(),
        "public_key_bytes": (ROOT / "runtime-assets/attestations/260711-R105_NUCLEI_BUNDLE_PROMOTION.pub").read_bytes(),
        "template_bytes": (ROOT / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml").read_bytes(),
        "certificate_bytes": (ROOT / "config/trust/r105-nuclei-user.crt").read_bytes(),
        "now": datetime(2026, 7, 11, 8, 0, tzinfo=timezone.utc),
    }


def test_signed_complete_bundle_promotion_is_verified() -> None:
    result = verify_nuclei_bundle_promotion(**_inputs())  # type: ignore[arg-type]
    assert result.bundle_sha256 == "6c16355c64475bbea0b647f5a0c8571a461a7382ec9acb9a0aff9800108bc768"
    assert result.signature_verified is True and result.file_inventory == ("templates/redagent-r105-missing-header.yaml",)


def test_template_or_manifest_drift_fails_closed() -> None:
    inputs = _inputs()
    inputs["template_bytes"] = bytes(inputs["template_bytes"]) + b"tamper"
    with pytest.raises(NucleiPromotionError, match="nuclei_promotion_(claim|template_or_certificate)_invalid"):
        verify_nuclei_bundle_promotion(**inputs)  # type: ignore[arg-type]
    inputs = _inputs()
    inputs["manifest_bytes"] = bytes(inputs["manifest_bytes"]).replace(b"approved-local-lab-only", b"approved-production")
    with pytest.raises(NucleiPromotionError, match="nuclei_promotion_digest_mismatch"):
        verify_nuclei_bundle_promotion(**inputs)  # type: ignore[arg-type]
    inputs = _inputs()
    inputs["certificate_bytes"] = b"invalid certificate"
    with pytest.raises(NucleiPromotionError, match="nuclei_promotion_(claim|template_or_certificate)_invalid"):
        verify_nuclei_bundle_promotion(**inputs)  # type: ignore[arg-type]
