from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from redagent_platform.zap_service.promotion import ZapPromotionError, verify_zap_promotion


ROOT = Path(__file__).resolve().parents[2]
PROMOTION = ROOT / "runtime-assets" / "attestations" / "260711-R104_ZAP_ARTIFACT_PROMOTION.json"
BUNDLE = ROOT / "runtime-assets" / "attestations" / "260711-R104_ZAP_ARTIFACT_PROMOTION.sigstore.json"
PUBLIC_KEY = ROOT / "runtime-assets" / "attestations" / "260711-R104_ZAP_ARTIFACT_PROMOTION.pub"
NOW = datetime(2026, 7, 11, 7, 10, tzinfo=timezone.utc)


def test_signed_zero_critical_promotion_builds_r100_receipt() -> None:
    receipt, signature_sha256 = verify_zap_promotion(
        promotion_bytes=PROMOTION.read_bytes(), bundle_bytes=BUNDLE.read_bytes(),
        public_key_bytes=PUBLIC_KEY.read_bytes(), now=NOW,
    )
    assert receipt.signature_verified is True
    assert receipt.vulnerability_review == "accepted_no_critical"
    assert receipt.image_digest == "sha256:ccd16df57aed6724abdafe71b1077099c2b992d0945359d32d84f0939186b0c3"
    assert len(signature_sha256) == 64


def test_promotion_tamper_and_expiry_fail_closed() -> None:
    promotion = PROMOTION.read_bytes()
    with pytest.raises(ZapPromotionError, match="zap_promotion_digest_mismatch"):
        verify_zap_promotion(
            promotion_bytes=promotion + b" ", bundle_bytes=BUNDLE.read_bytes(),
            public_key_bytes=PUBLIC_KEY.read_bytes(), now=NOW,
        )
    with pytest.raises(ZapPromotionError, match="zap_promotion_expired"):
        verify_zap_promotion(
            promotion_bytes=promotion, bundle_bytes=BUNDLE.read_bytes(),
            public_key_bytes=PUBLIC_KEY.read_bytes(), now=datetime(2026, 8, 11, tzinfo=timezone.utc),
        )
