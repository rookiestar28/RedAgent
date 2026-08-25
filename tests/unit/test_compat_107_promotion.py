from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import pytest

from redagent_platform.network_service.promotion import verify_network_promotion


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ACTIVE_AT = datetime(2026, 7, 12, tzinfo=timezone.utc)
FIXTURE_EXPIRED_AT = datetime(2026, 8, 11, tzinfo=timezone.utc)


def test_signed_network_promotion_binds_runtime_images_and_zero_critical_state() -> None:
    receipt = verify_network_promotion(ROOT, now=FIXTURE_ACTIVE_AT)
    assert receipt.receipt.signature_verified is True
    assert receipt.receipt.vulnerability_review == "accepted_no_critical"
    assert receipt.receipt.image_digest.startswith("sha256:")
    assert len(receipt.manifest_sha256) == 64
    assert len(receipt.signature_sha256) == 64


def test_signed_network_promotion_rejects_its_expired_window() -> None:
    with pytest.raises(ValueError, match="network_promotion_inactive"):
        verify_network_promotion(ROOT, now=FIXTURE_EXPIRED_AT)


def test_signed_network_promotion_rejects_manifest_and_lock_tamper(tmp_path: Path) -> None:
    planning = tmp_path / "runtime-assets" / "attestations"
    config = tmp_path / "config"
    planning.mkdir(parents=True); config.mkdir()
    for name in (
        "260711-R107_NETWORK_PROMOTION.json",
        "260711-R107_NETWORK_PROMOTION.pub",
        "260711-R107_NETWORK_PROMOTION.signature.json",
    ):
        shutil.copy2(ROOT / "runtime-assets" / "attestations" / name, planning / name)
    shutil.copy2(ROOT / "config/r107-network-runtime.json", config / "r107-network-runtime.json")
    manifest_path = planning / "260711-R107_NETWORK_PROMOTION.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["production_qualified"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="network_promotion_safety_invalid"):
        verify_network_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)

    shutil.copy2(ROOT / "runtime-assets/attestations/260711-R107_NETWORK_PROMOTION.json", manifest_path)
    lock_path = config / "r107-network-runtime.json"
    lock_path.write_text(lock_path.read_text(encoding="utf-8") + " ", encoding="utf-8")
    with pytest.raises(ValueError, match="network_promotion_safety_invalid"):
        verify_network_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)
