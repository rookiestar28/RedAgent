from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import pytest

from redagent_platform.identity_saas.promotion import verify_identity_promotion


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ACTIVE_AT = datetime(2026, 7, 12, tzinfo=timezone.utc)
FIXTURE_EXPIRED_AT = datetime(2026, 8, 11, tzinfo=timezone.utc)


def test_signed_identity_promotion_binds_local_qualification_and_disabled_external_execution() -> None:
    receipt = verify_identity_promotion(ROOT, now=FIXTURE_ACTIVE_AT)
    assert receipt.receipt.signature_verified is True
    assert receipt.receipt.vulnerability_review == "accepted_no_critical"
    assert receipt.receipt.image_digest.startswith("sha256:")


def test_signed_identity_promotion_rejects_its_expired_window() -> None:
    with pytest.raises(ValueError, match="identity_promotion_inactive"):
        verify_identity_promotion(ROOT, now=FIXTURE_EXPIRED_AT)


def test_identity_promotion_rejects_manifest_and_qualification_tamper(tmp_path: Path) -> None:
    planning = tmp_path / "runtime-assets" / "attestations"; config = tmp_path / "config"; planning.mkdir(parents=True); config.mkdir()
    for name in ("260711-R109_IDENTITY_PROMOTION.json", "260711-R109_IDENTITY_PROMOTION.pub", "260711-R109_IDENTITY_PROMOTION.signature.json", "260711-R109_IDENTITY_CONNECTOR_QUALIFICATION.json"):
        shutil.copy2(ROOT / "runtime-assets" / "attestations" / name, planning / name)
    shutil.copy2(ROOT / "config/r109-identity-runtime.json", config / "r109-identity-runtime.json")
    manifest_path = planning / "260711-R109_IDENTITY_PROMOTION.json"; manifest = json.loads(manifest_path.read_text(encoding="utf-8")); manifest["production_qualified"] = True; manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="identity_promotion_safety_invalid"): verify_identity_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)
    shutil.copy2(ROOT / "runtime-assets/attestations/260711-R109_IDENTITY_PROMOTION.json", manifest_path)
    qualification_path = planning / "260711-R109_IDENTITY_CONNECTOR_QUALIFICATION.json"; qualification = json.loads(qualification_path.read_text(encoding="utf-8")); qualification["status"] = "failed"; qualification_path.write_text(json.dumps(qualification), encoding="utf-8")
    with pytest.raises(ValueError, match="identity_promotion_safety_invalid"): verify_identity_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)
