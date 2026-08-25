from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import pytest

from redagent_platform.human_simulation.promotion import verify_human_simulation_promotion


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ACTIVE_AT = datetime(2026, 7, 12, tzinfo=timezone.utc)
FIXTURE_EXPIRED_AT = datetime(2026, 8, 11, tzinfo=timezone.utc)


def test_signed_promotion_binds_zero_human_delivery_minimization_and_deletion():
    receipt = verify_human_simulation_promotion(ROOT, now=FIXTURE_ACTIVE_AT)
    assert receipt.receipt.signature_verified and receipt.receipt.vulnerability_review == "accepted_no_critical"


def test_signed_human_promotion_rejects_its_expired_window() -> None:
    with pytest.raises(ValueError, match="human_promotion_inactive"):
        verify_human_simulation_promotion(ROOT, now=FIXTURE_EXPIRED_AT)


def test_promotion_rejects_delivery_and_qualification_tamper(tmp_path: Path):
    planning = tmp_path / "runtime-assets" / "attestations"; config = tmp_path / "config"; planning.mkdir(parents=True); config.mkdir()
    for name in ("260711-R112_HUMAN_SIMULATION_PROMOTION.json", "260711-R112_HUMAN_SIMULATION_PROMOTION.pub",
                 "260711-R112_HUMAN_SIMULATION_PROMOTION.signature.json", "260711-R112_HUMAN_SIMULATION_QUALIFICATION.json"):
        shutil.copy2(ROOT / "runtime-assets" / "attestations" / name, planning / name)
    shutil.copy2(ROOT / "config/r112-human-simulation-runtime.json", config / "r112-human-simulation-runtime.json")
    manifest_path = planning / "260711-R112_HUMAN_SIMULATION_PROMOTION.json"; manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["human_delivery"] = True; manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="human_promotion_safety_invalid"):
        verify_human_simulation_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)
    shutil.copy2(ROOT / "runtime-assets/attestations/260711-R112_HUMAN_SIMULATION_PROMOTION.json", manifest_path)
    qualification_path = planning / "260711-R112_HUMAN_SIMULATION_QUALIFICATION.json"
    qualification = json.loads(qualification_path.read_text(encoding="utf-8")); qualification["safety"]["real_recipient_count"] = 1
    qualification_path.write_text(json.dumps(qualification), encoding="utf-8")
    with pytest.raises(ValueError, match="human_promotion_safety_invalid"):
        verify_human_simulation_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)
