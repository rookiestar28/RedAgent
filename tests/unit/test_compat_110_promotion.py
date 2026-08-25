from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import pytest

from redagent_platform.artifact_pipeline.promotion import verify_artifact_promotion


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ACTIVE_AT = datetime(2026, 7, 12, tzinfo=timezone.utc)
FIXTURE_EXPIRED_AT = datetime(2026, 8, 11, tzinfo=timezone.utc)


def test_signed_artifact_promotion_binds_zero_execution_qualification() -> None:
    receipt = verify_artifact_promotion(ROOT, now=FIXTURE_ACTIVE_AT)
    assert receipt.receipt.signature_verified and receipt.receipt.vulnerability_review == "accepted_no_critical"


def test_signed_artifact_promotion_rejects_its_expired_window() -> None:
    with pytest.raises(ValueError, match="artifact_promotion_inactive"):
        verify_artifact_promotion(ROOT, now=FIXTURE_EXPIRED_AT)


def test_artifact_promotion_rejects_manifest_and_qualification_tamper(tmp_path: Path) -> None:
    planning = tmp_path / "runtime-assets" / "attestations"; config = tmp_path / "config"; planning.mkdir(parents=True); config.mkdir()
    for name in ("260711-R110_ARTIFACT_PROMOTION.json", "260711-R110_ARTIFACT_PROMOTION.pub", "260711-R110_ARTIFACT_PROMOTION.signature.json", "260711-R110_ARTIFACT_PIPELINE_QUALIFICATION.json"):
        shutil.copy2(ROOT / "runtime-assets" / "attestations" / name, planning / name)
    shutil.copy2(ROOT / "config/r110-artifact-runtime.json", config / "r110-artifact-runtime.json")
    manifest_path = planning / "260711-R110_ARTIFACT_PROMOTION.json"; manifest = json.loads(manifest_path.read_text(encoding="utf-8")); manifest["production_qualified"] = True; manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact_promotion_safety_invalid"): verify_artifact_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)
    shutil.copy2(ROOT / "runtime-assets/attestations/260711-R110_ARTIFACT_PROMOTION.json", manifest_path)
    qualification_path = planning / "260711-R110_ARTIFACT_PIPELINE_QUALIFICATION.json"; qualification = json.loads(qualification_path.read_text(encoding="utf-8")); qualification["safety"]["untrusted_execution_count"] = 1; qualification_path.write_text(json.dumps(qualification), encoding="utf-8")
    with pytest.raises(ValueError, match="artifact_promotion_safety_invalid"): verify_artifact_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)
