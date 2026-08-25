from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import pytest

from redagent_platform.finding_operations.promotion import verify_finding_operations_promotion


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ACTIVE_AT = datetime(2026, 7, 12, tzinfo=timezone.utc)
FIXTURE_EXPIRED_AT = datetime(2026, 8, 11, tzinfo=timezone.utc)


def test_signed_promotion_is_fixture_only_and_network_free() -> None:
    receipt = verify_finding_operations_promotion(ROOT, now=FIXTURE_ACTIVE_AT)
    assert receipt.fixture_connector_count == 1 and receipt.scenario_sha256


def test_signed_finding_promotion_rejects_its_expired_window() -> None:
    with pytest.raises(ValueError, match="finding_promotion_inactive"):
        verify_finding_operations_promotion(ROOT, now=FIXTURE_EXPIRED_AT)


def test_promotion_rejects_external_connector_or_publication_tamper(tmp_path: Path) -> None:
    planning = tmp_path / "runtime-assets" / "attestations"; config = tmp_path / "config"; planning.mkdir(parents=True); config.mkdir()
    for name in (
        "260712-R115_FINDING_OPERATIONS_PROMOTION.json", "260712-R115_FINDING_OPERATIONS_PROMOTION.pub",
        "260712-R115_FINDING_OPERATIONS_PROMOTION.signature.json",
        "260712-R115_FINDING_OPERATIONS_QUALIFICATION.json",
    ):
        shutil.copy2(ROOT / "runtime-assets" / "attestations" / name, planning / name)
    shutil.copy2(ROOT / "config/r115-finding-operations-runtime.json", config / "r115-finding-operations-runtime.json")
    manifest_path = planning / "260712-R115_FINDING_OPERATIONS_PROMOTION.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")); manifest["external_connectors"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="finding_promotion_safety_invalid"):
        verify_finding_operations_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)
