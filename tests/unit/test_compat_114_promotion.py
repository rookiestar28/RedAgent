from __future__ import annotations

from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import pytest

from redagent_platform.mcp_broker.promotion import verify_mcp_promotion


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ACTIVE_AT = datetime(2026, 7, 12, tzinfo=timezone.utc)
FIXTURE_EXPIRED_AT = datetime(2026, 8, 11, tzinfo=timezone.utc)


def test_signed_promotion_is_fixture_only_and_no_external_io() -> None:
    receipt = verify_mcp_promotion(ROOT, now=FIXTURE_ACTIVE_AT)
    assert receipt.fixture_inventory_count == 2 and receipt.inventory_sha256


def test_signed_mcp_promotion_rejects_its_expired_window() -> None:
    with pytest.raises(ValueError, match="mcp_promotion_inactive"):
        verify_mcp_promotion(ROOT, now=FIXTURE_EXPIRED_AT)


def test_promotion_rejects_remote_stdio_provider_or_qualification_tamper(tmp_path: Path) -> None:
    planning = tmp_path / "runtime-assets" / "attestations"; config = tmp_path / "config"; planning.mkdir(parents=True); config.mkdir()
    for name in ("260712-R114_MCP_WORKBENCH_PROMOTION.json", "260712-R114_MCP_WORKBENCH_PROMOTION.pub",
                 "260712-R114_MCP_WORKBENCH_PROMOTION.signature.json", "260712-R114_MCP_WORKBENCH_QUALIFICATION.json"):
        shutil.copy2(ROOT / "runtime-assets" / "attestations" / name, planning / name)
    shutil.copy2(ROOT / "config/r114-mcp-workbench-runtime.json", config / "r114-mcp-workbench-runtime.json")
    manifest_path = planning / "260712-R114_MCP_WORKBENCH_PROMOTION.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8")); manifest["remote_http"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="mcp_promotion_safety_invalid"):
        verify_mcp_promotion(tmp_path, now=FIXTURE_ACTIVE_AT)
