from __future__ import annotations

from datetime import datetime, timezone
import importlib
import json
from pathlib import Path
import shutil

import pytest


ROOT = Path(__file__).resolve().parents[2]
FIXTURE_ACTIVE_AT = datetime(2026, 7, 12, tzinfo=timezone.utc)
FIXTURE_EXPIRED_AT = datetime(2026, 8, 11, tzinfo=timezone.utc)


def _verify(workspace: Path, *, now: datetime = FIXTURE_ACTIVE_AT):
    try:
        verifier = importlib.import_module("redagent_platform.agent_kernel.promotion").verify_agent_kernel_promotion
    except ModuleNotFoundError:
        pytest.fail("compat_113 RED: signed agent-kernel promotion verifier is not implemented")
    return verifier(workspace, now=now)


def test_signed_promotion_binds_fake_only_provider_strict_projection_and_zero_external_authority() -> None:
    receipt = _verify(ROOT)
    assert receipt.receipt.signature_verified
    assert receipt.receipt.vulnerability_review == "accepted_no_critical"
    assert receipt.projected_capability_count == 9


def test_signed_agent_promotion_rejects_its_expired_window() -> None:
    with pytest.raises(ValueError, match="agent_promotion_inactive"):
        _verify(ROOT, now=FIXTURE_EXPIRED_AT)


def test_promotion_rejects_external_provider_storage_dispatch_or_qualification_tamper(tmp_path: Path) -> None:
    planning = tmp_path / "runtime-assets" / "attestations"
    config = tmp_path / "config"
    planning.mkdir(parents=True)
    config.mkdir()
    for name in (
        "260712-R113_AGENT_KERNEL_PROMOTION.json",
        "260712-R113_AGENT_KERNEL_PROMOTION.pub",
        "260712-R113_AGENT_KERNEL_PROMOTION.signature.json",
        "260712-R113_AGENT_KERNEL_QUALIFICATION.json",
    ):
        shutil.copy2(ROOT / "runtime-assets" / "attestations" / name, planning / name)
    shutil.copy2(ROOT / "config/r113-agent-kernel-runtime.json", config / "r113-agent-kernel-runtime.json")
    manifest_path = planning / "260712-R113_AGENT_KERNEL_PROMOTION.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["external_model_calls"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ValueError, match="agent_promotion_safety_invalid"):
        _verify(tmp_path)
    shutil.copy2(ROOT / "runtime-assets/attestations/260712-R113_AGENT_KERNEL_PROMOTION.json", manifest_path)
    qualification_path = planning / "260712-R113_AGENT_KERNEL_QUALIFICATION.json"
    qualification = json.loads(qualification_path.read_text(encoding="utf-8"))
    qualification["external_contact_count"] = 1
    qualification_path.write_text(json.dumps(qualification), encoding="utf-8")
    with pytest.raises(ValueError, match="agent_promotion_safety_invalid"):
        _verify(tmp_path)
