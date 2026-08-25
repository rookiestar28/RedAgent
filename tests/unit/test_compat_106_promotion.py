from datetime import datetime, timezone
import json
from pathlib import Path
import shutil

import pytest

from redagent_platform.api_differential_service.promotion import (
    ApiDifferentialPromotionError,
    verify_api_differential_promotion,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 11, 14, 0, tzinfo=timezone.utc)


def test_complete_signed_bundle_engine_spec_matrix_and_cleanup_grammar_pass() -> None:
    receipt, snapshot, manifest, signature_sha256 = verify_api_differential_promotion(ROOT, now=NOW)
    assert receipt.receipt_id == "artifact-r106-schemathesis-4224-r106-1"
    assert snapshot.operation_ids == (
        "createDocument", "deleteDocument", "getAudit", "getDocument", "getProfile", "transferDocument",
    )
    assert manifest["qualification"]["production_qualified"] is False
    assert len(signature_sha256) == 64


def test_file_signature_and_semantic_tamper_fail_closed(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    for relative in (
        "bundles/r106-api", "runtime-assets/attestations/260711-R106_API_DIFFERENTIAL_PROMOTION.pub",
        "runtime-assets/attestations/260711-R106_API_DIFFERENTIAL_PROMOTION.sigstore.json",
        "config/r106-schemathesis-runtime.json", "config/python-runtime-dependencies.json",
        "requirements-runtime.lock",
    ):
        source = ROOT / relative
        destination = workspace / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if source.is_dir():
            shutil.copytree(source, destination)
        else:
            shutil.copy2(source, destination)
    spec_path = workspace / "bundles/r106-api/openapi.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    spec["servers"] = [{"url": "https://public.example"}]
    spec_path.write_text(json.dumps(spec), encoding="utf-8")
    with pytest.raises(ApiDifferentialPromotionError, match="api_promotion_file_mismatch"):
        verify_api_differential_promotion(workspace, now=NOW)

    shutil.copy2(ROOT / "bundles/r106-api/openapi.json", spec_path)
    manifest_path = workspace / "bundles/r106-api/bundle-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["review"]["callbacks"] = True
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(ApiDifferentialPromotionError, match="api_promotion_signature_invalid"):
        verify_api_differential_promotion(workspace, now=NOW)
