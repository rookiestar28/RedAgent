from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from redagent_platform.nuclei_service.artifact_promotion import (
    NucleiArtifactPromotionError,
    verify_nuclei_artifact_promotion,
)


ROOT = Path(__file__).resolve().parents[2]


def _inputs() -> dict[str, object]:
    planning = ROOT / "runtime-assets" / "attestations"
    return {
        "promotion_bytes": (planning / "260711-R105_NUCLEI_ARTIFACT_PROMOTION.json").read_bytes(),
        "signature_bundle_bytes": (planning / "260711-R105_NUCLEI_ARTIFACT_PROMOTION.sigstore.json").read_bytes(),
        "public_key_bytes": (planning / "260711-R105_NUCLEI_ARTIFACT_PROMOTION.pub").read_bytes(),
        "now": datetime(2026, 7, 11, 8, 0, tzinfo=timezone.utc),
    }


def test_exact_engine_artifact_promotion_is_verified() -> None:
    receipt, signature_sha = verify_nuclei_artifact_promotion(**_inputs())  # type: ignore[arg-type]
    assert receipt.receipt_id == "artifact-r105-nuclei-380-r105-1"
    assert receipt.signature_verified is True and len(signature_sha) == 64


def test_engine_claim_or_signature_drift_fails_closed() -> None:
    values = _inputs()
    values["promotion_bytes"] = bytes(values["promotion_bytes"]).replace(b'"critical_vulnerability_count": 0', b'"critical_vulnerability_count": 1')
    with pytest.raises(NucleiArtifactPromotionError, match="nuclei_artifact_digest_mismatch"):
        verify_nuclei_artifact_promotion(**values)  # type: ignore[arg-type]
