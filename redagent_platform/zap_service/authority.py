"""Current additive compat_104 runtime-authority paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class SignedAuthorityPaths:
    document: Path
    signature: Path
    public_key: Path


CURRENT_ZAP_RUNTIME_LOCK = ROOT / "config/r104-zap-runtime-v2.json"
CURRENT_ZAP_ARTIFACT_PROMOTION = SignedAuthorityPaths(
    document=ROOT / "runtime-assets/attestations/260824-R104_ZAP_ARTIFACT_PROMOTION_V2.json",
    signature=ROOT / "runtime-assets/attestations/260824-R104_ZAP_ARTIFACT_PROMOTION_V2.sigstore.json",
    public_key=ROOT / "runtime-assets/attestations/260824-R104_ZAP_ARTIFACT_PROMOTION_V2.pub",
)
