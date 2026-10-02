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


CURRENT_ZAP_RUNTIME_LOCK = ROOT / "config/r104-zap-runtime-v3.json"
CURRENT_ZAP_ARTIFACT_PROMOTION = SignedAuthorityPaths(
    document=ROOT / "runtime-assets/attestations/261002-R104_ZAP_ARTIFACT_PROMOTION_V3.json",
    signature=ROOT / "runtime-assets/attestations/261002-R104_ZAP_ARTIFACT_PROMOTION_V3.sigstore.json",
    public_key=ROOT / "runtime-assets/attestations/261002-R104_ZAP_ARTIFACT_PROMOTION_V3.pub",
)

# CRITICAL: signer rotation is an explicit code change, never trust a mutable key file.
CURRENT_ZAP_PUBLIC_KEY_SHA256 = "e6fd1ad228ffb398ebcfbff78a265f6e6c2ba784aa58d596ca43a9ad341e2df8"
