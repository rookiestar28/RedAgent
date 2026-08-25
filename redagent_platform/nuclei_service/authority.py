"""Current additive compat_105 runtime and bundle-authority paths."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


@dataclass(frozen=True, slots=True)
class SignedAuthorityPaths:
    document: Path
    signature: Path
    public_key: Path


CURRENT_NUCLEI_RUNTIME_LOCK = ROOT / "config/r105-nuclei-runtime-v2.json"
CURRENT_NUCLEI_ARTIFACT_PROMOTION = SignedAuthorityPaths(
    document=ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.json",
    signature=ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.sigstore.json",
    public_key=ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_ARTIFACT_PROMOTION_V2.pub",
)
CURRENT_NUCLEI_BUNDLE_MANIFEST = ROOT / "bundles/r105-nuclei/bundle-manifest-v2.json"
CURRENT_NUCLEI_BUNDLE_PROMOTION = SignedAuthorityPaths(
    document=CURRENT_NUCLEI_BUNDLE_MANIFEST,
    signature=ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_BUNDLE_PROMOTION_V2.sigstore.json",
    public_key=ROOT / "runtime-assets/attestations/260824-R105_NUCLEI_BUNDLE_PROMOTION_V2.pub",
)
