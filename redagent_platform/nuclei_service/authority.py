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


CURRENT_NUCLEI_RUNTIME_LOCK = ROOT / "config/r105-nuclei-runtime-v3.json"
CURRENT_NUCLEI_ARTIFACT_PROMOTION = SignedAuthorityPaths(
    document=ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.json",
    signature=ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.sigstore.json",
    public_key=ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.pub",
)
CURRENT_NUCLEI_BUNDLE_MANIFEST = ROOT / "bundles/r105-nuclei/bundle-manifest-v3.json"
CURRENT_NUCLEI_BUNDLE_PROMOTION = SignedAuthorityPaths(
    document=CURRENT_NUCLEI_BUNDLE_MANIFEST,
    signature=ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.sigstore.json",
    public_key=ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.pub",
)

# CRITICAL: signer rotation is an explicit code change, never trust a mutable key file.
CURRENT_NUCLEI_ARTIFACT_PUBLIC_KEY_SHA256 = "799e977d575224dabd5d30d8b12b722404278afc3064274cc691f97616371696"

# CRITICAL: signer rotation is an explicit code change, never trust a mutable key file.
CURRENT_NUCLEI_BUNDLE_PUBLIC_KEY_SHA256 = "e460597a7b755b933310c2cfd2a3000c32c2295c27553ba992339117de2d122c"
