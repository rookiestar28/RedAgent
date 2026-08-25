#!/usr/bin/env python3
"""Create the reviewable compat_116 promotion using an ephemeral in-memory key."""

from __future__ import annotations

import base64
from datetime import UTC, datetime
import gzip
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


PLANNING = ROOT / "runtime-assets" / "attestations"
QUALIFICATION = PLANNING / "260712-R116_DEPLOYMENT_RELEASE_QUALIFICATION.json"
LOCK = ROOT / "config" / "r116-deployment-release-runtime.json"
MANIFEST = PLANNING / "260712-R116_DEPLOYMENT_RELEASE_PROMOTION.json"
SIGNATURE = PLANNING / "260712-R116_DEPLOYMENT_RELEASE_PROMOTION.signature.json"
PUBLIC_KEY = PLANNING / "260712-R116_DEPLOYMENT_RELEASE_PROMOTION.pub"
SBOM = PLANNING / "260712-R116_APP_IMAGE_SBOM.spdx.json.gz"
CYCLONEDX_SBOM = PLANNING / "260712-R116_APP_IMAGE_SBOM.cdx.json.gz"
APP_IMAGE = "redagent/r116-app@sha256:d8b1f9b8a60e8dc4820553d36799f18f07268d1f8d53e2a02b20c9f722c9ae19"


def main() -> int:
    qualification = json.loads(QUALIFICATION.read_text(encoding="utf-8"))
    assertion = dict(qualification)
    assertion.pop("ok", None)
    asserted_sha = assertion.pop("receipt_sha256")
    if asserted_sha != _digest(assertion) or qualification.get("status") != "passed":
        raise ValueError("r116_qualification_invalid")
    sources = sorted(
        [
            *ROOT.glob("redagent_platform/deployment_release/*.py"),
            ROOT / "scripts/compat_116_deployment_release.py",
            ROOT / "scripts/compat_116_sign_promotion.py",
        ]
    )
    source_hashes = [
        {"path": path.relative_to(ROOT).as_posix(), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for path in sources
    ]
    source_tree_sha = _digest(source_hashes)
    profile_paths = [
        ROOT / "deploy/profiles/r116-single-node.json",
        ROOT / "deploy/profiles/r116-kubernetes-enterprise.json",
    ]
    sbom = json.loads(gzip.decompress(SBOM.read_bytes()))
    if sbom.get("spdxVersion") != "SPDX-2.3" or sbom.get("name") != "redagent/r116-app" or not sbom.get("packages"):
        raise ValueError("r116_app_image_sbom_invalid")
    cyclonedx = json.loads(gzip.decompress(CYCLONEDX_SBOM.read_bytes()))
    if cyclonedx.get("bomFormat") != "CycloneDX" or not cyclonedx.get("specVersion") or not cyclonedx.get("components"):
        raise ValueError("r116_app_image_cyclonedx_invalid")
    lock = {
        "schema": "redagent.r116-runtime-lock/v1",
        "enabled_profiles": ["single_node", "kubernetes_enterprise"],
        "qualification_level": "structurally_conformant",
        "profile_sha256s": [
            {"path": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
            for path in profile_paths
        ],
        "bundled_images": [
            {
                "components": ["api", "worker"],
                "reference": APP_IMAGE,
                "sbom_path": SBOM.relative_to(ROOT).as_posix(),
                "sbom_sha256": hashlib.sha256(SBOM.read_bytes()).hexdigest(),
                "cyclonedx_sbom_path": CYCLONEDX_SBOM.relative_to(ROOT).as_posix(),
                "cyclonedx_sbom_sha256": hashlib.sha256(CYCLONEDX_SBOM.read_bytes()).hexdigest(),
            }
        ],
        "source_sha256s": source_hashes,
        "source_tree_sha256": source_tree_sha,
        "qualification_assertion_sha256": asserted_sha,
        "max_bundle_artifacts": 4096,
        "max_bundle_bytes": 107374182400,
        **_false_fields(),
    }
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    LOCK.write_bytes((json.dumps(lock, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    promoted = datetime(2026, 7, 12, 0, 0, tzinfo=UTC)
    manifest = {
        "schema": "redagent.r116-promotion/v1",
        "runtime_lock_sha256": hashlib.sha256(LOCK.read_bytes()).hexdigest(),
        "qualification_receipt_sha256": hashlib.sha256(QUALIFICATION.read_bytes()).hexdigest(),
        "source_tree_sha256": source_tree_sha,
        "author": "release-engineer",
        "reviewer": "security-reviewer",
        "promoted_at": promoted.isoformat(),
        "expires_at": datetime(2027, 7, 12, 0, 0, tzinfo=UTC).isoformat(),
        **_false_fields(),
    }
    content = _canonical(manifest)
    MANIFEST.write_bytes((json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    private = ec.generate_private_key(ec.SECP256R1())
    raw_signature = private.sign(content, ec.ECDSA(hashes.SHA256()))
    signature = {
        "schema": "redagent.ecdsa-p256-signature/v1",
        "manifest_sha256": hashlib.sha256(content).hexdigest(),
        "signature_base64": base64.b64encode(raw_signature).decode("ascii"),
    }
    SIGNATURE.write_bytes((json.dumps(signature, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    PUBLIC_KEY.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    print(json.dumps({"ok": True, "source_tree_sha256": source_tree_sha, "private_key_persisted": False}, sort_keys=True))
    return 0


def _false_fields() -> dict[str, bool]:
    return {
        "production_qualified": False,
        "real_environment_qualified": False,
        "network_enabled": False,
        "external_execution_enabled": False,
        "registry_fallback_enabled": False,
        "automatic_apply_enabled": False,
        "destructive_restore_enabled": False,
        "destructive_downgrade_enabled": False,
    }


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _digest(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


if __name__ == "__main__":
    raise SystemExit(main())
