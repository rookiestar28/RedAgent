"""Issue the closed revision-3 local authority from fresh physical qualification."""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from scripts.owned_runtime_requalification import verified_artifact_tuple  # noqa: E402

PROFILES = ("zap-passive-v1", "zap-auth-crawl-v1", "zap-client-spider-v1", "zap-active-xss-lab-v1")
STATE = ROOT / ".tmp/runtime-requalification-v3"
ATTESTATIONS = ROOT / "runtime-assets/attestations"


class AuthorityIssuanceError(ValueError):
    """Incomplete or drifted local evidence never grants authority."""


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def json_bytes(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2) + "\n").encode()


def verify_profile(result: dict[str, object], *, profile: str, image: str,
                   lock_sha256: str, now: datetime) -> None:
    try:
        qualified = datetime.fromisoformat(result["qualified_at"])
        valid = (result["profile_id"] == profile and result["ok"] is True
                 and result["engine_image_id"] == image and result["runtime_lock_sha256"] == lock_sha256
                 and result["network_isolation_verified"] is True and result["external_target_contacts"] == 0
                 and result["cleanup"]["cleanup_complete"] is True
                 and result["cleanup"]["residual_resource_count"] == 0
                 and result["cancel"]["native_stop_acknowledged"] is True
                 and result["cancel"]["sensitive_files_remaining"] == 0
                 and qualified.tzinfo is not None and timedelta(0) <= now - qualified <= timedelta(days=2))
    except (KeyError, TypeError, ValueError) as exc:
        raise AuthorityIssuanceError("physical_profile_evidence_invalid") from exc
    if not valid:
        raise AuthorityIssuanceError("physical_profile_not_current_or_qualified")


def _sign(document: bytes, name: str) -> tuple[bytes, bytes]:
    private = ROOT / f".local/redagent/runtime-authority-v3/{name}.key"
    private.parent.mkdir(parents=True, exist_ok=True)
    if private.exists():
        key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        private.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                           serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        private.chmod(0o600)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise AuthorityIssuanceError("local_signer_type_invalid")
    digest = hashlib.sha256(document).digest()
    bundle = {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json", "messageSignature": {
        "messageDigest": {"algorithm": "SHA2_256", "digest": base64.b64encode(digest).decode()},
        "signature": base64.b64encode(key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))).decode(),
    }}
    return (key.public_key().public_bytes(serialization.Encoding.PEM,
                                        serialization.PublicFormat.SubjectPublicKeyInfo), json_bytes(bundle))


def issue() -> dict[str, object]:
    verified_artifact_tuple()
    # CRITICAL: use the actual issuance clock after all physical profiles and static
    # proofs pass. Never extend/backdate historical authority or sign a failed image.
    now = datetime.now(timezone.utc)
    outputs = {}
    qualification = {}
    locks = {}
    for item, engine, profiles in (("r104", "zap", PROFILES),
                                   ("r105", "nuclei", ("nuclei-http-header-v1",))):
        lock_path = ROOT / f"config/{item}-{engine}-runtime-v3.json"
        lock = json.loads(lock_path.read_text())
        locks[item] = lock
        lock_sha = sha(lock_path)
        results = []
        tool = ROOT / ("scripts/compat_104_zap.py" if item == "r104" else "scripts/compat_105_nuclei.py")
        for profile in profiles:
            path = STATE / f"{profile}-qualified.json"
            result = json.loads(path.read_text())
            verify_profile(result, profile=profile, image=lock["engine_image_id"], lock_sha256=lock_sha, now=now)
            if result["qualifier_source_sha256"] != sha(tool):
                raise AuthorityIssuanceError("qualification_tool_source_drift")
            if item == "r105" and (result["owned_fixture_finding_count"] != 1
                    or any(result.get(key) is not True for key in (
                        "unsigned_template_denied", "payload_tamper_denied", "gateway_quota_denied"))):
                raise AuthorityIssuanceError("nuclei_negative_qualification_incomplete")
            public_path = ATTESTATIONS / f"261002-{item.upper()}_{profile}_V3.json"
            outputs[public_path] = json_bytes(result)
            results.append({"profile_id": profile, "receipt_path": public_path.relative_to(ROOT).as_posix(),
                            "receipt_sha256": hashlib.sha256(outputs[public_path]).hexdigest(),
                            "passed": True, "network_isolation_verified": True,
                            "external_target_contacts": 0, "cleanup_residual_resource_count": 0,
                            "native_stop_acknowledged": True})
        summary = {"schema": f"redagent.{item}-runtime-qualification/v3",
                   "qualified_at": max(json.loads((STATE / f"{p}-qualified.json").read_text())["qualified_at"]
                                       for p in profiles), "runtime_lock_sha256": lock_sha,
                   "engine_image_id": lock["engine_image_id"], "profiles": results,
                   "direct_target_route": False, "external_target_contacts": 0,
                   "network_isolation_verified": True, "cleanup_residual_resource_count": 0,
                   "production_qualified": False}
        if item == "r104":
            summary.update({"all_profiles_passed": True, "addon_inventory_sha256": lock["zap_addon_inventory_sha256"]})
        else:
            result = json.loads((STATE / "nuclei-http-header-v1-qualified.json").read_text())
            summary.update({"signed_bundle_verified": True, "owned_fixture_finding_count": 1,
                            "candidate_bundle_sha256": result["bundle_sha256"],
                            "false_positive_regression_passed": result["owned_fixture_finding_count"] == 1})
        summary_path = ATTESTATIONS / f"261002-{item.upper()}_{engine.upper()}_RUNTIME_QUALIFICATION_V3.json"
        outputs[summary_path] = json_bytes(summary)
        qualification[item] = (summary_path, summary)
        promotion = json.loads((ATTESTATIONS / f"260824-{item.upper()}_{engine.upper()}_ARTIFACT_PROMOTION_V2.json").read_text())
        promotion.update({"schema": f"redagent.{item}-artifact-promotion/v3",
                          "promotion_id": f"{item}-{engine}-revision3-local", "created_at": now.isoformat(),
                          "expires_at": (now + timedelta(days=30)).isoformat(),
                          "runtime_lock": {"path": lock_path.relative_to(ROOT).as_posix(), "sha256": lock_sha},
                          "local_signer_rotation": {"kind": "fresh-local-only-root",
                              "previous_public_key_sha256": sha(ATTESTATIONS / f"260824-{item.upper()}_{engine.upper()}_ARTIFACT_PROMOTION_V2.pub")}})
        promotion["artifact"].update({"local_tag": lock["engine_local_tag"], "image_digest": lock["engine_image_id"],
                                      "dockerfile_sha256": lock["engine_dockerfile_sha256"]})
        if item == "r105":
            promotion["artifact"]["engine_id"] = "nuclei-3.11.1-r105.3"
        promotion["owned_helpers"] = {key: lock[key] for key in promotion["owned_helpers"]}
        promotion["sbom"].update({"sha256": lock["sbom_sha256"], "package_count": lock["sbom_package_count"]})
        promotion["vulnerability_review"].update({"database_updated_at": lock["vulnerability_database_updated_at"],
                                                  "report_sha256": lock["critical_report_sha256"]})
        promotion["qualification"] = {**summary, "receipt_path": summary_path.relative_to(ROOT).as_posix(),
                                       "receipt_sha256": hashlib.sha256(outputs[summary_path]).hexdigest()}
        if item == "r104":
            promotion["qualification"]["profiles"] = list(PROFILES)
        outputs[ATTESTATIONS / f"261002-{item.upper()}_{engine.upper()}_ARTIFACT_PROMOTION_V3.json"] = json_bytes(promotion)
    old_manifest = ROOT / "bundles/r105-nuclei/bundle-manifest-v2.json"
    manifest = json.loads(old_manifest.read_text())
    summary_path, summary = qualification["r105"]
    manifest.update({"schema": "redagent.r105-template-bundle/v3", "bundle_revision": 3,
                     "engine": {"version": "3.11.1", "image_digest": locks["r105"]["engine_image_id"]},
                     "promoted_at": now.isoformat(), "expires_at": (now + timedelta(days=30)).isoformat()})
    manifest.pop("source_base", None)
    # This inherits review of identical template bytes, not a new candidate acceptance review.
    manifest["review"].update({"scope": "unchanged-template-source-only", "source_manifest_sha256": sha(old_manifest),
                                "template_sha256": locks["r105"]["template_sha256"]})
    manifest["qualification"] = {**summary, "receipt_path": summary_path.relative_to(ROOT).as_posix(),
                                   "receipt_sha256": hashlib.sha256(outputs[summary_path]).hexdigest()}
    manifest_path = ROOT / "bundles/r105-nuclei/bundle-manifest-v3.json"
    outputs[manifest_path] = json_bytes(manifest)
    signed = ((ATTESTATIONS / "261002-R104_ZAP_ARTIFACT_PROMOTION_V3.json", "r104-zap", "261002-R104_ZAP_ARTIFACT_PROMOTION_V3"),
              (ATTESTATIONS / "261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.json", "r105-nuclei", "261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3"),
              (manifest_path, "r105-bundle", "261002-R105_NUCLEI_BUNDLE_PROMOTION_V3"))
    if any(path.exists() for path in outputs):
        raise AuthorityIssuanceError("revision3_authority_already_materialized")
    for document, key, stem in signed:
        pub_path, sig_path = ATTESTATIONS / f"{stem}.pub", ATTESTATIONS / f"{stem}.sigstore.json"
        if pub_path.exists() or sig_path.exists():
            raise AuthorityIssuanceError("revision3_signer_output_already_materialized")
        outputs[pub_path], outputs[sig_path] = _sign(outputs[document], key)
    for path, data in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return {"schema": "redagent.local-runtime-authority-issuance/v3", "issued_at": now.isoformat(),
            "files": {path.relative_to(ROOT).as_posix(): hashlib.sha256(data).hexdigest()
                      for path, data in outputs.items()}, "production_qualified": False}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--confirm-owned-local-authority", action="store_true", required=True)
    parser.parse_args()
    print(json.dumps(issue(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
