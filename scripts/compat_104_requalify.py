#!/usr/bin/env python3
"""Build and sign the closed compat_104 revision-2 local authority."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, utils


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.zap_service.authority import (
    CURRENT_ZAP_ARTIFACT_PROMOTION,
    CURRENT_ZAP_RUNTIME_LOCK,
)


SOURCE_DATE_EPOCH = 1787529600
COMPATIBILITY_VERSION = "20"
RUNTIME = ROOT / ".tmp/r104-requalification-v2"
PRIVATE_KEY = ROOT / ".local/redagent/r104-requalification-v2/promotion.key"
ENGINE_DOCKERFILE = ROOT / "containers/r104-zap/Dockerfile"
TARGET_DOCKERFILE = ROOT / "containers/r104-target/Dockerfile"
GATEWAY_DOCKERFILE = ROOT / "containers/r104-gateway/Dockerfile"
SPECS = (
    ("engine", ENGINE_DOCKERFILE, ROOT / "containers/r104-zap", "redagent/r104-zap:2.17.0-r104.2", False),
    ("target", TARGET_DOCKERFILE, ROOT, "redagent/r104-target:1.0.1", True),
    ("gateway", GATEWAY_DOCKERFILE, ROOT, "redagent/r104-gateway:1.0.1", True),
)


class R104RequalificationError(RuntimeError):
    """Stable failure for the closed revision-2 assembly path."""


def _run(arguments: list[str], *, timeout: int = 1200) -> str:
    completed = subprocess.run(
        arguments, cwd=ROOT, text=True, capture_output=True, timeout=timeout, check=False
    )
    if completed.returncode != 0:
        raise R104RequalificationError(
            f"requalification_command_failed:{arguments[1]}:{completed.stderr.strip()[:300]}"
        )
    return completed.stdout.strip()


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _build_once(dockerfile: Path, context: Path, tag: str, network_none: bool) -> str:
    output = ",".join((
        "type=image",
        f"name={tag}",
        "rewrite-timestamp=true",
        "unpack=false",
        "compatibility-version=20",
    ))
    arguments = [
        "docker", "buildx", "build", "--no-cache", "--provenance=false",
        "--build-arg", "SOURCE_DATE_EPOCH=1787529600", "--output", output,
        "--file", str(dockerfile), "--label", "redagent.owner=r104",
    ]
    if network_none:
        arguments.extend(("--network", "none"))
    arguments.append(str(context))
    _run(arguments)
    return _run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"])


def build() -> dict[str, object]:
    validate()
    locked = json.loads(CURRENT_ZAP_RUNTIME_LOCK.read_text(encoding="utf-8"))
    observed: dict[str, str] = {}
    for name, dockerfile, context, tag, network_none in SPECS:
        first_tag = f"{tag}-repro-a"
        second_tag = f"{tag}-repro-b"
        first = _build_once(dockerfile, context, first_tag, network_none)
        second = _build_once(dockerfile, context, second_tag, network_none)
        if first != second:
            raise R104RequalificationError(
                f"requalification_build_not_reproducible:{name}:{first}:{second}"
            )
        # CRITICAL: reproducibility alone does not restore the reviewed image identity.
        # Reject a mutually equal replacement before it can take the operational tag.
        if second != locked[f"{name}_image_id"]:
            raise R104RequalificationError(f"requalification_locked_image_mismatch:{name}")
        _run(["docker", "tag", second_tag, tag])
        _run(["docker", "image", "rm", first_tag, second_tag])
        observed[name] = second
    receipt = {
        "schema": "redagent.r104-requalification-build/v2",
        "source_date_epoch": SOURCE_DATE_EPOCH,
        "buildkit_compatibility_version": COMPATIBILITY_VERSION,
        "images": observed,
        "dockerfile_sha256": {
            "engine": _sha256(ENGINE_DOCKERFILE),
            "target": _sha256(TARGET_DOCKERFILE),
            "gateway": _sha256(GATEWAY_DOCKERFILE),
        },
    }
    RUNTIME.mkdir(parents=True, exist_ok=True)
    temporary = RUNTIME / "build-receipt.json.tmp"
    temporary.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(RUNTIME / "build-receipt.json")
    return receipt


def validate() -> dict[str, object]:
    value = json.loads(CURRENT_ZAP_RUNTIME_LOCK.read_text(encoding="utf-8"))
    if (
        value.get("schema") != "redagent.r104-runtime-lock/v2"
        or value.get("source_date_epoch") != SOURCE_DATE_EPOCH
        or value.get("buildkit_compatibility_version") != COMPATIBILITY_VERSION
        or value.get("rewrite_timestamp") is not True
        or value.get("production_qualified") is not False
    ):
        raise R104RequalificationError("r104_revision_two_lock_invalid")
    return {"ok": True, "action": "validate"}


def _sign() -> None:
    document = CURRENT_ZAP_ARTIFACT_PROMOTION.document.read_bytes()
    PRIVATE_KEY.parent.mkdir(parents=True, exist_ok=True)
    if PRIVATE_KEY.exists():
        key = serialization.load_pem_private_key(PRIVATE_KEY.read_bytes(), password=None)
    else:
        key = ec.generate_private_key(ec.SECP256R1())
        PRIVATE_KEY.write_bytes(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
        os.chmod(PRIVATE_KEY, 0o600)
    if not isinstance(key, ec.EllipticCurvePrivateKey):
        raise R104RequalificationError("r104_revision_two_private_key_invalid")
    digest = hashlib.sha256(document).digest()
    signature = key.sign(digest, ec.ECDSA(utils.Prehashed(hashes.SHA256())))
    bundle = {
        "mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
        "messageSignature": {
            "messageDigest": {"algorithm": "SHA2_256", "digest": base64.b64encode(digest).decode()},
            "signature": base64.b64encode(signature).decode(),
        },
    }
    CURRENT_ZAP_ARTIFACT_PROMOTION.public_key.write_bytes(key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ))
    CURRENT_ZAP_ARTIFACT_PROMOTION.signature.write_text(
        json.dumps(bundle, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8"
    )


def sign() -> dict[str, object]:
    validate()
    _sign()
    return {"ok": True, "action": "sign"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("build", "sign", "validate"))
    parser.add_argument("--confirm-r104-local-lab", action="store_true")
    args = parser.parse_args()
    if not args.confirm_r104_local_lab:
        parser.error("--confirm-r104-local-lab is required")
    result = {"build": build, "sign": sign, "validate": validate}[args.action]()
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
