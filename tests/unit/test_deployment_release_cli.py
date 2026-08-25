from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from redagent_platform.deployment_release.distribution import (
    ArtifactClass,
    create_signed_bundle,
    signed_bundle_to_dict,
)


ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "compat_116_deployment_release.py"


def test_direct_cli_validates_enterprise_profile_without_network_or_execution() -> None:
    result = subprocess.run(
        [sys.executable, str(SCRIPT), "validate", "--profile", "kubernetes_enterprise"],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["network_contact_count"] == 0
    assert payload["external_execution_count"] == 0
    assert payload["manifest_count"] > 0
    assert payload["manifest_gaps"] == []


def test_cli_rejects_output_outside_workspace() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(SCRIPT),
            "compile",
            "--profile",
            "single_node",
            "--output",
            str(ROOT.parent / "forbidden-r116-output.json"),
        ],
        cwd=ROOT,
        text=True,
        capture_output=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 1
    assert json.loads(result.stderr)["error"] == "deployment_release_path_outside_workspace"
    assert not (ROOT.parent / "forbidden-r116-output.json").exists()


def test_direct_cli_verifies_complete_signed_bundle_offline() -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="r116-cli-", dir=local) as directory:
        work = Path(directory)
        content_root = work / "content"
        contents = {
            f"artifacts/{kind.value}.json": (kind, (kind.value + "\n").encode())
            for kind in ArtifactClass
        }
        private = ec.generate_private_key(ec.SECP256R1())
        signer = "release@example.invalid"
        builder = "https://github.com/example/redagent/.github/workflows/release.yml"
        revision = "a" * 40
        bundle = create_signed_bundle(
            contents,
            signer_identity=signer,
            builder_id=builder,
            source_revision=revision,
            private_key=private,
        )
        for path, (_, content) in contents.items():
            target = content_root / Path(*path.split("/"))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(content)
        bundle_path = work / "bundle.json"
        policy_path = work / "policy.json"
        public_path = work / "release.pub"
        bundle_path.write_text(json.dumps(signed_bundle_to_dict(bundle)), encoding="utf-8")
        policy_path.write_text(
            json.dumps(
                {
                    "trusted_signer": signer,
                    "expected_builder": builder,
                    "expected_source_revision": revision,
                    "max_artifacts": 64,
                    "max_total_bytes": 1_000_000,
                }
            ),
            encoding="utf-8",
        )
        public_path.write_bytes(
            private.public_key().public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )
        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "verify-bundle",
                "--bundle",
                str(bundle_path),
                "--content-root",
                str(content_root),
                "--policy",
                str(policy_path),
                "--public-key",
                str(public_path),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, result.stderr
        payload = json.loads(result.stdout)
        assert payload["accepted"] is True
        assert payload["network_contact_count"] == 0
        assert payload["executed_artifact_count"] == 0
        staging_root = work / "staged"
        staged = subprocess.run(
            [
                sys.executable,
                str(SCRIPT),
                "stage-bundle",
                "--bundle",
                str(bundle_path),
                "--content-root",
                str(content_root),
                "--policy",
                str(policy_path),
                "--public-key",
                str(public_path),
                "--staging-root",
                str(staging_root),
            ],
            cwd=ROOT,
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
        assert staged.returncode == 0, staged.stderr
        staged_payload = json.loads(staged.stdout)
        assert staged_payload["accepted"] is True
        assert staged_payload["network_contact_count"] == 0
        assert staged_payload["executed_artifact_count"] == 0
        assert (staging_root / staged_payload["staged_directory"] / "staging-receipt.json").is_file()
