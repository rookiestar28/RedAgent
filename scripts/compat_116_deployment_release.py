#!/usr/bin/env python3
"""Compile and verify compat_116 deployment-release contracts without network or execution."""

from __future__ import annotations

import argparse
from dataclasses import asdict
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path
import sys

# CRITICAL: direct script execution must add the fixed repository root before package imports.
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from redagent_platform.deployment_release.distribution import (
    BundlePolicy,
    signed_bundle_from_dict,
    stage_verified_bundle_files,
    verify_signed_bundle_files,
)
from redagent_platform.deployment_release.kubernetes import (
    compile_kubernetes_manifests,
    validate_kubernetes_manifests,
)
from redagent_platform.deployment_release.qualification import qualify_deployment_release
from redagent_platform.deployment_release.recovery import build_recovery_catalog, build_restore_plan
from redagent_platform.deployment_release.topology import (
    ProfileKind,
    build_supported_profile,
    compile_profile,
    validate_profile,
)
from redagent_platform.deployment_release.upgrade import plan_upgrade


MAX_DOCUMENT_BYTES = 2_000_000


def main(argv: list[str] | None = None) -> int:
    parser = _parser()
    args = parser.parse_args(argv)
    try:
        result = _run(args)
        _emit(result, getattr(args, "output", None))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for action in ("compile", "validate"):
        command = commands.add_parser(action)
        command.add_argument("--profile", choices=tuple(item.value for item in ProfileKind), required=True)
        command.add_argument("--output", type=Path)
    qualify = commands.add_parser("qualify")
    qualify.add_argument("--fixtures", type=Path)
    qualify.add_argument("--output", type=Path)
    restore = commands.add_parser("plan-restore")
    restore.add_argument("--output", type=Path)
    upgrade = commands.add_parser("plan-upgrade")
    upgrade.add_argument("--current", required=True)
    upgrade.add_argument("--target", required=True)
    upgrade.add_argument("--output", type=Path)
    verify = commands.add_parser("verify-bundle")
    verify.add_argument("--bundle", type=Path, required=True)
    verify.add_argument("--content-root", type=Path, required=True)
    verify.add_argument("--policy", type=Path, required=True)
    verify.add_argument("--public-key", type=Path, required=True)
    verify.add_argument("--output", type=Path)
    stage = commands.add_parser("stage-bundle")
    stage.add_argument("--bundle", type=Path, required=True)
    stage.add_argument("--content-root", type=Path, required=True)
    stage.add_argument("--policy", type=Path, required=True)
    stage.add_argument("--public-key", type=Path, required=True)
    stage.add_argument("--staging-root", type=Path, required=True)
    stage.add_argument("--output", type=Path)
    return parser


def _run(args: argparse.Namespace) -> dict[str, object]:
    now = datetime.now(UTC)
    if args.action in {"compile", "validate"}:
        profile = build_supported_profile(ProfileKind(args.profile))
        validation = validate_profile(profile, now=now)
        if args.action == "validate":
            result: dict[str, object] = {
                "ok": validation.accepted,
                "profile_id": profile.profile_id,
                "gaps": list(validation.gaps),
                "network_contact_count": 0,
                "external_execution_count": 0,
            }
            if profile.kind is ProfileKind.KUBERNETES_ENTERPRISE and validation.accepted:
                manifests = compile_kubernetes_manifests(profile, now=now)
                manifest_validation = validate_kubernetes_manifests(manifests)
                result["manifest_count"] = len(manifests)
                result["manifest_gaps"] = list(manifest_validation.gaps)
                result["ok"] = result["ok"] and manifest_validation.accepted
            return result
        compiled = compile_profile(profile)
        if profile.kind is ProfileKind.KUBERNETES_ENTERPRISE:
            compiled["kubernetes_manifests"] = compile_kubernetes_manifests(profile, now=now)
        return {"ok": validation.accepted, **compiled}
    if args.action == "qualify":
        if args.fixtures is not None:
            fixture_path = _contained(args.fixtures)
            if not fixture_path.is_dir():
                raise ValueError("qualification_fixture_directory_required")
        return {"ok": True, **qualify_deployment_release()}
    if args.action == "plan-restore":
        catalog = build_recovery_catalog(created_at=now - timedelta(minutes=5))
        return {"ok": True, **_jsonable(asdict(build_restore_plan(catalog, now=now)))}
    if args.action == "plan-upgrade":
        state = plan_upgrade(
            current_version=args.current,
            target_version=args.target,
            current_schema=22,
            expanded_schema=23,
            contract_schema=24,
            old_worker_build=f"worker-{args.current}",
            new_worker_build=f"worker-{args.target}",
            now=now,
        )
        return {"ok": True, **_jsonable(asdict(state))}
    if args.action in {"verify-bundle", "stage-bundle"}:
        return _verify_bundle(args)
    raise ValueError("deployment_release_action_invalid")


def _verify_bundle(args: argparse.Namespace) -> dict[str, object]:
    bundle = signed_bundle_from_dict(_read_json(args.bundle))
    policy_value = _read_json(args.policy)
    if not isinstance(policy_value, dict):
        raise ValueError("bundle_policy_invalid")
    policy = BundlePolicy(
        trusted_signer=str(policy_value["trusted_signer"]),
        expected_builder=str(policy_value["expected_builder"]),
        expected_source_revision=str(policy_value["expected_source_revision"]),
        max_artifacts=int(policy_value["max_artifacts"]),
        max_total_bytes=int(policy_value["max_total_bytes"]),
    )
    public = serialization.load_pem_public_key(_read_bytes(args.public_key, MAX_DOCUMENT_BYTES))
    if not isinstance(public, ec.EllipticCurvePublicKey):
        raise ValueError("bundle_public_key_invalid")
    content_root = _contained(args.content_root)
    if not content_root.is_dir():
        raise ValueError("bundle_content_root_invalid")
    if args.action == "stage-bundle":
        staging_root = _contained(args.staging_root)
        receipt = stage_verified_bundle_files(
            bundle,
            content_root,
            policy=policy,
            public_key=public,
            staging_root=staging_root,
        )
    else:
        receipt, _ = verify_signed_bundle_files(bundle, content_root, policy=policy, public_key=public)
    return {"ok": True, **_jsonable(asdict(receipt))}


def _emit(value: dict[str, object], output: Path | None) -> None:
    encoded = json.dumps(value, sort_keys=True, indent=2, default=str) + "\n"
    if output is None:
        print(encoded, end="")
        return
    path = _contained(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    # IMPORTANT: byte writes keep generated digest evidence LF-stable on Windows and Linux.
    path.write_bytes(encoded.encode("utf-8"))


def _read_json(path: Path) -> object:
    return json.loads(_read_bytes(_contained(path), MAX_DOCUMENT_BYTES))


def _read_bytes(path: Path, limit: int) -> bytes:
    if not path.is_file() or path.stat().st_size > limit:
        raise ValueError("deployment_release_input_invalid")
    return path.read_bytes()


def _contained(path: Path) -> Path:
    candidate = path if path.is_absolute() else ROOT / path
    resolved = candidate.resolve()
    if not resolved.is_relative_to(ROOT):
        raise ValueError("deployment_release_path_outside_workspace")
    return resolved


def _jsonable(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    if isinstance(value, dict):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(item) for item in value]
    return value


if __name__ == "__main__":
    raise SystemExit(main())
