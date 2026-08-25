#!/usr/bin/env python3
"""Operate the fixed, loopback-only compat_092 local dependency stack."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
from typing import Any

# IMPORTANT: direct execution places scripts/ on sys.path; keep repo imports deterministic.
REPO_ROOT = Path(__file__).resolve().parents[1]
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from redagent_platform.local_stack import (  # noqa: E402
    LocalStackError,
    allocate_available_runtime_ports,
    build_compose_command,
    create_runtime_oidc_provider_config,
    create_runtime_env,
    effective_runtime_config,
    parse_prerequisite_versions,
    redact_diagnostics,
    require_reset_confirmation,
    requires_port_preflight,
    verify_host_endpoints,
)
from redagent_platform.local_stack_config import (  # noqa: E402
    ConfigError,
    LocalStackConfig,
    ensure_approved_runtime_state_dir,
    load_local_stack_config,
)


def _run(command: tuple[str, ...], timeout: int = 240) -> subprocess.CompletedProcess[str]:
    # CRITICAL: closed-set argument arrays only; shell execution would cross the infrastructure trust boundary.
    return subprocess.run(command, check=False, capture_output=True, text=True, timeout=timeout, shell=False)


def _doctor() -> dict[str, Any]:
    docker = _run(("docker", "version", "--format", "{{.Client.Version}}|{{.Server.Version}}|{{.Server.Os}}|{{.Server.Arch}}"), 30)
    compose = _run(("docker", "compose", "version", "--short"), 30)
    if docker.returncode or compose.returncode:
        raise LocalStackError("docker_engine_unavailable")
    versions = parse_prerequisite_versions(docker.stdout, compose.stdout)
    return {
        "docker_client": versions.docker_client,
        "docker_server": versions.docker_server,
        "compose": versions.compose,
        "engine_platform": f"{versions.engine_os}/{versions.engine_arch}",
    }


def _ports_available(config: LocalStackConfig) -> None:
    for name, port in (
        ("postgres", config.postgres_port),
        ("keycloak", config.keycloak_port),
        ("temporal", config.temporal_port),
        ("rustfs", config.rustfs_port),
    ):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            try:
                probe.bind((config.bind_host, port))
            except OSError as exc:
                raise LocalStackError(f"port_conflict:{name}:{port}") from exc


def _operator_port_override() -> bool:
    return any(
        os.environ.get(name, "").strip()
        for name in (
            "REDAGENT_POSTGRES_PORT",
            "REDAGENT_KEYCLOAK_PORT",
            "REDAGENT_TEMPORAL_PORT",
            "REDAGENT_RUSTFS_PORT",
        )
    )


def _read_secret_values(env_file: Path) -> tuple[str, ...]:
    if not env_file.is_file():
        return ()
    values = []
    for line in env_file.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and ("PASSWORD" in name or "TOKEN" in name or "SECRET" in name):
            values.append(value)
    return tuple(values)


def _compose(action: str, config: LocalStackConfig, env_file: Path) -> dict[str, Any]:
    completed = _run(build_compose_command(action, config, env_file), config.startup_timeout_seconds + 60)
    secrets_to_hide = _read_secret_values(env_file)
    stdout = redact_diagnostics(completed.stdout, secrets_to_hide)
    stderr = redact_diagnostics(completed.stderr, secrets_to_hide)
    if completed.returncode:
        raise LocalStackError(f"compose_{action}_failed:{stderr.strip() or stdout.strip() or completed.returncode}")
    return {"action": action, "stdout": stdout.strip(), "stderr": stderr.strip()}


def _config_payload(config: LocalStackConfig) -> dict[str, Any]:
    return {
        "profile": config.profile,
        "compose_project_name": config.compose_project_name,
        "bind_host": config.bind_host,
        "postgres_endpoint": f"postgresql://{config.bind_host}:{config.postgres_port}/redagent",
        "keycloak_endpoint": f"http://{config.bind_host}:{config.keycloak_port}/realms/redagent-local",
        "temporal_endpoint": f"{config.bind_host}:{config.temporal_port}",
        "evidence_endpoint": f"http://{config.bind_host}:{config.rustfs_port}",
        "state_dir": str(config.state_dir),
        "images": {image.service: image.reference for image in config.images},
        "dangerous_capabilities": {
            "active_target_access": config.active_target_access,
            "real_scanners": config.real_scanners,
            "privileged_runners": config.privileged_runners,
            "external_delivery": config.external_delivery,
        },
    }


def _provision_evidence_bucket(env_file: Path) -> str:
    values = dict(
        line.partition("=")[::2]
        for line in env_file.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    required = (
        "REDAGENT_EVIDENCE_ENDPOINT", "REDAGENT_EVIDENCE_BUCKET", "REDAGENT_EVIDENCE_REGION",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    )
    if any(not values.get(name) for name in required):
        raise LocalStackError("evidence_bucket_configuration_incomplete")
    try:
        import boto3
        from botocore.client import Config
        from botocore.exceptions import ClientError

        client = boto3.client(
            "s3",
            endpoint_url=values["REDAGENT_EVIDENCE_ENDPOINT"],
            region_name=values["REDAGENT_EVIDENCE_REGION"],
            aws_access_key_id=values["AWS_ACCESS_KEY_ID"],
            aws_secret_access_key=values["AWS_SECRET_ACCESS_KEY"],
            config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
        )
        bucket = values["REDAGENT_EVIDENCE_BUCKET"]
        try:
            client.head_bucket(Bucket=bucket)
        except ClientError as exc:
            code = str(exc.response.get("Error", {}).get("Code", ""))
            if code not in {"404", "NoSuchBucket", "NotFound"}:
                raise
            client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
        client.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
        versioning = client.get_bucket_versioning(Bucket=bucket)
        lock = client.get_object_lock_configuration(Bucket=bucket)
        if versioning.get("Status") != "Enabled" or lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise LocalStackError("evidence_bucket_capability_missing")
        return bucket
    except LocalStackError:
        raise
    except Exception as exc:
        # CRITICAL: provider exceptions can include request metadata; expose only a stable secret-free error.
        raise LocalStackError("evidence_bucket_provision_failed") from exc


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("doctor", "config", "start", "status", "stop", "reset"))
    parser.add_argument("--json", action="store_true")
    parser.add_argument("--confirm-local-reset", action="store_true")
    args = parser.parse_args()
    payload: dict[str, Any]
    try:
        config = load_local_stack_config(REPO_ROOT)
        env_file = config.state_dir / "runtime" / "local-stack.env"
        config = effective_runtime_config(
            config,
            env_file,
            require_persisted_project=args.action in {"status", "stop", "reset"},
            allow_missing_project=args.action in {"doctor", "config"},
        )
        if args.action == "doctor":
            payload = {"ok": True, "action": "doctor", "prerequisites": _doctor(), "config": _config_payload(config)}
        elif args.action == "config":
            payload = {"ok": True, "action": "config", "config": _config_payload(config)}
        elif args.action == "start":
            prerequisites = _doctor()
            if requires_port_preflight(env_file):
                config = allocate_available_runtime_ports(
                    config,
                    allow_fallback=not _operator_port_override(),
                )
                _ports_available(config)
            created = create_runtime_env(config, env_file, secret_factory=lambda: secrets.token_urlsafe(32))
            identity_provider_config = create_runtime_oidc_provider_config(config)
            _compose("config", config, env_file)
            pull = _compose("pull", config, env_file)
            start = _compose("start", config, env_file)
            endpoints = verify_host_endpoints(config)
            evidence_bucket = _provision_evidence_bucket(env_file)
            payload = {
                "ok": True,
                "action": "start",
                "credentials_created": created,
                "prerequisites": prerequisites,
                "pull": pull,
                "start": start,
                "host_endpoints_verified": [
                    {"service": service, "host": host, "port": port}
                    for service, host, port in endpoints
                ],
                "evidence_bucket": evidence_bucket,
                "identity_provider_config": str(identity_provider_config),
                "config": _config_payload(config),
            }
        else:
            if not env_file.is_file():
                raise LocalStackError("local_stack_runtime_env_missing")
            if args.action == "reset":
                require_reset_confirmation(config, confirmed=args.confirm_local_reset)
            result = _compose(args.action, config, env_file)
            if args.action == "reset":
                try:
                    resolved = ensure_approved_runtime_state_dir(config.workspace, config.state_dir)
                except ConfigError as exc:
                    raise LocalStackError("local_reset_scope_invalid") from exc
                # CRITICAL: recursive deletion is permitted only for the verified workspace-local runtime directory.
                if not resolved.is_relative_to(config.workspace) or resolved == config.workspace:
                    raise LocalStackError("local_reset_scope_invalid")
                shutil.rmtree(resolved)
            payload = {"ok": True, "action": args.action, "result": result, "config": _config_payload(config)}
    except (ConfigError, LocalStackError, OSError, subprocess.SubprocessError) as exc:
        payload = {"ok": False, "action": args.action, "error": str(exc)}

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"local_stack_ok={str(payload['ok']).lower()}")
        print(json.dumps(payload, indent=2, sort_keys=True))
    return 0 if payload["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
