#!/usr/bin/env python3
"""Provision the closed, synthetic-only compat_098 OpenBao conformance fixture."""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any

import httpx


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".local" / "redagent" / "openbao"
ENDPOINT = "http://127.0.0.1:58200"
COMPOSE = ROOT / "compose.openbao-conformance.yaml"
IMAGE_LOCK = ROOT / "config" / "openbao-conformance-image.json"
LOCAL_ENV = ROOT / ".local" / "redagent" / "runtime" / "local-stack.env"
_COMPOSE_PROJECT_PREFIX = "redagent-openbao"


class ConformanceError(RuntimeError):
    pass


def _workspace_root() -> Path:
    try:
        root = ROOT.resolve(strict=True)
    except OSError as exc:
        raise ConformanceError("openbao_workspace_path_invalid") from exc
    if not root.is_dir():
        raise ConformanceError("openbao_workspace_path_invalid")
    return root


def _compose_project_name() -> str:
    root = _workspace_root()
    identity = os.path.normcase(str(root)).replace("\\", "/")
    digest = hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]
    return f"{_COMPOSE_PROJECT_PREFIX}-{digest}"


def _is_local_docker_host(value: str) -> bool:
    lowered = value.lower()
    if lowered.startswith("npipe:////./pipe/") or lowered.startswith("unix:///"):
        return True
    if not lowered.startswith("tcp://"):
        return False
    host_port = value[6:].rsplit("@", 1)[-1]
    host = host_port
    if host.startswith("["):
        closing = host.find("]")
        if closing < 0:
            return False
        host = host[1:closing]
    elif ":" in host:
        host = host.rsplit(":", 1)[0]
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _safe_compose_environment() -> dict[str, str]:
    env = dict(os.environ)
    for key in tuple(env):
        if key.upper().startswith("COMPOSE_"):
            env.pop(key, None)

    def remove_case_insensitive(name: str) -> tuple[str, ...]:
        values: list[str] = []
        for key in tuple(env):
            if key.upper() == name:
                values.append(env.pop(key))
        return tuple(values)

    contexts = remove_case_insensitive("DOCKER_CONTEXT")
    hosts = remove_case_insensitive("DOCKER_HOST")
    remove_case_insensitive("DOCKER_CONFIG")
    tls_values = remove_case_insensitive("DOCKER_TLS")
    tls_values += remove_case_insensitive("DOCKER_TLS_VERIFY")
    certificate_paths = remove_case_insensitive("DOCKER_CERT_PATH")
    if any(context not in {"", "default"} for context in contexts):
        raise ConformanceError("openbao_docker_target_override_forbidden")
    if any(host and not _is_local_docker_host(host) for host in hosts):
        raise ConformanceError("openbao_docker_target_override_forbidden")
    if any(tls_values) or any(certificate_paths):
        raise ConformanceError("openbao_docker_target_override_forbidden")
    return env


def _compose(*arguments: str) -> str:
    root = _workspace_root()
    env = _safe_compose_environment()
    env["REDAGENT_OPENBAO_IMAGE"] = json.loads(IMAGE_LOCK.read_text(encoding="utf-8"))["reference"]
    # CRITICAL: bind fixture volumes to this checkout; ambient Compose scope can cross-wire tokens.
    result = subprocess.run(
        [
            "docker",
            "--context",
            "default",
            "compose",
            "--project-directory",
            str(root),
            "--project-name",
            _compose_project_name(),
            "--file",
            str(COMPOSE),
            *arguments,
        ],
        cwd=root,
        env=env,
        check=False, capture_output=True, text=True, timeout=240, shell=False,
    )
    if result.returncode:
        raise ConformanceError(f"openbao_compose_failed:{result.returncode}")
    return result.stdout


def _path_is_reparse(path: Path) -> bool:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return False
    except OSError as exc:
        raise ConformanceError("openbao_runtime_path_invalid") from exc
    return stat.S_ISLNK(metadata.st_mode) or bool(
        getattr(metadata, "st_file_attributes", 0) & 0x00000400
    )


def _same_lexical_path(left: Path, right: Path) -> bool:
    return os.path.normcase(os.path.abspath(left)) == os.path.normcase(os.path.abspath(right))


def _runtime_directory(*, create: bool) -> Path:
    root = _workspace_root()
    expected = root / ".local" / "redagent" / "openbao"
    candidate = Path(os.path.abspath(RUNTIME))
    if not _same_lexical_path(candidate, expected):
        raise ConformanceError("openbao_runtime_path_invalid")

    current = root
    for component in (".local", "redagent", "openbao"):
        current /= component
        try:
            exists = current.exists() or current.is_symlink()
        except OSError as exc:
            raise ConformanceError("openbao_runtime_path_invalid") from exc
        if exists:
            if _path_is_reparse(current) or not current.is_dir():
                raise ConformanceError("openbao_runtime_path_invalid")
            continue
        if create:
            try:
                current.mkdir()
            except OSError as exc:
                raise ConformanceError("openbao_runtime_path_invalid") from exc
            if _path_is_reparse(current) or not current.is_dir():
                raise ConformanceError("openbao_runtime_path_invalid")

    if create and (not candidate.is_dir() or _path_is_reparse(candidate)):
        raise ConformanceError("openbao_runtime_path_invalid")
    return candidate


def _runtime_file(path: Path) -> Path:
    runtime = _runtime_directory(create=True)
    candidate = Path(os.path.abspath(path))
    if candidate.parent != runtime or not candidate.name:
        raise ConformanceError("openbao_runtime_path_invalid")
    try:
        exists = candidate.exists() or candidate.is_symlink()
    except OSError as exc:
        raise ConformanceError("openbao_runtime_path_invalid") from exc
    if exists and (_path_is_reparse(candidate) or not candidate.is_file()):
        raise ConformanceError("openbao_runtime_path_invalid")
    return candidate


def _request(
    method: str, path: str, *, token: str | None = None,
    payload: dict[str, Any] | None = None, expected: tuple[int, ...] = (200, 204),
) -> dict[str, Any]:
    headers = {"X-Vault-Request": "true", "Accept": "application/json"}
    if token:
        headers["X-Vault-Token"] = token
    try:
        response = httpx.request(method, f"{ENDPOINT}/v1{path}", headers=headers, json=payload, timeout=10)
    except Exception as exc:
        raise ConformanceError("openbao_transport_unavailable") from exc
    if response.status_code not in expected:
        raise ConformanceError(f"openbao_http_status:{response.status_code}:{path}")
    if response.status_code == 204 or not response.content:
        return {}
    try:
        result = response.json()
    except Exception as exc:
        raise ConformanceError("openbao_response_invalid") from exc
    if not isinstance(result, dict):
        raise ConformanceError("openbao_response_invalid")
    return result


def _wait_ready() -> dict[str, Any]:
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            response = httpx.get(f"{ENDPOINT}/v1/sys/health", timeout=2)
            if response.status_code in {200, 429, 472, 473, 501, 503}:
                payload = response.json()
                if isinstance(payload, dict):
                    return payload
        except Exception:
            pass
        time.sleep(1)
    raise ConformanceError("openbao_startup_timeout")


def _write_private(path: Path, value: str) -> None:
    target = _runtime_file(path)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=target.parent,
            prefix=f".{target.name}-",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(value.rstrip("\n") + "\n")
        target = _runtime_file(path)
        os.replace(temporary, target)
        temporary = None
        try:
            os.chmod(target, 0o600)
        except OSError:
            pass
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _read_private(path: Path) -> str:
    target = _runtime_file(path)
    if not target.is_file():
        return ""
    return target.read_text(encoding="utf-8").strip()


def _runtime_values() -> dict[str, str]:
    if not LOCAL_ENV.is_file():
        raise ConformanceError("local_stack_env_missing")
    return dict(
        line.partition("=")[::2]
        for line in LOCAL_ENV.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )


def _postgres_runtime_port(values: dict[str, str]) -> int:
    try:
        port = int(values.get("REDAGENT_POSTGRES_PORT", ""))
    except (TypeError, ValueError) as exc:
        raise ConformanceError("openbao_postgres_port_invalid") from exc
    if not 1024 <= port <= 65535:
        raise ConformanceError("openbao_postgres_port_invalid")
    return port


def _token_is_valid(token: str) -> bool:
    try:
        response = httpx.get(
            f"{ENDPOINT}/v1/auth/token/lookup-self",
            headers={"X-Vault-Request": "true", "X-Vault-Token": token},
            timeout=5,
        )
        return response.status_code == 200
    except Exception:
        return False


def provision() -> dict[str, Any]:
    runtime = _runtime_directory(create=True)
    _compose("up", "-d", "--force-recreate")
    health = _wait_ready()
    root_path = runtime / "root-token"
    unseal_path = runtime / "unseal-key"
    if not health.get("initialized"):
        initialized = _request("POST", "/sys/init", payload={"secret_shares": 1, "secret_threshold": 1})
        root = str(initialized["root_token"])
        unseal = str(initialized["keys_base64"][0])
        _write_private(root_path, root)
        _write_private(unseal_path, unseal)
    else:
        root = _read_private(root_path)
        unseal = _read_private(unseal_path)
        if not root or not unseal:
            raise ConformanceError("openbao_bootstrap_material_missing")
    health = _wait_ready()
    if health.get("sealed"):
        _request("POST", "/sys/unseal", payload={"key": unseal})
    audits_response = _request("GET", "/sys/audit", token=root)
    audits = audits_response.get("data", audits_response)
    if not isinstance(audits, dict) or not {"audit-file-1/", "audit-file-2/"}.issubset(audits):
        raise ConformanceError("openbao_declarative_audit_devices_missing")
    mounts = _request("GET", "/sys/mounts", token=root).get("data", {})
    if "database/" not in mounts:
        _request("POST", "/sys/mounts/database", token=root, payload={"type": "database"}, expected=(200, 204))
    values = _runtime_values()
    database_password = values.get("REDAGENT_POSTGRES_PASSWORD", "")
    if not database_password:
        raise ConformanceError("postgres_fixture_password_missing")
    database_port = _postgres_runtime_port(values)
    _request(
        "POST", "/database/config/redagent-r098", token=root,
        payload={
            "plugin_name": "postgresql-database-plugin",
            "allowed_roles": ["redagent-r098"],
            "connection_url": (
                "postgresql://{{username}}:{{password}}@host.docker.internal:"
                f"{database_port}/redagent?sslmode=disable"
            ),
            "username": "redagent", "password": database_password,
            "verify_connection": True,
        },
    )
    creation = (
        "CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; "
        "GRANT CONNECT ON DATABASE redagent TO \"{{name}}\"; "
        "GRANT USAGE ON SCHEMA public TO \"{{name}}\"; "
        "GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";"
    )
    _request(
        "POST", "/database/roles/redagent-r098", token=root,
        payload={
            "db_name": "redagent-r098", "creation_statements": [creation],
            "default_ttl": "5m", "max_ttl": "10m",
        },
    )
    policy = "\n".join((
        'path "sys/health" { capabilities = ["read"] }',
        'path "sys/seal-status" { capabilities = ["read"] }',
        'path "sys/audit" { capabilities = ["read", "sudo"] }',
        'path "database/creds/redagent-r098" { capabilities = ["read"] }',
        'path "sys/leases/renew" { capabilities = ["update"] }',
        'path "sys/leases/lookup" { capabilities = ["update"] }',
        'path "sys/leases/revoke" { capabilities = ["update"] }',
    ))
    _request("PUT", "/sys/policies/acl/redagent-r098", token=root, payload={"policy": policy})
    app_token_path = runtime / "app-token"
    app_token = _read_private(app_token_path)
    if not app_token or not _token_is_valid(app_token):
        token_result = _request(
            "POST", "/auth/token/create", token=root,
            payload={"policies": ["redagent-r098"], "ttl": "1h", "renewable": False, "no_parent": True},
        )
        app_token = str(token_result.get("auth", {}).get("client_token", ""))
        if not app_token:
            raise ConformanceError("openbao_application_token_missing")
        _write_private(app_token_path, app_token)
    mapping = {
        "schema_version": "1.0",
        "roles": {
            "role:database-readonly-v1": {
                "issue_path": "database/creds/redagent-r098",
                "material_fields": ["username", "password"],
                "max_ttl_seconds": 600,
            }
        },
    }
    _write_private(runtime / "role-mappings.json", json.dumps(mapping, indent=2, sort_keys=True))
    return {"ok": True, "version": health.get("version"), "audit_devices": 2, "endpoint": ENDPOINT}


def status() -> dict[str, Any]:
    services = tuple(
        line.strip()
        for line in _compose("ps", "--status", "running", "--services").splitlines()
        if line.strip()
    )
    if services != ("openbao",):
        raise ConformanceError("openbao_project_service_not_running")
    health = _wait_ready()
    return {"ok": bool(health.get("initialized") and not health.get("sealed")), "health": health}


def reset() -> dict[str, Any]:
    runtime = _runtime_directory(create=False)
    _compose("down", "--volumes")
    # CRITICAL: revalidate after Docker access; a junction swap must not redirect recursive deletion.
    runtime = _runtime_directory(create=False)
    if runtime.exists():
        shutil.rmtree(runtime)
    return {"ok": True, "action": "reset"}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("provision", "status", "stop", "reset"))
    args = parser.parse_args()
    try:
        if args.action == "provision":
            result = provision()
        elif args.action == "status":
            result = status()
        elif args.action == "stop":
            _compose("down")
            result = {"ok": True, "action": "stop"}
        else:
            result = reset()
    except (ConformanceError, OSError, subprocess.SubprocessError) as exc:
        result = {"ok": False, "error": str(exc)}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
