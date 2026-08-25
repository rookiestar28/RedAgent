#!/usr/bin/env python3
"""Qualify isolated PostgreSQL backup/restore for the compat_103 synthetic lab."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import subprocess
import sys

from sqlalchemy.engine import make_url


ROOT = Path(__file__).resolve().parents[1]
RUNTIME = ROOT / ".local" / "redagent" / "r103-lab" / "backup-restore"
PRIMARY_SECRET = ROOT / ".local" / "redagent" / "runtime" / "database-url"
POSTGRES = "redagent-local-postgres-1"
_DATABASE = re.compile(r"^r103_(?:source|restore)_[0-9a-f]{12}$")


class RestoreError(RuntimeError):
    pass


def command(arguments: list[str], *, env: dict[str, str] | None = None, timeout: int = 180) -> str:
    result = subprocess.run(
        arguments, cwd=ROOT, env=env, text=True, capture_output=True,
        timeout=timeout, check=False,
    )
    if result.returncode:
        raise RestoreError(f"command_failed:{Path(arguments[0]).name}:{result.stderr.strip()[:240]}")
    return result.stdout.strip()


def docker(*arguments: str, timeout: int = 180) -> str:
    return command(["docker", *arguments], timeout=timeout)


def _assert_owned_postgres() -> None:
    labels = json.loads(docker("inspect", POSTGRES, "--format", "{{json .Config.Labels}}"))
    if labels.get("com.docker.compose.project") != "redagent-local" or labels.get("com.docker.compose.service") != "postgres":
        raise RestoreError("postgres_container_ownership_mismatch")


def _database(action: str, name: str) -> None:
    if _DATABASE.fullmatch(name) is None:
        raise RestoreError("restore_database_name_forbidden")
    docker("exec", POSTGRES, action, "-U", "redagent", name)


def _psql(database: str, sql: str) -> str:
    if _DATABASE.fullmatch(database) is None:
        raise RestoreError("restore_database_name_forbidden")
    return docker("exec", POSTGRES, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "redagent", "-d", database, "-Atqc", sql)


def qualify() -> dict[str, object]:
    _assert_owned_postgres()
    if not PRIMARY_SECRET.is_file():
        raise RestoreError("database_url_file_required")
    RUNTIME.mkdir(parents=True, exist_ok=True)
    token = secrets.token_hex(6)
    source = f"r103_source_{token}"
    restored = f"r103_restore_{token}"
    dump_path = f"/tmp/r103-{token}.dump"
    source_secret = RUNTIME / f"source-{token}.url"
    created: list[str] = []
    try:
        primary = make_url(PRIMARY_SECRET.read_text(encoding="utf-8").strip())
        source_secret.write_text(primary.set(database=source).render_as_string(hide_password=False) + "\n", encoding="utf-8")
        _database("createdb", source); created.append(source)
        environment = dict(os.environ)
        environment.pop("REDAGENT_DATABASE_URL", None)
        environment["REDAGENT_DATABASE_URL_FILE"] = str(source_secret)
        command([str(ROOT / ".venv" / "Scripts" / "python.exe"), "-m", "alembic", "upgrade", "head"], env=environment)
        _psql(source, (
            "INSERT INTO tenants(id,name,version,created_at,updated_at) VALUES"
            "('tenant-r103-backup','R103 synthetic backup',1,now(),now());"
            "INSERT INTO lab_bundles(id,bundle_id,bundle_revision,fixture_digest,seed_manifest_sha256,"
            "network_id,manifest,bundle_state,activated_at,expires_at,tenant_id,version,created_at,updated_at) VALUES"
            "('bundle-r103-backup','r103-synthetic-backup',1,'sha256:" + "a" * 64 + "','" + "b" * 64 + "',"
            "'redagent-r103-lab','{\"schema\":\"redagent.local-lab/v1\",\"non_production\":true}'::jsonb,"
            "'active',now(),now()+interval '1 hour','tenant-r103-backup',1,now(),now());"
        ))
        source_inventory = _inventory(source)
        docker("exec", POSTGRES, "pg_dump", "-U", "redagent", "-d", source, "--format=custom", "--file", dump_path)
        _database("createdb", restored); created.append(restored)
        docker("exec", POSTGRES, "pg_restore", "-U", "redagent", "-d", restored, "--exit-on-error", dump_path)
        restored_inventory = _inventory(restored)
        if source_inventory != restored_inventory:
            raise RestoreError("backup_restore_inventory_mismatch")
        encoded = json.dumps(source_inventory, sort_keys=True, separators=(",", ":")).encode()
        docker("exec", POSTGRES, "rm", "-f", dump_path, timeout=30)
        for database in reversed(created):
            _database("dropdb", database)
        created.clear()
        source_removed = not _database_exists(source)
        restored_removed = not _database_exists(restored)
        if not source_removed or not restored_removed:
            raise RestoreError("backup_restore_database_cleanup_incomplete")
        return {
            "ok": True, "action": "qualify-backup-restore",
            "schema_revision": source_inventory["schema_revision"],
            "row_count": source_inventory["row_count"],
            "object_count": source_inventory["object_count"],
            "inventory_sha256": hashlib.sha256(encoded).hexdigest(),
            "source_database_removed": source_removed, "restored_database_removed": restored_removed,
        }
    finally:
        docker("exec", POSTGRES, "rm", "-f", dump_path, timeout=30)
        for database in reversed(created):
            try:
                _database("dropdb", database)
            except RestoreError:
                pass
        if source_secret.exists() and source_secret.resolve().is_relative_to(RUNTIME.resolve()):
            source_secret.unlink()
        if RUNTIME.exists() and not any(RUNTIME.iterdir()):
            shutil.rmtree(RUNTIME)


def _inventory(database: str) -> dict[str, object]:
    revision = _psql(database, "SELECT version_num FROM alembic_version")
    rows = int(_psql(database, "SELECT (SELECT count(*) FROM tenants)+(SELECT count(*) FROM lab_bundles)"))
    objects = int(_psql(database, (
        "SELECT count(*) FROM information_schema.tables WHERE table_schema='public' "
        "AND table_name IN ('tenants','lab_bundles')"
    )))
    return {"schema_revision": revision, "row_count": rows, "object_count": objects}


def _database_exists(database: str) -> bool:
    if _DATABASE.fullmatch(database) is None:
        raise RestoreError("restore_database_name_forbidden")
    observed = docker(
        "exec", POSTGRES, "psql", "-X", "-U", "redagent", "-d", "redagent",
        "-Atqc", f"SELECT count(*) FROM pg_database WHERE datname='{database}'",
    )
    return observed == "1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("qualify",))
    parser.add_argument("--confirm-local-lab", action="store_true")
    args = parser.parse_args(argv)
    if not args.confirm_local_lab:
        parser.error("--confirm-local-lab is required")
    try:
        print(json.dumps(qualify(), sort_keys=True))
        return 0
    except (RestoreError, OSError, ValueError, json.JSONDecodeError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
