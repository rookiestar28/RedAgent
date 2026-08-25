#!/usr/bin/env python3
"""Fail closed when the curated public-release trace inventory drifts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "config" / "public-release-residuals.json"
MANIFEST_RELATIVE = MANIFEST.relative_to(ROOT).as_posix()
ITEM_TOKEN = re.compile(r"(?i)r\d{3}")
STANDALONE_ITEM = re.compile(r"(?<![A-Za-z0-9_.-])(?i:r\d{3})(?![A-Za-z0-9_.-])")
ITEM_FILENAME = re.compile(r"(?i)(?:^|[_-])(r\d{3})(?=$|[_-])")
LEGACY_PATH = re.compile(r"\.planning(?:[/\\][A-Za-z0-9_.\-/\\]+)?")
FORBIDDEN_CONTENT = (
    re.compile(r"(?i)(?:^|[/\\])ROADMAP\.md(?:$|[/\\])"),
    re.compile(r"(?i)(?:^|[/\\])AGENTS\.md(?:$|[/\\])"),
    re.compile(r"(?i)(?:^|[/\\])\.sessions(?:$|[/\\])"),
    re.compile(r"(?i)(?:^|[/\\])reference[/\\]docs(?:$|[/\\])"),
    re.compile(r"(?i)(?:^|[/\\])\.agents[/\\]skills(?:$|[/\\])"),
    re.compile(r"(?i)(?:^|[/\\])\.claude[/\\]skills(?:$|[/\\])"),
    re.compile(r"(?i)tests[/\\](?:TEST_SOP|E2E_TESTING(?:_NOTICE|_SOP)?)\.md"),
)
PRIVATE_ENVIRONMENT_CONTENT = (
    # Reject concrete private Windows/WSL paths while allowing generic public examples
    # such as C:\\safe-bin and /mnt/* instructions.
    re.compile(r"(?i)(?<![A-Za-z0-9])(?:[A-Z]:[/\\][^\r\n`]*[\u3400-\u9fff]|/mnt/[a-z]/[^\r\n`]*[\u3400-\u9fff])"),
    re.compile(r"(?i)(?<![A-Za-z0-9])/mnt/[a-z]/(?![<*{])[^\s`]+"),
    re.compile(r"(?i)\bCodex workspace\b"),
    re.compile(r"(?i)\bthe user has (?:installed|initialized|configured|completed)\b"),
)
FORBIDDEN_PATH_PARTS = {".planning", ".sessions", ".agents", ".claude", "reference"}
FORBIDDEN_PATH_NAMES = {
    "roadmap.md",
    "agents.md",
    "test_sop.md",
    "e2e_testing_notice.md",
    "e2e_testing_sop.md",
}
STANDALONE_RESIDUAL_PREFIXES = (
    "runtime-assets/attestations/",
    "bundles/",
    "config/",
    "containers/",
    "migrations/",
    ".github/workflows/",
    "deploy/profiles/",
)


class PublicReleaseValidationError(RuntimeError):
    pass


def _git_paths() -> tuple[str, ...]:
    commands = (
        ("git", "ls-files", "-z"),
        ("git", "ls-files", "-z", "--others", "--exclude-standard"),
    )
    paths: set[str] = set()
    for command in commands:
        completed = subprocess.run(
            command,
            cwd=ROOT,
            capture_output=True,
            check=False,
            shell=False,
        )
        if completed.returncode != 0:
            raise PublicReleaseValidationError("public_git_inventory_unavailable")
        for raw_path in completed.stdout.split(b"\0"):
            if not raw_path:
                continue
            try:
                relative = raw_path.decode("utf-8", errors="strict").replace("\\", "/")
            except UnicodeDecodeError as exc:
                raise PublicReleaseValidationError("public_path_encoding_invalid") from exc
            candidate = (ROOT / relative).resolve()
            if not candidate.is_relative_to(ROOT.resolve()) or not candidate.is_file():
                raise PublicReleaseValidationError(f"public_path_invalid:{relative}")
            paths.add(candidate.relative_to(ROOT).as_posix())
    return tuple(sorted(paths))


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _text(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return None


def _entries(rows: Iterable[dict[str, object]]) -> dict[tuple[str, str], dict[str, object]]:
    result: dict[tuple[str, str], dict[str, object]] = {}
    for row in rows:
        path = row.get("path")
        token = row.get("token")
        if not isinstance(path, str) or not isinstance(token, str):
            raise PublicReleaseValidationError("public_residual_entry_invalid")
        key = (path, token)
        if key in result:
            raise PublicReleaseValidationError(f"public_residual_entry_duplicate:{path}:{token}")
        result[key] = row
    return result


def _validate_public_text(relative: str, text: str) -> None:
    if any(pattern.search(text) for pattern in FORBIDDEN_CONTENT):
        raise PublicReleaseValidationError(f"forbidden_public_content:{relative}")
    if any(pattern.search(text) for pattern in PRIVATE_ENVIRONMENT_CONTENT):
        raise PublicReleaseValidationError(f"forbidden_public_environment:{relative}")


def collect_observations() -> dict[str, list[dict[str, object]]]:
    filename_rows: list[dict[str, object]] = []
    content_rows: list[dict[str, object]] = []
    legacy_rows: list[dict[str, object]] = []
    for relative in _git_paths():
        lowered_parts = {part.casefold() for part in Path(relative).parts}
        if lowered_parts & FORBIDDEN_PATH_PARTS or Path(relative).name.casefold() in FORBIDDEN_PATH_NAMES:
            raise PublicReleaseValidationError(f"forbidden_public_path:{relative}")
        path = ROOT / relative
        digest = _digest(path)
        if relative == MANIFEST_RELATIVE:
            continue
        filename_tokens = Counter(match.group(1) for match in ITEM_FILENAME.finditer(path.name))
        for token, count in sorted(filename_tokens.items()):
            filename_rows.append({"path": relative, "token": token, "count": count, "sha256": digest})
        text = _text(path)
        if text is None:
            continue
        _validate_public_text(relative, text)
        content_tokens = Counter(match.group(0) for match in ITEM_TOKEN.finditer(text))
        for token, count in sorted(content_tokens.items()):
            content_rows.append({"path": relative, "token": token, "count": count, "sha256": digest})
        legacy_tokens = Counter(match.group(0) for match in LEGACY_PATH.finditer(text))
        for token, count in sorted(legacy_tokens.items()):
            legacy_rows.append({"path": relative, "token": token, "count": count, "sha256": digest})
    return {
        "allowed_filename_residuals": filename_rows,
        "allowed_content_residuals": content_rows,
        "allowed_legacy_path_residuals": legacy_rows,
    }


def validate(*, check_commit_message: bool) -> dict[str, int]:
    try:
        manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise PublicReleaseValidationError("public_residual_manifest_invalid") from exc
    if manifest.get("schema") != "redagent.public-release-residuals/v1":
        raise PublicReleaseValidationError("public_residual_manifest_schema_invalid")
    observed = collect_observations()
    for section, rows in observed.items():
        expected = _entries(manifest.get(section, ()))
        actual = _entries(rows)
        if set(expected) != set(actual):
            missing = sorted(set(expected) - set(actual))
            extra = sorted(set(actual) - set(expected))
            raise PublicReleaseValidationError(
                f"public_residual_inventory_drift:{section}:missing={missing[:3]}:extra={extra[:3]}"
            )
        for key, row in actual.items():
            expected_row = expected[key]
            if (
                expected_row.get("count") != row["count"]
                or expected_row.get("sha256") != row["sha256"]
                or not isinstance(expected_row.get("reason"), str)
                or not expected_row["reason"]
            ):
                raise PublicReleaseValidationError(f"public_residual_binding_drift:{section}:{key}")
    if check_commit_message:
        completed = subprocess.run(
            ("git", "log", "-1", "--format=%B"),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
            shell=False,
        )
        message = completed.stdout if completed.returncode == 0 else ""
        if not message.strip():
            raise PublicReleaseValidationError("public_commit_message_unavailable")
        if ITEM_TOKEN.search(message) or LEGACY_PATH.search(message) or any(
            pattern.search(message) for pattern in FORBIDDEN_CONTENT
        ):
            raise PublicReleaseValidationError("public_commit_message_trace_detected")
    return {section: len(rows) for section, rows in observed.items()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check-commit-message", action="store_true")
    args = parser.parse_args(argv)
    try:
        counts = validate(check_commit_message=args.check_commit_message)
    except PublicReleaseValidationError as exc:
        print(f"public_release_validation=failed reason={exc}", file=sys.stderr)
        return 1
    print("public_release_validation=passed " + " ".join(f"{key}={value}" for key, value in counts.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
