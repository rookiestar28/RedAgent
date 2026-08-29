"""Deterministic baseline-and-ratchet backend static-analysis gates."""

from __future__ import annotations

import argparse
import ast
from collections import Counter
import hashlib
from importlib.metadata import PackageNotFoundError, version
import json
from pathlib import Path
import subprocess
import sys
from typing import Iterable, Mapping, Sequence


ROOT = Path(__file__).resolve().parents[2]
STATIC_ANALYSIS_ROOT = ROOT / "config" / "validation" / "backend-static-analysis"
RUFF_BASELINE = STATIC_ANALYSIS_ROOT / "ruff-baseline.json"
BROAD_EXCEPTION_TRIAGE = STATIC_ANALYSIS_ROOT / "broad-exception-triage.json"
MYPY_BASELINE = ROOT / "mypy-baseline.txt"
MYPY_LINUX_BASELINE = ROOT / "mypy-baseline-linux.txt"
MYPY_PLATFORMS = ("win32", "linux")
MYPY_BASELINE_FILENAMES = ("mypy-baseline.txt", "mypy-baseline-linux.txt")
MYPY_TARGETS = (
    ("win32", MYPY_BASELINE),
    ("linux", MYPY_LINUX_BASELINE),
)
RUFF_SOURCE_PATHS = ("redagent_platform", "scripts", "tests")
MYPY_SOURCE_PATHS = ("redagent_platform",)
PRODUCT_SOURCE_PATHS = ("redagent_platform",)
RUFF_RULES = ("E4", "E7", "E9", "F", "BLE001", "TID251")
EXPECTED_TOOL_VERSIONS = {
    "ruff": "0.16.4",
    "mypy": "2.3.1",
    "mypy-baseline": "0.7.4",
}
TRIAGE_CLASSIFICATIONS = {
    "legitimate_cleanup",
    "narrow_to_specific",
    "must_reraise",
}


class StaticAnalysisError(RuntimeError):
    """Raised when a static-analysis contract or ratchet fails closed."""


RuffKey = tuple[str, str, str]


def _require_tool_version(distribution: str) -> None:
    expected = EXPECTED_TOOL_VERSIONS[distribution]
    try:
        observed = version(distribution)
    except PackageNotFoundError as exc:
        raise StaticAnalysisError(f"required static-analysis tool is missing: {distribution}") from exc
    if observed != expected:
        raise StaticAnalysisError(
            f"static-analysis tool version mismatch: {distribution} expected {expected}, observed {observed}"
        )


def _relative_path(repository_root: Path, raw_path: str) -> str:
    path = Path(raw_path)
    if not path.is_absolute():
        path = repository_root / path
    try:
        return path.resolve().relative_to(repository_root.resolve()).as_posix()
    except ValueError as exc:
        raise StaticAnalysisError("static-analysis diagnostic escaped the repository root") from exc


def _run_ruff(
    repository_root: Path,
    source_paths: Sequence[str],
) -> Counter[RuffKey]:
    _require_tool_version("ruff")
    completed = subprocess.run(
        (
            sys.executable,
            "-m",
            "ruff",
            "check",
            *source_paths,
            "--select",
            ",".join(RUFF_RULES),
            "--output-format",
            "json",
            "--no-cache",
        ),
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    if completed.returncode not in {0, 1}:
        raise StaticAnalysisError(
            f"Ruff execution failed with exit {completed.returncode}: {completed.stderr.strip()[:1000]}"
        )
    try:
        payload = json.loads(completed.stdout or "[]")
    except json.JSONDecodeError as exc:
        raise StaticAnalysisError("Ruff emitted invalid JSON diagnostics") from exc
    if not isinstance(payload, list):
        raise StaticAnalysisError("Ruff diagnostic payload must be a list")
    findings: Counter[RuffKey] = Counter()
    for item in payload:
        if not isinstance(item, dict):
            raise StaticAnalysisError("Ruff diagnostic item must be an object")
        code = item.get("code")
        message = item.get("message")
        filename = item.get("filename")
        if (
            not isinstance(code, str)
            or not code
            or not isinstance(message, str)
            or not message
            or not isinstance(filename, str)
            or not filename
        ):
            raise StaticAnalysisError("Ruff diagnostic fields are invalid")
        findings[(_relative_path(repository_root, filename), code, message)] += 1
    return findings


def _ruff_payload(findings: Mapping[RuffKey, int]) -> dict[str, object]:
    rows = [
        {"path": path, "code": code, "message": message, "count": count}
        for (path, code, message), count in sorted(findings.items())
    ]
    return {
        "schema_version": "1",
        "tool": "ruff",
        "tool_version": EXPECTED_TOOL_VERSIONS["ruff"],
        "rules": list(RUFF_RULES),
        "findings": rows,
    }


def _load_ruff_baseline(path: Path) -> Counter[RuffKey]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StaticAnalysisError("Ruff baseline is unavailable or invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {
        "schema_version",
        "tool",
        "tool_version",
        "rules",
        "findings",
    }:
        raise StaticAnalysisError("Ruff baseline schema is invalid")
    if payload["schema_version"] != "1" or payload["tool"] != "ruff":
        raise StaticAnalysisError("Ruff baseline identity is invalid")
    if payload["tool_version"] != EXPECTED_TOOL_VERSIONS["ruff"]:
        raise StaticAnalysisError("Ruff baseline tool version is stale")
    if payload["rules"] != list(RUFF_RULES):
        raise StaticAnalysisError("Ruff baseline rule set is stale")
    rows = payload["findings"]
    if not isinstance(rows, list):
        raise StaticAnalysisError("Ruff baseline findings must be a list")
    findings: Counter[RuffKey] = Counter()
    for row in rows:
        if not isinstance(row, dict) or set(row) != {"path", "code", "message", "count"}:
            raise StaticAnalysisError("Ruff baseline finding schema is invalid")
        path_value = row["path"]
        code = row["code"]
        message = row["message"]
        count = row["count"]
        if (
            not isinstance(path_value, str)
            or not isinstance(code, str)
            or not isinstance(message, str)
            or not isinstance(count, int)
            or count <= 0
        ):
            raise StaticAnalysisError("Ruff baseline finding value is invalid")
        if code == "BLE001":
            raise StaticAnalysisError("BLE001 cannot be stored in the Ruff baseline")
        key = (path_value, code, message)
        if key in findings:
            raise StaticAnalysisError("Ruff baseline contains duplicate findings")
        findings[key] = count
    return findings


def sync_ruff_baseline(
    repository_root: Path,
    source_paths: Sequence[str],
    baseline_path: Path,
) -> None:
    findings = _run_ruff(repository_root, source_paths)
    blind = [key for key in findings if key[1] == "BLE001"]
    if blind:
        raise StaticAnalysisError(f"BLE001 must be resolved before baseline sync: {len(blind)} finding groups")
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    baseline_path.write_text(
        json.dumps(_ruff_payload(findings), indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
    )
    # IMPORTANT: Windows text writes use CRLF; normalize ratchets so Git and CI see byte-stable LF.
    payload = baseline_path.read_bytes()
    normalized = payload.replace(b"\r\n", b"\n")
    if normalized != payload:
        baseline_path.write_bytes(normalized)


def run_ruff_gate(
    repository_root: Path,
    source_paths: Sequence[str],
    baseline_path: Path,
) -> None:
    baseline = _load_ruff_baseline(baseline_path)
    current = _run_ruff(repository_root, source_paths)
    blind = [key for key in current if key[1] == "BLE001"]
    if blind:
        path_value, code, message = sorted(blind)[0]
        raise StaticAnalysisError(f"new Ruff finding: {path_value} {code} {message}")
    added = current - baseline
    removed = baseline - current
    if added:
        (path_value, code, message), count = sorted(added.items())[0]
        raise StaticAnalysisError(
            f"new Ruff finding: {path_value} {code} {message} (count +{count})"
        )
    if removed:
        (path_value, code, message), count = sorted(removed.items())[0]
        raise StaticAnalysisError(
            f"Ruff baseline is stale after resolved finding: {path_value} {code} {message} (count -{count})"
        )


def _mypy_output(
    repository_root: Path,
    source_paths: Sequence[str],
    config_path: Path | None,
    *,
    platform: str,
) -> str:
    if platform not in MYPY_PLATFORMS:
        raise StaticAnalysisError(f"unsupported Mypy platform: {platform}")
    _require_tool_version("mypy")
    command = [
        sys.executable,
        "-m",
        "mypy",
        "--show-error-codes",
        "--no-error-summary",
        "--no-pretty",
        "--no-color-output",
        "--platform",
        platform,
    ]
    if config_path is not None:
        command.extend(("--config-file", str(config_path)))
    command.extend(source_paths)
    completed = subprocess.run(
        command,
        cwd=repository_root,
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    if completed.returncode not in {0, 1}:
        raise StaticAnalysisError(
            f"Mypy {platform} execution failed with exit {completed.returncode}: "
            f"{completed.stderr.strip()[:1000]}"
        )
    return completed.stdout


def _run_mypy_baseline(
    repository_root: Path,
    baseline_path: Path,
    mypy_output: str,
    mode: str,
) -> None:
    _require_tool_version("mypy-baseline")
    completed = subprocess.run(
        (
            sys.executable,
            "-m",
            "mypy_baseline",
            mode,
            "--baseline-path",
            str(baseline_path),
            "--sort-baseline",
            "--no-colors",
        ),
        cwd=repository_root,
        input=mypy_output,
        check=False,
        capture_output=True,
        text=True,
        shell=False,
    )
    if completed.returncode != 0:
        diagnostic = (completed.stdout + "\n" + completed.stderr).strip()[:2000]
        label = "new Mypy error or stale baseline" if mode == "filter" else "Mypy baseline sync failed"
        raise StaticAnalysisError(f"{label}: {diagnostic}")


def sync_mypy_baseline(
    repository_root: Path,
    source_paths: Sequence[str],
    baseline_path: Path,
    *,
    config_path: Path | None,
    platform: str,
) -> None:
    baseline_path.parent.mkdir(parents=True, exist_ok=True)
    _run_mypy_baseline(
        repository_root,
        baseline_path,
        _mypy_output(repository_root, source_paths, config_path, platform=platform),
        "sync",
    )
    # IMPORTANT: mypy-baseline writes host-native newlines; keep ratchets byte-stable across runners.
    payload = baseline_path.read_bytes()
    normalized = payload.replace(b"\r\n", b"\n")
    if normalized != payload:
        baseline_path.write_bytes(normalized)


def run_mypy_gate(
    repository_root: Path,
    source_paths: Sequence[str],
    baseline_path: Path,
    *,
    config_path: Path | None,
    platform: str,
) -> None:
    if not baseline_path.is_file():
        raise StaticAnalysisError("Mypy baseline is unavailable")
    _run_mypy_baseline(
        repository_root,
        baseline_path,
        _mypy_output(repository_root, source_paths, config_path, platform=platform),
        "filter",
    )


def _validated_mypy_targets(
    repository_root: Path,
    targets: Sequence[tuple[str, Path]],
) -> tuple[tuple[str, Path], ...]:
    normalized = tuple(targets)
    platforms = tuple(platform for platform, _baseline in normalized)
    if platforms != MYPY_PLATFORMS:
        raise StaticAnalysisError(
            "Mypy target matrix must contain win32 then linux exactly once"
        )
    try:
        root = repository_root.resolve(strict=True)
    except OSError as exc:
        raise StaticAnalysisError("Mypy repository root is unavailable") from exc
    baseline_paths = tuple(baseline.resolve() for _platform, baseline in normalized)
    if len(set(baseline_paths)) != len(baseline_paths):
        raise StaticAnalysisError("Mypy target baselines must use distinct paths")
    expected_paths = tuple((root / filename).resolve() for filename in MYPY_BASELINE_FILENAMES)
    if (
        any(not path.is_relative_to(root) for path in baseline_paths)
        or baseline_paths != expected_paths
    ):
        raise StaticAnalysisError(
            "Mypy targets must use the canonical repo-contained platform baselines"
        )
    return normalized


def sync_mypy_matrix(
    repository_root: Path,
    source_paths: Sequence[str],
    targets: Sequence[tuple[str, Path]],
    *,
    config_path: Path | None,
) -> None:
    for platform, baseline_path in _validated_mypy_targets(repository_root, targets):
        try:
            sync_mypy_baseline(
                repository_root,
                source_paths,
                baseline_path,
                config_path=config_path,
                platform=platform,
            )
        except StaticAnalysisError as exc:
            raise StaticAnalysisError(f"Mypy target {platform} failed: {exc}") from exc


def run_mypy_matrix(
    repository_root: Path,
    source_paths: Sequence[str],
    targets: Sequence[tuple[str, Path]],
    *,
    config_path: Path | None,
) -> None:
    for platform, baseline_path in _validated_mypy_targets(repository_root, targets):
        try:
            run_mypy_gate(
                repository_root,
                source_paths,
                baseline_path,
                config_path=config_path,
                platform=platform,
            )
        except StaticAnalysisError as exc:
            raise StaticAnalysisError(f"Mypy target {platform} failed: {exc}") from exc


def _broad_exception_kind(handler: ast.ExceptHandler) -> str | None:
    if handler.type is None:
        return "bare"
    if isinstance(handler.type, ast.Name) and handler.type.id in {"Exception", "BaseException"}:
        return handler.type.id
    if isinstance(handler.type, ast.Tuple):
        names = sorted(
            item.id
            for item in handler.type.elts
            if isinstance(item, ast.Name) and item.id in {"Exception", "BaseException"}
        )
        if names:
            return "tuple:" + ",".join(names)
    return None


def _python_files(repository_root: Path, source_paths: Sequence[str]) -> Iterable[Path]:
    for source in source_paths:
        target = repository_root / source
        if target.is_file() and target.suffix == ".py":
            yield target
        elif target.is_dir():
            yield from sorted(target.rglob("*.py"))


def build_broad_exception_inventory(
    repository_root: Path,
    source_paths: Sequence[str],
) -> list[dict[str, object]]:
    sites: list[dict[str, object]] = []
    occurrences: Counter[tuple[str, str]] = Counter()
    for path in _python_files(repository_root, source_paths):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        except (OSError, SyntaxError, UnicodeDecodeError) as exc:
            raise StaticAnalysisError(f"cannot inventory broad exceptions in {path}") from exc
        relative = path.resolve().relative_to(repository_root.resolve()).as_posix()
        handlers = sorted(
            (node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)),
            key=lambda node: (node.lineno, node.col_offset),
        )
        for handler in handlers:
            kind = _broad_exception_kind(handler)
            if kind is None:
                continue
            digest = hashlib.sha256(
                ast.dump(handler, annotate_fields=True, include_attributes=False).encode("utf-8")
            ).hexdigest()
            # IMPORTANT: keep the full source-binding digest but mark and group it so secret
            # scanners do not mistake deterministic AST identities for credential material.
            fingerprint = "ast-v1-" + "-".join(
                digest[index : index + 8] for index in range(0, len(digest), 8)
            )
            occurrence_key = (relative, fingerprint)
            occurrences[occurrence_key] += 1
            sites.append(
                {
                    "path": relative,
                    "line": handler.lineno,
                    "exception": kind,
                    "fingerprint": fingerprint,
                    "occurrence": occurrences[occurrence_key],
                }
            )
    return sites


def _site_identity(site: Mapping[str, object]) -> tuple[object, ...]:
    return (
        site.get("path"),
        site.get("line"),
        site.get("exception"),
        site.get("fingerprint"),
        site.get("occurrence"),
    )


def validate_broad_exception_triage(
    repository_root: Path,
    source_paths: Sequence[str],
    manifest_path: Path,
) -> None:
    current = build_broad_exception_inventory(repository_root, source_paths)
    try:
        payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StaticAnalysisError("broad-exception triage manifest is unavailable or invalid") from exc
    if not isinstance(payload, dict) or set(payload) != {"schema_version", "sites"}:
        raise StaticAnalysisError("broad-exception triage manifest schema is invalid")
    if payload["schema_version"] != "1" or not isinstance(payload["sites"], list):
        raise StaticAnalysisError("broad-exception triage manifest identity is invalid")
    classified: list[dict[str, object]] = []
    for site in payload["sites"]:
        if not isinstance(site, dict) or set(site) != {
            "path",
            "line",
            "exception",
            "fingerprint",
            "occurrence",
            "classification",
            "rationale",
        }:
            raise StaticAnalysisError("broad-exception triage site schema is invalid")
        if site["classification"] not in TRIAGE_CLASSIFICATIONS:
            raise StaticAnalysisError("broad-exception triage classification is invalid")
        if not isinstance(site["rationale"], str) or not site["rationale"].strip():
            raise StaticAnalysisError("broad-exception triage rationale is required")
        classified.append(site)
    current_ids = [_site_identity(site) for site in current]
    classified_ids = [_site_identity(site) for site in classified]
    if len(classified_ids) != len(set(classified_ids)) or sorted(current_ids) != sorted(classified_ids):
        raise StaticAnalysisError(
            f"broad-exception triage drift: source={len(current_ids)} manifest={len(classified_ids)}"
        )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        choices=("lint", "typecheck", "sync-lint", "sync-typecheck", "validate-triage"),
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command in {"lint", "sync-lint", "validate-triage"}:
            validate_broad_exception_triage(ROOT, PRODUCT_SOURCE_PATHS, BROAD_EXCEPTION_TRIAGE)
        if args.command == "lint":
            run_ruff_gate(ROOT, RUFF_SOURCE_PATHS, RUFF_BASELINE)
        elif args.command == "typecheck":
            run_mypy_matrix(
                ROOT,
                MYPY_SOURCE_PATHS,
                MYPY_TARGETS,
                config_path=ROOT / "pyproject.toml",
            )
        elif args.command == "sync-lint":
            sync_ruff_baseline(ROOT, RUFF_SOURCE_PATHS, RUFF_BASELINE)
        elif args.command == "sync-typecheck":
            sync_mypy_matrix(
                ROOT,
                MYPY_SOURCE_PATHS,
                MYPY_TARGETS,
                config_path=ROOT / "pyproject.toml",
            )
    except StaticAnalysisError as exc:
        print(f"backend static analysis failed: {exc}", file=sys.stderr)
        return 1
    print(f"backend static analysis passed: {args.command}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
