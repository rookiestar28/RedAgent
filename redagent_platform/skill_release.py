"""Release manifest builder for RedAgent operator skill packages."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
from typing import Any


RELEASE_VERSION = "phase8.r052.v1"
SKILL_NAME = "redagent-operator"
REQUIRED_CLIENTS = ("codex", "claude")
REQUIRED_RELEASE_DOCS = (
    "docs/sop/AGENT_SKILL_OPERATOR_SOP.md",
    "docs/release/AGENT_SKILL_RELEASE_PACKAGE.md",
    "docs/security/AGENT_SKILL_OPERATOR_SAFETY_ARCHITECTURE.md",
    "docs/security/SKILL_COMMAND_CONTRACT_POLICY.md",
    "docs/security/AGENT_SKILL_VALIDATION_POLICY.md",
    "docs/security/SKILL_INVOCATION_EVIDENCE_POLICY.md",
)
VALIDATION_COMMANDS = (
    ".venv\\Scripts\\python.exe scripts\\validate_agent_skills.py --json",
    ".venv\\Scripts\\python.exe -m pytest tests\\unit\\test_codex_skill_package.py tests\\unit\\test_claude_skill_package.py tests\\unit\\test_skill_validation.py",
    ".venv\\Scripts\\python.exe -m pytest tests\\unit\\test_skill_invocation.py tests\\unit\\test_skill_command_contract.py",
    ".venv\\Scripts\\python.exe -m pytest tests\\unit\\test_skill_release.py",
    "powershell -ExecutionPolicy Bypass -File scripts\\run_full_tests_windows.ps1",
)
KNOWN_LIMITATIONS = (
    "Skills are not authorization records and cannot approve their own actions.",
    "The R051 artifact recorder does not execute the real assessment wrapper.",
    "Global user-directory installation is not performed by this repository release package.",
    "External sharing of generated reports still requires redaction review approval.",
)


@dataclass(frozen=True, kw_only=True)
class ReleaseFile:
    relative_path: str
    sha256: str
    size_bytes: int

    def to_jsonable(self) -> dict[str, object]:
        return {
            "relative_path": self.relative_path,
            "sha256": self.sha256,
            "size_bytes": self.size_bytes,
        }


@dataclass(frozen=True, kw_only=True)
class ReleaseClient:
    platform: str
    package_path: str
    activation: str
    install_path: str
    files: tuple[ReleaseFile, ...]

    def to_jsonable(self) -> dict[str, object]:
        return {
            "platform": self.platform,
            "package_path": self.package_path,
            "activation": self.activation,
            "install_path": self.install_path,
            "files": [file.to_jsonable() for file in self.files],
        }


@dataclass(frozen=True, kw_only=True)
class SkillReleaseManifest:
    release_version: str
    skill_name: str
    generated_from: str
    clients: tuple[ReleaseClient, ...]
    release_docs: tuple[ReleaseFile, ...]
    validation_commands: tuple[str, ...]
    known_limitations: tuple[str, ...]

    def to_jsonable(self) -> dict[str, object]:
        return {
            "release_version": self.release_version,
            "skill_name": self.skill_name,
            "generated_from": self.generated_from,
            "clients": [client.to_jsonable() for client in self.clients],
            "release_docs": [doc.to_jsonable() for doc in self.release_docs],
            "validation_commands": list(self.validation_commands),
            "known_limitations": list(self.known_limitations),
        }


def build_skill_release_manifest(repo_root: str | Path = ".") -> SkillReleaseManifest:
    root = Path(repo_root)
    codex_root = root / "skills" / "codex" / SKILL_NAME
    claude_root = root / "skills" / "claude" / SKILL_NAME
    clients = (
        ReleaseClient(
            platform="codex",
            package_path="skills/codex/redagent-operator",
            activation="$redagent-operator",
            install_path="repository-local skills/codex/redagent-operator",
            files=_release_files(root, codex_root),
        ),
        ReleaseClient(
            platform="claude",
            package_path="skills/claude/redagent-operator",
            activation="/redagent-operator",
            install_path="repository-local skills/claude/redagent-operator",
            files=_release_files(root, claude_root),
        ),
    )
    return SkillReleaseManifest(
        release_version=RELEASE_VERSION,
        skill_name=SKILL_NAME,
        generated_from=str(root.resolve()),
        clients=clients,
        release_docs=tuple(_file_record(root, root / path) for path in REQUIRED_RELEASE_DOCS),
        validation_commands=VALIDATION_COMMANDS,
        known_limitations=KNOWN_LIMITATIONS,
    )


def validate_skill_release_manifest(manifest: SkillReleaseManifest) -> tuple[str, ...]:
    issues: list[str] = []
    if manifest.release_version != RELEASE_VERSION:
        issues.append("invalid_release_version")
    if manifest.skill_name != SKILL_NAME:
        issues.append("invalid_skill_name")

    platforms = {client.platform for client in manifest.clients}
    for platform in REQUIRED_CLIENTS:
        if platform not in platforms:
            issues.append(f"missing_client:{platform}")
    for client in manifest.clients:
        if not client.files:
            issues.append(f"missing_client_files:{client.platform}")
        if client.platform == "codex" and "$redagent-operator" not in client.activation:
            issues.append("invalid_codex_activation")
        if client.platform == "claude" and "/redagent-operator" not in client.activation:
            issues.append("invalid_claude_activation")

    doc_paths = {doc.relative_path for doc in manifest.release_docs}
    for required_doc in REQUIRED_RELEASE_DOCS:
        if required_doc not in doc_paths:
            issues.append(f"missing_release_doc:{required_doc}")

    all_files = [file for client in manifest.clients for file in client.files] + list(manifest.release_docs)
    for file in all_files:
        if not _safe_relative_path(file.relative_path):
            issues.append(f"unsafe_path:{file.relative_path}")
        if not re.fullmatch(r"[0-9a-f]{64}", file.sha256):
            issues.append(f"invalid_hash:{file.relative_path}")
        if file.size_bytes <= 0:
            issues.append(f"empty_file:{file.relative_path}")

    command_blob = "\n".join(manifest.validation_commands)
    for required in (
        "validate_agent_skills.py",
        "test_codex_skill_package.py",
        "test_claude_skill_package.py",
        "test_skill_validation.py",
        "test_skill_invocation.py",
        "test_skill_release.py",
        "run_full_tests_windows.ps1",
    ):
        if required not in command_blob:
            issues.append(f"missing_validation_command:{required}")

    limitation_blob = " ".join(manifest.known_limitations).lower()
    if "not authorization records" not in limitation_blob or "cannot approve their own actions" not in limitation_blob:
        issues.append("missing_authorization_limitation")
    return tuple(issues)


def manifest_to_json(manifest: SkillReleaseManifest) -> str:
    return json.dumps(manifest.to_jsonable(), indent=2, sort_keys=True) + "\n"


def _release_files(repo_root: Path, package_root: Path) -> tuple[ReleaseFile, ...]:
    if not package_root.exists():
        raise FileNotFoundError(package_root)
    files = tuple(path for path in sorted(package_root.rglob("*")) if path.is_file())
    return tuple(_file_record(repo_root, path) for path in files)


def _file_record(repo_root: Path, path: Path) -> ReleaseFile:
    if not path.exists():
        raise FileNotFoundError(path)
    data = path.read_bytes()
    return ReleaseFile(
        relative_path=path.resolve().relative_to(repo_root.resolve()).as_posix(),
        sha256=hashlib.sha256(data).hexdigest(),
        size_bytes=len(data),
    )


def _safe_relative_path(value: str) -> bool:
    path = Path(value)
    return not path.is_absolute() and ".." not in path.parts and bool(path.parts)
