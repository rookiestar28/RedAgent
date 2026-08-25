"""Canonical manifest validator; compat_110 does not extract or execute artifact entries."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import PurePosixPath
import re


_SHA = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, kw_only=True)
class ManifestEntry:
    path: str; kind: str; size: int; sha256: str; compressed_size: int


@dataclass(frozen=True, kw_only=True)
class ValidatedManifest:
    entries: tuple[ManifestEntry, ...]; file_count: int; total_bytes: int; manifest_sha256: str


def validate_manifest(*, entries: tuple[ManifestEntry, ...], max_files: int, max_bytes: int, max_depth: int, max_expansion_ratio: int) -> ValidatedManifest:
    if not entries or len(entries) > max_files: raise ValueError("artifact_file_count_exceeded")
    normalized: list[ManifestEntry] = []; casefolded: set[str] = set(); total = 0
    for entry in entries:
        path = entry.path.replace("\\", "/"); candidate = PurePosixPath(path)
        if path.startswith("/") or re.match(r"^[A-Za-z]:", path): raise ValueError("artifact_absolute_path")
        if any(part in {"", ".", ".."} for part in candidate.parts) or ".." in candidate.parts: raise ValueError("artifact_path_traversal")
        if len(candidate.parts) > max_depth: raise ValueError("artifact_path_depth_exceeded")
        if entry.kind != "file": raise ValueError("artifact_entry_kind_denied")
        if not _SHA.fullmatch(entry.sha256) or entry.size < 0 or entry.compressed_size < 1: raise ValueError("artifact_entry_invalid")
        if entry.size > entry.compressed_size * max_expansion_ratio: raise ValueError("artifact_expansion_ratio_exceeded")
        collision = path.casefold()
        if collision in casefolded: raise ValueError("artifact_path_collision")
        casefolded.add(collision); total += entry.size
        if total > max_bytes: raise ValueError("artifact_byte_budget_exceeded")
        normalized.append(ManifestEntry(path=path, kind="file", size=entry.size, sha256=entry.sha256, compressed_size=entry.compressed_size))
    ordered = tuple(sorted(normalized, key=lambda item: item.path))
    material = [[item.path, item.kind, item.size, item.sha256, item.compressed_size] for item in ordered]
    digest = hashlib.sha256(json.dumps(material, separators=(",", ":")).encode()).hexdigest()
    return ValidatedManifest(entries=ordered, file_count=len(ordered), total_bytes=total, manifest_sha256=digest)
