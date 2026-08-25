"""Local safety checks for repository bootstrap validation."""

from __future__ import annotations

from pathlib import Path

ALLOWED_REFERENCE_ENTRIES = frozenset({"docs"})


def repository_root() -> Path:
    """Return the repository root based on this package location."""
    return Path(__file__).resolve().parents[1]


def path_is_inside(path: Path, parent: Path) -> bool:
    """Return True when path resolves inside parent."""
    resolved_path = path.resolve()
    resolved_parent = parent.resolve()
    return resolved_path == resolved_parent or resolved_parent in resolved_path.parents


def unexpected_reference_entries(root: Path | None = None) -> list[str]:
    """Return unexpected top-level entries under reference/."""
    repo_root = root or repository_root()
    reference_dir = repo_root / "reference"
    if not reference_dir.exists():
        return []
    return sorted(
        entry.name
        for entry in reference_dir.iterdir()
        if entry.name not in ALLOWED_REFERENCE_ENTRIES
    )


def assert_reference_docs_only(root: Path | None = None) -> None:
    """Raise if reference/ contains anything except approved documentation."""
    unexpected = unexpected_reference_entries(root)
    if unexpected:
        joined = ", ".join(unexpected)
        raise RuntimeError(f"Unexpected external reference entries: {joined}")


def external_reference_execution_allowed() -> bool:
    """External reference execution is disabled by project policy."""
    return False
