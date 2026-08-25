from pathlib import Path

import pytest

from redagent_platform.safety import (
    assert_reference_docs_only,
    external_reference_execution_allowed,
    path_is_inside,
    repository_root,
    unexpected_reference_entries,
)


def test_reference_directory_contains_only_docs() -> None:
    assert unexpected_reference_entries() == []
    assert_reference_docs_only()


def test_external_reference_execution_is_disabled() -> None:
    assert external_reference_execution_allowed() is False


def test_workspace_path_guard_accepts_child_paths() -> None:
    root = repository_root()
    assert path_is_inside(root / "tests", root)


def test_workspace_path_guard_rejects_sibling_paths(tmp_path: Path) -> None:
    parent = tmp_path / "workspace"
    sibling = tmp_path / "other"
    parent.mkdir()
    sibling.mkdir()

    assert not path_is_inside(sibling, parent)


def test_reference_docs_only_raises_for_unexpected_entry(tmp_path: Path) -> None:
    reference = tmp_path / "reference"
    reference.mkdir()
    (reference / "docs").mkdir()
    (reference / "external-tool").mkdir()

    with pytest.raises(RuntimeError, match="external-tool"):
        assert_reference_docs_only(tmp_path)
