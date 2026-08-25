from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = ROOT / "scripts" / "validate_public_release.py"
SPEC = importlib.util.spec_from_file_location("public_release_validator", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VALIDATOR)


@pytest.mark.parametrize(
    "text",
    (
        "Private checkout: " + "B:" + "\\我的專案\\RedTeam",
        "Private WSL checkout: " + "/mnt/" + "b/我的專案/RedTeam",
        "The user " + "has installed and initialized Kali Linux on WSL2.",
        "This is the primary " + "Codex " + "workspace.",
    ),
)
def test_private_environment_traces_fail_closed(text: str) -> None:
    with pytest.raises(
        VALIDATOR.PublicReleaseValidationError,
        match=r"^forbidden_public_environment:docs/example\.md$",
    ):
        VALIDATOR._validate_public_text("docs/example.md", text)


@pytest.mark.parametrize(
    "text",
    (
        r"Use C:\safe-bin for a synthetic PATH fixture.",
        "When working below /mnt/*, use a repository-local temporary directory.",
        "Install dependencies in a project-local virtual environment.",
    ),
)
def test_generic_public_environment_guidance_remains_allowed(text: str) -> None:
    VALIDATOR._validate_public_text("docs/example.md", text)
