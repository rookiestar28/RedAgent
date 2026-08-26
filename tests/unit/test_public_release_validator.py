from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path
import subprocess

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


def _blob_oid(payload: bytes) -> str:
    return hashlib.sha1(f"blob {len(payload)}\0".encode("ascii") + payload).hexdigest()


def test_public_residual_bytes_accept_only_head_equivalent_utf8_crlf(tmp_path: Path) -> None:
    candidate = tmp_path / "workflow.yml"
    committed = b"name: public\nitem: r" + b"116\n"
    candidate.write_bytes(committed)
    canonical_lf = VALIDATOR._canonical_bytes(candidate, head_oid=_blob_oid(committed))

    candidate.write_bytes(b"name: public\r\nitem: r" + b"116\r\n")
    canonical_crlf = VALIDATOR._canonical_bytes(candidate, head_oid=_blob_oid(committed))

    assert canonical_lf == committed
    assert canonical_crlf == canonical_lf


def test_public_residual_bytes_preserve_an_intentional_head_crlf_blob(tmp_path: Path) -> None:
    candidate = tmp_path / "runtime.json"
    committed = b'{\r\n  "item": "r' + b'114"\r\n}\r\n'
    candidate.write_bytes(committed)

    assert VALIDATOR._canonical_bytes(candidate, head_oid=_blob_oid(committed)) == committed


@pytest.mark.parametrize(
    "payload",
    (
        b"name: public\ritem: r" + b"116\r",
        b"name: public\nitem: r" + b"116\n\xff",
        b"name: changed\nitem: r" + b"116\n",
    ),
)
def test_public_residual_bytes_preserve_non_crlf_byte_drift(tmp_path: Path, payload: bytes) -> None:
    candidate = tmp_path / "workflow.yml"
    candidate.write_bytes(payload)
    committed = b"name: public\nitem: r" + b"116\n"

    assert VALIDATOR._canonical_bytes(candidate, head_oid=_blob_oid(committed)) == payload
    assert VALIDATOR._canonical_bytes(candidate, head_oid=None) == payload


def test_head_blob_inventory_rejects_malformed_git_output(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        VALIDATOR.subprocess,
        "run",
        lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, b"malformed\0", b""),
    )

    with pytest.raises(VALIDATOR.PublicReleaseValidationError, match="public_head_inventory_invalid"):
        VALIDATOR._head_blob_oids()
