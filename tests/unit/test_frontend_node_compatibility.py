"""Fail before mutable frontend validation on unsupported toolchain runtimes."""

from types import SimpleNamespace

import pytest

from scripts import run_validation_gate


def _reported_version(monkeypatch: pytest.MonkeyPatch, version: str) -> None:
    monkeypatch.setattr(
        run_validation_gate.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(stdout=version + "\n"),
    )


@pytest.mark.parametrize("version", [
    "v18.20.8", "v19.9.0", "v20.8.99", "v21.7.3", "v23.11.0",
])
def test_unpatched_or_unsupported_node_line_denied_before_validation(
    monkeypatch: pytest.MonkeyPatch, version: str,
) -> None:
    _reported_version(monkeypatch, version)
    with pytest.raises(RuntimeError, match="Node.js 20.9"):
        run_validation_gate._node_version()


@pytest.mark.parametrize("version", ["v20.9.0", "v20.19.0", "v22.0.0", "v24.0.0", "v25.0.0"])
def test_supported_node_line_is_preserved_in_validation_identity(
    monkeypatch: pytest.MonkeyPatch, version: str,
) -> None:
    _reported_version(monkeypatch, version)
    assert run_validation_gate._node_version() == version


@pytest.mark.parametrize("version", ["v22.invalid.0", "v24", "24.0.0", "v24.0.0-nightly", ""])
def test_malformed_or_prerelease_node_identity_denied(
    monkeypatch: pytest.MonkeyPatch, version: str,
) -> None:
    _reported_version(monkeypatch, version)
    with pytest.raises(RuntimeError, match="cannot parse Node.js version"):
        run_validation_gate._node_version()
