from __future__ import annotations

from types import SimpleNamespace

import pytest

from redagent_platform.local_stack import LocalStackError
from tests.integration import runtime_coordinates


REQUIRED = {
    "REDAGENT_COMPOSE_PROJECT_NAME": "public-test-project",
    "REDAGENT_BIND_HOST": "127.0.0.1",
    "REDAGENT_TEMPORAL_PORT": "57321",
}


def _configured(tmp_path):
    state_dir = tmp_path / ".local" / "redagent"
    runtime_dir = state_dir / "runtime"
    runtime_dir.mkdir(parents=True)
    return SimpleNamespace(state_dir=state_dir, profile="local"), runtime_dir


def _write_runtime_env(runtime_dir, values: list[tuple[str, str]]) -> None:
    (runtime_dir / "local-stack.env").write_text(
        "".join(f"{name}={value}\n" for name, value in values),
        encoding="utf-8",
    )


def _install_config(monkeypatch, configured, *, effective=None):
    calls = []

    def load_config(workspace, *, env):
        if not env:
            return configured
        calls.append(dict(env))
        if effective is None:
            raise AssertionError("typed config validation must not run for invalid persisted coordinates")
        return effective

    monkeypatch.setattr(runtime_coordinates, "load_local_stack_config", load_config)
    return calls


def test_missing_runtime_env_fails_before_effective_fallback(tmp_path, monkeypatch) -> None:
    configured, _ = _configured(tmp_path)
    calls = _install_config(monkeypatch, configured)

    with pytest.raises(LocalStackError, match="integration_runtime_coordinates_invalid"):
        runtime_coordinates.persisted_temporal_target(tmp_path)

    assert calls == []


@pytest.mark.parametrize("missing", sorted(REQUIRED))
def test_missing_required_coordinate_fails_before_effective_fallback(
    tmp_path, monkeypatch, missing: str,
) -> None:
    configured, runtime_dir = _configured(tmp_path)
    _write_runtime_env(runtime_dir, [(name, value) for name, value in REQUIRED.items() if name != missing])
    calls = _install_config(monkeypatch, configured)

    with pytest.raises(LocalStackError, match="integration_runtime_coordinates_invalid"):
        runtime_coordinates.persisted_temporal_target(tmp_path)

    assert calls == []


def test_duplicate_required_coordinate_fails_before_effective_fallback(tmp_path, monkeypatch) -> None:
    configured, runtime_dir = _configured(tmp_path)
    values = list(REQUIRED.items()) + [("REDAGENT_TEMPORAL_PORT", "57322")]
    _write_runtime_env(runtime_dir, values)
    calls = _install_config(monkeypatch, configured)

    with pytest.raises(LocalStackError, match="integration_runtime_coordinates_invalid"):
        runtime_coordinates.persisted_temporal_target(tmp_path)

    assert calls == []


@pytest.mark.parametrize("redirected", ("runtime_dir", "runtime_env"))
def test_reparse_runtime_artifact_fails_before_effective_fallback(
    tmp_path, monkeypatch, redirected: str,
) -> None:
    configured, runtime_dir = _configured(tmp_path)
    _write_runtime_env(runtime_dir, list(REQUIRED.items()))
    runtime_env = runtime_dir / "local-stack.env"
    calls = _install_config(monkeypatch, configured)
    rejected = runtime_dir if redirected == "runtime_dir" else runtime_env
    monkeypatch.setattr(runtime_coordinates, "is_reparse_path", lambda path: path == rejected)

    with pytest.raises(LocalStackError, match="integration_runtime_coordinates_invalid"):
        runtime_coordinates.persisted_temporal_target(tmp_path)

    assert calls == []


def test_valid_coordinates_delegate_to_existing_validator(tmp_path, monkeypatch) -> None:
    configured, runtime_dir = _configured(tmp_path)
    _write_runtime_env(runtime_dir, list(REQUIRED.items()))
    effective = SimpleNamespace(bind_host="127.0.0.1", temporal_port=57321)
    calls = _install_config(monkeypatch, configured, effective=effective)
    monkeypatch.setattr(runtime_coordinates, "is_reparse_path", lambda path: False)

    assert runtime_coordinates.persisted_temporal_target(tmp_path) == "127.0.0.1:57321"
    assert len(calls) == 1
    assert calls[0]["REDAGENT_COMPOSE_PROJECT_NAME"] == "public-test-project"
    assert calls[0]["REDAGENT_BIND_HOST"] == "127.0.0.1"
    assert calls[0]["REDAGENT_TEMPORAL_PORT"] == "57321"


def test_env_removed_after_read_uses_validated_snapshot_without_fallback(tmp_path, monkeypatch) -> None:
    configured, runtime_dir = _configured(tmp_path)
    configured.bind_host = "127.0.0.1"
    configured.temporal_port = 57233
    _write_runtime_env(runtime_dir, list(REQUIRED.items()))
    runtime_env = runtime_dir / "local-stack.env"
    snapshot_calls = []

    def load_config(workspace, *, env):
        if not env:
            return configured
        snapshot_calls.append(dict(env))
        assert not runtime_env.exists()
        return SimpleNamespace(bind_host=env["REDAGENT_BIND_HOST"], temporal_port=int(env["REDAGENT_TEMPORAL_PORT"]))

    env_checks = 0

    def reparse(path):
        nonlocal env_checks
        if path == runtime_env:
            env_checks += 1
            if env_checks == 2:
                runtime_env.unlink()
        return False

    monkeypatch.setattr(runtime_coordinates, "load_local_stack_config", load_config)
    monkeypatch.setattr(runtime_coordinates, "is_reparse_path", reparse)

    assert runtime_coordinates.persisted_temporal_target(tmp_path) == "127.0.0.1:57321"
    assert len(snapshot_calls) == 1
