from __future__ import annotations

from pathlib import Path

import pytest

from redagent_platform.policy_service.config import PolicyConfigError, load_policy_settings


def test_fake_policy_provider_is_explicit_synthetic_only(tmp_path: Path) -> None:
    settings = load_policy_settings(tmp_path, {
        "REDAGENT_POLICY_PROFILE": "synthetic-local", "REDAGENT_POLICY_PROVIDER": "fake",
    })
    assert settings.provider == "fake"
    with pytest.raises(PolicyConfigError, match="policy_production_fake_provider_forbidden"):
        load_policy_settings(tmp_path, {
            "REDAGENT_POLICY_PROFILE": "production", "REDAGENT_POLICY_PROVIDER": "fake",
        })


def test_local_opa_requires_loopback_token_file_public_key_and_revision(tmp_path: Path) -> None:
    token = _file(tmp_path / ".local" / "opa-token", "synthetic-token")  # pragma: allowlist secret
    public_key = _file(tmp_path / ".local" / "opa-public.pem", "synthetic-public-key")
    settings = load_policy_settings(tmp_path, {
        "REDAGENT_POLICY_PROFILE": "local-conformance", "REDAGENT_POLICY_PROVIDER": "opa",
        "REDAGENT_POLICY_ENDPOINT": "http://127.0.0.1:58181",
        "REDAGENT_POLICY_TOKEN_FILE": str(token), "REDAGENT_POLICY_BUNDLE_PUBLIC_KEY_FILE": str(public_key),
        "REDAGENT_POLICY_REQUIRED_REVISION": "r099-v1",
    })
    assert settings.endpoint == "http://127.0.0.1:58181"
    with pytest.raises(PolicyConfigError, match="policy_local_loopback_required"):
        load_policy_settings(tmp_path, {
            "REDAGENT_POLICY_PROFILE": "local-conformance", "REDAGENT_POLICY_PROVIDER": "opa",
            "REDAGENT_POLICY_ENDPOINT": "http://opa.example.test:8181",
            "REDAGENT_POLICY_TOKEN_FILE": str(token), "REDAGENT_POLICY_BUNDLE_PUBLIC_KEY_FILE": str(public_key),
            "REDAGENT_POLICY_REQUIRED_REVISION": "r099-v1",
        })


def test_production_requires_https_ca_mtls_token_and_workspace_files(tmp_path: Path) -> None:
    with pytest.raises(PolicyConfigError, match="policy_production_tls_required"):
        load_policy_settings(tmp_path, {
            "REDAGENT_POLICY_PROFILE": "production", "REDAGENT_POLICY_PROVIDER": "opa",
            "REDAGENT_POLICY_ENDPOINT": "http://127.0.0.1:8181",
            "REDAGENT_POLICY_REQUIRED_REVISION": "r099-v1",
        })


def test_inline_policy_token_and_arbitrary_decision_path_are_forbidden(tmp_path: Path) -> None:
    with pytest.raises(PolicyConfigError, match="policy_inline_token_forbidden"):
        load_policy_settings(tmp_path, {
            "REDAGENT_POLICY_PROFILE": "synthetic-local", "REDAGENT_POLICY_PROVIDER": "fake",
            "REDAGENT_POLICY_TOKEN": "synthetic",
        })
    with pytest.raises(PolicyConfigError, match="policy_decision_path_forbidden"):
        load_policy_settings(tmp_path, {
            "REDAGENT_POLICY_PROFILE": "synthetic-local", "REDAGENT_POLICY_PROVIDER": "fake",
            "REDAGENT_POLICY_DECISION_PATH": "/v1/data/arbitrary",
        })


def _file(path: Path, value: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value + "\n", encoding="utf-8")
    return path
