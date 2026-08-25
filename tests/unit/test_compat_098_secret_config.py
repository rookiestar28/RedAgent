from __future__ import annotations

from pathlib import Path

import pytest

from redagent_platform.secret_service.config import SecretConfigError, load_secret_settings


def test_fake_provider_is_explicit_synthetic_and_workspace_confined(tmp_path: Path) -> None:
    settings = load_secret_settings(tmp_path, {
        "REDAGENT_SECRET_PROFILE": "synthetic-local",  # pragma: allowlist secret
        "REDAGENT_SECRET_PROVIDER": "fake",  # pragma: allowlist secret
    })
    assert settings.profile == "synthetic-local" and settings.provider == "fake"
    with pytest.raises(SecretConfigError, match="secret_production_fake_provider_forbidden"):
        load_secret_settings(tmp_path, {
            "REDAGENT_SECRET_PROFILE": "production",  # pragma: allowlist secret
            "REDAGENT_SECRET_PROVIDER": "fake",  # pragma: allowlist secret
        })


def test_openbao_local_requires_loopback_file_auth_and_mapping(tmp_path: Path) -> None:
    token = tmp_path / ".local" / "openbao-app-token"
    mapping = tmp_path / "config" / "secret-role-mappings.json"
    token.parent.mkdir(parents=True)
    mapping.parent.mkdir(parents=True)
    token.write_text("ignored-runtime-value\n", encoding="utf-8")  # pragma: allowlist secret
    mapping.write_text('{"schema_version":"1.0","roles":{}}\n', encoding="utf-8")
    settings = load_secret_settings(tmp_path, {
        "REDAGENT_SECRET_PROFILE": "local-conformance",  # pragma: allowlist secret
        "REDAGENT_SECRET_PROVIDER": "openbao",  # pragma: allowlist secret
        "REDAGENT_SECRET_ENDPOINT": "http://127.0.0.1:58200",  # pragma: allowlist secret
        "REDAGENT_SECRET_AUTH_METHOD": "token-file",  # pragma: allowlist secret
        "REDAGENT_SECRET_TOKEN_FILE": str(token),  # pragma: allowlist secret
        "REDAGENT_SECRET_ROLE_MAPPING_FILE": str(mapping),  # pragma: allowlist secret
    })
    assert settings.endpoint == "http://127.0.0.1:58200"
    with pytest.raises(SecretConfigError, match="secret_local_conformance_loopback_required"):
        load_secret_settings(tmp_path, {
            "REDAGENT_SECRET_PROFILE": "local-conformance",  # pragma: allowlist secret
            "REDAGENT_SECRET_PROVIDER": "openbao",  # pragma: allowlist secret
            "REDAGENT_SECRET_ENDPOINT": "http://example.test:8200",  # pragma: allowlist secret
            "REDAGENT_SECRET_AUTH_METHOD": "token-file",  # pragma: allowlist secret
            "REDAGENT_SECRET_TOKEN_FILE": str(token),  # pragma: allowlist secret
            "REDAGENT_SECRET_ROLE_MAPPING_FILE": str(mapping),  # pragma: allowlist secret
        })


def test_production_requires_tls_ca_workload_auth_mapping_and_capability_record(tmp_path: Path) -> None:
    with pytest.raises(SecretConfigError, match="secret_production_tls_required"):
        load_secret_settings(tmp_path, {
            "REDAGENT_SECRET_PROFILE": "production",  # pragma: allowlist secret
            "REDAGENT_SECRET_PROVIDER": "openbao",  # pragma: allowlist secret
            "REDAGENT_SECRET_ENDPOINT": "http://127.0.0.1:8200",  # pragma: allowlist secret
            "REDAGENT_SECRET_AUTH_METHOD": "approle",  # pragma: allowlist secret
        })


def test_inline_tokens_secret_ids_and_root_material_are_forbidden(tmp_path: Path) -> None:
    for name in (
        "REDAGENT_SECRET_TOKEN", "REDAGENT_SECRET_ID", "REDAGENT_SECRET_ROOT_TOKEN",
        "BAO_TOKEN", "VAULT_TOKEN",
    ):
        with pytest.raises(SecretConfigError, match="secret_inline_material_forbidden"):
            load_secret_settings(tmp_path, {
                "REDAGENT_SECRET_PROFILE": "synthetic-local",  # pragma: allowlist secret
                "REDAGENT_SECRET_PROVIDER": "fake",  # pragma: allowlist secret
                name: "synthetic-value",  # pragma: allowlist secret
            })


def test_mapping_allows_closed_material_field_names_but_rejects_material_values(tmp_path: Path) -> None:
    token = tmp_path / "token-file"
    mapping = tmp_path / "mapping.json"
    token.write_text("synthetic-runtime-token\n", encoding="utf-8")  # pragma: allowlist secret
    mapping.write_text(
        '{"schema_version":"1.0","roles":{"role:db":{"issue_path":"database/creds/role","material_fields":["username","password"],"max_ttl_seconds":300}}}',
        encoding="utf-8",
    )
    settings = load_secret_settings(tmp_path, {
        "REDAGENT_SECRET_PROFILE": "local-conformance",  # pragma: allowlist secret
        "REDAGENT_SECRET_PROVIDER": "openbao",  # pragma: allowlist secret
        "REDAGENT_SECRET_ENDPOINT": "http://127.0.0.1:58200",  # pragma: allowlist secret
        "REDAGENT_SECRET_AUTH_METHOD": "token-file",  # pragma: allowlist secret
        "REDAGENT_SECRET_TOKEN_FILE": str(token),  # pragma: allowlist secret
        "REDAGENT_SECRET_ROLE_MAPPING_FILE": str(mapping),  # pragma: allowlist secret
    })
    assert settings.role_mapping_file == mapping
    mapping.write_text('{"schema_version":"1.0","roles":{},"token":"forbidden"}', encoding="utf-8")
    with pytest.raises(SecretConfigError, match="secret_role_mapping_material_forbidden"):
        load_secret_settings(tmp_path, {
            "REDAGENT_SECRET_PROFILE": "local-conformance",  # pragma: allowlist secret
            "REDAGENT_SECRET_PROVIDER": "openbao",  # pragma: allowlist secret
            "REDAGENT_SECRET_ENDPOINT": "http://127.0.0.1:58200",  # pragma: allowlist secret
            "REDAGENT_SECRET_AUTH_METHOD": "token-file",  # pragma: allowlist secret
            "REDAGENT_SECRET_TOKEN_FILE": str(token),  # pragma: allowlist secret
            "REDAGENT_SECRET_ROLE_MAPPING_FILE": str(mapping),  # pragma: allowlist secret
        })
