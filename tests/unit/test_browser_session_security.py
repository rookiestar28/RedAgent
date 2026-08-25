from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from starlette.responses import Response

from redagent_platform.identity.session_security import (
    BrowserSessionError,
    SessionCipher,
    apply_session_cookie,
    create_session_material,
    evaluate_session_lifetime,
    validate_browser_csrf,
)


NOW = datetime(2026, 7, 10, 9, 30, tzinfo=timezone.utc)


def test_opaque_session_material_hashes_handles_and_encrypts_pkce(tmp_path: Path) -> None:
    key_file = tmp_path / ".local" / "identity-key"
    key_file.parent.mkdir(parents=True)
    key_file.write_bytes(bytes(range(32)))
    cipher = SessionCipher.load(tmp_path, key_file)
    material = create_session_material(cipher, now=NOW)

    assert material.session_handle not in material.session_handle_hash
    assert material.csrf_token not in material.csrf_token_hash
    assert len(material.session_handle_hash) == 64
    ciphertext = cipher.encrypt("pkce-verifier", purpose="oidc-login")
    assert b"pkce-verifier" not in ciphertext
    assert cipher.decrypt(ciphertext, purpose="oidc-login") == "pkce-verifier"
    assert "session_handle='" not in repr(material)
    assert "csrf_token='" not in repr(material)


def test_session_cookie_is_host_only_secure_http_only_and_not_token_bearing() -> None:
    response = Response()
    apply_session_cookie(response, "opaque-handle", max_age_seconds=900)
    header = response.headers["set-cookie"]

    assert header.startswith("__Host-redagent_session=opaque-handle;")
    assert "HttpOnly" in header
    assert "Secure" in header
    assert "SameSite=lax" in header
    assert "Path=/" in header
    assert "Domain=" not in header
    assert "Bearer" not in header


@pytest.mark.parametrize(
    ("csrf", "origin", "fetch_site", "error"),
    [
        (None, "https://redagent.example.test", "same-origin", "csrf_token_required"),
        ("wrong", "https://redagent.example.test", "same-origin", "csrf_token_invalid"),
        ("csrf-1", "https://attacker.invalid", "cross-site", "csrf_origin_invalid"),
        ("csrf-1", None, None, "csrf_origin_required"),
        ("csrf-1", "https://redagent.example.test", "same-site", "csrf_fetch_site_invalid"),
    ],
)
def test_browser_mutations_require_synchronizer_token_exact_origin_and_fetch_metadata(
    csrf: str | None,
    origin: str | None,
    fetch_site: str | None,
    error: str,
) -> None:
    with pytest.raises(BrowserSessionError, match=error):
        validate_browser_csrf(
            method="POST",
            supplied_token=csrf,
            expected_token="csrf-1",
            origin=origin,
            referer=None,
            fetch_site=fetch_site,
            allowed_origin="https://redagent.example.test",
        )


def test_safe_method_bypasses_csrf_but_active_session_enforces_idle_absolute_and_revocation() -> None:
    validate_browser_csrf(
        method="GET",
        supplied_token=None,
        expected_token="csrf-1",
        origin=None,
        referer=None,
        fetch_site=None,
        allowed_origin="https://redagent.example.test",
    )
    assert evaluate_session_lifetime(
        now=NOW,
        last_seen_at=NOW - timedelta(minutes=1),
        idle_expires_at=NOW + timedelta(minutes=4),
        absolute_expires_at=NOW + timedelta(hours=1),
        revoked_at=None,
    ) == "active"
    assert evaluate_session_lifetime(
        now=NOW,
        last_seen_at=NOW - timedelta(minutes=10),
        idle_expires_at=NOW,
        absolute_expires_at=NOW + timedelta(hours=1),
        revoked_at=None,
    ) == "idle_expired"
    assert evaluate_session_lifetime(
        now=NOW,
        last_seen_at=NOW,
        idle_expires_at=NOW + timedelta(minutes=5),
        absolute_expires_at=NOW,
        revoked_at=None,
    ) == "absolute_expired"
    assert evaluate_session_lifetime(
        now=NOW,
        last_seen_at=NOW,
        idle_expires_at=NOW + timedelta(minutes=5),
        absolute_expires_at=NOW + timedelta(hours=1),
        revoked_at=NOW,
    ) == "revoked"
