"""Opaque browser-session key, cookie, CSRF, and lifetime primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import hashlib
import hmac
from pathlib import Path
import secrets
from urllib.parse import urlparse

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from starlette.responses import Response


class BrowserSessionError(ValueError):
    """Raised when browser-session state or request context fails closed."""


@dataclass(frozen=True)
class SessionMaterial:
    session_handle: str = field(repr=False)
    session_handle_hash: str
    csrf_token: str = field(repr=False)
    csrf_token_hash: str
    created_at: datetime


class SessionCipher:
    def __init__(self, key: bytes) -> None:
        if len(key) != 32:
            raise BrowserSessionError("session_key_length_invalid")
        self._key = key
        self._aead = AESGCM(key)

    @classmethod
    def load(cls, workspace: Path, path: Path) -> "SessionCipher":
        root = workspace.resolve()
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            raise BrowserSessionError("session_key_outside_workspace")
        try:
            key = resolved.read_bytes()
        except OSError as exc:
            raise BrowserSessionError("session_key_load_failed") from exc
        return cls(key)

    def digest(self, value: str, *, purpose: str) -> str:
        return hmac.new(self._key, f"{purpose}\x1f{value}".encode("utf-8"), hashlib.sha256).hexdigest()

    def encrypt(self, value: str, *, purpose: str) -> bytes:
        nonce = secrets.token_bytes(12)
        ciphertext = self._aead.encrypt(nonce, value.encode("utf-8"), purpose.encode("utf-8"))
        return nonce + ciphertext

    def decrypt(self, value: bytes, *, purpose: str) -> str:
        if len(value) < 29:
            raise BrowserSessionError("session_ciphertext_invalid")
        try:
            return self._aead.decrypt(value[:12], value[12:], purpose.encode("utf-8")).decode("utf-8")
        except Exception as exc:
            raise BrowserSessionError("session_ciphertext_invalid") from exc


def create_session_material(cipher: SessionCipher, *, now: datetime) -> SessionMaterial:
    _aware(now)
    handle = secrets.token_urlsafe(32)
    csrf = secrets.token_urlsafe(32)
    return SessionMaterial(
        session_handle=handle,
        session_handle_hash=cipher.digest(handle, purpose="browser-session"),
        csrf_token=csrf,
        csrf_token_hash=cipher.digest(csrf, purpose="browser-csrf"),
        created_at=now,
    )


def apply_session_cookie(response: Response, handle: str, *, max_age_seconds: int) -> None:
    if not handle or not 60 <= max_age_seconds <= 86_400:
        raise BrowserSessionError("session_cookie_invalid")
    response.set_cookie(
        "__Host-redagent_session",
        handle,
        max_age=max_age_seconds,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def validate_browser_csrf(
    *,
    method: str,
    supplied_token: str | None,
    expected_token: str,
    origin: str | None,
    referer: str | None,
    fetch_site: str | None,
    allowed_origin: str,
) -> None:
    if method.upper() in {"GET", "HEAD", "OPTIONS"}:
        return
    if supplied_token is None:
        raise BrowserSessionError("csrf_token_required")
    if not hmac.compare_digest(supplied_token, expected_token):
        raise BrowserSessionError("csrf_token_invalid")
    request_origin = origin or _referer_origin(referer)
    if request_origin is None:
        raise BrowserSessionError("csrf_origin_required")
    if request_origin != allowed_origin:
        raise BrowserSessionError("csrf_origin_invalid")
    if fetch_site != "same-origin":
        raise BrowserSessionError("csrf_fetch_site_invalid")


def evaluate_session_lifetime(
    *,
    now: datetime,
    last_seen_at: datetime,
    idle_expires_at: datetime,
    absolute_expires_at: datetime,
    revoked_at: datetime | None,
) -> str:
    for value in (now, last_seen_at, idle_expires_at, absolute_expires_at):
        _aware(value)
    if revoked_at is not None:
        _aware(revoked_at)
        return "revoked"
    if now >= absolute_expires_at:
        return "absolute_expired"
    if now >= idle_expires_at:
        return "idle_expired"
    return "active"


def _referer_origin(referer: str | None) -> str | None:
    if not referer:
        return None
    parsed = urlparse(referer)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return None
    return f"{parsed.scheme}://{parsed.netloc}"


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise BrowserSessionError("session_timezone_required")
