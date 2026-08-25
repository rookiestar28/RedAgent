"""Same-origin OIDC BFF routes and opaque-session request identity resolution."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import re
from typing import Awaitable, Callable, Protocol
from urllib.parse import parse_qs, urlencode, urlparse
from uuid import uuid4

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response

from redagent_platform.identity.authorization import ROLE_PERMISSIONS
from redagent_platform.identity.config import OidcProviderConfig
from redagent_platform.identity.protocol import (
    build_authorization_request,
    generate_login_material,
    validate_authorization_callback,
)
from redagent_platform.identity.repository import (
    IdentityPrincipal,
    IdentityRepository,
    ServicePrincipal,
)
from redagent_platform.identity.session_security import (
    SessionCipher,
    apply_session_cookie,
    create_session_material,
    validate_browser_csrf,
)
from redagent_platform.identity.tokens import validate_backchannel_logout_token, validate_id_token
from redagent_platform.persistence.repository import ControlPlaneRepository


TENANT_PATTERN = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
LOGIN_COOKIE = "__Host-redagent_login"
SESSION_COOKIE = "__Host-redagent_session"
CSRF_COOKIE = "__Host-redagent_csrf"


@dataclass(frozen=True)
class OidcProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    end_session_endpoint: str | None


class OidcTransport(Protocol):
    async def discover(self, config: OidcProviderConfig) -> OidcProviderMetadata: ...

    async def exchange_code(
        self,
        config: OidcProviderConfig,
        metadata: OidcProviderMetadata,
        *,
        code: str,
        code_verifier: str,
    ) -> dict[str, object]: ...

    async def jwks(
        self, config: OidcProviderConfig, metadata: OidcProviderMetadata
    ) -> dict[str, object]: ...


@dataclass(frozen=True)
class ResolvedRequestIdentity:
    principal: IdentityPrincipal | ServicePrincipal
    permissions: frozenset[str]

    @property
    def subject(self) -> str:
        if isinstance(self.principal, IdentityPrincipal):
            return self.principal.user_id
        return f"service:{self.principal.service_identity_id}"

    @property
    def tenant_id(self) -> str:
        return self.principal.tenant_id

    @property
    def is_browser(self) -> bool:
        return isinstance(self.principal, IdentityPrincipal)


class IdentityRuntime:
    def __init__(
        self,
        *,
        config: OidcProviderConfig,
        cipher: SessionCipher,
        transport: OidcTransport,
        public_origin: str,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        parsed = urlparse(public_origin)
        if parsed.scheme != "https" or not parsed.netloc or parsed.path or parsed.query or parsed.fragment:
            raise ValueError("identity_public_origin_invalid")
        if not config.redirect_uri.startswith(public_origin + "/"):
            raise ValueError("identity_redirect_origin_invalid")
        self.config = config
        self.cipher = cipher
        self.transport = transport
        self.public_origin = public_origin
        self._now = now or (lambda: datetime.now(timezone.utc))

    def install(self, app: FastAPI) -> None:
        @app.get("/auth/login", operation_id="identity_login")
        async def login(request: Request, tenant_id: str) -> Response:
            if not TENANT_PATTERN.fullmatch(tenant_id):
                return _error(400, "tenant_invalid")
            now = self._now()
            try:
                metadata = await self._metadata()
                material = generate_login_material(now=now, lifetime=timedelta(minutes=5))
                transaction_id = str(uuid4())
                factory = _session_factory(request)
                async with factory() as session, session.begin():
                    repo = IdentityRepository(
                        session,
                        tenant_id=tenant_id,
                        actor_user_id="oidc-login",
                        correlation_id=_correlation(request),
                    )
                    await repo.register_provider(
                        provider_id=self.config.provider_id,
                        issuer=self.config.issuer,
                        client_id=self.config.client_id,
                        occurred_at=now,
                    )
                    await repo.create_login_transaction(
                        transaction_id=transaction_id,
                        provider_id=self.config.provider_id,
                        state_hash=self.cipher.digest(material.state, purpose="oidc-state"),
                        nonce_hash=self.cipher.digest(material.nonce, purpose="oidc-nonce"),
                        nonce_ciphertext=_encode_bytes(
                            self.cipher.encrypt(material.nonce, purpose="oidc-nonce")
                        ),
                        verifier_ciphertext=_encode_bytes(
                            self.cipher.encrypt(material.code_verifier, purpose="oidc-login")
                        ),
                        redirect_uri=self.config.redirect_uri,
                        expires_at=material.expires_at,
                        occurred_at=now,
                    )
                location = build_authorization_request(
                    self.config,
                    authorization_endpoint=metadata.authorization_endpoint,
                    material=material,
                )
                response = RedirectResponse(location, status_code=302)
                _set_login_cookie(response, self._protect_context(tenant_id, transaction_id))
                return response
            except Exception:
                return _error(503, "identity_provider_unavailable")

        @app.get("/auth/callback", operation_id="identity_callback")
        async def callback(request: Request) -> Response:
            raw_context = request.cookies.get(LOGIN_COOKIE)
            params = _unique_query(request)
            if raw_context is None or params is None or not params.get("state"):
                return _error(400, "oidc_callback_rejected")
            try:
                tenant_id, transaction_id = self._unprotect_context(raw_context)
                now = self._now()
                factory = _session_factory(request)
                # CRITICAL: consume state in its own committed transaction before any provider call.
                async with factory() as session, session.begin():
                    transaction = await IdentityRepository(
                        session,
                        tenant_id=tenant_id,
                        actor_user_id="oidc-callback",
                        correlation_id=_correlation(request),
                    ).consume_login_transaction(
                        transaction_id=transaction_id,
                        state_hash=self.cipher.digest(params["state"], purpose="oidc-state"),
                        now=now,
                    )
                callback_value = validate_authorization_callback(
                    self.config,
                    params=params,
                    expected_state=params["state"],
                )
                if transaction.redirect_uri != self.config.redirect_uri:
                    raise ValueError("redirect mismatch")
                metadata = await self._metadata()
                verifier = self.cipher.decrypt(
                    _decode_bytes(transaction.verifier_ciphertext), purpose="oidc-login"
                )
                expected_nonce = self.cipher.decrypt(
                    _decode_bytes(transaction.nonce_ciphertext), purpose="oidc-nonce"
                )
                token_response = await self.transport.exchange_code(
                    self.config,
                    metadata,
                    code=callback_value.code,
                    code_verifier=verifier,
                )
                raw_id_token = token_response.get("id_token")
                if not isinstance(raw_id_token, str):
                    raise ValueError("id token missing")
                claims = validate_id_token(
                    raw_id_token,
                    jwks=await self.transport.jwks(self.config, metadata),
                    config=self.config,
                    expected_nonce=expected_nonce,
                    now=now,
                    access_token=(
                        token_response.get("access_token")
                        if isinstance(token_response.get("access_token"), str)
                        else None
                    ),
                    authorization_code=callback_value.code,
                )
                if claims.tenant_id != tenant_id:
                    raise ValueError("tenant claim mismatch")
                roles = _map_roles(claims.external_roles)
                user_id = _subject_id(tenant_id, claims.issuer, claims.subject)
                session_material = create_session_material(self.cipher, now=now)
                opaque_cookie = self._protect_context(tenant_id, session_material.session_handle)
                async with factory() as session, session.begin():
                    core = ControlPlaneRepository(
                        session,
                        tenant_id=tenant_id,
                        actor_user_id=user_id,
                        correlation_id=_correlation(request),
                    )
                    await core.bootstrap_user(
                        user_id=user_id,
                        subject=_subject_reference(claims.issuer, claims.subject),
                        occurred_at=now,
                    )
                    identity = IdentityRepository(
                        session,
                        tenant_id=tenant_id,
                        actor_user_id=user_id,
                        correlation_id=_correlation(request),
                    )
                    await identity.provision_membership(user_id=user_id, roles=roles, occurred_at=now)
                    await identity.create_session(
                        session_id=str(uuid4()),
                        provider_id=self.config.provider_id,
                        user_id=user_id,
                        handle_hash=self.cipher.digest(opaque_cookie, purpose="browser-session"),
                        csrf_hash=session_material.csrf_token_hash,
                        oidc_session_id=claims.oidc_session_id,
                        idle_expires_at=now + timedelta(minutes=30),
                        absolute_expires_at=now + timedelta(hours=8),
                        occurred_at=now,
                    )
                response = RedirectResponse("/", status_code=303)
                apply_session_cookie(response, opaque_cookie, max_age_seconds=8 * 60 * 60)
                response.set_cookie(
                    CSRF_COOKIE,
                    session_material.csrf_token,
                    max_age=8 * 60 * 60,
                    path="/",
                    secure=True,
                    httponly=False,
                    samesite="strict",
                )
                response.delete_cookie(LOGIN_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
                return response
            except Exception:
                return _error(400, "oidc_callback_rejected")

        @app.get("/auth/session", operation_id="identity_session")
        async def current_session(request: Request) -> Response:
            identity = await self.resolve_request(request)
            if identity is None or not isinstance(identity.principal, IdentityPrincipal):
                return _error(401, "session_invalid")
            return JSONResponse(
                {
                    "data": {
                        "authenticated": True,
                        "tenant_id": identity.principal.tenant_id,
                        "roles": list(identity.principal.roles),
                    }
                }
            )

        @app.post("/auth/logout", operation_id="identity_logout")
        async def logout(request: Request) -> Response:
            identity = await self.resolve_request(request)
            if identity is None or not isinstance(identity.principal, IdentityPrincipal):
                return _error(401, "session_invalid")
            try:
                self.enforce_csrf(request, identity)
            except Exception:
                return _error(403, "csrf_rejected")
            now = self._now()
            raw_cookie = request.cookies.get(SESSION_COOKIE, "")
            factory = _session_factory(request)
            async with factory() as session, session.begin():
                await IdentityRepository(
                    session,
                    tenant_id=identity.principal.tenant_id,
                    actor_user_id=identity.principal.user_id,
                    correlation_id=_correlation(request),
                ).revoke_browser_session(
                    handle_hash=self.cipher.digest(raw_cookie, purpose="browser-session"),
                    occurred_at=now,
                )
            location = self.config.post_logout_redirect_uri
            try:
                metadata = await self._metadata()
                if metadata.end_session_endpoint:
                    location = metadata.end_session_endpoint + "?" + urlencode(
                        {
                            "client_id": self.config.client_id,
                            "post_logout_redirect_uri": self.config.post_logout_redirect_uri,
                        }
                    )
            except Exception:
                pass
            response = RedirectResponse(location, status_code=303)
            response.delete_cookie(SESSION_COOKIE, path="/", secure=True, httponly=True, samesite="lax")
            response.delete_cookie(CSRF_COOKIE, path="/", secure=True, samesite="strict")
            return response

        @app.post("/auth/backchannel-logout/{tenant_id}", operation_id="identity_backchannel_logout")
        async def backchannel_logout(tenant_id: str, request: Request) -> Response:
            if not TENANT_PATTERN.fullmatch(tenant_id):
                return _error(400, "logout_token_rejected")
            body = await request.body()
            if len(body) > 20_000:
                return _error(400, "logout_token_rejected")
            values = parse_qs(body.decode("ascii", errors="ignore"), strict_parsing=True)
            if set(values) != {"logout_token"} or len(values["logout_token"]) != 1:
                return _error(400, "logout_token_rejected")
            try:
                metadata = await self._metadata()
                claims = validate_backchannel_logout_token(
                    values["logout_token"][0],
                    jwks=await self.transport.jwks(self.config, metadata),
                    config=self.config,
                    now=self._now(),
                )
                if claims.oidc_session_id is None:
                    raise ValueError("subject-only logout unsupported")
                factory = _session_factory(request)
                async with factory() as session, session.begin():
                    repo = IdentityRepository(
                        session,
                        tenant_id=tenant_id,
                        actor_user_id="oidc-backchannel",
                        correlation_id=_correlation(request),
                    )
                    await repo.consume_replay(
                        replay_type="logout_jti",
                        replay_key_hash=self.cipher.digest(claims.jti, purpose="logout-jti"),
                        expires_at=self._now() + timedelta(minutes=10),
                        occurred_at=self._now(),
                    )
                    await repo.revoke_sessions_for_oidc_session(
                        provider_id=self.config.provider_id,
                        oidc_session_id=claims.oidc_session_id,
                        occurred_at=self._now(),
                    )
                return Response(status_code=204)
            except Exception:
                return _error(400, "logout_token_rejected")

        @app.get("/auth/frontchannel-logout/{tenant_id}", operation_id="identity_frontchannel_logout")
        async def frontchannel_logout(tenant_id: str, request: Request, iss: str, sid: str) -> Response:
            if not TENANT_PATTERN.fullmatch(tenant_id) or iss != self.config.issuer or not sid or len(sid) > 200:
                return _error(400, "frontchannel_logout_rejected")
            try:
                factory = _session_factory(request)
                async with factory() as session, session.begin():
                    await IdentityRepository(
                        session,
                        tenant_id=tenant_id,
                        actor_user_id="oidc-frontchannel",
                        correlation_id=_correlation(request),
                    ).revoke_sessions_for_oidc_session(
                        provider_id=self.config.provider_id,
                        oidc_session_id=sid,
                        occurred_at=self._now(),
                    )
                return Response(status_code=204)
            except Exception:
                return _error(400, "frontchannel_logout_rejected")

    async def resolve_request(self, request: Request) -> ResolvedRequestIdentity | None:
        raw_cookie = request.cookies.get(SESSION_COOKIE)
        if not raw_cookie:
            return await self._resolve_service_request(request)
        try:
            tenant_id, _ = self._unprotect_context(raw_cookie)
            factory = _session_factory(request)
            async with factory() as session, session.begin():
                principal = await IdentityRepository(
                    session,
                    tenant_id=tenant_id,
                    actor_user_id="session-resolver",
                    correlation_id=_correlation(request),
                ).resolve_browser_session(
                    handle_hash=self.cipher.digest(raw_cookie, purpose="browser-session"),
                    now=self._now(),
                )
            if principal is None:
                return None
            permissions = frozenset().union(*(ROLE_PERMISSIONS[role] for role in principal.roles))
            return ResolvedRequestIdentity(principal=principal, permissions=permissions)
        except Exception:
            return None

    async def _resolve_service_request(self, request: Request) -> ResolvedRequestIdentity | None:
        tenant_id = request.headers.get("X-RedAgent-Service-Tenant")
        client_id = request.headers.get("X-RedAgent-Service-Client")
        supplied_secret = request.headers.get("X-RedAgent-Service-Secret")
        if tenant_id is None and client_id is None and supplied_secret is None:
            return None
        if (
            tenant_id is None
            or client_id is None
            or supplied_secret is None
            or not TENANT_PATTERN.fullmatch(tenant_id)
            or not client_id
            or len(client_id) > 200
            or not supplied_secret
            or len(supplied_secret) > 512
        ):
            return None
        try:
            secret_hash = self.service_secret_hash(
                tenant_id=tenant_id, client_id=client_id, secret=supplied_secret
            )
            factory = _session_factory(request)
            async with factory() as session, session.begin():
                principal = await IdentityRepository(
                    session,
                    tenant_id=tenant_id,
                    actor_user_id="service-resolver",
                    correlation_id=_correlation(request),
                ).resolve_service_identity(client_id=client_id, secret_hash=secret_hash, now=self._now())
            if principal is None:
                return None
            permissions = frozenset().union(*(ROLE_PERMISSIONS[role] for role in principal.roles))
            return ResolvedRequestIdentity(principal=principal, permissions=permissions)
        except Exception:
            return None

    def service_secret_hash(self, *, tenant_id: str, client_id: str, secret: str) -> str:
        if (
            not TENANT_PATTERN.fullmatch(tenant_id)
            or not client_id
            or len(client_id) > 200
            or not secret
            or len(secret) > 512
        ):
            raise ValueError("service_identity_credential_invalid")
        return self.cipher.digest(secret, purpose=f"service-identity:{tenant_id}:{client_id}")

    def enforce_csrf(self, request: Request, identity: ResolvedRequestIdentity) -> None:
        if not isinstance(identity.principal, IdentityPrincipal):
            raise ValueError("browser_identity_required")
        supplied = request.headers.get("X-CSRF-Token")
        if supplied is None or not hmac.compare_digest(
            self.cipher.digest(supplied, purpose="browser-csrf"), identity.principal.csrf_hash
        ):
            raise ValueError("csrf token invalid")
        validate_browser_csrf(
            method=request.method,
            supplied_token=supplied,
            expected_token=supplied,
            origin=request.headers.get("Origin"),
            referer=request.headers.get("Referer"),
            fetch_site=request.headers.get("Sec-Fetch-Site"),
            allowed_origin=self.public_origin,
        )

    async def _metadata(self) -> OidcProviderMetadata:
        metadata = await self.transport.discover(self.config)
        if metadata.issuer != self.config.issuer:
            raise ValueError("issuer mismatch")
        for endpoint in (
            metadata.authorization_endpoint,
            metadata.token_endpoint,
            metadata.jwks_uri,
            metadata.end_session_endpoint,
        ):
            if endpoint is not None:
                _provider_endpoint(self.config, endpoint)
        return metadata

    def _protect_context(self, tenant_id: str, value: str) -> str:
        if not TENANT_PATTERN.fullmatch(tenant_id) or "|" in value or not value:
            raise ValueError("identity_context_invalid")
        return _encode_bytes(self.cipher.encrypt(f"{tenant_id}|{value}", purpose="identity-context"))

    def _unprotect_context(self, value: str) -> tuple[str, str]:
        decoded = self.cipher.decrypt(_decode_bytes(value), purpose="identity-context")
        tenant_id, separator, context_value = decoded.partition("|")
        if separator != "|" or not TENANT_PATTERN.fullmatch(tenant_id) or not context_value:
            raise ValueError("identity_context_invalid")
        return tenant_id, context_value


def _map_roles(external_roles: tuple[str, ...]) -> tuple[str, ...]:
    mapped = tuple(sorted({role.removeprefix("redagent-") for role in external_roles if role.startswith("redagent-")}))
    if not mapped or any(role not in ROLE_PERMISSIONS for role in mapped):
        raise ValueError("identity_role_mapping_invalid")
    return mapped


def _subject_id(tenant_id: str, issuer: str, subject: str) -> str:
    return "oidc-" + hashlib.sha256(
        f"{tenant_id}\x1f{issuer}\x1f{subject}".encode("utf-8")
    ).hexdigest()[:40]


def _subject_reference(issuer: str, subject: str) -> str:
    return "oidc:" + hashlib.sha256(f"{issuer}\x1f{subject}".encode("utf-8")).hexdigest()


def _provider_endpoint(config: OidcProviderConfig, value: str) -> None:
    endpoint = urlparse(value)
    issuer = urlparse(config.issuer)
    if (
        endpoint.scheme != issuer.scheme
        or endpoint.netloc != issuer.netloc
        or endpoint.username
        or endpoint.password
        or endpoint.fragment
    ):
        raise ValueError("provider endpoint invalid")


def _session_factory(request: Request):
    factory = request.app.state.session_factory
    if factory is None:
        raise RuntimeError("database unavailable")
    return factory


def _correlation(request: Request) -> str:
    return str(getattr(request.state, "correlation_id", uuid4()))


def _unique_query(request: Request) -> dict[str, str] | None:
    result: dict[str, str] = {}
    for key, value in request.query_params.multi_items():
        if key in result:
            return None
        result[key] = value
    return result


def _set_login_cookie(response: Response, value: str) -> None:
    response.set_cookie(
        LOGIN_COOKIE,
        value,
        max_age=300,
        path="/",
        secure=True,
        httponly=True,
        samesite="lax",
    )


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _decode_bytes(value: str) -> bytes:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise ValueError("encoded_value_invalid")
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _error(status_code: int, code: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": "The identity operation was rejected."}},
    )
