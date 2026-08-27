"""compat_093 FastAPI control plane with fail-closed guards and relational transactions."""

from __future__ import annotations

from dataclasses import dataclass
import re
from typing import (
    Awaitable,
    Callable,
)


SAFE_CONTEXT_VALUE = re.compile(r"^[A-Za-z0-9._:/-]+$")


@dataclass(frozen=True)
class SecurityContext:
    subject: str
    tenant_id: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class AuthorizationDecision:
    permission: str
    object_id: str | None
    allowed: bool


@dataclass(frozen=True)
class RequestGuard:
    security: SecurityContext
    decision: AuthorizationDecision
    policy_reference: str
    roe_version_id: str | None
    correlation_id: str
    audit_intent: str
    idempotency_key: str | None


AuthorizationHook = Callable[[SecurityContext, str, str | None], bool | Awaitable[bool]]


R123ApiServiceFactory = Callable[..., object | Awaitable[object]]


class ApiError(RuntimeError):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(code)
        self.status_code = status_code
        self.code = code
        self.message = message


def _valid_context_value(value: str, maximum: int) -> bool:
    return bool(value and len(value) <= maximum and SAFE_CONTEXT_VALUE.fullmatch(value))
