"""Loopback-only CLI transport for the bounded compat_123 internal API seam."""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import json
import ipaddress
from pathlib import Path
from typing import Callable, Mapping
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen
from uuid import uuid4


_STATUS_PATH = "/api/v1/internal/r123/status"
_QUALIFICATION_PATH = "/api/v1/internal/r123/qualification"
_ALLOWED_AUTH_HEADERS = frozenset({
    "Authorization",
    "Cookie",
    "X-RedAgent-Test-Subject",
    "X-RedAgent-Test-Tenant",
    "X-RedAgent-Test-Permissions",
})


@dataclass(frozen=True, slots=True)
class CampaignApiCall:
    method: str
    url: str
    headers: dict[str, str]
    payload: dict[str, object] | None


def build_cli_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Run the fixed R123 owned-loopback qualification or read its readiness status."
    )
    commands = parser.add_subparsers(dest="command", required=True)
    status = commands.add_parser("status", help="Read the closed R123 readiness projection.")
    _transport_arguments(status)
    qualify = commands.add_parser(
        "qualify",
        help="Start the sole server-owned owned-loopback qualification fixture.",
    )
    _transport_arguments(qualify)
    qualify.add_argument(
        "--objective",
        choices=("http_posture", "security_header_assertion"),
        required=True,
    )
    qualify.add_argument(
        "--corroborate",
        action="store_true",
        help="Request the one bounded corroboration successor when the strategy permits it.",
    )
    return parser


def build_status_call(
    *, api_base: str, auth_headers: Mapping[str, str]
) -> CampaignApiCall:
    base = _loopback_base(api_base)
    return CampaignApiCall(
        method="GET",
        url=base + _STATUS_PATH,
        headers=_validated_headers(auth_headers),
        payload=None,
    )


def build_qualification_call(
    *,
    api_base: str,
    auth_headers: Mapping[str, str],
    objective_kind: str,
    require_corroboration: bool,
    idempotency_factory: Callable[[], str] | None = None,
) -> CampaignApiCall:
    base = _loopback_base(api_base)
    if objective_kind not in {"http_posture", "security_header_assertion"}:
        raise ValueError("r123_cli_objective_invalid")
    if not isinstance(require_corroboration, bool):
        raise ValueError("r123_cli_corroboration_invalid")
    token = (idempotency_factory or (lambda: f"r123-cli-{uuid4().hex}"))()
    _bounded("r123_cli_idempotency", token, 200)
    headers = _validated_headers(auth_headers)
    headers.update({
        "Content-Type": "application/json",
        "Idempotency-Key": token,
        "X-RedAgent-Policy-Reference": "policy-r123-owned-loopback",
    })
    return CampaignApiCall(
        method="POST",
        url=base + _QUALIFICATION_PATH,
        headers=headers,
        payload={
            "fixture_id": "owned-loopback-http-first-slice",
            "objective_kind": objective_kind,
            "header_code": (
                "x-content-type-options"
                if objective_kind == "security_header_assertion"
                else None
            ),
            "require_corroboration": require_corroboration,
            "risk_profile": "tier1_passive",
        },
    )


def run_cli(workspace: Path, argv: list[str] | None = None) -> int:
    args = build_cli_parser().parse_args(argv)
    headers = load_auth_headers(workspace, Path(args.auth_header_file))
    call = (
        build_status_call(api_base=args.api_base, auth_headers=headers)
        if args.command == "status"
        else build_qualification_call(
            api_base=args.api_base,
            auth_headers=headers,
            objective_kind=args.objective,
            require_corroboration=args.corroborate,
        )
    )
    try:
        response = send_api_call(call)
    except (OSError, ValueError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 1
    print(json.dumps(response, sort_keys=True, separators=(",", ":")))
    return 0


def load_auth_headers(workspace: Path, path: Path) -> dict[str, str]:
    root = workspace.resolve()
    resolved = (path if path.is_absolute() else root / path).resolve()
    if not resolved.is_relative_to(root) or not resolved.is_file():
        raise ValueError("r123_cli_auth_header_file_invalid")
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("r123_cli_auth_header_file_invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("r123_cli_auth_headers_invalid")
    return _validated_headers(payload)


def send_api_call(call: CampaignApiCall) -> dict[str, object]:
    body = None
    if call.payload is not None:
        body = json.dumps(call.payload, sort_keys=True, separators=(",", ":")).encode()
    request = Request(call.url, data=body, headers=call.headers, method=call.method)
    try:
        with urlopen(request, timeout=10) as response:  # noqa: S310 - URL is loopback-validated.
            raw = response.read(256 * 1024 + 1)
    except HTTPError as exc:
        raw = exc.read(4097)
        raise ValueError(f"r123_cli_http_error:{exc.code}:{_safe_error(raw)}") from exc
    except URLError as exc:
        raise ValueError("r123_cli_api_unavailable") from exc
    if len(raw) > 256 * 1024:
        raise ValueError("r123_cli_response_too_large")
    try:
        payload = json.loads(raw)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("r123_cli_response_invalid") from exc
    if not isinstance(payload, dict):
        raise ValueError("r123_cli_response_invalid")
    return payload


def _transport_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--api-base", default="http://127.0.0.1:58000")
    parser.add_argument(
        "--auth-header-file",
        required=True,
        help="Repo-local JSON containing only the approved authentication headers.",
    )


def _loopback_base(value: str) -> str:
    if not isinstance(value, str) or len(value) > 300:
        raise ValueError("r123_cli_api_base_invalid")
    parsed = urlsplit(value)
    if parsed.scheme != "http" or parsed.username or parsed.password:
        raise ValueError("r123_cli_api_loopback_required")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("r123_cli_api_base_invalid")
    try:
        loopback = parsed.hostname == "localhost" or ipaddress.ip_address(
            str(parsed.hostname)
        ).is_loopback
    except ValueError:
        loopback = False
    if not loopback or parsed.port is None or not 1024 <= parsed.port <= 65535:
        raise ValueError("r123_cli_api_loopback_required")
    return f"http://{parsed.hostname}:{parsed.port}"


def _validated_headers(values: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(values, Mapping) or not values:
        raise ValueError("r123_cli_auth_headers_invalid")
    result: dict[str, str] = {}
    for name, value in values.items():
        if name not in _ALLOWED_AUTH_HEADERS:
            raise ValueError("r123_cli_auth_header_forbidden")
        _bounded("r123_cli_auth_header", value, 2000)
        if "\r" in value or "\n" in value:
            raise ValueError("r123_cli_auth_header_invalid")
        result[name] = value
    return result


def _bounded(name: str, value: object, maximum: int) -> None:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name}_invalid")


def _safe_error(raw: bytes) -> str:
    try:
        payload = json.loads(raw[:4096])
        code = payload.get("error", {}).get("code") if isinstance(payload, dict) else None
    except (UnicodeError, json.JSONDecodeError):
        code = None
    return str(code)[:100] if isinstance(code, str) else "request_failed"
