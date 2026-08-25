#!/usr/bin/env python3
"""Controlled authorized web-assessment runner.

This runner intentionally uses only Python standard library networking and exposes
no arbitrary command execution, scanner, payload, fuzzing, authentication, or form
submission path.
"""

from __future__ import annotations

import html.parser
import http.client
import hashlib
import json
import math
import os
import re
import socket
import ssl
import stat
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote, urljoin, urlparse, urlunparse


LEXICAL_REPO_ROOT = Path(__file__).absolute().parents[1]
REPO_ROOT = LEXICAL_REPO_ROOT.resolve()
RUN_ROOT = REPO_ROOT / ".tmp" / "assessments"
REPORT_ROOT = REPO_ROOT / "reports" / "assessments"
MAX_CONFIG_BYTES = 64 * 1024
MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_TARGETS = 10
MAX_REQUEST_SECONDS = 10.0
MAX_UNEXPECTED_5XX = 2
STATIC_EVIDENCE_PATHS = frozenset(
    {
        "/",
        "/robots.txt",
        "/.well-known/security.txt",
        "/sitemap.xml",
    }
)
CONFIG_KEYS = frozenset(
    {
        "run_id",
        "mode",
        "execution_intent",
        "targets",
        "window_start",
        "window_end",
        "authorization_label",
        "max_interactions",
        "min_delay_seconds",
        "directory_dictionary",
        "output_dir",
        "report_path",
        "summary_path",
        "user_agent",
    }
)
SENSITIVE_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authenticate",
        "proxy-authorization",
        "set-cookie",
        "set-cookie2",
        "www-authenticate",
    }
)
PERSISTED_HEADER_NAMES = SENSITIVE_HEADERS | frozenset(
    {
        "cache-control",
        "content-length",
        "content-location",
        "content-security-policy",
        "content-security-policy-report-only",
        "content-type",
        "cross-origin-opener-policy",
        "cross-origin-resource-policy",
        "date",
        "location",
        "permissions-policy",
        "referrer-policy",
        "server",
        "strict-transport-security",
        "vary",
        "x-content-type-options",
        "x-frame-options",
    }
)
SECURITY_TXT_FIELDS = frozenset(
    {
        "acknowledgments",
        "canonical",
        "contact",
        "encryption",
        "expires",
        "hiring",
        "policy",
        "preferred-languages",
    }
)
SENSITIVE_BODY_PATTERNS = (
    re.compile(br"-----BEGIN " + br"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(br"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(br"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    re.compile(br"\bsk-[A-Za-z0-9_-]{20,}\b"),
    re.compile(br"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"),
)


class SafetyError(RuntimeError):
    """Raised when the requested assessment would exceed the approved scope."""


def parse_time(value: str) -> datetime:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise SafetyError("time value must be a bounded string")
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise SafetyError("time value is not valid ISO-8601") from error
    if parsed.tzinfo is None:
        raise SafetyError("time value must include timezone offset")
    return parsed


def normalize_host(value: str) -> str:
    raw = value.strip().lower()
    if "://" in raw:
        parsed = urlparse(raw)
        raw = parsed.hostname or ""
    if not re.fullmatch(r"[a-z0-9.-]{1,253}", raw):
        raise SafetyError(f"invalid hostname: {value}")
    if raw.startswith(".") or raw.endswith(".") or ".." in raw:
        raise SafetyError(f"invalid hostname: {value}")
    return raw


def validate_dictionary_path(value: str) -> str:
    if not isinstance(value, str):
        raise SafetyError("dictionary path must be a string")
    if not re.fullmatch(r"/[A-Za-z0-9._~/-]{1,80}", value):
        raise SafetyError(f"invalid dictionary path: {value}")
    if "//" in value or "/../" in value or value.endswith("/.."):
        raise SafetyError(f"invalid dictionary path traversal: {value}")
    if any(segment in {".", ".."} for segment in value.split("/")):
        raise SafetyError(f"dictionary path cannot contain dot segments: {value}")
    return value


def sanitize_name(value: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9]+", "_", value).strip("_")
    return safe[:100] or "artifact"


def validate_identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise SafetyError(f"{label} must use the approved identifier grammar")
    return value


def validate_user_agent(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[\x20-\x7e]{1,128}", value):
        raise SafetyError("user_agent must be 1-128 printable ASCII characters")
    if value != value.strip():
        raise SafetyError("user_agent cannot have leading or trailing whitespace")
    return value


def validate_int(value: Any, label: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SafetyError(f"{label} must be an integer")
    if value < minimum or value > maximum:
        raise SafetyError(f"{label} must be between {minimum} and {maximum}")
    return value


def validate_delay(value: Any) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise SafetyError("min_delay_seconds must be numeric")
    delay = float(value)
    if not math.isfinite(delay) or delay < 1 or delay > 60:
        raise SafetyError("min_delay_seconds must be finite and between 1 and 60")
    return delay


def resolve_path(value: Any, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SafetyError(f"{label} must be a non-empty path string")
    try:
        return Path(value).resolve()
    except (OSError, RuntimeError, ValueError) as error:
        raise SafetyError(f"{label} could not be resolved") from error


def is_reparse_path(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    if callable(is_junction) and is_junction():
        return True
    try:
        attributes = getattr(path.lstat(), "st_file_attributes", 0)
    except OSError:
        return False
    return bool(attributes & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0))


def canonical_repo_root() -> Path:
    lexical = Path(os.path.abspath(LEXICAL_REPO_ROOT))
    current = Path(lexical.anchor)
    for component in lexical.parts[1:]:
        current /= component
        if current.exists() and is_reparse_path(current):
            raise SafetyError("repository root traverses a symlink or reparse point")
    try:
        return lexical.resolve()
    except (OSError, RuntimeError) as error:
        raise SafetyError("repository root could not be resolved") from error


def ensure_repo_path(path: Path, label: str) -> Path:
    repo_root = canonical_repo_root()
    lexical = Path(os.path.abspath(path))
    try:
        relative = lexical.relative_to(repo_root)
    except ValueError as error:
        raise SafetyError(f"{label} is outside the repository") from error
    current = repo_root
    for component in relative.parts:
        current /= component
        if current.exists() and is_reparse_path(current):
            raise SafetyError(f"{label} traverses a symlink or reparse point")
    try:
        resolved = lexical.resolve()
        resolved.relative_to(repo_root)
    except (OSError, RuntimeError, ValueError) as error:
        raise SafetyError(f"{label} could not be contained in the repository") from error
    return resolved


def ensure_exact_path(value: Any, expected: Path, label: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise SafetyError(f"{label} must be a non-empty path string")
    resolved = ensure_repo_path(Path(value), label)
    expected_resolved = ensure_repo_path(expected, f"expected {label}")
    if resolved != expected_resolved:
        raise SafetyError(f"{label} is outside the fixed repository path")
    return resolved


def safe_text(value: Any, maximum: int = 240) -> str:
    text = str(value)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", text)
    text = " ".join(text.split())
    text = "".join(character for character in text if character.isprintable())
    return text.replace("`", "'").replace("|", "/")[:maximum]


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise SafetyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def reject_non_finite(value: str) -> Any:
    raise SafetyError(f"non-finite JSON value is prohibited: {value}")


def request_url_without_query(url: str) -> str:
    parsed = urlparse(url)
    host = normalize_host(parsed.hostname or "")
    path = quote(parsed.path or "/", safe="/%:@-._~!$&'()*+,;=")
    return urlunparse(("https", host, path, "", "", ""))


def sanitized_evidence_url(url: str) -> str:
    parsed = urlparse(url)
    host = normalize_host(parsed.hostname or "")
    path = parsed.path or "/"
    evidence_path = path if path in STATIC_EVIDENCE_PATHS else "/{path-redacted}"
    return urlunparse(("https", host, evidence_path, "", "", ""))


def has_safe_discretionary_path(url: str) -> bool:
    path = urlparse(url).path or "/"
    if "\\" in path or "%" in path or "//" in path:
        return False
    if any(segment in {".", ".."} for segment in path.split("/")):
        return False
    return bool(re.fullmatch(r"/[A-Za-z0-9._~!$&'()*+,;=:@/-]*", path))


def has_safe_robots_rule(value: str) -> bool:
    if (
        not value.startswith("/")
        or len(value) > 256
        or "%" in value
        or "\\" in value
        or "//" in value
        or not re.fullmatch(r"[\x21-\x7e]+", value)
    ):
        return False
    rule_without_anchor = value[:-1] if value.endswith("$") else value
    path = rule_without_anchor.split("?", 1)[0]
    return not any(segment in {".", ".."} for segment in path.split("/"))


def contains_high_confidence_sensitive_material(body: bytes) -> bool:
    return any(pattern.search(body) for pattern in SENSITIVE_BODY_PATTERNS)


class LinkParser(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        values = dict(attrs)
        href = values.get("href")
        if href:
            self.links.append(href)


@dataclass
class HttpObservation:
    method: str
    url: str
    status: int
    reason: str
    artifact: str
    headers: dict[str, str] = field(default_factory=dict)
    body_artifact: str | None = None
    body_bytes: int = 0
    body_sha256: str | None = None
    elapsed_ms: float = 0.0
    body: bytes = field(default=b"", repr=False, compare=False)

    def evidence(self) -> dict[str, Any]:
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "reason": self.reason,
            "artifact": self.artifact,
            "headers": self.headers,
            "body_artifact": self.body_artifact,
            "body_bytes": self.body_bytes,
            "body_sha256": self.body_sha256,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass
class Runner:
    config: dict[str, Any]
    allowed_hosts: set[str]
    output_dir: Path
    artifacts_dir: Path
    count: int = 0
    observations: dict[str, Any] = field(default_factory=dict)
    config_sha256: str = ""
    unexpected_5xx: int = 0
    robots_disallow: dict[str, list[str]] = field(default_factory=dict, repr=False)

    @classmethod
    def from_config(cls, config: dict[str, Any]) -> "Runner":
        if not isinstance(config, dict):
            raise SafetyError("config must be a JSON object")
        unknown = set(config) - CONFIG_KEYS
        missing = CONFIG_KEYS - set(config)
        if unknown or missing:
            raise SafetyError("config keys do not match the fixed runner contract")

        run_id = validate_identifier(config["run_id"], "run_id")
        authorization_label = validate_identifier(config["authorization_label"], "authorization_label")
        mode = config["mode"]
        if mode not in {"passive", "progressive"}:
            raise SafetyError("mode must be passive or progressive")
        execution_intent = config["execution_intent"]
        if execution_intent not in {"execute", "validate_only"}:
            raise SafetyError("execution_intent must be execute or validate_only")

        targets = config["targets"]
        if not isinstance(targets, list) or not targets or len(targets) > MAX_TARGETS:
            raise SafetyError("targets must be a non-empty list")
        if any(not isinstance(target, str) for target in targets):
            raise SafetyError("every target must be a hostname string")
        if any(
            target != target.strip().lower()
            or not re.fullmatch(r"[a-z0-9.-]{1,253}", target)
            for target in targets
        ):
            raise SafetyError("every target must already be a canonical hostname")
        allowed_hosts = {normalize_host(target) for target in targets}
        if len(allowed_hosts) != len(targets):
            raise SafetyError("targets must be unique after normalization")

        start = parse_time(config["window_start"])
        end = parse_time(config["window_end"])
        if end <= start:
            raise SafetyError("window_end must be later than window_start")
        max_interactions = validate_int(config["max_interactions"], "max_interactions", 1, 500)
        min_delay_seconds = validate_delay(config["min_delay_seconds"])
        user_agent = validate_user_agent(config["user_agent"])

        dictionary = config["directory_dictionary"]
        if not isinstance(dictionary, list) or len(dictionary) > 20:
            raise SafetyError("directory_dictionary must be a list with at most 20 entries")
        validated_dictionary = [validate_dictionary_path(entry) for entry in dictionary]
        if len(set(validated_dictionary)) != len(validated_dictionary):
            raise SafetyError("directory_dictionary entries must be unique")

        run_root = ensure_repo_path(RUN_ROOT, "run root")
        report_root = ensure_repo_path(REPORT_ROOT, "report root")
        expected_output = run_root / run_id
        output_dir = ensure_exact_path(config["output_dir"], expected_output, "output_dir")
        summary_path = ensure_exact_path(
            config["summary_path"],
            output_dir / "summary.json",
            "summary_path",
        )
        report_path = ensure_exact_path(
            config["report_path"],
            report_root / f"{run_id}-report.md",
            "report_path",
        )
        artifacts_dir = output_dir / "artifacts"
        ensure_repo_path(artifacts_dir, "artifact directory")

        # CRITICAL: validate every network and filesystem boundary before creating evidence paths.
        if summary_path.exists() or report_path.exists():
            raise SafetyError("run evidence already exists; refusing to overwrite")
        if artifacts_dir.exists() and any(artifacts_dir.iterdir()):
            raise SafetyError("artifact directory is not empty; refusing to mix runs")
        artifacts_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir = ensure_repo_path(artifacts_dir, "artifact directory")
        normalized = dict(config)
        normalized.update(
            {
                "run_id": run_id,
                "mode": mode,
                "execution_intent": execution_intent,
                "targets": sorted(allowed_hosts),
                "authorization_label": authorization_label,
                "max_interactions": max_interactions,
                "min_delay_seconds": min_delay_seconds,
                "directory_dictionary": validated_dictionary,
                "output_dir": str(output_dir),
                "summary_path": str(summary_path),
                "report_path": str(report_path),
                "user_agent": user_agent,
            }
        )
        return cls(
            config=normalized,
            allowed_hosts=allowed_hosts,
            output_dir=output_dir,
            artifacts_dir=artifacts_dir,
            observations={
                "tls": [],
                "http": [],
                "robots": {},
                "security_txt": {},
                "sitemaps": [],
                "crawl": [],
                "directory": [],
                "fingerprint": [],
                "review_notes": [],
            },
        )

    @classmethod
    def from_config_path(
        cls,
        value: str | Path,
        expected_sha256: str,
        expected_intent: str,
    ) -> "Runner":
        if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
            raise SafetyError("expected config digest must be lowercase SHA-256")
        if expected_intent not in {"execute", "validate_only"}:
            raise SafetyError("expected execution intent is invalid")
        original_path = Path(value)
        if original_path.is_symlink():
            raise SafetyError("config path cannot be a symlink")
        config_path = ensure_repo_path(original_path, "config path")
        run_root = ensure_repo_path(RUN_ROOT, "run root")
        try:
            relative = config_path.relative_to(run_root)
        except ValueError as error:
            raise SafetyError("config path is outside the fixed run root") from error
        if len(relative.parts) != 2 or relative.name != "config.json":
            raise SafetyError("config path must be RUN_ROOT/<run_id>/config.json")
        try:
            with config_path.open("rb") as handle:
                raw = handle.read(MAX_CONFIG_BYTES + 1)
            if len(raw) < 2 or len(raw) > MAX_CONFIG_BYTES:
                raise SafetyError("config file size is outside the approved bound")
            consumed_sha256 = hashlib.sha256(raw).hexdigest()
            if consumed_sha256 != expected_sha256:
                raise SafetyError("config digest does not match the wrapper record")
            config = json.loads(
                raw.decode("utf-8-sig"),
                object_pairs_hook=reject_duplicate_keys,
                parse_constant=reject_non_finite,
            )
        except SafetyError:
            raise
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SafetyError("config file is not strict UTF-8 JSON") from error
        if not isinstance(config, dict):
            raise SafetyError("config must be a JSON object")
        run_id = validate_identifier(config.get("run_id"), "run_id")
        if config_path.parent != run_root / run_id:
            raise SafetyError("config path does not match run_id before filesystem creation")
        if config.get("execution_intent") != expected_intent:
            raise SafetyError("config execution intent does not match the CLI mode")
        runner = cls.from_config(config)
        runner.config_sha256 = consumed_sha256
        return runner

    @property
    def max_interactions(self) -> int:
        return int(self.config.get("max_interactions", 50))

    @property
    def min_delay_seconds(self) -> float:
        return float(self.config.get("min_delay_seconds", 1))

    @property
    def user_agent(self) -> str:
        return str(self.config.get("user_agent", "RedAgentAuthorizedAutomation/0.1"))

    def log(self, message: str = "") -> None:
        print(message, flush=True)

    def check_window(self) -> None:
        start = parse_time(str(self.config["window_start"]))
        end = parse_time(str(self.config["window_end"]))
        now = datetime.now(start.tzinfo)
        if now < start or now > end:
            raise SafetyError(
                f"current time {now.isoformat()} is outside approved window "
                f"{start.isoformat()} - {end.isoformat()}"
            )

    def interaction(self, label: str) -> None:
        if self.config.get("execution_intent") != "execute":
            raise SafetyError("validate-only config cannot perform target interactions")
        self.check_window()
        if self.count >= self.max_interactions:
            raise SafetyError("request cap reached before the next interaction")
        self.count += 1
        self.log()
        self.log(f"[{self.count}/{self.max_interactions}] {safe_text(label)}")

    def delay(self) -> None:
        if self.min_delay_seconds > 0:
            time.sleep(self.min_delay_seconds)

    def assert_allowed_url(self, url: str) -> str:
        if not isinstance(url, str) or not url or len(url) > 2048:
            raise SafetyError("URL must be a bounded string")
        if any(ord(character) < 0x20 or ord(character) == 0x7F for character in url):
            raise SafetyError("URL contains prohibited control characters")
        parsed = urlparse(url)
        if parsed.scheme.lower() != "https":
            raise SafetyError("blocked non-HTTPS URL")
        if parsed.username is not None or parsed.password is not None:
            raise SafetyError("blocked URL userinfo")
        try:
            port = parsed.port
        except ValueError as error:
            raise SafetyError("blocked malformed URL port") from error
        if port not in {None, 443}:
            raise SafetyError("blocked non-default HTTPS port")
        host = normalize_host(parsed.hostname or "")
        if host not in self.allowed_hosts:
            raise SafetyError(f"blocked out-of-scope host: {host}")
        return host

    def sanitize_headers(
        self,
        headers: list[tuple[str, str]],
        request_url: str,
    ) -> dict[str, str]:
        sanitized: dict[str, str] = {}
        for raw_name, raw_value in headers:
            name = raw_name.strip().lower()
            if not re.fullmatch(r"[a-z0-9!#$%&'*+.^_`|~-]{1,128}", name):
                continue
            if name not in PERSISTED_HEADER_NAMES:
                continue
            if name in SENSITIVE_HEADERS:
                sanitized[name] = "<redacted>"
            elif name in {"location", "content-location"}:
                resolved = urljoin(request_url, raw_value)
                try:
                    self.assert_allowed_url(resolved)
                except SafetyError:
                    sanitized[name] = "<blocked>"
                else:
                    sanitized[name] = sanitized_evidence_url(resolved)
            else:
                # IMPORTANT: retain header presence, not target-controlled values that may contain secrets.
                sanitized[name] = "<present>"
        return sanitized

    def artifact_path(self, name: str) -> tuple[Path, str]:
        purpose_digest = hashlib.sha256(name.encode("utf-8", errors="replace")).hexdigest()[:12]
        stem = f"http_{self.count:03d}_{purpose_digest}"
        header_relative = Path("artifacts") / f"{stem}.headers.txt"
        header_absolute = self.output_dir / header_relative
        return header_absolute, header_relative.as_posix()

    def response_stop_reason(
        self,
        status: int,
        raw_headers: list[tuple[str, str]],
        raw_body: bytes,
        elapsed_seconds: float,
    ) -> str | None:
        header_challenge = any(
            key.lower() in {"cf-mitigated", "x-sucuri-block", "x-waf-action"}
            and "challenge" in value.lower()
            for key, value in raw_headers
        )
        body_prefix = raw_body[:64_000].lower()
        body_challenge = any(
            marker in body_prefix
            for marker in (
                b"cf-chl-",
                b"challenge-platform",
                b"captcha",
                b"<title>just a moment",
            )
        )
        if status in {401, 403}:
            return "access denial"
        if status == 429:
            return "rate limit"
        if header_challenge or body_challenge:
            return "WAF challenge"
        if 500 <= status <= 599:
            self.unexpected_5xx += 1
            if self.unexpected_5xx >= MAX_UNEXPECTED_5XX:
                return "second unexpected 5xx"
        if elapsed_seconds > MAX_REQUEST_SECONDS:
            return "material request latency"
        return None

    def request(
        self,
        method: str,
        url: str,
        name: str,
        max_body_bytes: int = 0,
    ) -> HttpObservation:
        method = method.upper()
        if method not in {"GET", "HEAD"}:
            raise SafetyError(f"blocked method: {method}")
        if isinstance(max_body_bytes, bool) or not isinstance(max_body_bytes, int):
            raise SafetyError("max_body_bytes must be an integer")
        if method == "GET" and not 1 <= max_body_bytes <= MAX_BODY_BYTES:
            raise SafetyError(f"GET max_body_bytes must be between 1 and {MAX_BODY_BYTES}")
        if method == "HEAD" and max_body_bytes != 0:
            raise SafetyError("HEAD max_body_bytes must be zero")
        host = self.assert_allowed_url(url)
        parsed = urlparse(url)
        path = urlunparse(("", "", parsed.path or "/", "", parsed.query, ""))
        evidence_url = sanitized_evidence_url(url)
        self.interaction(f"{method} {evidence_url}")
        headers = {
            "User-Agent": self.user_agent,
            "Accept": "text/html,text/plain,application/xml;q=0.9,*/*;q=0.5",
        }
        started = time.monotonic()
        conn: http.client.HTTPSConnection | None = None
        try:
            conn = http.client.HTTPSConnection(host, timeout=15)
            conn.request(method, path, headers=headers)
            response = conn.getresponse()
            raw_headers = response.getheaders()
            raw_location = next(
                (value for key, value in reversed(raw_headers) if key.lower() == "location"),
                None,
            )
            # CRITICAL: reject redirect scope changes before persisting any target-controlled bytes.
            if raw_location:
                self.assert_allowed_url(urljoin(url, raw_location))
            if method == "GET":
                raw_body = response.read(max_body_bytes + 1)
                if len(raw_body) > max_body_bytes:
                    raise SafetyError("response body exceeds approved cap")
                if contains_high_confidence_sensitive_material(raw_body):
                    self.log("SAFETY STOP: high-confidence sensitive material")
                    raise SafetyError("high-confidence sensitive material stop condition triggered")
            else:
                response.read(1)
                raw_body = b""
            header_map = self.sanitize_headers(raw_headers, url)
            status = int(response.status)
            reason = http.client.responses.get(status, "Unknown")
            elapsed_seconds = time.monotonic() - started
        except SafetyError:
            raise
        except (OSError, http.client.HTTPException) as error:
            raise SafetyError("network failure stop condition triggered") from error
        finally:
            if conn is not None:
                conn.close()

        header_path, header_record = self.artifact_path(name)
        with header_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(f"HTTP {status} {reason}\n")
            for key, value in header_map.items():
                handle.write(f"{key}: {value}\n")

        observation = HttpObservation(
            method=method,
            url=evidence_url,
            status=status,
            reason=reason,
            artifact=header_record,
            headers=header_map,
            body_artifact=None,
            body_bytes=len(raw_body),
            body_sha256=hashlib.sha256(raw_body).hexdigest() if raw_body else None,
            elapsed_ms=round(elapsed_seconds * 1000, 3),
            body=raw_body,
        )
        # IMPORTANT: response bodies remain in memory for parsing and never enter persisted evidence.
        self.observations["http"].append(observation.evidence())
        self.log(f"HTTP {status} {reason}")
        stop_reason = self.response_stop_reason(status, raw_headers, raw_body, elapsed_seconds)
        if stop_reason:
            self.log(f"SAFETY STOP: {stop_reason}")
            raise SafetyError(f"stop condition triggered: {stop_reason}")
        self.delay()
        return observation

    def tls_probe(self, host: str) -> None:
        host = normalize_host(host)
        if host not in self.allowed_hosts:
            raise SafetyError(f"blocked out-of-scope TLS host: {host}")
        self.interaction(f"TLS {host}:443")
        context = ssl.create_default_context()
        started = time.monotonic()
        try:
            with socket.create_connection((host, 443), timeout=15) as sock:
                with context.wrap_socket(sock, server_hostname=host) as tls:
                    cert = tls.getpeercert()
        except (OSError, ssl.SSLError) as error:
            raise SafetyError("TLS network failure stop condition triggered") from error
        elapsed_seconds = time.monotonic() - started
        subject = safe_text(
            " ".join("=".join(item) for part in cert.get("subject", []) for item in part),
            512,
        )
        issuer = safe_text(
            " ".join("=".join(item) for part in cert.get("issuer", []) for item in part),
            512,
        )
        sans = [
            safe_text(value, 253)
            for key, value in cert.get("subjectAltName", [])
            if key.lower() == "dns"
        ][:100]
        record = {
            "host": host,
            "subject": subject,
            "issuer": issuer,
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "sans": sans,
            "elapsed_ms": round(elapsed_seconds * 1000, 3),
        }
        self.observations["tls"].append(record)
        tls_path = self.artifacts_dir / f"tls_{sanitize_name(host)}.json"
        with tls_path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(record, handle, indent=2)
            handle.write("\n")
        self.log(f"subject: {subject}")
        self.log(f"issuer: {issuer}")
        if elapsed_seconds > MAX_REQUEST_SECONDS:
            self.log("SAFETY STOP: material TLS latency")
            raise SafetyError("stop condition triggered: material TLS latency")
        self.delay()

    def read_body_text(self, observation: HttpObservation) -> str:
        return observation.body.decode("utf-8", errors="ignore")

    def extract_security_txt_fields(self, host: str, body: str) -> None:
        fields: dict[str, str] = {}
        for line in body.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip()
            if key.lower() in SECURITY_TXT_FIELDS and value.strip():
                fields[key] = "<present>"
        self.observations["security_txt"][host] = fields

    def extract_robots(self, host: str, body: str) -> list[str]:
        disallow_count = 0
        disallow_rules: list[str] = []
        safe_sitemaps: list[str] = []
        blocked_sitemaps = 0
        for line in body.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            key = key.strip().lower()
            value = value.split("#", 1)[0].strip()
            if key == "disallow":
                disallow_count += 1
                if value:
                    if not has_safe_robots_rule(value) or len(disallow_rules) >= 100:
                        disallow_rules = ["/"]
                    elif disallow_rules != ["/"]:
                        disallow_rules.append(value)
            elif key == "sitemap":
                candidate = urljoin(f"https://{host}/", value)
                parsed = urlparse(candidate)
                try:
                    self.assert_allowed_url(candidate)
                except SafetyError:
                    blocked_sitemaps += 1
                    continue
                if parsed.query or parsed.fragment:
                    blocked_sitemaps += 1
                    continue
                if not has_safe_discretionary_path(candidate):
                    blocked_sitemaps += 1
                    continue
                safe_sitemaps.append(request_url_without_query(candidate))
        self.observations["robots"][host] = {
            "disallow": ["<present>"] * min(disallow_count, 50),
            "sitemaps": [sanitized_evidence_url(item) for item in safe_sitemaps[:20]],
            "blocked_sitemap_count": blocked_sitemaps,
        }
        self.robots_disallow[host] = disallow_rules
        return safe_sitemaps[:20]

    def apply_robots_observation(self, host: str, observation: HttpObservation) -> list[str]:
        if not 200 <= observation.status <= 299:
            self.robots_disallow[host] = ["/"]
            self.observations["robots"][host] = {
                "disallow": ["<fail-closed>"],
                "sitemaps": [],
                "blocked_sitemap_count": 0,
                "fetch_status": observation.status,
            }
            self.observations["review_notes"].append(
                f"robots unavailable for {host}; discretionary paths blocked"
            )
            return []
        return self.extract_robots(host, self.read_body_text(observation))

    def is_robots_disallowed(self, url: str) -> bool:
        parsed = urlparse(url)
        host = normalize_host(parsed.hostname or "")
        candidate = parsed.path or "/"
        if parsed.query:
            candidate = f"{candidate}?{parsed.query}"
        for raw_rule in self.robots_disallow.get(host, []):
            rule = raw_rule
            anchored_end = rule.endswith("$")
            if anchored_end:
                rule = rule[:-1]
            expression = re.escape(rule).replace(r"\*", ".*")
            expression = f"^{expression}{'$' if anchored_end else ''}"
            try:
                if re.search(expression, candidate):
                    return True
            except re.error:
                return True
        return False

    def extract_sitemap_count(self, url: str, body: str) -> None:
        locs = re.findall(r"<loc>(.*?)</loc>", body, flags=re.IGNORECASE)
        samples: list[str] = []
        for value in locs[:12]:
            try:
                self.assert_allowed_url(value)
            except SafetyError:
                samples.append("<out-of-scope>")
            else:
                samples.append(sanitized_evidence_url(value))
        self.observations["sitemaps"].append(
            {
                "url": sanitized_evidence_url(url),
                "loc_count": len(locs),
                "sample": samples,
            }
        )

    def fingerprint(self, body: str) -> None:
        signals: list[str] = []
        if "/_next/" in body or "__NEXT_DATA__" in body:
            signals.append("Next.js signal present")
        if "cdn-cgi" in body.lower():
            signals.append("Cloudflare cdn-cgi signal present")
        title = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
        if title:
            normalized_title = " ".join(title.group(1).split()).encode("utf-8", errors="replace")
            signals.append("title element present")
            signals.append(f"title sha256: {hashlib.sha256(normalized_title).hexdigest()}")
        self.observations["fingerprint"].extend(signals or ["no obvious homepage technology marker found"])

    def extract_links(self, base_url: str, body: str, max_links: int = 8) -> list[str]:
        parser = LinkParser()
        parser.feed(body)
        links: list[str] = []
        seen: set[str] = set()
        skip_ext = (
            ".png",
            ".jpg",
            ".jpeg",
            ".gif",
            ".webp",
            ".svg",
            ".ico",
            ".css",
            ".js",
            ".woff",
            ".woff2",
            ".pdf",
            ".zip",
            ".mp4",
            ".webm",
        )
        for href in parser.links:
            absolute = urljoin(base_url, href)
            parsed = urlparse(absolute)
            try:
                self.assert_allowed_url(absolute)
            except SafetyError:
                continue
            # CRITICAL: never turn a discovered parameterized URL into a different request.
            if parsed.query or parsed.fragment:
                continue
            if self.is_robots_disallowed(absolute):
                continue
            if not has_safe_discretionary_path(absolute):
                continue
            if parsed.path.lower().endswith(skip_ext):
                continue
            normalized = request_url_without_query(absolute)
            if normalized in seen:
                continue
            seen.add(normalized)
            links.append(normalized)
            if len(links) >= max_links:
                break
        return links

    def passive(self) -> None:
        for host in sorted(self.allowed_hosts):
            self.tls_probe(host)
            base = f"https://{host}"
            robots = self.request("GET", f"{base}/robots.txt", f"get_{host}_robots", 50_000)
            self.apply_robots_observation(host, robots)
            for purpose, path in (
                ("root", "/"),
                ("security", "/.well-known/security.txt"),
            ):
                url = f"{base}{path}"
                if self.is_robots_disallowed(url):
                    self.observations["review_notes"].append(
                        f"passive {purpose} HEAD skipped for {host}: robots restriction present"
                    )
                    continue
                self.request("HEAD", url, f"head_{host}_{purpose}")

    def progressive(self) -> None:
        for host in sorted(self.allowed_hosts):
            self.tls_probe(host)
        sitemaps: list[str] = []
        for host in sorted(self.allowed_hosts):
            base = f"https://{host}"
            robots = self.request("GET", f"{base}/robots.txt", f"get_{host}_robots", 50_000)
            sitemaps.extend(self.apply_robots_observation(host, robots))
            security_url = f"{base}/.well-known/security.txt"
            if self.is_robots_disallowed(security_url):
                self.observations["review_notes"].append(
                    f"security.txt GET skipped for {host}: robots restriction present"
                )
            else:
                security = self.request(
                    "GET",
                    security_url,
                    f"get_{host}_security",
                    50_000,
                )
                self.extract_security_txt_fields(host, self.read_body_text(security))

        home_host = "www.agentique.io" if "www.agentique.io" in self.allowed_hosts else sorted(self.allowed_hosts)[0]
        homepage_url = f"https://{home_host}/"
        if not sitemaps:
            fallback_sitemap = f"https://{home_host}/sitemap.xml"
            if not self.is_robots_disallowed(fallback_sitemap):
                sitemaps.append(fallback_sitemap)
        unique_sitemaps = list(dict.fromkeys(sitemaps))
        for index, sitemap in enumerate(unique_sitemaps[:3]):
            parsed_sitemap = urlparse(sitemap)
            self.assert_allowed_url(sitemap)
            if parsed_sitemap.query or parsed_sitemap.fragment:
                raise SafetyError("discovered sitemap URL cannot contain query or fragment")
            if self.is_robots_disallowed(sitemap):
                self.observations["review_notes"].append(
                    "sitemap GET skipped: robots restriction present"
                )
                continue
            sitemap_observation = self.request("GET", sitemap, f"sitemap_{index}", 150_000)
            self.extract_sitemap_count(sitemap, self.read_body_text(sitemap_observation))

        homepage_body = ""
        if self.is_robots_disallowed(homepage_url):
            self.observations["review_notes"].append(
                f"homepage GET and crawl skipped for {home_host}: robots restriction present"
            )
        else:
            homepage = self.request("GET", homepage_url, f"homepage_{home_host}", 200_000)
            homepage_body = self.read_body_text(homepage)
            self.fingerprint(homepage_body)

        for index, link in enumerate(self.extract_links(homepage_url, homepage_body)):
            obs = self.request("HEAD", link, f"crawl_{index}")
            self.observations["crawl"].append(
                {
                    "url": sanitized_evidence_url(link),
                    "status": obs.status,
                }
            )

        dictionary = self.config.get("directory_dictionary") or []
        if len(dictionary) > 20:
            raise SafetyError("directory dictionary cannot exceed 20 entries")
        for entry in dictionary:
            path = validate_dictionary_path(str(entry))
            url = f"https://{home_host}{path}"
            if self.is_robots_disallowed(url):
                self.observations["directory"].append(
                    {
                        "path": "<redacted>",
                        "status": "skipped-robots",
                    }
                )
                continue
            obs = self.request("HEAD", url, f"dir_{path}")
            self.observations["directory"].append(
                {
                    "path": path,
                    "status": obs.status,
                }
            )

    def security_header_summary(self) -> dict[str, int]:
        names = [
            "strict-transport-security",
            "content-security-policy",
            "content-security-policy-report-only",
            "cross-origin-opener-policy",
            "cross-origin-resource-policy",
            "permissions-policy",
            "referrer-policy",
            "x-content-type-options",
            "x-frame-options",
        ]
        counts = {name: 0 for name in names}
        for observation in self.observations["http"]:
            headers = observation.get("headers") or {}
            for name in names:
                if name in headers:
                    counts[name] += 1
        return counts

    def write_summary(self, started_at: str, ended_at: str) -> None:
        summary = {
            "run_id": self.config.get("run_id"),
            "execution_intent": self.config.get("execution_intent"),
            "config_sha256": self.config_sha256,
            "mode": self.config.get("mode"),
            "authorization_label": self.config.get("authorization_label"),
            "started_at": started_at,
            "ended_at": ended_at,
            "targets": sorted(self.allowed_hosts),
            "total_interactions": self.count,
            "max_interactions": self.max_interactions,
            "min_delay_seconds": self.min_delay_seconds,
            "observations": self.observations,
            "security_header_counts": self.security_header_summary(),
            "non_claims": [
                "No exploitation",
                "No fuzzing",
                "No brute force",
                "No authentication testing",
                "No form submission",
                "No parameter mutation",
                "No DoS, load, stress, or availability testing",
            ],
            "automatic_stop_contract": {
                "first_access_denial": True,
                "first_429": True,
                "first_waf_challenge": True,
                "high_confidence_sensitive_body": True,
                "unexpected_5xx_count": MAX_UNEXPECTED_5XX,
                "max_completed_request_seconds": MAX_REQUEST_SECONDS,
            },
        }
        summary_path = Path(self.config["summary_path"])
        with summary_path.open("x", encoding="utf-8", newline="\n") as handle:
            json.dump(summary, handle, indent=2)
            handle.write("\n")
        self.write_report(summary)

    def write_report(self, summary: dict[str, Any]) -> None:
        report_path = Path(self.config["report_path"])
        report_path.parent.mkdir(parents=True, exist_ok=True)
        observations = summary["observations"]
        lines: list[str] = [
            f"# Authorized Web Assessment Report - {summary['run_id']}",
            "",
            f"Mode: `{summary['mode']}`",
            f"Authorization label: `{summary['authorization_label']}`",
            f"Started: `{summary['started_at']}`",
            f"Ended: `{summary['ended_at']}`",
            f"Targets: `{', '.join(summary['targets'])}`",
            f"Interactions: `{summary['total_interactions']}/{summary['max_interactions']}`",
            "",
            "## Execution Boundaries",
            "",
        ]
        lines.extend(f"- {item}" for item in summary["non_claims"])
        lines.extend(["", "## TLS", ""])
        for item in observations["tls"]:
            lines.append(f"- `{item['host']}`: subject `{item['subject']}`, issuer `{item['issuer']}`, valid `{item['not_before']}` to `{item['not_after']}`")
        lines.extend(["", "## HTTP Status Observations", "", "| URL | Method | Status |", "| --- | --- | --- |"])
        for item in observations["http"]:
            lines.append(f"| `{item['url']}` | `{item['method']}` | `{item['status']}` |")
        lines.extend(["", "## Robots", ""])
        for host, item in observations["robots"].items():
            lines.append(f"- `{host}` disallow entries: {len(item.get('disallow', []))}; sitemaps: {len(item.get('sitemaps', []))}")
        lines.extend(["", "## Security.txt", ""])
        for host, fields in observations["security_txt"].items():
            field_list = ", ".join(sorted(fields.keys())) or "none"
            lines.append(f"- `{host}` fields observed: {field_list}")
        lines.extend(["", "## Sitemap", ""])
        for item in observations["sitemaps"]:
            lines.append(f"- `{item['url']}` contained `{item['loc_count']}` `<loc>` entries.")
        lines.extend(["", "## Directory Checks", "", "| Path | Status |", "| --- | --- |"])
        for item in observations["directory"]:
            lines.append(f"| `{item['path']}` | `{item['status']}` |")
        lines.extend(["", "## Non-Intrusive Fingerprint", ""])
        lines.extend(f"- {item}" for item in observations["fingerprint"])
        lines.extend(["", "## Security Header Coverage", ""])
        for name, count in summary["security_header_counts"].items():
            lines.append(f"- `{name}` observed on `{count}` responses.")
        lines.extend(
            [
                "",
                "## Analysis Notes",
                "",
                "- Treat this report as configuration and exposure evidence, not vulnerability proof.",
                "- Review CSP, route exposure, login, upload, third-party dependency, and certificate governance posture separately.",
                "- Prepare a dedicated improvement recommendation report under `reports/` when owner-facing remediation guidance is required.",
                "",
            ]
        )
        with report_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write("\n".join(lines))

    def run(self) -> None:
        if self.config.get("execution_intent") != "execute":
            raise SafetyError("validate-only config cannot execute target traffic")
        self.check_window()
        started_at = datetime.now().astimezone().isoformat()
        self.log("=== Authorized web assessment runner ===")
        self.log(f"run_id: {self.config.get('run_id')}")
        self.log(f"mode: {self.config.get('mode')}")
        self.log(f"config_sha256: {self.config_sha256}")
        self.log(f"targets: {', '.join(sorted(self.allowed_hosts))}")
        self.log(f"limits: max {self.max_interactions}, min delay {self.min_delay_seconds}s")
        mode = str(self.config.get("mode"))
        if mode == "passive":
            self.passive()
        elif mode == "progressive":
            self.progressive()
        else:
            raise SafetyError(f"unsupported mode: {mode}")
        ended_at = datetime.now().astimezone().isoformat()
        self.write_summary(started_at, ended_at)
        self.log()
        self.log("=== Completed authorized web assessment ===")
        self.log(f"total target interactions: {self.count}")


def main(argv: list[str]) -> int:
    arguments = list(argv[1:])
    validate_only = False
    if arguments and arguments[0] == "--validate-only":
        validate_only = True
        arguments.pop(0)
    if len(arguments) != 3 or arguments[0] != "--expected-config-sha256":
        print(
            "usage: authorized_web_assessment_runner.py [--validate-only] "
            "--expected-config-sha256 <sha256> <config.json>",
            file=sys.stderr,
        )
        return 2
    try:
        expected_intent = "validate_only" if validate_only else "execute"
        runner = Runner.from_config_path(arguments[2], arguments[1], expected_intent)
        if validate_only:
            print(f"CONFIG SHA256 VERIFIED: {runner.config_sha256}", flush=True)
            print("CONFIG VALID: no target traffic executed", flush=True)
            return 0
        runner.run()
        return 0
    except SafetyError as error:
        print(f"SAFETY ERROR: {error}", file=sys.stderr)
        return 10
    except Exception as error:  # pragma: no cover - final safety net for CLI use.
        print(f"RUNNER ERROR: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
