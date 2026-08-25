"""Bounded JSONL normalization for untrusted compat_105 output."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from urllib.parse import urlsplit

from redagent_platform.nuclei_service.contracts import NucleiBundleManifest, NucleiTargetBinding


MAX_RESULT_BYTES = 1024 * 1024
MAX_RESULT_LINES = 100
_ALLOWED_KEYS = frozenset({
    "template-id", "template-path", "info", "matcher-name", "type", "host", "port",
    "scheme", "url", "matched-at", "ip", "timestamp", "curl-command", "matcher-status",
})


@dataclass(frozen=True, kw_only=True)
class NormalizedNucleiResult:
    template_id: str
    matcher_name: str
    title: str
    severity: str
    affected_resource: str
    fingerprint: str
    source_sha256: str


def normalize_nuclei_jsonl(
    content: bytes, *, bundle: NucleiBundleManifest, target: NucleiTargetBinding,
) -> tuple[NormalizedNucleiResult, ...]:
    if len(content) > MAX_RESULT_BYTES:
        raise ValueError("nuclei_result_too_large")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("nuclei_result_encoding_invalid") from exc
    lines = [line for line in text.splitlines() if line]
    if len(lines) > MAX_RESULT_LINES:
        raise ValueError("nuclei_result_count_exceeded")
    normalized: list[NormalizedNucleiResult] = []
    for line in lines:
        if len(line) > 64 * 1024:
            raise ValueError("nuclei_result_line_too_large")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ValueError("nuclei_result_json_invalid") from exc
        if not isinstance(value, dict) or not set(value).issubset(_ALLOWED_KEYS) or any(
            key in value for key in ("request", "response", "template")
        ):
            raise ValueError("nuclei_result_field_forbidden")
        _bounded_value(value)
        if value.get("template-id") != bundle.template_id:
            raise ValueError("nuclei_result_template_mismatch")
        matcher_value = value.get("matcher-name")
        if matcher_value is None and len(bundle.expected_matcher_names) == 1:
            matcher_value = bundle.expected_matcher_names[0]
        if matcher_value not in bundle.expected_matcher_names or value.get("type") != "http":
            raise ValueError("nuclei_result_matcher_mismatch")
        info = value.get("info")
        if not isinstance(info, dict) or info.get("severity") != bundle.severity:
            raise ValueError("nuclei_result_info_invalid")
        matched = value.get("matched-at")
        host = value.get("host")
        if not isinstance(matched, str) or host != "redagent-r105-gateway" or value.get("url") != target.endpoint:
            raise ValueError("nuclei_result_scope_mismatch")
        parsed = urlsplit(matched)
        if f"{parsed.scheme}://{parsed.netloc}" != target.endpoint or parsed.path not in target.allowed_paths or parsed.query:
            raise ValueError("nuclei_result_scope_mismatch")
        matcher = str(matcher_value)
        title = str(info.get("name", ""))
        if not 1 <= len(title) <= 200:
            raise ValueError("nuclei_result_info_invalid")
        source_sha = hashlib.sha256(line.encode()).hexdigest()
        fingerprint = hashlib.sha256(
            f"{bundle.template_id}\0{matcher}\0{parsed.path}".encode()
        ).hexdigest()
        normalized.append(NormalizedNucleiResult(
            template_id=bundle.template_id, matcher_name=matcher, title=title,
            severity=bundle.severity, affected_resource=parsed.path,
            fingerprint=fingerprint, source_sha256=source_sha,
        ))
    return tuple(normalized)


def _bounded_value(value: object, *, depth: int = 0) -> None:
    if depth > 4:
        raise ValueError("nuclei_result_depth_exceeded")
    if isinstance(value, str):
        if len(value) > 4096:
            raise ValueError("nuclei_result_string_too_large")
    elif isinstance(value, dict):
        if len(value) > 32:
            raise ValueError("nuclei_result_shape_invalid")
        for key, item in value.items():
            if not isinstance(key, str) or len(key) > 100:
                raise ValueError("nuclei_result_shape_invalid")
            _bounded_value(item, depth=depth + 1)
    elif isinstance(value, list):
        if len(value) > 32:
            raise ValueError("nuclei_result_shape_invalid")
        for item in value:
            _bounded_value(item, depth=depth + 1)
    elif value is not None and not isinstance(value, (bool, int, float)):
        raise ValueError("nuclei_result_shape_invalid")
