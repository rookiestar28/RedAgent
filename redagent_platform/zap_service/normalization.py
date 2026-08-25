"""Bounded normalization for untrusted ZAP alerts."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from typing import Mapping, Sequence
from urllib.parse import urlsplit

from redagent_platform.zap_service.contracts import CertifiedProfileId, GATEWAY_ENDPOINT, certified_profiles


@dataclass(frozen=True, slots=True)
class NormalizedZapAlert:
    rule_id: str
    title: str
    severity: str
    confidence: str
    affected_resource: str
    method: str
    fingerprint: str


def normalize_alerts(
    values: Sequence[Mapping[str, object]], *, profile_id: CertifiedProfileId,
    declared_count: int | None = None,
) -> tuple[NormalizedZapAlert, ...]:
    if declared_count is not None and (isinstance(declared_count, bool) or declared_count < 0 or declared_count > 1000):
        raise ValueError("zap_alert_count_exceeded")
    if len(values) > 1000 or (declared_count is not None and declared_count != len(values)):
        raise ValueError("zap_alert_count_exceeded")
    profile = certified_profiles().get(profile_id)
    if profile is None:
        raise ValueError("zap_profile_unknown")
    allowed_rules = frozenset((*profile.passive_rule_ids, *profile.active_rule_ids))
    output: list[NormalizedZapAlert] = []
    for raw in values:
        rule_id = _text(raw, "pluginId", 16)
        if rule_id not in allowed_rules:
            raise ValueError("zap_alert_rule_denied")
        title = _text(raw, "name", 200)
        risk = _text(raw, "risk", 16).lower()
        confidence = _text(raw, "confidence", 16).lower()
        if risk not in {"informational", "low", "medium", "high"}:
            raise ValueError("zap_alert_risk_invalid")
        if confidence not in {"low", "medium", "high", "confirmed"}:
            raise ValueError("zap_alert_confidence_invalid")
        method = _text(raw, "method", 8).upper()
        if method not in {"GET", "HEAD"}:
            raise ValueError("zap_alert_method_denied")
        url = _text(raw, "url", 2048)
        parsed = urlsplit(url)
        if f"{parsed.scheme}://{parsed.netloc}" != GATEWAY_ENDPOINT or parsed.path not in profile.allowed_paths:
            raise ValueError("zap_alert_scope_invalid")
        identity = {
            "profile": profile_id.value, "rule": rule_id, "title": title,
            "severity": risk, "confidence": confidence, "path": parsed.path, "method": method,
        }
        encoded = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        output.append(NormalizedZapAlert(
            rule_id=rule_id, title=title, severity=risk, confidence=confidence,
            affected_resource=parsed.path, method=method,
            fingerprint=hashlib.sha256(encoded).hexdigest(),
        ))
    return tuple(output)


def _text(value: Mapping[str, object], key: str, maximum: int) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item or len(item) > maximum or any(ord(char) < 32 for char in item):
        raise ValueError(f"zap_alert_{key}_invalid")
    return item
