"""compat_110 transient match projection that cannot return raw matched material."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import re


_SHA = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, kw_only=True)
class RedactedFinding:
    artifact_sha256: str; path: str; line: int; rule_id: str; classification: str
    fingerprint: str; redacted_fragment: str = "[REDACTED]"


def match_redacted_finding(*, artifact_sha256: str, path: str, line: int, rule_id: str, classification: str, raw_match: str, fingerprint_key: bytes) -> RedactedFinding:
    if not _SHA.fullmatch(artifact_sha256) or not path.strip() or line < 1 or not rule_id.strip() or not classification.strip(): raise ValueError("artifact_secret_finding_invalid")
    if not raw_match or len(fingerprint_key) < 8: raise ValueError("artifact_secret_match_invalid")
    # CRITICAL: raw matched bytes are consumed only by this keyed digest and never enter the returned object.
    match_digest = hmac.new(fingerprint_key, raw_match.encode(), hashlib.sha256).hexdigest()
    material = f"{artifact_sha256}\0{path}\0{line}\0{rule_id}\0{match_digest}".encode()
    fingerprint = hashlib.sha256(material).hexdigest()
    return RedactedFinding(artifact_sha256=artifact_sha256, path=path, line=line, rule_id=rule_id,
        classification=classification, fingerprint=fingerprint)
