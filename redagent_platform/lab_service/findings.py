"""Closed compat_103 golden-oracle mapping into the canonical compat_093 finding contract."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re

from redagent_platform.persistence.models import compute_issue_fingerprint


_SHA = re.compile(r"^[0-9a-f]{64}$")
_SEVERITIES = {"informational", "low", "medium", "high", "critical"}
_CONFIDENCES = {"tentative", "firm", "confirmed"}


@dataclass(frozen=True, kw_only=True)
class GoldenObservation:
    expectation_id: str
    indicator: str
    affected_resource: str
    evidence_reference: str
    evidence_sha256: str
    redaction_state: str = "sanitized"

    def __post_init__(self) -> None:
        if not self.expectation_id or not self.indicator or not self.affected_resource:
            raise ValueError("golden_observation_field_required")
        if not self.evidence_reference.startswith("evidence:r103:"):
            raise ValueError("golden_evidence_reference_invalid")
        if _SHA.fullmatch(self.evidence_sha256) is None:
            raise ValueError("golden_evidence_sha256_invalid")
        if self.redaction_state != "sanitized":
            raise ValueError("golden_evidence_not_sanitized")


class GoldenFindingMapper:
    def __init__(self, manifest: dict[str, object]) -> None:
        if manifest.get("schema") != "redagent.r103-golden-findings/v1":
            raise ValueError("golden_manifest_schema_invalid")
        expectations = manifest.get("expectations")
        if not isinstance(expectations, list) or not expectations:
            raise ValueError("golden_manifest_expectations_invalid")
        self._manifest = manifest
        self._expectations: dict[str, dict[str, str]] = {}
        for raw in expectations:
            if not isinstance(raw, dict) or not isinstance(raw.get("expectation_id"), str):
                raise ValueError("golden_expectation_invalid")
            item = {key: str(value) for key, value in raw.items()}
            expectation_id = item["expectation_id"]
            if expectation_id in self._expectations:
                raise ValueError("golden_expectation_duplicate")
            if item.get("severity") not in _SEVERITIES or item.get("confidence") not in _CONFIDENCES:
                raise ValueError("golden_expectation_classification_invalid")
            observed = compute_issue_fingerprint(
                tool=str(manifest["tool"]), rule_id=item["rule_id"],
                database_version=str(manifest["database_version"]), title=item["title"],
            )
            if observed != item.get("expected_fingerprint"):
                raise ValueError("golden_expectation_fingerprint_invalid")
            self._expectations[expectation_id] = item

    @classmethod
    def from_path(cls, path: Path) -> "GoldenFindingMapper":
        return cls(json.loads(path.read_text(encoding="utf-8")))

    @property
    def manifest_sha256(self) -> str:
        return hashlib.sha256(_canonical(self._manifest)).hexdigest()

    def map(self, observation: GoldenObservation) -> dict[str, str]:
        expected = self._expectations.get(observation.expectation_id)
        if expected is None:
            raise ValueError("golden_observation_unmapped")
        if (
            observation.affected_resource != expected["affected_resource"]
            or observation.indicator != observation.expectation_id
        ):
            raise ValueError("golden_observation_mutated")
        return {
            "tool": str(self._manifest["tool"]),
            "rule_id": expected["rule_id"],
            "tool_version": str(self._manifest["tool_version"]),
            "database_version": str(self._manifest["database_version"]),
            "title": expected["title"],
            "severity": expected["severity"],
            "confidence": expected["confidence"],
            "affected_resource": expected["affected_resource"],
            "location": expected["location"],
            "evidence_reference": observation.evidence_reference,
            "redaction_state": observation.redaction_state,
            "fingerprint": expected["expected_fingerprint"],
            "evidence_sha256": observation.evidence_sha256,
        }

    def reconcile(self, observations: tuple[GoldenObservation, ...]) -> tuple[dict[str, str], ...]:
        if len(observations) != len(self._expectations):
            raise ValueError("golden_observation_count_mismatch")
        mapped = tuple(self.map(item) for item in observations)
        if {item.expectation_id for item in observations} != set(self._expectations):
            raise ValueError("golden_observation_set_mismatch")
        return mapped


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
