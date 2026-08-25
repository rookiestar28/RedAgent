from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from redagent_platform.lab_service.findings import GoldenFindingMapper, GoldenObservation
from redagent_platform.persistence.models import compute_issue_fingerprint


ROOT = Path(__file__).resolve().parents[2]
SHA = "a" * 64


def _mapper() -> GoldenFindingMapper:
    return GoldenFindingMapper.from_path(ROOT / "config/r103-golden-findings.json")


def _observations() -> tuple[GoldenObservation, ...]:
    return (
        GoldenObservation(
            expectation_id="r103-header-training-marker", indicator="r103-header-training-marker",
            affected_resource="synthetic-web-root", evidence_reference="evidence:r103:header",
            evidence_sha256=SHA,
        ),
        GoldenObservation(
            expectation_id="r103-api-training-marker", indicator="r103-api-training-marker",
            affected_resource="synthetic-api-profile", evidence_reference="evidence:r103:profile",
            evidence_sha256="b" * 64,
        ),
    )


def test_exact_golden_set_maps_to_stable_r093_fingerprints() -> None:
    mapper = _mapper()
    mapped = mapper.reconcile(_observations())
    assert len(mapped) == 2
    for finding in mapped:
        assert finding["fingerprint"] == compute_issue_fingerprint(
            tool=finding["tool"], rule_id=finding["rule_id"],
            database_version=finding["database_version"], title=finding["title"],
        )
        assert finding["redaction_state"] == "sanitized"
    assert len(mapper.manifest_sha256) == 64


def test_unmapped_mutated_unsanitized_or_incomplete_oracle_fails_closed() -> None:
    mapper = _mapper()
    first, second = _observations()
    with pytest.raises(ValueError, match="golden_observation_unmapped"):
        mapper.map(replace(first, expectation_id="unknown", indicator="unknown"))
    with pytest.raises(ValueError, match="golden_observation_mutated"):
        mapper.map(replace(first, affected_resource="different"))
    with pytest.raises(ValueError, match="golden_evidence_not_sanitized"):
        replace(first, redaction_state="restricted")
    with pytest.raises(ValueError, match="golden_observation_count_mismatch"):
        mapper.reconcile((first,))
    with pytest.raises(ValueError, match="golden_observation_set_mismatch"):
        mapper.reconcile((first, first))
