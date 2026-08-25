from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.policy_service.contracts import (
    POLICY_DECISION_CONTRACT_VERSION,
    PolicyBoundary,
    PolicyDecision,
    PolicyDecisionInput,
    PolicyObligation,
    canonical_policy_input,
    policy_input_hash,
)


NOW = datetime(2026, 7, 10, 14, 0, tzinfo=timezone.utc)


def test_canonical_policy_input_is_stable_closed_and_metadata_only() -> None:
    first = _input(attributes={"job_status": "pending", "resource_version": 3})
    repeated = _input(attributes={"resource_version": 3, "job_status": "pending"})
    assert POLICY_DECISION_CONTRACT_VERSION == "1.0"
    assert canonical_policy_input(first) == canonical_policy_input(repeated)
    assert policy_input_hash(first) == policy_input_hash(repeated)
    assert len(policy_input_hash(first)) == 64
    assert b"tenant-1" in canonical_policy_input(first)
    with pytest.raises(TypeError):
        first.attributes["job_status"] = "mutated"


@pytest.mark.parametrize(
    "attributes",
    (
        {"password": "synthetic"},  # pragma: allowlist secret
        {"token": "synthetic"},  # pragma: allowlist secret
        {"evidence_bytes": "synthetic"},
        {"provider_path": "database/creds/example"},
        {"request_body": {"arbitrary": True}},
        {"float_value": 1.25},
    ),
)
def test_input_rejects_sensitive_arbitrary_or_nondeterministic_attributes(attributes) -> None:
    with pytest.raises(ValueError, match="policy_attribute"):
        _input(attributes=attributes)


def test_decision_requires_exact_hash_revision_deadline_and_closed_obligations() -> None:
    request = _input(attributes={"job_status": "pending", "resource_version": 3})
    decision = PolicyDecision(
        decision_id="decision-1",
        bundle_revision="r099-v1",
        input_hash=policy_input_hash(request),
        allowed=True,
        reason_code="boundary_authorized",
        obligations=(PolicyObligation.AUDIT, PolicyObligation.REQUIRE_EXPECTED_VERSION),
        issued_at=NOW,
        valid_until=NOW + timedelta(seconds=30),
    )
    decision.assert_current(request, required_revision="r099-v1", now=NOW + timedelta(seconds=5))
    with pytest.raises(ValueError, match="policy_bundle_revision_mismatch"):
        decision.assert_current(request, required_revision="r099-v2", now=NOW)
    with pytest.raises(ValueError, match="policy_decision_expired"):
        decision.assert_current(request, required_revision="r099-v1", now=NOW + timedelta(minutes=1))


def test_decision_is_nonserializable_by_default_and_repr_is_bounded() -> None:
    request = _input(attributes={"job_status": "pending"})
    decision = PolicyDecision(
        decision_id="decision-1", bundle_revision="r099-v1", input_hash=policy_input_hash(request),
        allowed=False, reason_code="policy_denied", obligations=(PolicyObligation.AUDIT,),
        issued_at=NOW, valid_until=NOW + timedelta(seconds=30),
    )
    assert "tenant-1" not in repr(decision)


def _input(*, attributes: dict[str, object]) -> PolicyDecisionInput:
    return PolicyDecisionInput(
        boundary=PolicyBoundary.API,
        action="job.create",
        tenant_id="tenant-1",
        subject_id="operator-1",
        roles=("operator",),
        permissions=("job:create",),
        resource_type="job",
        resource_id="job-1",
        policy_reference="policy:compat_099:1",
        roe_version_id="roe-1",
        correlation_id="correlation-1",
        requested_at=NOW,
        attributes=attributes,
    )
