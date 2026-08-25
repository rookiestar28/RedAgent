from __future__ import annotations

from dataclasses import replace

import pytest

from redagent_platform.policy_service.lifecycle import (
    BundleAcknowledgement,
    BundleRevision,
    PolicyLifecycleError,
    activate_bundle,
)


HASH_A = "a" * 64
HASH_B = "b" * 64


def test_bundle_revision_is_reviewed_signed_snapshot_metadata_only() -> None:
    candidate = _bundle()
    assert candidate.manifest_roots == ("redagent", "system")
    assert candidate.rego_version == 1
    assert not hasattr(candidate, "bundle_bytes")
    assert not hasattr(candidate, "rego_source")
    with pytest.raises(PolicyLifecycleError, match="policy_bundle_review_separation_required"):
        replace(candidate, reviewer_user_id="author-1")
    with pytest.raises(PolicyLifecycleError, match="policy_bundle_signature_invalid"):
        replace(candidate, signature_verified=False)


def test_activation_requires_accepted_evidence_and_every_exact_agent_ack() -> None:
    candidate = _bundle()
    required = ("api-pdp", "workflow-pdp", "evidence-pdp", "secret-pdp")
    incomplete = tuple(_ack(agent) for agent in required[:-1])
    with pytest.raises(PolicyLifecycleError, match="policy_bundle_agent_convergence_required"):
        activate_bundle(candidate, required_agents=required, acknowledgements=incomplete, current_revision="r099-v0")
    mismatched = tuple(_ack(agent, revision="r099-other") for agent in required)
    with pytest.raises(PolicyLifecycleError, match="policy_bundle_agent_revision_mismatch"):
        activate_bundle(candidate, required_agents=required, acknowledgements=mismatched, current_revision="r099-v0")


def test_activation_is_atomic_and_rollback_is_new_explicit_promotion() -> None:
    required = ("api-pdp", "workflow-pdp", "evidence-pdp", "secret-pdp")
    activation = activate_bundle(
        _bundle(), required_agents=required,
        acknowledgements=tuple(_ack(agent) for agent in required), current_revision="r099-v0",
    )
    assert activation.required_revision == "r099-v1"
    assert activation.previous_revision == "r099-v0"
    assert activation.rollback is False

    prior = replace(_bundle(), revision="r099-v0", artifact_sha256=HASH_B)
    rollback = activate_bundle(
        prior, required_agents=required,
        acknowledgements=tuple(_ack(agent, revision="r099-v0", artifact_hash=HASH_B) for agent in required),
        current_revision="r099-v1", rollback=True,
    )
    assert rollback.required_revision == "r099-v0"
    assert rollback.previous_revision == "r099-v1"
    assert rollback.rollback is True


def _bundle() -> BundleRevision:
    return BundleRevision(
        revision="r099-v1", source_sha256=HASH_B, artifact_sha256=HASH_A,
        artifact_size=4096, manifest_roots=("redagent", "system"), rego_version=1,
        signing_key_id="r099-local-key", signing_scope="redagent-policy",
        signing_algorithm="RS256", author_user_id="author-1", reviewer_user_id="reviewer-1",
        test_evidence_sha256=HASH_A, conformance_sha256=HASH_B,
        coverage_basis_points=9000, signature_verified=True, status="accepted",
    )


def _ack(agent: str, *, revision: str = "r099-v1", artifact_hash: str = HASH_A) -> BundleAcknowledgement:
    return BundleAcknowledgement(
        agent_id=agent, active_revision=revision, artifact_sha256=artifact_hash,
        bundle_state="OK", status_fresh=True,
    )
