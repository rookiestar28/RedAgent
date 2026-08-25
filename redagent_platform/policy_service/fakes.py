"""Deterministic synthetic-only policy provider for unit and local tests."""

from __future__ import annotations

from datetime import timedelta
import hashlib

from redagent_platform.policy_service.contracts import (
    PolicyBoundary,
    PolicyDecision,
    PolicyDecisionInput,
    PolicyObligation,
    policy_input_hash,
)
from redagent_platform.policy_service.providers import PolicyProviderReadiness


class DeterministicFakePolicyProvider:
    def __init__(self, *, revision: str) -> None:
        self.revision = revision

    async def assess_readiness(self, *, required_revision: str) -> PolicyProviderReadiness:
        if required_revision != self.revision:
            raise RuntimeError("fake_policy_revision_mismatch")
        return PolicyProviderReadiness(True, self.revision, "OK")

    async def decide(self, request: PolicyDecisionInput, *, required_revision: str, now):
        allowed = _allowed(request) and required_revision == self.revision
        digest = hashlib.sha256(
            f"{request.correlation_id}\0{policy_input_hash(request)}".encode("utf-8")
        ).hexdigest()[:40]
        obligations = [PolicyObligation.AUDIT]
        if request.boundary is PolicyBoundary.SECRET:
            obligations.append(PolicyObligation.EXACT_REVOKE)
        else:
            obligations.append(PolicyObligation.REQUIRE_EXPECTED_VERSION)
        return PolicyDecision(
            decision_id=f"synthetic-{digest}", bundle_revision=self.revision,
            input_hash=policy_input_hash(request), allowed=allowed,
            reason_code="boundary_authorized" if allowed else "boundary_denied",
            obligations=tuple(obligations), issued_at=request.requested_at,
            valid_until=request.requested_at + timedelta(seconds=30),
        )


def _allowed(request: PolicyDecisionInput) -> bool:
    if request.boundary is PolicyBoundary.API:
        return request.action in request.permissions
    if request.boundary is PolicyBoundary.WORKFLOW:
        return (
            request.action in {"job.start", "job.command", "job.stop"}
            and "workflow:command" in request.permissions
            and request.attributes.get("roe_status") == "current"
        )
    if request.boundary is PolicyBoundary.EVIDENCE:
        return (
            request.action == "evidence.write"
            and "evidence:write" in request.permissions
            and request.attributes.get("classification") in {"internal", "confidential", "restricted"}
        )
    if request.boundary is PolicyBoundary.SECRET:
        return (
        request.action == "secret.lease"
        and "secret:lease" in request.permissions
        and request.attributes.get("reference_status") == "active"
        and request.attributes.get("revoke_pending") is False
        )
    runner_stages = {
        "runner.manifest.issue": ("runner:issue", "draft", "absent", "certified"),
        "runner.manifest.claim": ("runner:claim", "issued", "absent", "certified"),
        "runner.secret.resolve": ("runner:secret", "claimed", "claimed", "verified"),
        "runner.execute": ("runner:execute", "claimed", "claimed", "verified"),
        "runner.evidence.submit": ("runner:evidence", "running", "claimed", "verified"),
    }
    stage = runner_stages.get(request.action)
    return (
        request.boundary is PolicyBoundary.RUNNER
        and stage is not None
        and stage[0] in request.permissions
        and request.attributes.get("registration_state") == "active"
        and request.attributes.get("capability_status") == "certified"
        and request.attributes.get("artifact_status") == "verified"
        and request.attributes.get("manifest_state") == stage[1]
        and request.attributes.get("lease_state") == stage[2]
        and request.attributes.get("sandbox_status") == stage[3]
        and request.attributes.get("cleanup_required") is True
        and isinstance(request.attributes.get("runner_generation"), int)
        and request.attributes.get("runner_generation", 0) > 0
        and request.attributes.get("identity_generation")
        == request.attributes.get("runner_generation")
    )
