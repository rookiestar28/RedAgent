from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import hashlib

import pytest

from redagent_platform.campaign_service.authority_envelope import (
    CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION,
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
)
from redagent_platform.campaign_service.dag_effect_authority import (
    DagAuthorityMaterialV1,
    DagEffectAuthorityGate,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DagNodeState,
    DagRunState,
)
from redagent_platform.campaign_service.resolver import (
    CanonicalAuthoritySnapshot,
    ResolutionResult,
)
from redagent_platform.policy_service.contracts import (
    PolicyDecision,
    PolicyObligation,
    policy_input_hash,
)
from tests.unit.test_compat_123_effect_coordinator import _command


NOW = datetime(2026, 8, 29, 14, 0, tzinfo=timezone.utc)


def _material(**changes) -> DagAuthorityMaterialV1:
    values = {
        "tenant_id": "tenant-r123",
        "principal_id": "principal-r123",
        "campaign_id": "campaign-a",
        "engagement_id": "engagement-r123",
        "execution_run_id": "dag-run-a",
        "node_id": "node-a",
        "node_sha256": "1" * 64,
        "target_id": "target-r123",
        "effect_id": "effect-r123",
        "effect_intent_sha256": "2" * 64,
        "envelope_sha256": "1" * 64,
        "authority_sha256": "3" * 64,
        "policy_bundle_revision": "policy-current",
        "policy_bundle_sha256": "4" * 64,
        "domain_sha256": "5" * 64,
        "plan_sha256": "6" * 64,
        "certificate_sha256": "7" * 64,
        "subset_proof_sha256": "8" * 64,
        "admission_receipt_sha256": "9" * 64,
        "post_residual_budget_sha256": "a" * 64,
        "reserved_budget_sha256": "b" * 64,
        "reservation_id": "reservation-a",
        "reservation_state": "reserved",
        "reservation_lease_expires_at": NOW + timedelta(minutes=2),
        "lifecycle_epoch": 1,
        "policy_revocation_epoch": 2,
        "roe_revocation_epoch": 3,
        "kill_switch_epoch": 4,
        "capability_id": "nuclei-trusted-runtime",
        "effect_class": "read_only_observation",
        "data_access_class": "metadata_only",
        "credential_class": "none",
        "environment_class": "synthetic_loopback",
        "rate_limit": 5,
        "rate_claimed_requests": 0,
        "concurrency_limit": 1,
        "active_concurrency": 0,
        "run_state": DagRunState.RUNNING,
        "node_state": DagNodeState.RESERVED,
        "effect_state": "reserved",
    }
    values.update(changes)
    return DagAuthorityMaterialV1(**values)


def _snapshot() -> CanonicalAuthoritySnapshot:
    target_value = "http://127.0.0.1:41731"
    target_document = (
        '{"normalized_value":"http://127.0.0.1:41731","revision":1,'
        '"target_id":"target-r123","target_type":"url"}'
    )
    return CanonicalAuthoritySnapshot(
        tenant_id="tenant-r123",
        principal_id="principal-r123",
        engagement_id="engagement-r123",
        engagement_version=1,
        roe_version_id="roe-current",
        roe_revision=1,
        roe_sha256="c" * 64,
        roe_status="approved",
        roe_revocation_epoch=3,
        policy_decision_id="resolver-decision",
        policy_revision="policy-current",
        policy_sha256="4" * 64,
        policy_status="allowed",
        policy_revocation_epoch=2,
        target_id="target-r123",
        target_revision=1,
        target_sha256=hashlib.sha256(target_document.encode()).hexdigest(),
        target_value=target_value,
        target_resolution_mode="owned-loopback",
        credential_class="none",
        credential_reference=None,
        quota_reference="quota-a",
        quota_available=True,
        runner_id="runner-r123",
        runner_workload_identity="spiffe://redagent.test/runner/dag",
        runner_ready=True,
        reservation_id="reservation-a",
        lease_id="lease-a",
        lease_expires_at=NOW + timedelta(minutes=2),
        stop_requested=False,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=1),
    )


def _lifecycle(**changes) -> CampaignAuthorityLifecycleV2:
    values = {
        "schema_version": CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION,
        "authority_sha256": "3" * 64,
        "tenant_id": "tenant-r123",
        "engagement_id": "engagement-r123",
        "state": CampaignAuthorityLifecycleState.ACTIVE,
        "lifecycle_epoch": 1,
        "policy_revocation_epoch": 2,
        "roe_revocation_epoch": 3,
        "kill_switch_epoch": 4,
        "observed_at": NOW,
        "valid_until": NOW + timedelta(minutes=2),
        "revoked_at": None,
        "reason_code": None,
    }
    values.update(changes)
    return CampaignAuthorityLifecycleV2(**values)


class StateOwner:
    def __init__(self, materials) -> None:
        self.materials = list(materials)
        self.commits = []
        self.observations = []

    async def read(self, command, *, now):
        return self.materials.pop(0)

    async def observe_lifecycle(self, material, lifecycle, *, now):
        self.observations.append((material, lifecycle, now))

    async def commit_pre_io(self, material, *, decision, request, runner_binding_sha256, now):
        self.commits.append((material, decision, request, runner_binding_sha256, now))


class Resolver:
    async def resolve(self, request, *, now):
        return ResolutionResult(True, "resolved", _snapshot())


class LifecycleOwner:
    def __init__(self, current=None) -> None:
        self.current = current or _lifecycle()

    async def read_current_lifecycle(self, *, tenant_id, authority_sha256):
        return self.current


class Policy:
    def __init__(self, *, allowed=True, fail=False) -> None:
        self.allowed = allowed
        self.fail = fail
        self.requests = []

    async def decide(self, request, *, now):
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("synthetic-policy-unavailable")
        return PolicyDecision(
            decision_id=f"decision-{len(self.requests)}",
            bundle_revision="policy-current",
            input_hash=policy_input_hash(request),
            allowed=self.allowed,
            reason_code="boundary_authorized" if self.allowed else "boundary_denied",
            obligations=(PolicyObligation.AUDIT, PolicyObligation.REQUIRE_EXPECTED_VERSION),
            issued_at=now,
            valid_until=now + timedelta(seconds=30),
        )


def test_gate_uses_32_closed_attributes_and_persists_only_dispatching_decision() -> None:
    state = StateOwner((_material(), _material(effect_state="dispatching", node_state=DagNodeState.DISPATCHING)))
    policy = Policy()
    gate = DagEffectAuthorityGate(state, Resolver(), LifecycleOwner(), policy)

    first = asyncio.run(gate.recheck(_command(), now=NOW))
    second = asyncio.run(gate.recheck(_command(), now=NOW + timedelta(seconds=1)))

    assert first.allowed is second.allowed is True
    assert first.policy_decision_id == "decision-1"
    assert second.policy_decision_id == "decision-2"
    assert len(state.commits) == 1
    assert len(state.observations) == 2
    request = policy.requests[-1]
    assert request.action == "campaign.node.execute"
    assert request.permissions == ("campaign:execute",)
    assert len(request.attributes) == 32
    assert request.attributes["campaign_node_id"] == "node-a"
    assert request.attributes["campaign_runner_binding_sha256"] == state.commits[0][3]


@pytest.mark.parametrize(
    "lifecycle_owner, policy, reason",
    (
        (LifecycleOwner(_lifecycle(lifecycle_epoch=2)), Policy(), "lifecycle_epoch_drift"),
        (LifecycleOwner(), Policy(allowed=False), "boundary_denied"),
        (LifecycleOwner(), Policy(fail=True), "policy_unavailable"),
    ),
)
def test_gate_fails_closed_without_pre_io_commit(lifecycle_owner, policy, reason) -> None:
    state = StateOwner((_material(effect_state="dispatching"),))
    decision = asyncio.run(
        DagEffectAuthorityGate(state, Resolver(), lifecycle_owner, policy).recheck(
            _command(), now=NOW
        )
    )
    assert decision.allowed is False
    assert decision.reason == reason
    assert state.commits == []


def test_gate_denies_expired_reservation_before_resolver_or_policy() -> None:
    class UnexpectedResolver:
        async def resolve(self, request, *, now):
            raise AssertionError("resolver must not run")

    policy = Policy()
    state = StateOwner((_material(reservation_lease_expires_at=NOW),))
    decision = asyncio.run(
        DagEffectAuthorityGate(state, UnexpectedResolver(), LifecycleOwner(), policy).recheck(
            _command(), now=NOW
        )
    )
    assert decision.allowed is False
    assert decision.reason == "reservation_expired"
    assert policy.requests == []


@pytest.mark.parametrize(
    "material_change, reason",
    (
        ({"rate_claimed_requests": 5}, "rate_limit_exhausted"),
        ({"active_concurrency": 1}, "concurrency_limit_exhausted"),
    ),
)
def test_gate_denies_exhausted_server_limits_before_resolver_or_policy(
    material_change, reason
) -> None:
    class UnexpectedResolver:
        async def resolve(self, request, *, now):
            raise AssertionError("resolver must not run")

    policy = Policy()
    state = StateOwner((_material(**material_change),))
    decision = asyncio.run(
        DagEffectAuthorityGate(state, UnexpectedResolver(), LifecycleOwner(), policy).recheck(
            _command(), now=NOW
        )
    )
    assert decision.allowed is False
    assert decision.reason == reason
    assert policy.requests == []
