from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest

from redagent_platform.campaign_service.activity_coordinator import (
    ContainmentCommit,
    DispatchMaterial,
    CampaignActivityCoordinator,
    ReconcileMaterial,
)
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.execution import (
    NodeDesiredV1,
    NodeObservedV1,
    ReconciliationState,
    SafetyObligationsV1,
)
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.service import (
    EffectAmbiguityPersistenceError,
    EffectDispatchCommand,
    EffectReconciliationCommand,
)
from redagent_platform.runner_service.campaign_dispatch import CampaignAdapterRequest
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ClosedLoopContainActivityCommand,
    ClosedLoopDispatchActivityCommand,
    ClosedLoopReconcileActivityCommand,
)


NOW = datetime(2026, 8, 24, 2, tzinfo=timezone.utc)


def _binding() -> CapabilityBindingKeyV1:
    closed = closed_execution_registry()["zap-controlled-runtime@3"]
    return CapabilityBindingKeyV1(
        schema_version="redagent.r119-capability-binding/v1",
        capability_id="zap-controlled-runtime",
        capability_revision=3,
        execution_manifest_sha256="a" * 64,
        adapter_id=closed.adapter_id,
        adapter_version=closed.adapter_version,
        profile_id=closed.profile_id,
        profile_revision=closed.profile_revision,
        profile_sha256=closed.profile_sha256,
        bundle_id=closed.bundle_id,
        bundle_revision=closed.bundle_revision,
        bundle_sha256=closed.bundle_sha256,
        semantics_revision=1,
        semantics_sha256="b" * 64,
        normalized_output_sha256="c" * 64,
        projection_revision=1,
        projection_sha256="d" * 64,
    )


def _desired() -> NodeDesiredV1:
    return NodeDesiredV1(
        schema_version="redagent.r123-node-desired/v1",
        tenant_id="tenant-r123",
        plan_revision_id="strategy-r123-v1",
        node_id="node-server-zap",
        effect_intent_sha256="e" * 64,
        max_attempts=2,
        stop_requested=False,
        authority_current=True,
        budget_available=True,
        successor_allowed=True,
        obligations=SafetyObligationsV1(
            evidence_required=True,
            report_safe_evidence_required=True,
            cleanup_required=True,
            compensation_required=True,
            reconciliation_required=True,
            secret_revocation_required=True,
            containment_required=True,
            residual_risk_required=True,
            finding_or_coverage_required=True,
            retest_required=True,
            stop_on_authority_drift=True,
        ),
    )


def _observed() -> NodeObservedV1:
    return NodeObservedV1(
        schema_version="redagent.r123-node-observed/v1",
        effect_state="absent",
        attempt_count=0,
        next_retry_at=None,
        receipt_state=None,
        effect_receipt_sha256=None,
        evidence_complete=False,
        report_safe_evidence_complete=False,
        finding_or_coverage_complete=False,
        retest_complete=False,
        secret_revocation_complete=False,
        containment_complete=False,
        cleanup_complete=False,
        reconciliation_complete=False,
        residual_risk_complete=False,
        infrastructure_available=True,
    )


def _effect_command() -> EffectDispatchCommand:
    return EffectDispatchCommand(
        tenant_id="tenant-r123",
        principal_id="principal-db-owner",
        engagement_id="engagement-db-owner",
        target_id="target-db-owner",
        effect_id="effect-server-zap",
        invocation_id="invocation-server-zap",
        effect_intent_sha256="a" * 64,
        envelope_sha256="1" * 64,
        expected_claim_version=0,
        expected_dispatch_attempt=0,
        expected_dispatch_generation=0,
        claim_owner="r123-activity-worker",
        binding=_binding(),
    )


def _effect_reconciliation_command() -> EffectReconciliationCommand:
    command = replace(
        _effect_command(),
        expected_claim_version=3,
        expected_dispatch_attempt=1,
        expected_dispatch_generation=1,
    )
    binding = command.binding
    request = CampaignAdapterRequest(
        tenant_id=command.tenant_id,
        capability_id=binding.capability_id,
        capability_revision=binding.capability_revision,
        adapter_id=binding.adapter_id,
        adapter_version=binding.adapter_version,
        profile_id=binding.profile_id,
        profile_revision=binding.profile_revision,
        profile_sha256=binding.profile_sha256,
        bundle_id=binding.bundle_id,
        bundle_revision=binding.bundle_revision,
        bundle_sha256=binding.bundle_sha256,
        invocation_id=command.invocation_id,
        effect_id=command.effect_id,
        envelope_sha256=command.envelope_sha256,
        manifest_v2_sha256="9" * 64,
    )
    request_sha256 = hashlib.sha256(
        json.dumps(asdict(request), sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return EffectReconciliationCommand(
        effect_command=command,
        request=request,
        request_sha256=request_sha256,
        runner_id="runner-r123",
        workload_identity="spiffe://redagent/runner/r123",
        started_at=NOW,
    )


def _reconcile_material() -> ReconcileMaterial:
    return ReconcileMaterial(
        tenant_id="tenant-r123",
        campaign_id="campaign-r123",
        strategy_revision_id="strategy-r123-v1",
        envelope_sha256="1" * 64,
        workflow_request_sha256="2" * 64,
        revision=1,
        depth=1,
        replan_count=0,
        node_id="node-server-zap",
        effect_id="effect-server-zap",
        desired=_desired(),
        observed=_observed(),
    )


def _dispatch_material() -> DispatchMaterial:
    return DispatchMaterial(
        tenant_id="tenant-r123",
        campaign_id="campaign-r123",
        strategy_revision_id="strategy-r123-v1",
        node_id="node-server-zap",
        effect_id="effect-server-zap",
        envelope_sha256="1" * 64,
        revision=2,
        effect_command=_effect_command(),
    )


class StateOwner:
    def __init__(self) -> None:
        self.reconcile_material = _reconcile_material()
        self.reconcile_after_lookup: ReconcileMaterial | None = None
        self.dispatch_material = _dispatch_material()
        self.events: list[tuple[str, object]] = []

    async def read_reconcile(self, command, *, now, correlation_id):
        self.events.append(("read_reconcile", correlation_id))
        if self.reconcile_after_lookup is not None and sum(
            name == "read_reconcile" for name, _ in self.events
        ) > 1:
            return self.reconcile_after_lookup
        return self.reconcile_material

    async def commit_reconcile(self, command, material, decision, *, now, correlation_id):
        self.events.append(("commit_reconcile", decision.outcome.value))
        return command.revision + 1

    async def read_dispatch(self, command, *, now, correlation_id):
        self.events.append(("read_dispatch", correlation_id))
        return self.dispatch_material

    async def commit_dispatch(
        self, command, material, *, state, failure_code, now, correlation_id
    ):
        self.events.append(("commit_dispatch", (state, failure_code)))
        return command.expected_revision + 1

    async def contain(self, command, *, now, correlation_id):
        self.events.append(("contain", command.signal_id))
        return ContainmentCommit(
            campaign_id=command.campaign_id,
            state="contained",
            revision=command.expected_revision + 1,
            reason="stop_contained",
        )


class EffectCoordinator:
    def __init__(
        self,
        *,
        ambiguous: bool = False,
        ambiguity_persistence_failed: bool = False,
        cancelled: bool = False,
    ) -> None:
        self.ambiguous = ambiguous
        self.ambiguity_persistence_failed = ambiguity_persistence_failed
        self.cancelled = cancelled
        self.commands: list[EffectDispatchCommand] = []
        self.reconciliations: list[EffectReconciliationCommand] = []

    async def dispatch(self, command, *, now):
        self.commands.append(command)
        if self.cancelled:
            raise asyncio.CancelledError
        if self.ambiguity_persistence_failed:
            raise EffectAmbiguityPersistenceError(
                "effect_ambiguity_persistence_failed"
            )
        if self.ambiguous:
            raise RuntimeError("effect_dispatch_reconciliation_required")
        return {"state": "confirmed"}

    async def reconcile(self, command, *, now):
        self.reconciliations.append(command)
        return {"state": "manual_review_required"}


def _reconcile_command() -> ClosedLoopReconcileActivityCommand:
    return ClosedLoopReconcileActivityCommand(
        CONTRACT_SCHEMA_VERSION,
        "tenant-r123",
        "campaign-r123",
        "strategy-r123-v1",
        "1" * 64,
        "2" * 64,
        1,
        False,
    )


def _dispatch_command() -> ClosedLoopDispatchActivityCommand:
    return ClosedLoopDispatchActivityCommand(
        CONTRACT_SCHEMA_VERSION,
        "tenant-r123",
        "campaign-r123",
        "strategy-r123-v1",
        "node-server-zap",
        "effect-server-zap",
        "1" * 64,
        2,
    )


def test_reconcile_uses_fresh_owner_material_and_commits_pure_decision() -> None:
    owner = StateOwner()
    coordinator = CampaignActivityCoordinator(owner, EffectCoordinator())

    result = asyncio.run(
        coordinator.reconcile(
            _reconcile_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
        )
    )

    assert result.outcome == "dispatch_once"
    assert result.node_id == "node-server-zap"
    assert result.effect_id == "effect-server-zap"
    assert result.revision == 2 and result.terminal is False
    assert owner.events == [
        ("read_reconcile", "workflow-run-r123"),
        ("commit_reconcile", "dispatch_once"),
    ]


def test_reconcile_runs_read_only_effect_lookup_then_rereads_canonical_state() -> None:
    owner = StateOwner()
    owner.reconcile_material = replace(
        owner.reconcile_material,
        observed=replace(
            owner.reconcile_material.observed,
            effect_state="reconciliation_required",
            attempt_count=1,
            receipt_state=ReconciliationState.RECONCILIATION_REQUIRED,
            effect_receipt_sha256="f" * 64,
        ),
        effect_reconciliation=_effect_reconciliation_command(),
    )
    owner.reconcile_after_lookup = replace(
        owner.reconcile_material,
        observed=replace(
            owner.reconcile_material.observed,
            effect_state="manual_review_required",
            receipt_state=ReconciliationState.MANUAL_REVIEW_REQUIRED,
        ),
        effect_reconciliation=None,
    )
    effect = EffectCoordinator()
    coordinator = CampaignActivityCoordinator(owner, effect)

    result = asyncio.run(
        coordinator.reconcile(
            _reconcile_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
        )
    )

    assert result.outcome == "blocked"
    assert result.reason == "manual_review_required"
    assert result.terminal is True
    assert effect.commands == []
    assert effect.reconciliations == [_effect_reconciliation_command()]
    assert [name for name, _ in owner.events] == [
        "read_reconcile",
        "read_reconcile",
        "commit_reconcile",
    ]


def test_reconcile_honors_scheduled_lookup_backoff_without_early_adapter_read() -> None:
    owner = StateOwner()
    retry_at = NOW + timedelta(seconds=5)
    owner.reconcile_material = replace(
        owner.reconcile_material,
        observed=replace(
            owner.reconcile_material.observed,
            effect_state="reconciliation_required",
            attempt_count=1,
            next_retry_at=retry_at,
            receipt_state=ReconciliationState.RECONCILIATION_REQUIRED,
            effect_receipt_sha256="f" * 64,
        ),
        effect_reconciliation=_effect_reconciliation_command(),
    )
    effect = EffectCoordinator()
    coordinator = CampaignActivityCoordinator(owner, effect)

    result = asyncio.run(
        coordinator.reconcile(
            _reconcile_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
        )
    )

    assert result.outcome == "retry_at"
    assert result.reason == "status_lookup_retry_scheduled"
    assert result.retry_delay_seconds == 5
    assert effect.reconciliations == []
    assert [name for name, _ in owner.events] == [
        "read_reconcile",
        "commit_reconcile",
    ]


def test_reconcile_rejects_stale_temporal_binding_before_commit() -> None:
    owner = StateOwner()
    owner.reconcile_material = replace(owner.reconcile_material, envelope_sha256="f" * 64)
    coordinator = CampaignActivityCoordinator(owner, EffectCoordinator())

    with pytest.raises(ValueError, match="r123_reconcile_authoritative_binding_mismatch"):
        asyncio.run(
            coordinator.reconcile(
                _reconcile_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
            )
        )
    assert [event[0] for event in owner.events] == ["read_reconcile"]


def test_dispatch_rehydrates_effect_command_and_commits_terminal_receipt_state() -> None:
    owner = StateOwner()
    effect = EffectCoordinator()
    coordinator = CampaignActivityCoordinator(owner, effect)

    result = asyncio.run(
        coordinator.dispatch(
            _dispatch_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
        )
    )

    assert result.state == "dispatched" and result.revision == 3
    assert effect.commands == [_effect_command()]
    assert effect.commands[0].principal_id == "principal-db-owner"
    assert owner.events[-1] == ("commit_dispatch", ("dispatched", None))


def test_dispatch_converts_possible_acceptance_to_durable_ambiguity_without_retry() -> None:
    owner = StateOwner()
    coordinator = CampaignActivityCoordinator(owner, EffectCoordinator(ambiguous=True))

    result = asyncio.run(
        coordinator.dispatch(
            _dispatch_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
        )
    )

    assert result.state == "reconciliation_required"
    assert result.failure_code == "adapter_acceptance_ambiguous"
    assert owner.events[-1] == (
        "commit_dispatch",
        ("reconciliation_required", "adapter_acceptance_ambiguous"),
    )


def test_dispatch_uses_state_owner_as_durable_fallback_when_primary_ambiguity_write_fails() -> None:
    owner = StateOwner()
    coordinator = CampaignActivityCoordinator(
        owner, EffectCoordinator(ambiguity_persistence_failed=True)
    )

    result = asyncio.run(coordinator.dispatch(
        _dispatch_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
    ))

    assert result.state == "reconciliation_required"
    assert result.failure_code == "ambiguity_persistence_fallback"
    assert owner.events[-1] == (
        "commit_dispatch",
        ("reconciliation_required", "ambiguity_persistence_fallback"),
    )


def test_dispatch_persists_manual_reconciliation_before_preserving_cancellation() -> None:
    owner = StateOwner()
    coordinator = CampaignActivityCoordinator(owner, EffectCoordinator(cancelled=True))

    with pytest.raises(asyncio.CancelledError):
        asyncio.run(coordinator.dispatch(
            _dispatch_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
        ))

    assert owner.events[-1] == (
        "commit_dispatch",
        ("reconciliation_required", "activity_cancelled_after_possible_acceptance"),
    )


@pytest.mark.parametrize("effect_state", ("dispatching", "reconciliation_required"))
def test_dispatch_retry_never_calls_adapter_after_possible_acceptance(effect_state) -> None:
    owner = StateOwner()
    owner.dispatch_material = replace(
        owner.dispatch_material,
        effect_state=effect_state,
    )
    effect = EffectCoordinator()
    coordinator = CampaignActivityCoordinator(owner, effect)

    result = asyncio.run(
        coordinator.dispatch(
            _dispatch_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
        )
    )

    assert result.state == "reconciliation_required"
    assert result.failure_code == "adapter_acceptance_ambiguous"
    assert effect.commands == []
    assert owner.events[-1] == (
        "commit_dispatch",
        ("reconciliation_required", "adapter_acceptance_ambiguous"),
    )


def test_dispatch_retry_commits_existing_confirmation_without_adapter_call() -> None:
    owner = StateOwner()
    owner.dispatch_material = replace(
        owner.dispatch_material,
        effect_state="confirmed",
    )
    effect = EffectCoordinator()

    result = asyncio.run(
        CampaignActivityCoordinator(owner, effect).dispatch(
            _dispatch_command(), occurred_at=NOW, correlation_id="workflow-run-r123"
        )
    )

    assert result.state == "dispatched"
    assert result.failure_code is None
    assert effect.commands == []
    assert owner.events[-1] == ("commit_dispatch", ("dispatched", None))


def test_containment_is_committed_by_owner_and_advances_revision() -> None:
    owner = StateOwner()
    coordinator = CampaignActivityCoordinator(owner, EffectCoordinator())
    command = ClosedLoopContainActivityCommand(
        CONTRACT_SCHEMA_VERSION,
        "tenant-r123",
        "campaign-r123",
        "strategy-r123-v1",
        "stop-server-r123",
        "operator-r123",
        "3" * 64,
        3,
    )

    result = asyncio.run(
        coordinator.contain(
            command, occurred_at=NOW, correlation_id="workflow-run-r123"
        )
    )

    assert result.state == "contained" and result.revision == 4
    assert owner.events == [("contain", "stop-server-r123")]
