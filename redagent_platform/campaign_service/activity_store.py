"""PostgreSQL state owner for compat_123 Temporal Activity coordination."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
from typing import Protocol
from uuid import uuid4

from sqlalchemy import and_, insert, select, text

from redagent_platform.campaign_service.activity_coordinator import (
    ContainmentCommit,
    DispatchMaterial,
    ReconcileMaterial,
)
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.execution import (
    NodeDesiredV1,
    NodeObservedV1,
    ReconcileResultV1,
    ReconciliationState,
    SafetyObligationsV1,
)
from redagent_platform.campaign_service.repository import (
    EffectReservationCommand,
    CampaignRepository,
    CampaignRecordConflict,
)
from redagent_platform.campaign_service.registry import (
    ExecutionReadinessFacts,
    StrategyLoopMode,
    closed_execution_registry,
    evaluate_strategy_loop_readiness,
)
from redagent_platform.campaign_service.resolver import (
    CampaignContextResolver,
    ResolutionRequest,
)
from redagent_platform.campaign_service.service import (
    EffectDispatchCommand,
    EffectReconciliationCommand,
    CampaignCoreEtagConflict,
    binding_from_campaign_context,
)
from redagent_platform.runner_service.campaign_dispatch import CampaignAdapterRequest
from redagent_platform.containment_service.contracts import (
    ControlScope,
    ControlScopeKind,
    SCHEMA_VERSION as CONTAINMENT_SCHEMA_VERSION,
    StopRequest,
)
from redagent_platform.containment_service.repository import ContainmentRepository
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    ClosedLoopContainActivityCommand,
    ClosedLoopDispatchActivityCommand,
    ClosedLoopReconcileActivityCommand,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import IdempotencyConflict


class ActivitySafetyGate(Protocol):
    async def check(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        engagement_id: str,
        target_id: str,
        capability_id: str,
        now: datetime,
    ) -> tuple[bool, bool]:
        """Return (current authority, infrastructure readiness)."""
        ...


class ActivityContainmentOwner(Protocol):
    async def contain(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        signal_id: str,
        actor_user_id: str,
        reason_sha256: str,
        now: datetime,
        correlation_id: str,
    ) -> tuple[str, str]:
        """Return one closed containment state and reason after cleanup observation."""
        ...


class ActivityReadinessFactsOwner(Protocol):
    async def read(
        self,
        *,
        tenant_id: str,
        capability_id: str,
        now: datetime,
    ) -> ExecutionReadinessFacts:
        """Read current dependency health without granting execution authority."""
        ...


class ResolverActivitySafetyGate:
    """Recheck canonical authority and complete two-capability readiness per Activity."""

    def __init__(
        self,
        resolver: CampaignContextResolver,
        readiness_facts_owner: ActivityReadinessFactsOwner,
    ) -> None:
        self._resolver = resolver
        self._readiness_facts_owner = readiness_facts_owner

    async def check(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        engagement_id: str,
        target_id: str,
        capability_id: str,
        now: datetime,
    ) -> tuple[bool, bool]:
        # CRITICAL: the workflow payload is not an execution registry or authority source.
        capability_key = f"{capability_id}@2"
        if capability_key not in closed_execution_registry():
            return False, False
        resolution = await self._resolver.resolve(
            ResolutionRequest(
                tenant_id=tenant_id,
                principal_id=principal_id,
                engagement_id=engagement_id,
                target_id=target_id,
            ),
            now=now,
        )
        facts = await self._readiness_facts_owner.read(
            tenant_id=tenant_id,
            capability_id=capability_id,
            now=now,
        )
        readiness = evaluate_strategy_loop_readiness(
            StrategyLoopMode.TWO_CAPABILITY,
            facts,
        )
        infrastructure_available = (
            readiness.ready
            and readiness.execution_enabled
            and capability_key in readiness.capability_ids
        )
        return bool(resolution.allowed), infrastructure_available


class PostgresActivityContainmentOwner:
    """Persist a campaign stop without bypassing compat_101 dual-control activation."""

    def __init__(self, sessions: object) -> None:
        self._sessions = sessions

    async def contain(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        signal_id: str,
        actor_user_id: str,
        reason_sha256: str,
        now: datetime,
        correlation_id: str,
    ) -> tuple[str, str]:
        if (
            len(reason_sha256) != 64
            or any(character not in "0123456789abcdef" for character in reason_sha256)
        ):
            raise ValueError("campaign_containment_reason_sha256_invalid")
        stable = hashlib.sha256(
            f"{tenant_id}\0{campaign_id}\0{signal_id}".encode("utf-8")
        ).hexdigest()[:32]
        request = StopRequest(
            schema_version=CONTAINMENT_SCHEMA_VERSION,
            stop_id=f"stop-r123-{stable}",
            tenant_id=tenant_id,
            scope=ControlScope(ControlScopeKind.CAMPAIGN, campaign_id),
            initiated_by=actor_user_id,
            reason=f"r123_campaign_stop:{reason_sha256}",
            requested_at=now,
            expected_version=1,
            idempotency_key=f"r123-campaign-stop-{stable}",
        )
        async with self._sessions() as session, session.begin():
            control = await ContainmentRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_user_id,
                correlation_id=correlation_id,
            ).request_stop(request)
        # CRITICAL: campaign-scope compat_101 controls require distinct-person approval and
        # cleanup observation; a durable request alone must never claim containment.
        state = str(control["control_state"])
        if state == "pending_approval":
            return "manual_review_required", "campaign_stop_pending_dual_control"
        if state == "active":
            return "manual_review_required", "campaign_stop_active_cleanup_required"
        return "containment_failed", "campaign_stop_state_invalid"


@dataclass(frozen=True, slots=True)
class _Common:
    tenant_id: str
    campaign_id: str
    engagement_id: str
    target_id: str
    principal_id: str
    strategy_record_id: str
    strategy_revision_id: str
    envelope_sha256: str
    workflow_request_sha256: str
    aggregate_sequence: int
    replan_count: int
    context_payload: dict[str, object]
    plan_payload: dict[str, object]
    status: str


class PostgresCampaignActivityStateOwner:
    """Fresh-read, tenant-scoped owner for reconcile/dispatch/contain transitions."""

    def __init__(
        self,
        sessions: object,
        *,
        safety_gate: ActivitySafetyGate,
        containment_owner: ActivityContainmentOwner,
        actor_user_id: str = "redagent-workflow",
    ) -> None:
        self._sessions = sessions
        self._safety_gate = safety_gate
        self._containment_owner = containment_owner
        self._actor_user_id = actor_user_id

    async def read_reconcile(
        self,
        command: ClosedLoopReconcileActivityCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ReconcileMaterial:
        async with self._sessions() as session, session.begin():
            common = await _read_common(session, command.tenant_id, command.campaign_id)
            await _validate_common_reconcile(session, common, command)
            action, effect = await _current_action_and_effect(session, common)
        capability_id = _required_text(action, "capability_id")
        capability_revision = 2
        binding = binding_from_campaign_context(common.context_payload, capability_id)
        node_id, effect_id, invocation_id, effect_record_id = _stable_effect_ids(
            common, capability_id
        )
        if effect is not None:
            node_id = str(effect["node_id"])
            effect_id = str(effect["effect_id"])
            invocation_id = str(effect["invocation_id"])
        intent_payload = _effect_intent_payload(
            common,
            capability_id=capability_id,
            capability_revision=capability_revision,
            node_id=node_id,
            effect_id=effect_id,
            invocation_id=invocation_id,
        )
        intent_sha256 = _canonical_sha256(intent_payload)
        if effect is not None and (
            effect["effect_intent_sha256"] != intent_sha256
            or effect["effect_intent_payload"] != intent_payload
            or effect["envelope_sha256"] != common.envelope_sha256
        ):
            raise CampaignRecordConflict("campaign_effect_intent_binding_mismatch")
        authority_current, infrastructure_available = await self._safety_gate.check(
            tenant_id=common.tenant_id,
            principal_id=common.principal_id,
            engagement_id=common.engagement_id,
            target_id=common.target_id,
            capability_id=capability_id,
            now=now,
        )
        observed = await self._observed(
            common, effect, infrastructure_available=infrastructure_available
        )
        effect_reconciliation = None
        if effect is not None and effect["effect_state"] == "reconciliation_required":
            effect_reconciliation = await self._effect_reconciliation_command(
                common,
                effect,
                binding=binding,
            )
        replay_revision = (
            common.aggregate_sequence
            if common.aggregate_sequence == command.revision + 1
            and await self._is_reconcile_replay(
                command, node_id=node_id, effect_id=effect_id
            )
            else None
        )
        if common.aggregate_sequence not in {
            command.revision,
            command.revision + 1 if replay_revision is not None else command.revision,
        }:
            raise CampaignRecordConflict("campaign_reconcile_revision_conflict")
        return ReconcileMaterial(
            tenant_id=common.tenant_id,
            campaign_id=common.campaign_id,
            strategy_revision_id=common.strategy_revision_id,
            envelope_sha256=common.envelope_sha256,
            workflow_request_sha256=common.workflow_request_sha256,
            revision=command.revision,
            depth=_effect_depth(common.plan_payload, capability_id),
            replan_count=common.replan_count,
            node_id=node_id,
            effect_id=effect_id,
            desired=NodeDesiredV1(
                schema_version="redagent.r123-node-desired/v1",
                tenant_id=common.tenant_id,
                plan_revision_id=common.strategy_revision_id,
                node_id=node_id,
                effect_intent_sha256=intent_sha256,
                max_attempts=2,
                stop_requested=command.stop_requested or common.status == "contained",
                authority_current=authority_current,
                budget_available=(effect is None or int(effect["dispatch_attempt"]) < 2),
                successor_allowed=_plan_depth(common.plan_payload) > 1,
                obligations=_obligations(),
            ),
            observed=observed,
            committed_revision=replay_revision,
            effect_reconciliation=effect_reconciliation,
        )

    async def _effect_reconciliation_command(
        self,
        common: _Common,
        effect: object,
        *,
        binding: CapabilityBindingKeyV1,
    ) -> EffectReconciliationCommand:
        jobs = metadata.tables["jobs"]
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, common.tenant_id)
            rows = (
                await session.execute(
                    select(jobs.c.manifest_v2_sha256).where(
                        jobs.c.tenant_id == common.tenant_id,
                        jobs.c.campaign_id == common.campaign_id,
                        jobs.c.strategy_revision_id == common.strategy_record_id,
                        jobs.c.effect_id == effect["effect_id"],
                    )
                )
            ).scalars().all()
        if len(rows) != 1 or not isinstance(rows[0], str):
            raise CampaignRecordConflict("campaign_effect_manifest_v2_ambiguous")
        command = _effect_dispatch_command(common, effect, binding)
        request = CampaignAdapterRequest(
            tenant_id=command.tenant_id,
            capability_id=command.binding.capability_id,
            capability_revision=command.binding.capability_revision,
            adapter_id=command.binding.adapter_id,
            adapter_version=command.binding.adapter_version,
            profile_id=command.binding.profile_id,
            profile_revision=command.binding.profile_revision,
            profile_sha256=command.binding.profile_sha256,
            bundle_id=command.binding.bundle_id,
            bundle_revision=command.binding.bundle_revision,
            bundle_sha256=command.binding.bundle_sha256,
            invocation_id=command.invocation_id,
            effect_id=command.effect_id,
            envelope_sha256=command.envelope_sha256,
            manifest_v2_sha256=rows[0],
        )
        request_sha256 = _canonical_sha256(asdict(request))
        started_at = effect["started_at"]
        runner_id = effect["runner_id"]
        workload_identity = effect["workload_identity"]
        if (
            effect["request_sha256"] != request_sha256
            or not isinstance(started_at, datetime)
            or not isinstance(runner_id, str)
            or not isinstance(workload_identity, str)
        ):
            raise CampaignRecordConflict("campaign_effect_reconciliation_binding_invalid")
        return EffectReconciliationCommand(
            effect_command=command,
            request=request,
            request_sha256=request_sha256,
            runner_id=runner_id,
            workload_identity=workload_identity,
            started_at=started_at,
        )

    async def commit_reconcile(
        self,
        command: ClosedLoopReconcileActivityCommand,
        material: ReconcileMaterial,
        decision: ReconcileResultV1,
        *,
        now: datetime,
        correlation_id: str,
    ) -> int:
        if material.committed_revision is not None:
            return material.committed_revision
        async with self._sessions() as session, session.begin():
            repo = _repo(
                session,
                tenant_id=command.tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=correlation_id,
            )
            if decision.outcome.value == "dispatch_once" and material.observed.effect_state == "absent":
                common = await _read_common(session, command.tenant_id, command.campaign_id)
                action = _action_for_node(common, material.node_id)
                capability_id = _required_text(action, "capability_id")
                node_id, effect_id, invocation_id, record_id = _stable_effect_ids(
                    common, capability_id
                )
                intent = _effect_intent_payload(
                    common,
                    capability_id=capability_id,
                    capability_revision=2,
                    node_id=node_id,
                    effect_id=effect_id,
                    invocation_id=invocation_id,
                )
                result = await repo.reserve_effect(
                    EffectReservationCommand(
                        effect_record_id=record_id,
                        effect_id=effect_id,
                        campaign_id=common.campaign_id,
                        strategy_record_id=common.strategy_record_id,
                        node_id=node_id,
                        invocation_id=invocation_id,
                        effect_intent_sha256=_canonical_sha256(intent),
                        effect_intent_payload=intent,
                        envelope_sha256=common.envelope_sha256,
                    ),
                    occurred_at=now,
                )
                return result.aggregate_sequence
            return await repo.record_activity_checkpoint(
                campaign_id=material.campaign_id,
                strategy_revision_id=material.strategy_revision_id,
                expected_aggregate_sequence=command.revision,
                checkpoint_kind="reconcile",
                outcome=decision.outcome.value,
                reason=decision.reason_code,
                effect_id=material.effect_id,
                occurred_at=now,
            )

    async def read_dispatch(
        self,
        command: ClosedLoopDispatchActivityCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> DispatchMaterial:
        async with self._sessions() as session, session.begin():
            common = await _read_common(session, command.tenant_id, command.campaign_id)
            effect = await _read_effect(session, common, effect_id=command.effect_id)
            if effect is None:
                raise CampaignRecordConflict("campaign_dispatch_effect_not_found")
            replay = await _read_checkpoint_replay(
                session,
                tenant_id=command.tenant_id,
                campaign_id=command.campaign_id,
                source_revision=command.expected_revision,
                checkpoint_kind="dispatch",
            )
        binding = binding_from_campaign_context(
            common.context_payload,
            _effect_capability_id(effect),
        )
        material = DispatchMaterial(
            tenant_id=common.tenant_id,
            campaign_id=common.campaign_id,
            strategy_revision_id=common.strategy_revision_id,
            node_id=str(effect["node_id"]),
            effect_id=str(effect["effect_id"]),
            envelope_sha256=common.envelope_sha256,
            revision=command.expected_revision,
            effect_command=_effect_dispatch_command(common, effect, binding),
            effect_state=str(effect["effect_state"]),
            committed_state=None if replay is None else str(replay["outcome"]),
            committed_failure_code=(
                None
                if replay is None or replay["reason"] == "effect_receipt_committed"
                else str(replay["reason"])
            ),
            committed_revision=(None if replay is None else command.expected_revision + 1),
        )
        if common.aggregate_sequence != (
            material.committed_revision or command.expected_revision
        ):
            raise CampaignRecordConflict("campaign_dispatch_revision_conflict")
        return material

    async def commit_dispatch(
        self,
        command: ClosedLoopDispatchActivityCommand,
        material: DispatchMaterial,
        *,
        state: str,
        failure_code: str | None,
        now: datetime,
        correlation_id: str,
    ) -> int:
        if material.committed_revision is not None:
            return material.committed_revision
        reason = failure_code or "effect_receipt_committed"
        async with self._sessions() as session, session.begin():
            repo = _repo(
                session,
                tenant_id=command.tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=correlation_id,
            )
            if (
                state == "reconciliation_required"
                and material.effect_state != "reconciliation_required"
            ):
                expected_dispatching_version = (
                    material.effect_command.expected_claim_version
                    if material.effect_state == "dispatching"
                    else material.effect_command.expected_claim_version + 2
                )
                # CRITICAL: close possible acceptance and checkpoint in one transaction.
                await repo.record_effect_ambiguity(
                    effect_id=material.effect_id,
                    claim_owner=material.effect_command.claim_owner,
                    expected_claim_version=expected_dispatching_version,
                    failure_code="adapter_receipt_commit_unknown",
                    occurred_at=now,
                )
            return await repo.record_activity_checkpoint(
                campaign_id=material.campaign_id,
                strategy_revision_id=material.strategy_revision_id,
                expected_aggregate_sequence=command.expected_revision,
                checkpoint_kind="dispatch",
                outcome=state,
                reason=reason,
                effect_id=material.effect_id,
                occurred_at=now,
            )

    async def contain(
        self,
        command: ClosedLoopContainActivityCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ContainmentCommit:
        async with self._sessions() as session, session.begin():
            return await self.contain_in_session(
                session,
                command,
                now=now,
                correlation_id=correlation_id,
            )

    async def contain_in_session(
        self,
        session: object,
        command: ClosedLoopContainActivityCommand,
        *,
        now: datetime,
        correlation_id: str,
    ) -> ContainmentCommit:
        """Commit the canonical containment checkpoint in the caller-owned transaction."""

        common = await _read_common(session, command.tenant_id, command.campaign_id)
        replay = await _read_checkpoint_replay(
            session,
            tenant_id=command.tenant_id,
            campaign_id=command.campaign_id,
            source_revision=command.expected_revision,
            checkpoint_kind="contain",
        )
        if replay is not None:
            return ContainmentCommit(
                campaign_id=common.campaign_id,
                state=str(replay["outcome"]),
                revision=command.expected_revision + 1,
                reason=str(replay["reason"]),
            )
        if (
            common.strategy_revision_id != command.strategy_revision_id
            or common.aggregate_sequence != command.expected_revision
        ):
            raise CampaignRecordConflict("campaign_containment_binding_conflict")
        state, reason = await self._containment_owner.contain(
            tenant_id=common.tenant_id,
            campaign_id=common.campaign_id,
            signal_id=command.signal_id,
            actor_user_id=command.actor_user_id,
            reason_sha256=command.reason_sha256,
            now=now,
            correlation_id=correlation_id,
        )
        if state not in {"contained", "manual_review_required", "containment_failed"}:
            raise ValueError("campaign_containment_state_invalid")
        revision = await _repo(
            session,
            tenant_id=command.tenant_id,
            actor_user_id=command.actor_user_id,
            correlation_id=correlation_id,
        ).record_activity_checkpoint(
            campaign_id=common.campaign_id,
            strategy_revision_id=common.strategy_revision_id,
            expected_aggregate_sequence=command.expected_revision,
            checkpoint_kind="contain",
            outcome=state,
            reason=reason,
            effect_id=None,
            occurred_at=now,
        )
        return ContainmentCommit(
            campaign_id=common.campaign_id,
            state=state,
            revision=revision,
            reason=reason,
        )

    async def _observed(
        self,
        common: _Common,
        effect: object,
        *,
        infrastructure_available: bool,
    ) -> NodeObservedV1:
        if effect is None:
            state = "absent"
            attempts = 0
            next_retry = None
            receipt_state = None
            receipt_sha = None
            evidence_ids: tuple[str, ...] = ()
            cleanup = False
        else:
            row = effect
            state = "absent" if row["effect_state"] == "reserved" else str(row["effect_state"])
            attempts = int(row["dispatch_attempt"])
            next_retry = row["next_retry_at"]
            receipt_state = (
                None
                if row["reconciliation_state"] == "none"
                else ReconciliationState(str(row["reconciliation_state"]))
            )
            receipt_sha = row["effect_receipt_sha256"]
            evidence_ids = tuple(row["evidence_ids"] or ())
            cleanup = row["cleanup_receipt_id"] is not None
        report_safe = False
        base_result_complete = False
        trusted_result_complete = False
        terminal_result_complete = False
        if evidence_ids:
            async with self._sessions() as session, session.begin():
                await _tenant_context(session, common.tenant_id)
                artifacts = metadata.tables["evidence_artifacts"]
                rows = (
                    await session.execute(
                        select(artifacts).where(
                            artifacts.c.tenant_id == common.tenant_id,
                            artifacts.c.id.in_(evidence_ids),
                        )
                    )
                ).mappings().all()
                report_safe = len(rows) == len(evidence_ids) and all(
                    row["artifact_class"] in {"report_safe", "export_safe"}
                    and row["redaction_state"] == row["artifact_class"]
                    and row["quarantine_reason"] is None
                    and row["finalized_at"] is not None
                    for row in rows
                )
        confirmed = state == "confirmed"
        if confirmed and effect is not None:
            external_receipt_id = effect["external_receipt_id"]
            cleanup_receipt_id = effect["cleanup_receipt_id"]
            if isinstance(external_receipt_id, str) and isinstance(
                cleanup_receipt_id, str
            ):
                try:
                    async with self._sessions() as session, session.begin():
                        await _repo(
                            session,
                            tenant_id=common.tenant_id,
                            actor_user_id=self._actor_user_id,
                            correlation_id=f"r123-observed-{effect['effect_id']}",
                        ).validate_trusted_effect_owners(
                            effect_id=str(effect["effect_id"]),
                            external_receipt_id=external_receipt_id,
                            evidence_ids=evidence_ids,
                            cleanup_receipt_id=cleanup_receipt_id,
                            require_complete_coverage=False,
                            require_retest=False,
                        )
                    base_result_complete = True
                    try:
                        async with self._sessions() as session, session.begin():
                            await _repo(
                                session,
                                tenant_id=common.tenant_id,
                                actor_user_id=self._actor_user_id,
                                correlation_id=f"r123-terminal-observed-{effect['effect_id']}",
                            ).validate_trusted_effect_owners(
                                effect_id=str(effect["effect_id"]),
                                external_receipt_id=external_receipt_id,
                                evidence_ids=evidence_ids,
                                cleanup_receipt_id=cleanup_receipt_id,
                                require_retest=False,
                            )
                        trusted_result_complete = True
                    except CampaignRecordConflict:
                        trusted_result_complete = False
                    try:
                        async with self._sessions() as session, session.begin():
                            await _repo(
                                session,
                                tenant_id=common.tenant_id,
                                actor_user_id=self._actor_user_id,
                                correlation_id=f"r123-terminal-observed-{effect['effect_id']}",
                            ).validate_trusted_effect_owners(
                                effect_id=str(effect["effect_id"]),
                                external_receipt_id=external_receipt_id,
                                evidence_ids=evidence_ids,
                                cleanup_receipt_id=cleanup_receipt_id,
                            )
                        terminal_result_complete = True
                    except CampaignRecordConflict:
                        terminal_result_complete = False
                except CampaignRecordConflict:
                    # Missing owner truth is an observed incomplete obligation, not success.
                    base_result_complete = False
        return NodeObservedV1(
            schema_version="redagent.r123-node-observed/v1",
            effect_state=state,
            attempt_count=attempts,
            next_retry_at=next_retry,
            receipt_state=receipt_state,
            effect_receipt_sha256=receipt_sha,
            evidence_complete=base_result_complete,
            report_safe_evidence_complete=report_safe and base_result_complete,
            finding_or_coverage_complete=trusted_result_complete,
            retest_complete=terminal_result_complete,
            secret_revocation_complete=base_result_complete,
            containment_complete=base_result_complete,
            cleanup_complete=cleanup and base_result_complete,
            reconciliation_complete=confirmed and base_result_complete,
            residual_risk_complete=base_result_complete,
            infrastructure_available=infrastructure_available,
        )

    async def _is_reconcile_replay(
        self,
        command: ClosedLoopReconcileActivityCommand,
        *,
        node_id: str,
        effect_id: str,
    ) -> bool:
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, command.tenant_id)
            outbox = metadata.tables["outbox_events"]
            row = (
                await session.execute(
                    select(outbox.c.event_type, outbox.c.payload).where(
                        outbox.c.tenant_id == command.tenant_id,
                        outbox.c.aggregate_id == command.campaign_id,
                        outbox.c.aggregate_sequence == command.revision + 1,
                    )
                )
            ).mappings().one_or_none()
        if row is None:
            return False
        if row["event_type"] == "effect.dispatch.requested.v1":
            return row["payload"].get("node_id") == node_id and row["payload"].get("effect_id") == effect_id
        return (
            row["event_type"] == "campaign.activity.checkpoint.v1"
            and row["payload"].get("source_revision") == command.revision
            and row["payload"].get("checkpoint_kind") == "reconcile"
            and row["payload"].get("effect_id") == effect_id
        )


@dataclass(frozen=True, slots=True)
class CampaignCoreRecoveryCommit:
    state: str
    revision: int
    replayed: bool


class PostgresCampaignCoreRecoveryOwner:
    """Persist compat_124 idempotency around the canonical campaign containment transition."""

    def __init__(
        self,
        sessions: object,
        state_owner: PostgresCampaignActivityStateOwner,
    ) -> None:
        self._sessions = sessions
        self._state_owner = state_owner

    async def recover(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        signal_id: str,
        actor_user_id: str,
        reason_sha256: str,
        expected_revision: int,
        idempotency_key: str,
        request_sha256: str,
        now: datetime,
        correlation_id: str,
    ) -> CampaignCoreRecoveryCommit:
        operation = "campaign.r124.recovery"
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, tenant_id)
            await session.execute(
                text("SELECT pg_advisory_xact_lock(:lock_key)"),
                {"lock_key": _campaign_core_recovery_lock(tenant_id, idempotency_key)},
            )
            replay = await _campaign_core_recovery_replay(
                session,
                tenant_id=tenant_id,
                operation=operation,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            common = await _read_common(session, tenant_id, campaign_id)
            if common.aggregate_sequence != expected_revision:
                raise CampaignCoreEtagConflict("r124_etag_conflict")
            command = ClosedLoopContainActivityCommand(
                schema_version=CONTRACT_SCHEMA_VERSION,
                tenant_id=tenant_id,
                campaign_id=campaign_id,
                strategy_revision_id=common.strategy_revision_id,
                signal_id=signal_id,
                actor_user_id=actor_user_id,
                reason_sha256=reason_sha256,
                expected_revision=expected_revision,
            )
            try:
                # CRITICAL: checkpoint and replay receipt share this locked transaction.
                committed = await self._state_owner.contain_in_session(
                    session,
                    command,
                    now=now,
                    correlation_id=correlation_id,
                )
            except CampaignRecordConflict as exc:
                raise CampaignCoreEtagConflict("r124_etag_conflict") from exc

            result = CampaignCoreRecoveryCommit(
                state=committed.state,
                revision=committed.revision,
                replayed=False,
            )
            await session.execute(
                insert(metadata.tables["idempotency_records"]).values(
                    id=f"idem-{uuid4().hex}",
                    tenant_id=tenant_id,
                    operation=operation,
                    idempotency_key=idempotency_key,
                    request_hash=request_sha256,
                    response_status=202,
                    response_body={
                        "state": result.state,
                        "revision": result.revision,
                    },
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )
        return result


async def _campaign_core_recovery_replay(
    session: object,
    *,
    tenant_id: str,
    operation: str,
    idempotency_key: str,
    request_sha256: str,
) -> CampaignCoreRecoveryCommit | None:
    records = metadata.tables["idempotency_records"]
    prior = (
        await session.execute(
            select(records.c.request_hash, records.c.response_body).where(
                records.c.tenant_id == tenant_id,
                records.c.operation == operation,
                records.c.idempotency_key == idempotency_key,
            )
        )
    ).mappings().one_or_none()
    if prior is None:
        return None
    if prior["request_hash"] != request_sha256:
        raise IdempotencyConflict("idempotency_key_request_mismatch")
    body = prior["response_body"]
    if not isinstance(body, dict):
        raise ValueError("r124_recovery_replay_invalid")
    state = body.get("state")
    revision = body.get("revision")
    if not isinstance(state, str) or isinstance(revision, bool) or not isinstance(revision, int):
        raise ValueError("r124_recovery_replay_invalid")
    return CampaignCoreRecoveryCommit(state=state, revision=revision, replayed=True)


def _campaign_core_recovery_lock(tenant_id: str, idempotency_key: str) -> int:
    digest = hashlib.sha256(
        f"{tenant_id}\x1fcampaign.r124.recovery\x1f{idempotency_key}".encode()
    ).digest()
    return int.from_bytes(digest[:8], "big", signed=True)


async def _read_common(session, tenant_id: str, campaign_id: str) -> _Common:
    await _tenant_context(session, tenant_id)
    campaigns = metadata.tables["campaigns"]
    strategies = metadata.tables["campaign_strategy_revisions"]
    outbox = metadata.tables["outbox_events"]
    row = (
        await session.execute(
            select(
                campaigns.c.id.label("campaign_id"),
                campaigns.c.engagement_id,
                campaigns.c.status,
                campaigns.c.aggregate_sequence,
                campaigns.c.replan_count,
                strategies.c.id.label("strategy_record_id"),
                strategies.c.strategy_revision_id,
                strategies.c.envelope_sha256,
                strategies.c.context_payload,
                strategies.c.plan_payload,
                strategies.c.created_by_user_id,
            )
            .join(strategies, strategies.c.id == campaigns.c.current_strategy_revision_id)
            .where(
                campaigns.c.tenant_id == tenant_id,
                campaigns.c.id == campaign_id,
                strategies.c.tenant_id == tenant_id,
            )
        )
    ).mappings().one_or_none()
    if row is None:
        raise CampaignRecordConflict("campaign_activity_state_not_found")
    start_payload = await session.scalar(
        select(outbox.c.payload).where(
            outbox.c.tenant_id == tenant_id,
            outbox.c.aggregate_id == campaign_id,
            outbox.c.event_type == "workflow.start.requested.v1",
            outbox.c.aggregate_sequence == 1,
        )
    )
    if not isinstance(start_payload, dict):
        raise CampaignRecordConflict("campaign_activity_start_lineage_not_found")
    if (
        start_payload.get("principal_id") != row["created_by_user_id"]
        or start_payload.get("engagement_id") != row["engagement_id"]
    ):
        raise CampaignRecordConflict("campaign_activity_start_lineage_mismatch")
    return _Common(
        tenant_id=tenant_id,
        campaign_id=str(row["campaign_id"]),
        engagement_id=str(row["engagement_id"]),
        target_id=str(start_payload["target_id"]),
        principal_id=str(row["created_by_user_id"]),
        strategy_record_id=str(row["strategy_record_id"]),
        strategy_revision_id=str(row["strategy_revision_id"]),
        envelope_sha256=str(row["envelope_sha256"]),
        workflow_request_sha256=str(start_payload["workflow_request_sha256"]),
        aggregate_sequence=int(row["aggregate_sequence"]),
        replan_count=int(row["replan_count"]),
        context_payload=dict(row["context_payload"]),
        plan_payload=dict(row["plan_payload"]),
        status=str(row["status"]),
    )


async def _validate_common_reconcile(session, common: _Common, command) -> None:
    if (
        common.tenant_id != command.tenant_id
        or common.campaign_id != command.campaign_id
        or common.strategy_revision_id != command.strategy_revision_id
        or common.envelope_sha256 != command.envelope_sha256
        or common.workflow_request_sha256 != command.workflow_request_sha256
        or common.status == "completed"
    ):
        raise CampaignRecordConflict("campaign_reconcile_binding_conflict")


async def _read_effect(session, common: _Common, *, effect_id: str | None = None):
    rows = await _read_effect_rows(session, common, effect_id=effect_id)
    return rows[-1] if rows else None


async def _read_effect_rows(
    session,
    common: _Common,
    *,
    effect_id: str | None = None,
):
    effects = metadata.tables["campaign_effects"]
    query = select(effects).where(
        effects.c.tenant_id == common.tenant_id,
        effects.c.campaign_id == common.campaign_id,
        effects.c.strategy_revision_id == common.strategy_record_id,
    )
    if effect_id is not None:
        query = query.where(effects.c.effect_id == effect_id)
    rows = (await session.execute(query.order_by(effects.c.outbox_sequence))).mappings().all()
    if len(rows) > 1 and effect_id is not None:
        raise CampaignRecordConflict("campaign_dispatch_effect_inventory_invalid")
    if len(rows) > 2:
        raise CampaignRecordConflict("campaign_effect_depth_exceeded")
    return rows


async def _read_checkpoint_replay(
    session,
    *,
    tenant_id: str,
    campaign_id: str,
    source_revision: int,
    checkpoint_kind: str,
):
    await _tenant_context(session, tenant_id)
    outbox = metadata.tables["outbox_events"]
    payload = await session.scalar(
        select(outbox.c.payload).where(
            outbox.c.tenant_id == tenant_id,
            outbox.c.aggregate_id == campaign_id,
            outbox.c.aggregate_sequence == source_revision + 1,
            outbox.c.event_type == "campaign.activity.checkpoint.v1",
        )
    )
    if payload is None:
        return None
    if (
        payload.get("source_revision") != source_revision
        or payload.get("checkpoint_kind") != checkpoint_kind
    ):
        raise CampaignRecordConflict("campaign_activity_checkpoint_replay_conflict")
    return payload


def _selected_action(plan: dict[str, object], effect) -> dict[str, object]:
    primary = plan.get("primary")
    if not isinstance(primary, dict):
        raise CampaignRecordConflict("campaign_plan_primary_invalid")
    if effect is None or _effect_capability_id(effect) == primary.get("capability_id"):
        return primary
    successor = plan.get("successor")
    if not isinstance(successor, dict) or not isinstance(successor.get("action"), dict):
        raise CampaignRecordConflict("campaign_plan_effect_binding_invalid")
    return successor["action"]


async def _current_action_and_effect(
    session: object,
    common: _Common,
) -> tuple[dict[str, object], object | None]:
    effects = await _read_effect_rows(session, common)
    primary = common.plan_payload.get("primary")
    if not isinstance(primary, dict):
        raise CampaignRecordConflict("campaign_plan_primary_invalid")
    primary_effect = next(
        (
            row
            for row in effects
            if _effect_capability_id(row) == primary.get("capability_id")
        ),
        None,
    )
    if primary_effect is None:
        return primary, None
    successor = common.plan_payload.get("successor")
    if not isinstance(successor, dict) or not isinstance(successor.get("action"), dict):
        return primary, primary_effect
    if primary_effect["effect_state"] != "confirmed":
        return primary, primary_effect
    coverage_state = await _effect_observation_coverage(
        session,
        common,
        primary_effect,
    )
    if coverage_state is None:
        return primary, primary_effect
    condition = successor.get("condition")
    successor_required = condition == "explicit_corroboration" or (
        condition == "fresh_inconclusive_or_insufficient_observation"
        and coverage_state in {"partial", "unknown"}
    )
    if not successor_required:
        return primary, primary_effect
    action = successor["action"]
    successor_effect = next(
        (
            row
            for row in effects
            if _effect_capability_id(row) == action.get("capability_id")
        ),
        None,
    )
    return action, successor_effect


async def _effect_observation_coverage(
    session: object,
    common: _Common,
    effect: object,
) -> str | None:
    external_receipt_id = effect["external_receipt_id"]
    if not isinstance(external_receipt_id, str):
        return None
    capability = effect["effect_intent_payload"].get("capability_id")
    binding = closed_execution_registry().get(capability)
    if binding is None:
        return None
    imports = metadata.tables["finding_import_sessions"]
    row = (
        await session.execute(
            select(
                imports.c.coverage_state,
                imports.c.adapter_id,
                imports.c.import_state,
            ).where(
                imports.c.tenant_id == common.tenant_id,
                imports.c.run_id == external_receipt_id,
            )
        )
    ).mappings().one_or_none()
    if row is None or (
        row["adapter_id"] != binding.adapter_id
        or row["import_state"] != "accepted"
        or row["coverage_state"] not in {"complete", "partial", "unknown"}
    ):
        return None
    return str(row["coverage_state"])


def _action_for_node(common: _Common, node_id: str) -> dict[str, object]:
    primary = common.plan_payload.get("primary")
    candidates = [primary]
    successor = common.plan_payload.get("successor")
    if isinstance(successor, dict):
        candidates.append(successor.get("action"))
    for action in candidates:
        if not isinstance(action, dict):
            continue
        capability_id = action.get("capability_id")
        if isinstance(capability_id, str) and _stable_effect_ids(
            common, capability_id
        )[0] == node_id:
            return action
    raise CampaignRecordConflict("campaign_plan_node_binding_invalid")


def _effect_capability_id(effect) -> str:
    value = effect["effect_intent_payload"].get("capability_id")
    if not isinstance(value, str) or "@" not in value:
        raise CampaignRecordConflict("campaign_effect_capability_invalid")
    capability_id, revision = value.rsplit("@", 1)
    if revision != "2":
        raise CampaignRecordConflict("campaign_effect_capability_revision_invalid")
    return capability_id


def _effect_dispatch_command(
    common: _Common,
    effect: object,
    binding: CapabilityBindingKeyV1,
) -> EffectDispatchCommand:
    return EffectDispatchCommand(
        tenant_id=common.tenant_id,
        principal_id=common.principal_id,
        engagement_id=common.engagement_id,
        target_id=common.target_id,
        effect_id=str(effect["effect_id"]),
        invocation_id=str(effect["invocation_id"]),
        effect_intent_sha256=str(effect["effect_intent_sha256"]),
        envelope_sha256=common.envelope_sha256,
        expected_claim_version=int(effect["claim_version"]),
        expected_dispatch_attempt=int(effect["dispatch_attempt"]),
        expected_dispatch_generation=int(effect["dispatch_generation"]),
        claim_owner=_claim_owner(common.campaign_id, str(effect["effect_id"])),
        binding=binding,
    )


def _stable_effect_ids(common: _Common, capability_id: str) -> tuple[str, str, str, str]:
    digest = hashlib.sha256(
        f"r123\0{common.tenant_id}\0{common.campaign_id}\0{common.strategy_revision_id}\0{capability_id}".encode()
    ).hexdigest()
    return (
        f"node-r123-{digest[:24]}",
        f"effect-r123-{digest[:24]}",
        f"invocation-r123-{digest[:24]}",
        f"r123ef-{digest[:32]}",
    )


def _effect_intent_payload(
    common: _Common,
    *,
    capability_id: str,
    capability_revision: int,
    node_id: str,
    effect_id: str,
    invocation_id: str,
) -> dict[str, object]:
    return {
        "schema_version": "redagent.r123-effect-intent/v1",
        "tenant_id": common.tenant_id,
        "campaign_id": common.campaign_id,
        "strategy_revision_id": common.strategy_revision_id,
        "node_id": node_id,
        "invocation_id": invocation_id,
        "effect_id": effect_id,
        "capability_id": f"{capability_id}@{capability_revision}",
        "target_id": common.target_id,
        "envelope_sha256": common.envelope_sha256,
    }


def _effect_depth(plan: dict[str, object], capability_id: str) -> int:
    primary = plan.get("primary")
    return 1 if isinstance(primary, dict) and primary.get("capability_id") == capability_id else 2


def _plan_depth(plan: dict[str, object]) -> int:
    value = plan.get("depth")
    if isinstance(value, bool) or not isinstance(value, int) or value not in {1, 2}:
        raise CampaignRecordConflict("campaign_plan_depth_invalid")
    return value


def _required_text(value: dict[str, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise CampaignRecordConflict(f"campaign_plan_{key}_invalid")
    return item


def _obligations() -> SafetyObligationsV1:
    return SafetyObligationsV1(
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
    )


def _claim_owner(campaign_id: str, effect_id: str) -> str:
    digest = hashlib.sha256(f"{campaign_id}\0{effect_id}".encode()).hexdigest()[:24]
    return f"r123-activity-{digest}"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _repo(session, *, tenant_id: str, actor_user_id: str, correlation_id: str):
    return CampaignRepository(
        session,
        tenant_id=tenant_id,
        actor_user_id=actor_user_id,
        correlation_id=correlation_id[:100],
    )


async def _tenant_context(session, tenant_id: str) -> None:
    # CRITICAL: Activity reads must use the same exact tenant RLS scope as writes.
    await session.execute(
        text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )
