"""PostgreSQL owner for deterministic DAG frontier and effect preparation."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from typing import Any
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.dag_execution import (
    DagFrontierOutcome,
    NodeExecutionFact,
    derive_dag_frontier,
)
from redagent_platform.campaign_service.dag_execution_activity import (
    DagActivityAction,
    DagActivityMaterialV1,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
    DagWorkflowInputV1,
    dag_workflow_request_sha256,
)
from redagent_platform.campaign_service.planning.contracts import (
    CapabilityOperatorV1,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.planning.serde import (
    parse_attack_path_dag_revision,
    parse_planning_domain,
)
from redagent_platform.campaign_service.repository import CampaignRepository
from redagent_platform.campaign_service.service import (
    EffectDispatchCommand,
    EffectReconciliationCommand,
    binding_from_campaign_context,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.runner_service.campaign_dispatch import (
    CampaignAdapterRequest,
)


class DagExecutionActivityConflict(RuntimeError):
    """Current durable facts do not match the admitted workflow input."""


class PostgresDagExecutionActivityStateOwner:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        actor_user_id: str,
        correlation_prefix: str,
    ) -> None:
        self._sessions = session_factory
        self._actor_user_id = actor_user_id
        self._correlation_prefix = correlation_prefix

    async def prepare(
        self, request: DagWorkflowInputV1, *, now: datetime
    ) -> DagActivityMaterialV1:
        _aware(now)
        async with self._sessions() as session, session.begin():
            repository = _Repository(
                session,
                actor_user_id=self._actor_user_id,
                correlation_prefix=self._correlation_prefix,
            )
            return await repository.prepare(request, now=now)

    async def snapshot(
        self, request: DagWorkflowInputV1, *, now: datetime
    ) -> DagExecutionSnapshotV1:
        _aware(now)
        async with self._sessions() as session, session.begin():
            repository = _Repository(
                session,
                actor_user_id=self._actor_user_id,
                correlation_prefix=self._correlation_prefix,
            )
            run, nodes = await repository.locked_run(request)
            return _snapshot(run, nodes)


class _Repository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        actor_user_id: str,
        correlation_prefix: str,
    ) -> None:
        self.session = session
        self.actor_user_id = actor_user_id
        self.correlation_prefix = correlation_prefix

    async def prepare(
        self, request: DagWorkflowInputV1, *, now: datetime
    ) -> DagActivityMaterialV1:
        run, nodes = await self.locked_run(request)
        if DagRunState(str(run["run_state"])) in {
            DagRunState.COMPLETED,
            DagRunState.CONTAINED,
            DagRunState.MANUAL_REVIEW_REQUIRED,
            DagRunState.FAILED_BEFORE_IO,
            DagRunState.FAILED,
        }:
            return DagActivityMaterialV1(
                DagActivityAction.TERMINAL, _snapshot(run, nodes), None, None
            )
        input_payload = run["input_payload"]
        if not isinstance(input_payload, dict):
            raise DagExecutionActivityConflict("dag_execution_input_invalid")
        revision_payload = input_payload.get("revision")
        domain_payload = input_payload.get("domain")
        if not isinstance(revision_payload, dict) or not isinstance(
            domain_payload, dict
        ):
            raise DagExecutionActivityConflict("dag_execution_input_invalid")
        revision = parse_attack_path_dag_revision(revision_payload)
        domain = parse_planning_domain(domain_payload)
        facts = tuple(
            NodeExecutionFact(str(node["node_id"]), DagNodeState(str(node["node_state"])))
            for node in nodes
        )
        frontier = derive_dag_frontier(revision, domain, facts)
        if run["run_state"] == DagRunState.START_PENDING.value:
            run = await self._advance_run(
                run,
                target=DagRunState.RUNNING,
                terminal_reason=None,
                now=now,
                started=True,
            )

        effects = metadata.tables["campaign_effects"]
        effect_rows = (
            await self.session.execute(
                select(effects)
                .where(
                    effects.c.tenant_id == request.tenant_id,
                    effects.c.execution_run_id == request.execution_run_id,
                    effects.c.strategy_revision_id.is_(None),
                )
                .order_by(effects.c.outbox_sequence, effects.c.effect_id)
                .with_for_update()
            )
        ).mappings().all()
        effects_by_node = {str(row["node_id"]): row for row in effect_rows}

        if frontier.outcome is DagFrontierOutcome.COMPLETED:
            if run["run_state"] != DagRunState.COMPLETED.value:
                run = await self._advance_run(
                    run,
                    target=DagRunState.COMPLETED,
                    terminal_reason="all_nodes_confirmed",
                    now=now,
                )
            return DagActivityMaterialV1(
                DagActivityAction.TERMINAL, _snapshot(run, nodes), None, None
            )
        if frontier.outcome in {
            DagFrontierOutcome.BLOCKED,
            DagFrontierOutcome.MANUAL_REVIEW_REQUIRED,
        }:
            target = (
                DagRunState.MANUAL_REVIEW_REQUIRED
                if frontier.outcome is DagFrontierOutcome.MANUAL_REVIEW_REQUIRED
                else DagRunState.FAILED_BEFORE_IO
            )
            run = await self._advance_run(
                run,
                target=target,
                terminal_reason=frontier.reason,
                now=now,
            )
            return DagActivityMaterialV1(
                DagActivityAction.TERMINAL, _snapshot(run, nodes), None, None
            )

        node_id = frontier.ready_node_id or frontier.active_node_id
        if node_id is None:
            raise DagExecutionActivityConflict("dag_execution_frontier_invalid")
        node = next((row for row in nodes if row["node_id"] == node_id), None)
        if node is None:
            raise DagExecutionActivityConflict("dag_execution_node_missing")
        binding = await self._binding_for_run(run, str(node["capability_id"]))
        operator = next(
            (item for item in domain.operators if item.operator_id == node["operator_id"]),
            None,
        )
        if operator is None or (
            operator.capability.capability_id != binding.capability_id
            or operator.capability.capability_revision != binding.capability_revision
            or operator.capability.execution_manifest_sha256
            != binding.execution_manifest_sha256
        ):
            raise DagExecutionActivityConflict("dag_execution_binding_substitution")

        effect: Any = effects_by_node.get(node_id)
        if effect is None:
            effect, node, run = await self._reserve_effect(
                run, node, operator, binding, now=now
            )
            nodes = tuple(
                node if item["node_id"] == node_id else item for item in nodes
            )
        command = _effect_command(run, node, effect, binding)
        if effect["effect_state"] in {"reserved", "not_applied"}:
            return DagActivityMaterialV1(
                DagActivityAction.DISPATCH,
                _snapshot(run, nodes),
                command,
                None,
            )
        if effect["effect_state"] == "claimed" and effect["claim_expires_at"] <= now:
            return DagActivityMaterialV1(
                DagActivityAction.DISPATCH,
                _snapshot(run, nodes),
                command,
                None,
            )
        if effect["effect_state"] == "claimed":
            return DagActivityMaterialV1(
                DagActivityAction.WAIT, _snapshot(run, nodes), None, None
            )
        if effect["effect_state"] == "dispatching":
            result = await CampaignRepository(
                self.session,
                tenant_id=request.tenant_id,
                actor_user_id=self.actor_user_id,
                correlation_id=f"{self.correlation_prefix}-recover-{node_id[-12:]}",
            ).record_effect_ambiguity(
                effect_id=command.effect_id,
                claim_owner=command.claim_owner,
                expected_claim_version=command.expected_claim_version,
                failure_code="worker_recovery_unknown",
                occurred_at=now,
            )
            effect = {**dict(effect), "effect_state": result.effect_state, "claim_version": result.claim_version}
            node, run = await self._mark_reconciliation(node, run, now=now)
            nodes = tuple(
                node if item["node_id"] == node_id else item for item in nodes
            )
            command = _effect_command(run, node, effect, binding)
        if effect["effect_state"] == "reconciliation_required":
            reconciliation = await self._reconciliation_command(
                run, node, effect, binding
            )
            return DagActivityMaterialV1(
                DagActivityAction.RECONCILE,
                _snapshot(run, nodes),
                None,
                reconciliation,
            )
        if effect["effect_state"] == "manual_review_required":
            return DagActivityMaterialV1(
                DagActivityAction.TERMINAL, _snapshot(run, nodes), None, None
            )
        raise DagExecutionActivityConflict("dag_execution_effect_state_invalid")

    async def _binding_for_run(
        self, run: Any, capability_id: str
    ) -> CapabilityBindingKeyV1:
        campaigns = metadata.tables["campaigns"]
        strategies = metadata.tables["campaign_strategy_revisions"]
        context_payload = await self.session.scalar(
            select(strategies.c.context_payload)
            .join(campaigns, campaigns.c.current_strategy_revision_id == strategies.c.id)
            .where(
                campaigns.c.tenant_id == run["tenant_id"],
                campaigns.c.id == run["campaign_id"],
                strategies.c.tenant_id == run["tenant_id"],
                strategies.c.campaign_id == run["campaign_id"],
            )
        )
        if not isinstance(context_payload, dict):
            raise DagExecutionActivityConflict("dag_execution_binding_context_missing")
        try:
            # CRITICAL: the immutable campaign context is the sole complete semantics binding;
            # rebuilding it from the smaller execution registry can silently drift digests.
            return binding_from_campaign_context(context_payload, capability_id)
        except ValueError as exc:
            raise DagExecutionActivityConflict(
                "dag_execution_binding_context_invalid"
            ) from exc

    async def locked_run(
        self, request: DagWorkflowInputV1
    ) -> tuple[Any, tuple[Any, ...]]:
        if not isinstance(request, DagWorkflowInputV1):
            raise ValueError("dag_activity_workflow_input_invalid")
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": request.tenant_id},
        )
        runs = metadata.tables["campaign_execution_runs"]
        run = (
            await self.session.execute(
                select(runs)
                .where(
                    runs.c.tenant_id == request.tenant_id,
                    runs.c.id == request.execution_run_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if run is None or (
            run["input_sha256"] != request.input_sha256
            or run["plan_sha256"] != request.plan_sha256
            or run["request_sha256"] != dag_workflow_request_sha256(request)
            or int(run["max_transitions"]) != request.max_transitions
        ):
            raise DagExecutionActivityConflict("dag_execution_workflow_binding_mismatch")
        nodes_table = metadata.tables["campaign_execution_nodes"]
        nodes = tuple(
            (
                await self.session.execute(
                    select(nodes_table)
                    .where(
                        nodes_table.c.tenant_id == request.tenant_id,
                        nodes_table.c.execution_run_id == request.execution_run_id,
                        nodes_table.c.campaign_id == run["campaign_id"],
                    )
                    .order_by(nodes_table.c.node_order)
                    .with_for_update()
                )
            ).mappings().all()
        )
        if not nodes:
            raise DagExecutionActivityConflict("dag_execution_nodes_missing")
        return run, nodes

    async def _reserve_effect(
        self,
        run: Any,
        node: Any,
        operator: CapabilityOperatorV1,
        binding: CapabilityBindingKeyV1,
        *,
        now: datetime,
    ) -> tuple[Any, Any, Any]:
        digest = hashlib.sha256(
            (
                f"campaign-dag-effect-v1\0{run['tenant_id']}\0{run['id']}\0"
                f"{node['node_id']}"
            ).encode("utf-8")
        ).hexdigest()
        effect_id = f"effect-dag-{digest[:32]}"
        invocation_id = f"invocation-dag-{digest[:32]}"
        intent = {
            "schema_version": "redagent.campaign-dag-effect-intent/v1",
            "tenant_id": str(run["tenant_id"]),
            "campaign_id": str(run["campaign_id"]),
            "execution_run_id": str(run["id"]),
            "node_id": str(node["node_id"]),
            "node_sha256": str(node["node_sha256"]),
            "target_id": str(node["target_id"]),
            "effect_id": effect_id,
            "invocation_id": invocation_id,
            "capability_id": binding.capability_id,
            "effect_class": operator.effect_class.value,
            "data_access_class": operator.data_access_class.value,
            "credential_class": operator.credential_class.value,
            "environment_class": str(node["environment"]),
            "binding": asdict(binding),
        }
        effect_sha256 = canonical_planning_sha256(intent)
        effects = metadata.tables["campaign_effects"]
        effect = (
            await self.session.execute(
                insert(effects)
                .values(
                    id=f"dagef-{digest[:32]}",
                    effect_id=effect_id,
                    campaign_id=run["campaign_id"],
                    strategy_revision_id=None,
                    execution_run_id=run["id"],
                    node_id=node["node_id"],
                    invocation_id=invocation_id,
                    effect_intent_sha256=effect_sha256,
                    effect_intent_payload=intent,
                    envelope_sha256=run["authority_sha256"],
                    effect_state="reserved",
                    claim_owner=None,
                    claim_expires_at=None,
                    claim_version=0,
                    dispatch_attempt=0,
                    dispatch_generation=0,
                    runner_id=None,
                    workload_identity=None,
                    request_sha256=None,
                    pre_io_policy_decision_id=None,
                    pre_io_policy_input_sha256=None,
                    pre_io_policy_valid_until=None,
                    pre_io_authorized_at=None,
                    effect_receipt_sha256=None,
                    effect_receipt_payload=None,
                    external_status=None,
                    external_receipt_id=None,
                    evidence_ids=[],
                    cleanup_receipt_id=None,
                    reconciliation_state="none",
                    reconciliation_evidence_ids=[],
                    redispatch_permitted=False,
                    failure_code=None,
                    next_retry_at=None,
                    outbox_sequence=int(run["transition_count"]) + 1,
                    started_at=None,
                    completed_at=None,
                    tenant_id=run["tenant_id"],
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
                .returning(effects)
            )
        ).mappings().one()
        nodes = metadata.tables["campaign_execution_nodes"]
        node = (
            await self.session.execute(
                update(nodes)
                .where(
                    nodes.c.tenant_id == run["tenant_id"],
                    nodes.c.id == node["id"],
                    nodes.c.version == node["version"],
                )
                .values(
                    node_state=DagNodeState.RESERVED.value,
                    version=nodes.c.version + 1,
                    updated_at=now,
                )
                .returning(nodes)
            )
        ).mappings().one()
        run = await self._advance_run(
            run, target=DagRunState.RUNNING, terminal_reason=None, now=now
        )
        await self._record_reservation(run, node, effect, now=now)
        return effect, node, run

    async def _mark_reconciliation(
        self, node: Any, run: Any, *, now: datetime
    ) -> tuple[Any, Any]:
        nodes = metadata.tables["campaign_execution_nodes"]
        node = (
            await self.session.execute(
                update(nodes)
                .where(
                    nodes.c.tenant_id == run["tenant_id"],
                    nodes.c.id == node["id"],
                    nodes.c.version == node["version"],
                )
                .values(
                    node_state=DagNodeState.RECONCILIATION_REQUIRED.value,
                    version=nodes.c.version + 1,
                    updated_at=now,
                )
                .returning(nodes)
            )
        ).mappings().one()
        run = await self._advance_run(
            run,
            target=DagRunState.RECONCILIATION_REQUIRED,
            terminal_reason="worker_recovery_unknown",
            now=now,
            decrement_concurrency=True,
        )
        return node, run

    async def _advance_run(
        self,
        run: Any,
        *,
        target: DagRunState,
        terminal_reason: str | None,
        now: datetime,
        started: bool = False,
        decrement_concurrency: bool = False,
    ) -> Any:
        if int(run["transition_count"]) >= int(run["max_transitions"]):
            raise DagExecutionActivityConflict("dag_execution_transition_budget_exhausted")
        runs = metadata.tables["campaign_execution_runs"]
        values: dict[str, object] = {
            "run_state": target.value,
            "transition_count": runs.c.transition_count + 1,
            "terminal_reason": terminal_reason,
            "version": runs.c.version + 1,
            "updated_at": now,
        }
        if started:
            values["started_at"] = now
        if decrement_concurrency:
            values["active_concurrency"] = max(
                int(run["active_concurrency"]) - 1, 0
            )
        if target in {DagRunState.COMPLETED, DagRunState.CONTAINED}:
            values["completed_at"] = now
        updated = (
            await self.session.execute(
                update(runs)
                .where(
                    runs.c.tenant_id == run["tenant_id"],
                    runs.c.id == run["id"],
                    runs.c.version == run["version"],
                )
                .values(**values)
                .returning(runs)
            )
        ).mappings().one_or_none()
        if updated is None:
            raise DagExecutionActivityConflict("dag_execution_run_conflict")
        return updated

    async def _reconciliation_command(
        self,
        run: Any,
        node: Any,
        effect: Any,
        binding: CapabilityBindingKeyV1,
    ) -> EffectReconciliationCommand:
        command = _effect_command(run, node, effect, binding)
        jobs = metadata.tables["jobs"]
        manifest_rows = (
            await self.session.execute(
                select(jobs.c.manifest_v2_sha256).where(
                    jobs.c.tenant_id == run["tenant_id"],
                    jobs.c.execution_run_id == run["id"],
                    jobs.c.node_id == node["node_id"],
                    jobs.c.effect_id == effect["effect_id"],
                    jobs.c.strategy_revision_id.is_(None),
                )
            )
        ).scalars().all()
        if len(manifest_rows) != 1 or not isinstance(manifest_rows[0], str):
            raise DagExecutionActivityConflict("dag_effect_manifest_v2_ambiguous")
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
            manifest_v2_sha256=manifest_rows[0],
        )
        request_sha256 = _canonical_sha256(asdict(request))
        if (
            effect["request_sha256"] != request_sha256
            or not isinstance(effect["started_at"], datetime)
            or not isinstance(effect["runner_id"], str)
            or not isinstance(effect["workload_identity"], str)
        ):
            raise DagExecutionActivityConflict("dag_effect_reconciliation_binding_invalid")
        return EffectReconciliationCommand(
            effect_command=command,
            request=request,
            request_sha256=request_sha256,
            runner_id=str(effect["runner_id"]),
            workload_identity=str(effect["workload_identity"]),
            started_at=effect["started_at"],
        )

    async def _record_reservation(
        self,
        run: Any,
        node: Any,
        effect: Any,
        *,
        now: datetime,
    ) -> None:
        audit_id = str(uuid4())
        outbox_id = str(uuid4())
        payload = {
            "schema_version": "redagent.campaign-dag-effect-reserved/v1",
            "execution_run_id": str(run["id"]),
            "node_id": str(node["node_id"]),
            "effect_id": str(effect["effect_id"]),
            "effect_intent_sha256": str(effect["effect_intent_sha256"]),
        }
        await self.session.execute(
            insert(metadata.tables["audit_events"]).values(
                id=audit_id,
                tenant_id=run["tenant_id"],
                actor_user_id=self.actor_user_id,
                action="campaign.dag.effect_reserved",
                subject_type="campaign_execution_run",
                subject_id=run["id"],
                correlation_id=f"{self.correlation_prefix}-{effect['effect_id'][-12:]}",
                details=payload,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        await self.session.execute(
            insert(metadata.tables["outbox_events"]).values(
                id=outbox_id,
                tenant_id=run["tenant_id"],
                event_type="campaign.dag.effect.reserved.v1",
                aggregate_id=run["id"],
                payload=payload,
                published=True,
                schema_revision=1,
                aggregate_type="campaign_execution_run",
                aggregate_sequence=run["transition_count"],
                available_at=now,
                claim_owner=None,
                claim_expires_at=None,
                attempt_count=0,
                last_error=None,
                delivered_at=now,
                delivery_state="delivered",
                reconciliation_state="none",
                dead_lettered_at=None,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )


def _effect_command(
    run: Any,
    node: Any,
    effect: Any,
    binding: CapabilityBindingKeyV1,
) -> EffectDispatchCommand:
    return EffectDispatchCommand(
        tenant_id=str(run["tenant_id"]),
        principal_id=str(run["principal_id"]),
        engagement_id=_input_text(run, "admission_receipt", "engagement_id"),
        target_id=str(node["target_id"]),
        effect_id=str(effect["effect_id"]),
        invocation_id=str(effect["invocation_id"]),
        effect_intent_sha256=str(effect["effect_intent_sha256"]),
        envelope_sha256=str(effect["envelope_sha256"]),
        expected_claim_version=int(effect["claim_version"]),
        expected_dispatch_attempt=int(effect["dispatch_attempt"]),
        expected_dispatch_generation=int(effect["dispatch_generation"]),
        claim_owner=_claim_owner(str(run["id"]), str(node["node_id"])),
        binding=binding,
    )


def _snapshot(
    run: Any, nodes: tuple[Any, ...]
) -> DagExecutionSnapshotV1:
    state = DagRunState(str(run["run_state"]))
    current = next(
        (
            node
            for node in nodes
            if node["node_state"]
            not in {DagNodeState.CONFIRMED.value, DagNodeState.SKIPPED.value}
        ),
        None,
    )
    if state in {DagRunState.COMPLETED, DagRunState.CONTAINED}:
        current = None
    return DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        execution_run_id=str(run["id"]),
        workflow_request_sha256=str(run["request_sha256"]),
        state=state,
        revision=int(run["version"]),
        transition_count=int(run["transition_count"]),
        current_node_id=None if current is None else str(current["node_id"]),
        current_node_state=(
            None if current is None else DagNodeState(str(current["node_state"]))
        ),
        stop_requested=bool(run["stop_requested"]),
        terminal_reason=(
            None if run["terminal_reason"] is None else str(run["terminal_reason"])
        ),
    )


def _input_text(run: Any, section: str, key: str) -> str:
    payload = run["input_payload"]
    nested = payload.get(section) if isinstance(payload, dict) else None
    value = nested.get(key) if isinstance(nested, dict) else None
    if not isinstance(value, str):
        raise DagExecutionActivityConflict("dag_execution_input_invalid")
    return value


def _claim_owner(run_id: str, node_id: str) -> str:
    digest = hashlib.sha256(f"{run_id}\0{node_id}".encode("utf-8")).hexdigest()[:24]
    return f"dag-activity-{digest}"


def _canonical_sha256(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("dag_activity_time_invalid")
