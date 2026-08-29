"""DAG projections around the single shared campaign-effect state machine."""

from __future__ import annotations

from datetime import datetime
import hashlib
from typing import Any
from uuid import uuid4

from sqlalchemy import insert, select, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.admission_contracts import (
    CampaignReservationState,
)
from redagent_platform.campaign_service.admission_repository import (
    CampaignAdmissionRepository,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DagNodeState,
    DagRunState,
)
from redagent_platform.campaign_service.repository import (
    CampaignRepository,
)
from redagent_platform.campaign_service.service import EffectDispatchCommand
from redagent_platform.persistence.models import metadata


class DagEffectProjectionConflict(RuntimeError):
    """Shared effect truth cannot be projected to its exact DAG lineage."""


class PostgresDagEffectTransitionStore:
    """Delegate effect transitions and atomically maintain run/node projections."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        actor_user_id: str,
        correlation_prefix: str,
        lease_seconds: int = 30,
    ) -> None:
        self._sessions = session_factory
        self._actor_user_id = actor_user_id
        self._correlation_prefix = correlation_prefix
        if type(lease_seconds) is not int or not 1 <= lease_seconds <= 300:
            raise ValueError("dag_effect_lease_seconds_invalid")
        self._lease_seconds = lease_seconds

    async def claim(self, command: EffectDispatchCommand, *, now: datetime) -> int:
        async with self._sessions() as session, session.begin():
            result = await self._repository(session, command, "claim").claim_effect(
                effect_id=command.effect_id,
                claim_owner=command.claim_owner,
                expected_claim_version=command.expected_claim_version,
                now=now,
                lease_seconds=self._lease_seconds,
            )
            await self._project(
                session,
                command,
                target=DagNodeState.CLAIMED,
                run_target=DagRunState.RUNNING,
                decrement_concurrency=False,
                now=now,
            )
        return result.claim_version

    async def mark_dispatching(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        request_sha256: str,
        runner_id: str,
        workload_identity: str,
        now: datetime,
    ) -> int:
        async with self._sessions() as session, session.begin():
            result = await self._repository(
                session, command, "dispatch"
            ).mark_effect_dispatching(
                effect_id=command.effect_id,
                claim_owner=command.claim_owner,
                expected_claim_version=expected_claim_version,
                request_sha256=request_sha256,
                runner_id=runner_id,
                workload_identity=workload_identity,
                occurred_at=now,
            )
        # The second authority recheck is the sole pre-I/O owner of the
        # node's dispatching projection and rate/concurrency reservation.
        return result.claim_version

    async def confirm(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        receipt_sha256: str,
        receipt_payload: dict[str, object],
        now: datetime,
    ) -> object:
        async with self._sessions() as session, session.begin():
            result = await self._repository(
                session, command, "confirm"
            ).record_effect_receipt(
                effect_id=command.effect_id,
                claim_owner=command.claim_owner,
                expected_claim_version=expected_claim_version,
                receipt_sha256=receipt_sha256,
                receipt_payload=receipt_payload,
                occurred_at=now,
            )
            await self._project_confirmed(session, command, now=now)
        return result

    async def ambiguity(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        failure_code: str,
        now: datetime,
    ) -> None:
        async with self._sessions() as session, session.begin():
            await self._repository(
                session, command, "ambiguity"
            ).record_effect_ambiguity(
                effect_id=command.effect_id,
                claim_owner=command.claim_owner,
                expected_claim_version=expected_claim_version,
                failure_code=failure_code,
                occurred_at=now,
            )
            await self._project(
                session,
                command,
                target=DagNodeState.RECONCILIATION_REQUIRED,
                run_target=DagRunState.RECONCILIATION_REQUIRED,
                decrement_concurrency=True,
                now=now,
            )

    async def not_applied(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        receipt_sha256: str,
        receipt_payload: dict[str, object],
        now: datetime,
    ) -> object:
        async with self._sessions() as session, session.begin():
            result = await self._repository(
                session, command, "not-applied"
            ).record_effect_not_applied(
                effect_id=command.effect_id,
                expected_claim_version=expected_claim_version,
                receipt_sha256=receipt_sha256,
                receipt_payload=receipt_payload,
                occurred_at=now,
            )
            await self._project(
                session,
                command,
                target=DagNodeState.NOT_APPLIED,
                run_target=DagRunState.RUNNING,
                decrement_concurrency=False,
                now=now,
            )
        return result

    async def lookup_unavailable(
        self,
        command: EffectDispatchCommand,
        *,
        expected_claim_version: int,
        failure_code: str,
        now: datetime,
    ) -> object:
        async with self._sessions() as session, session.begin():
            result = await self._repository(
                session, command, "lookup"
            ).record_effect_lookup_unavailable(
                effect_id=command.effect_id,
                expected_claim_version=expected_claim_version,
                failure_code=failure_code,
                occurred_at=now,
            )
            if result.effect_state == "manual_review_required":
                await self._project(
                    session,
                    command,
                    target=DagNodeState.MANUAL_REVIEW_REQUIRED,
                    run_target=DagRunState.MANUAL_REVIEW_REQUIRED,
                    decrement_concurrency=False,
                    now=now,
                )
        return result

    def _repository(
        self, session: AsyncSession, command: EffectDispatchCommand, phase: str
    ) -> CampaignRepository:
        suffix = hashlib.sha256(command.effect_id.encode("utf-8")).hexdigest()[:12]
        return CampaignRepository(
            session,
            tenant_id=command.tenant_id,
            actor_user_id=self._actor_user_id,
            correlation_id=f"{self._correlation_prefix}-{phase}-{suffix}",
        )

    async def _project_confirmed(
        self, session: AsyncSession, command: EffectDispatchCommand, *, now: datetime
    ) -> None:
        lineage = await self._locked_lineage(session, command)
        if lineage is None:
            raise DagEffectProjectionConflict("dag_effect_projection_lineage_missing")
        _effect, run, node = lineage
        if node["node_state"] == DagNodeState.CONFIRMED.value:
            return
        await self._update_node(
            session, node, target=DagNodeState.CONFIRMED, now=now
        )
        nodes = metadata.tables["campaign_execution_nodes"]
        incomplete = await session.scalar(
            select(nodes.c.id)
            .where(
                nodes.c.tenant_id == command.tenant_id,
                nodes.c.execution_run_id == run["id"],
                nodes.c.node_state != DagNodeState.CONFIRMED.value,
            )
            .limit(1)
        )
        terminal = incomplete is None
        await self._update_run(
            session,
            run,
            target=(DagRunState.COMPLETED if terminal else DagRunState.RUNNING),
            decrement_concurrency=True,
            terminal_reason="all_nodes_confirmed" if terminal else None,
            now=now,
        )
        if terminal:
            await CampaignAdmissionRepository(
                session,
                tenant_id=command.tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=f"{self._correlation_prefix}-consume-{command.effect_id[-12:]}",
            ).transition_reservation(
                reservation_id=str(run["reservation_id"]),
                target=CampaignReservationState.CONSUMED,
                effect_started=True,
                reconciliation_code="applied",
                now=now,
            )
        await self._audit(
            session,
            command,
            action="campaign.dag.node_confirmed",
            node_state=DagNodeState.CONFIRMED,
            run_state=(DagRunState.COMPLETED if terminal else DagRunState.RUNNING),
            now=now,
        )

    async def _project(
        self,
        session: AsyncSession,
        command: EffectDispatchCommand,
        *,
        target: DagNodeState,
        run_target: DagRunState,
        decrement_concurrency: bool,
        now: datetime,
    ) -> None:
        lineage = await self._locked_lineage(session, command)
        if lineage is None:
            raise DagEffectProjectionConflict("dag_effect_projection_lineage_missing")
        _effect, run, node = lineage
        if node["node_state"] == target.value:
            return
        await self._update_node(session, node, target=target, now=now)
        await self._update_run(
            session,
            run,
            target=run_target,
            decrement_concurrency=decrement_concurrency,
            terminal_reason=None,
            now=now,
        )
        await self._audit(
            session,
            command,
            action=f"campaign.dag.node_{target.value}",
            node_state=target,
            run_state=run_target,
            now=now,
        )

    async def _locked_lineage(
        self, session: AsyncSession, command: EffectDispatchCommand
    ) -> tuple[Any, Any, Any] | None:
        effects = metadata.tables["campaign_effects"]
        effect = (
            await session.execute(
                select(effects)
                .where(
                    effects.c.tenant_id == command.tenant_id,
                    effects.c.effect_id == command.effect_id,
                    effects.c.execution_run_id.is_not(None),
                    effects.c.strategy_revision_id.is_(None),
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if effect is None:
            return None
        runs = metadata.tables["campaign_execution_runs"]
        run = (
            await session.execute(
                select(runs)
                .where(
                    runs.c.tenant_id == command.tenant_id,
                    runs.c.id == effect["execution_run_id"],
                    runs.c.campaign_id == effect["campaign_id"],
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        nodes = metadata.tables["campaign_execution_nodes"]
        node = (
            await session.execute(
                select(nodes)
                .where(
                    nodes.c.tenant_id == command.tenant_id,
                    nodes.c.execution_run_id == effect["execution_run_id"],
                    nodes.c.campaign_id == effect["campaign_id"],
                    nodes.c.node_id == effect["node_id"],
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if run is None or node is None:
            return None
        return effect, run, node

    async def _update_node(
        self,
        session: AsyncSession,
        node: Any,
        *,
        target: DagNodeState,
        now: datetime,
    ) -> None:
        nodes = metadata.tables["campaign_execution_nodes"]
        result = await session.execute(
            update(nodes)
            .where(
                nodes.c.tenant_id == node["tenant_id"],
                nodes.c.id == node["id"],
                nodes.c.version == node["version"],
            )
            .values(
                node_state=target.value,
                version=nodes.c.version + 1,
                updated_at=now,
            )
        )
        if getattr(result, "rowcount", None) != 1:
            raise DagEffectProjectionConflict("dag_effect_node_projection_conflict")

    async def _update_run(
        self,
        session: AsyncSession,
        run: Any,
        *,
        target: DagRunState,
        decrement_concurrency: bool,
        terminal_reason: str | None,
        now: datetime,
    ) -> None:
        if int(run["transition_count"]) >= int(run["max_transitions"]):
            raise DagEffectProjectionConflict("dag_execution_transition_budget_exhausted")
        runs = metadata.tables["campaign_execution_runs"]
        active = int(run["active_concurrency"])
        if decrement_concurrency:
            active = max(int(run["active_concurrency"]) - 1, 0)
        result = await session.execute(
            update(runs)
            .where(
                runs.c.tenant_id == run["tenant_id"],
                runs.c.id == run["id"],
                runs.c.version == run["version"],
            )
            .values(
                run_state=target.value,
                active_concurrency=active,
                transition_count=runs.c.transition_count + 1,
                terminal_reason=terminal_reason,
                completed_at=now if target is DagRunState.COMPLETED else None,
                version=runs.c.version + 1,
                updated_at=now,
            )
        )
        if getattr(result, "rowcount", None) != 1:
            raise DagEffectProjectionConflict("dag_effect_run_projection_conflict")

    async def _audit(
        self,
        session: AsyncSession,
        command: EffectDispatchCommand,
        *,
        action: str,
        node_state: DagNodeState,
        run_state: DagRunState,
        now: datetime,
    ) -> None:
        audits = metadata.tables["audit_events"]
        await session.execute(
            insert(audits).values(
                id=str(uuid4()),
                tenant_id=command.tenant_id,
                actor_user_id=self._actor_user_id,
                action=action,
                subject_type="campaign_execution_effect",
                subject_id=command.effect_id,
                correlation_id=f"{self._correlation_prefix}-{command.effect_id[-12:]}",
                details={
                    "effect_id": command.effect_id,
                    "node_state": node_state.value,
                    "run_state": run_state.value,
                },
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
