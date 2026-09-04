"""Atomic PostgreSQL owner for admitted campaign DAG start state."""

from __future__ import annotations

from datetime import datetime
import hashlib
import re
from typing import Any, Mapping

from sqlalchemy import insert, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.admission_contracts import (
    CampaignBudgetVectorV1,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
)
from redagent_platform.campaign_service.dag_execution_service import (
    DagExecutionStartMaterialV1,
)
from redagent_platform.persistence.models import metadata


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")


class DagExecutionConflict(RuntimeError):
    """Current durable admission/run facts do not match the requested exact replay."""


class CampaignDagExecutionRepository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        self.session = session
        self.tenant_id = _required("dag_repository_tenant", tenant_id, 64)
        self.actor_user_id = _required("dag_repository_actor", actor_user_id, 64)
        self.correlation_id = _required(
            "dag_repository_correlation", correlation_id, 100
        )

    async def start(
        self, material: DagExecutionStartMaterialV1, *, now: datetime
    ) -> DagExecutionSnapshotV1:
        if not isinstance(material, DagExecutionStartMaterialV1):
            raise ValueError("dag_start_material_invalid")
        if material.tenant_id != self.tenant_id:
            raise ValueError("dag_start_material_tenant_mismatch")
        _aware("dag_start_store_now", now)
        await self._set_tenant()
        # CRITICAL: replay, admission, reservation, run, nodes, audit, and outbox are one lock scope.
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": f"campaign-dag:{self.tenant_id}:{material.campaign_id}"},
        )
        replay = await self._existing(material)
        if replay is not None:
            return replay
        await self._lock_current_admission(material, now=now)

        await self.insert_prepared_material(material, now=now)

        stable = hashlib.sha256(material.execution_run_id.encode("utf-8")).hexdigest()[:32]
        await self.session.execute(
            insert(metadata.tables["audit_events"]).values(
                id=f"audit-dag-{stable}",
                actor_user_id=self.actor_user_id,
                action="campaign.dag.start.requested",
                subject_type="campaign_execution",
                subject_id=material.execution_run_id,
                correlation_id=self.correlation_id,
                details={
                    "input_sha256": material.input_sha256,
                    "plan_sha256": material.plan_sha256,
                    "admission_receipt_sha256": material.admission_receipt_sha256,
                    "workflow_request_sha256": material.workflow_request_sha256,
                },
                tenant_id=self.tenant_id,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        await self.session.execute(
            insert(metadata.tables["outbox_events"]).values(
                id=f"outbox-dag-{stable}",
                event_type="campaign.dag.start.requested.v1",
                aggregate_id=material.execution_run_id,
                payload=material.outbox_payload,
                published=False,
                schema_revision=2,
                aggregate_type="campaign_execution",
                aggregate_sequence=1,
                available_at=now,
                claim_owner=None,
                claim_expires_at=None,
                attempt_count=0,
                last_error=None,
                delivered_at=None,
                delivery_state="pending",
                reconciliation_state="none",
                dead_lettered_at=None,
                tenant_id=self.tenant_id,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        return _start_snapshot(material)

    async def insert_prepared_material(
        self,
        material: DagExecutionStartMaterialV1,
        *,
        now: datetime,
    ) -> None:
        """Insert one already-validated DAG run/node graph in the caller transaction."""
        if not isinstance(material, DagExecutionStartMaterialV1):
            raise ValueError("dag_start_material_invalid")
        if material.tenant_id != self.tenant_id:
            raise ValueError("dag_start_material_tenant_mismatch")
        _aware("dag_start_store_now", now)
        # CRITICAL: callers must lock and validate admission before this insert-only seam.
        await self._set_tenant()
        runs = metadata.tables["campaign_execution_runs"]
        await self.session.execute(
            insert(runs).values(
                id=material.execution_run_id,
                execution_id=material.execution_id,
                principal_id=material.principal_id,
                campaign_id=material.campaign_id,
                admission_receipt_id=material.admission_receipt_id,
                reservation_id=material.reservation_id,
                workflow_id=material.workflow_id,
                workflow_run_id=None,
                idempotency_key=material.idempotency_key,
                request_sha256=material.workflow_request_sha256,
                input_sha256=material.input_sha256,
                input_payload=material.input_payload,
                signed_authority_sha256=material.signed_authority_sha256,
                authority_sha256=material.authority_sha256,
                domain_sha256=material.domain_sha256,
                plan_sha256=material.plan_sha256,
                certificate_sha256=material.certificate_sha256,
                admission_receipt_sha256=material.admission_receipt_sha256,
                reserved_budget_sha256=material.reserved_budget_sha256,
                lifecycle_epoch=material.lifecycle_epoch,
                policy_revocation_epoch=material.policy_revocation_epoch,
                roe_revocation_epoch=material.roe_revocation_epoch,
                kill_switch_epoch=material.kill_switch_epoch,
                run_state=material.run_state.value,
                transition_count=0,
                max_transitions=material.max_transitions,
                rate_window_started_at=now,
                rate_claimed_requests=0,
                active_concurrency=0,
                stop_requested=False,
                terminal_reason=None,
                started_at=None,
                completed_at=None,
                tenant_id=self.tenant_id,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )
        nodes = metadata.tables["campaign_execution_nodes"]
        for node in material.nodes:
            node_stable = hashlib.sha256(
                f"{material.execution_run_id}\0{node.node_id}".encode("utf-8")
            ).hexdigest()[:32]
            await self.session.execute(
                insert(nodes).values(
                    id=f"dag-node-{node_stable}",
                    execution_run_id=material.execution_run_id,
                    campaign_id=material.campaign_id,
                    node_id=node.node_id,
                    node_order=node.node_order,
                    operator_id=node.operator_id,
                    capability_id=node.capability_id,
                    capability_revision=node.capability_revision,
                    target_id=node.target_id,
                    environment=node.environment,
                    arguments_sha256=node.arguments_sha256,
                    incoming_edges_sha256=node.incoming_edges_sha256,
                    join_sha256=node.join_sha256,
                    node_sha256=node.node_sha256,
                    node_state=node.node_state.value,
                    tenant_id=self.tenant_id,
                    version=1,
                    created_at=now,
                    updated_at=now,
                )
            )


    async def _existing(
        self, material: DagExecutionStartMaterialV1
    ) -> DagExecutionSnapshotV1 | None:
        runs = metadata.tables["campaign_execution_runs"]
        rows = (
            await self.session.execute(
                select(runs)
                .where(
                    runs.c.tenant_id == self.tenant_id,
                    or_(
                        runs.c.id == material.execution_run_id,
                        runs.c.execution_id == material.execution_id,
                        runs.c.workflow_id == material.workflow_id,
                        (
                            (runs.c.campaign_id == material.campaign_id)
                            & (runs.c.plan_sha256 == material.plan_sha256)
                        ),
                        (
                            (runs.c.campaign_id == material.campaign_id)
                            & (runs.c.idempotency_key == material.idempotency_key)
                        ),
                    ),
                )
                .with_for_update()
            )
        ).mappings().all()
        if not rows:
            return None
        if len(rows) != 1:
            raise DagExecutionConflict("dag_start_identity_ambiguous")
        row = rows[0]
        exact = (
            row["id"] == material.execution_run_id
            and row["execution_id"] == material.execution_id
            and row["campaign_id"] == material.campaign_id
            and row["admission_receipt_id"] == material.admission_receipt_id
            and row["reservation_id"] == material.reservation_id
            and row["workflow_id"] == material.workflow_id
            and row["idempotency_key"] == material.idempotency_key
            and row["request_sha256"] == material.workflow_request_sha256
            and row["input_sha256"] == material.input_sha256
            and row["input_payload"] == material.input_payload
            and row["plan_sha256"] == material.plan_sha256
            and row["certificate_sha256"] == material.certificate_sha256
            and row["admission_receipt_sha256"]
            == material.admission_receipt_sha256
        )
        if not exact:
            raise DagExecutionConflict("dag_start_idempotency_mismatch")
        nodes = metadata.tables["campaign_execution_nodes"]
        first = (
            await self.session.execute(
                select(nodes)
                .where(
                    nodes.c.tenant_id == self.tenant_id,
                    nodes.c.execution_run_id == material.execution_run_id,
                )
                .order_by(nodes.c.node_order)
                .limit(1)
            )
        ).mappings().one_or_none()
        if first is None:
            raise DagExecutionConflict("dag_start_replay_nodes_missing")
        return DagExecutionSnapshotV1(
            schema_version=DAG_EXECUTION_SCHEMA_VERSION,
            execution_run_id=material.execution_run_id,
            workflow_request_sha256=material.workflow_request_sha256,
            state=DagRunState(str(row["run_state"])),
            revision=int(row["version"]),
            transition_count=int(row["transition_count"]),
            current_node_id=str(first["node_id"]),
            current_node_state=DagNodeState(str(first["node_state"])),
            stop_requested=bool(row["stop_requested"]),
            terminal_reason=row["terminal_reason"],
        )

    async def _lock_current_admission(
        self, material: DagExecutionStartMaterialV1, *, now: datetime
    ) -> None:
        campaigns = metadata.tables["campaigns"]
        campaign = (
            await self.session.execute(
                select(campaigns)
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == material.campaign_id,
                    campaigns.c.engagement_id == material.engagement_id,
                    campaigns.c.status != "completed",
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if campaign is None:
            raise DagExecutionConflict("dag_start_campaign_binding_mismatch")

        receipts = metadata.tables["plan_admission_receipts"]
        receipt = (
            await self.session.execute(
                select(receipts)
                .where(
                    receipts.c.tenant_id == self.tenant_id,
                    receipts.c.id == material.admission_receipt_id,
                    receipts.c.campaign_id == material.campaign_id,
                    receipts.c.reservation_id == material.reservation_id,
                    receipts.c.outcome == "admitted",
                    receipts.c.receipt_sha256 == material.admission_receipt_sha256,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        expected_receipt = material.input_payload.get("admission_receipt")
        if receipt is None or receipt["receipt_payload"] != expected_receipt:
            raise DagExecutionConflict("dag_start_admission_binding_mismatch")
        expires_at = _payload_time(receipt["receipt_payload"], "expires_at")
        if now >= expires_at:
            raise DagExecutionConflict("dag_start_admission_expired")

        reservations = metadata.tables["campaign_budget_reservations"]
        reservation = (
            await self.session.execute(
                select(reservations)
                .where(
                    reservations.c.tenant_id == self.tenant_id,
                    reservations.c.id == material.reservation_id,
                    reservations.c.campaign_id == material.campaign_id,
                    reservations.c.plan_sha256 == material.plan_sha256,
                    reservations.c.reservation_state == "reserved",
                    reservations.c.effect_started.is_(False),
                    reservations.c.lease_expires_at > now,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if reservation is None:
            raise DagExecutionConflict("dag_start_reservation_not_current")
        reserved = CampaignBudgetVectorV1(
            duration_seconds=int(reservation["duration_seconds"]),
            requests=int(reservation["requests"]),
            rate_per_minute=int(reservation["rate_per_minute"]),
            concurrency=int(reservation["concurrency"]),
            risk_micropoints=int(reservation["risk_micropoints"]),
            cost_microunits=int(reservation["cost_microunits"]),
            evidence_bytes=int(reservation["evidence_bytes"]),
            data_bytes=int(reservation["data_bytes"]),
        )
        if reserved.budget_sha256 != material.reserved_budget_sha256:
            raise DagExecutionConflict("dag_start_reservation_budget_mismatch")

    async def _set_tenant(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )


class PostgresDagExecutionStartStore:
    """Transaction-owning service adapter for one atomic start or exact replay."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        actor_user_id: str,
        correlation_prefix: str,
    ) -> None:
        self._sessions = session_factory
        self._actor_user_id = _required("dag_store_actor", actor_user_id, 64)
        self._correlation_prefix = _required(
            "dag_store_correlation", correlation_prefix, 60
        )

    async def start(
        self, material: DagExecutionStartMaterialV1, *, now: datetime
    ) -> DagExecutionSnapshotV1:
        suffix = hashlib.sha256(material.execution_run_id.encode("utf-8")).hexdigest()[:12]
        async with self._sessions() as session, session.begin():
            return await CampaignDagExecutionRepository(
                session,
                tenant_id=material.tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=f"{self._correlation_prefix}-{suffix}",
            ).start(material, now=now)


def _start_snapshot(material: DagExecutionStartMaterialV1) -> DagExecutionSnapshotV1:
    first = material.nodes[0]
    return DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        execution_run_id=material.execution_run_id,
        workflow_request_sha256=material.workflow_request_sha256,
        state=material.run_state,
        revision=1,
        transition_count=0,
        current_node_id=first.node_id,
        current_node_state=first.node_state,
        stop_requested=False,
        terminal_reason=None,
    )


def _required(name: str, value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > maximum
        or not _IDENTIFIER.fullmatch(value)
    ):
        raise ValueError(f"{name}_invalid")
    return value


def _aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_invalid")


def _payload_time(payload: Mapping[str, Any], name: str) -> datetime:
    if not isinstance(payload, dict) or not isinstance(payload.get(name), str):
        raise DagExecutionConflict("dag_start_admission_payload_invalid")
    try:
        value = datetime.fromisoformat(str(payload[name]).replace("Z", "+00:00"))
    except ValueError as exc:
        raise DagExecutionConflict("dag_start_admission_payload_invalid") from exc
    _aware("dag_start_admission_payload_time", value)
    return value
