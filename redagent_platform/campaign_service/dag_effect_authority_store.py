"""PostgreSQL current-fact owner for DAG effect-time authority."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
import hashlib
import json
import re
from typing import Any

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.admission_contracts import (
    CampaignBudgetVectorV1,
    CampaignReservationState,
)
from redagent_platform.campaign_service.child_admission import transition_repository_for_run
from redagent_platform.campaign_service.authority_envelope import (
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
)
from redagent_platform.campaign_service.dag_effect_authority import (
    DagAuthorityMaterialV1,
)
from redagent_platform.campaign_service.dag_execution_contracts import (
    DagNodeState,
    DagRunState,
)
from redagent_platform.campaign_service.planning.contracts import (
    canonical_planning_bytes,
    canonical_planning_sha256,
)
from redagent_platform.campaign_service.service import EffectDispatchCommand
from redagent_platform.persistence.models import metadata
from redagent_platform.campaign_service.owned_execution_store import assert_owned_execution_current
from redagent_platform.campaign_service.child_lineage import ChildLineageVerifier
from redagent_platform.policy_service.contracts import (
    PolicyDecision,
    PolicyDecisionInput,
    policy_input_hash,
)


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")


class DagEffectAuthorityConflict(RuntimeError):
    """Locked effect-time facts no longer match the admitted execution."""


class PostgresDagEffectAuthorityStateOwner:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        actor_user_id: str,
        correlation_prefix: str,
        owned_execution_enabled: bool = False,
        child_lineage_verifier: ChildLineageVerifier | None = None,
    ) -> None:
        self._sessions = session_factory
        self._owned_execution_enabled = owned_execution_enabled
        self._child_lineage_verifier = child_lineage_verifier
        self._actor_user_id = _required(
            "dag_authority_store_actor", actor_user_id, 64
        )
        self._correlation_prefix = _required(
            "dag_authority_store_correlation", correlation_prefix, 60
        )

    async def read(
        self, command: EffectDispatchCommand, *, now: datetime
    ) -> DagAuthorityMaterialV1:
        _aware("dag_authority_store_now", now)
        suffix = _suffix(command.effect_id)
        async with self._sessions() as session, session.begin():
            return await _Repository(
                session,
                tenant_id=command.tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=f"{self._correlation_prefix}-read-{suffix}",
                owned_execution_enabled=self._owned_execution_enabled,
                child_lineage_verifier=self._child_lineage_verifier,
            ).read(command, now=now)

    async def observe_lifecycle(
        self,
        material: DagAuthorityMaterialV1,
        lifecycle: CampaignAuthorityLifecycleV2,
        *,
        now: datetime,
    ) -> None:
        suffix = _suffix(material.effect_id)
        async with self._sessions() as session, session.begin():
            await _Repository(
                session,
                tenant_id=material.tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=f"{self._correlation_prefix}-observe-{suffix}",
                owned_execution_enabled=self._owned_execution_enabled,
                child_lineage_verifier=self._child_lineage_verifier,
            ).observe_lifecycle(material, lifecycle, now=now)

    async def commit_pre_io(
        self,
        material: DagAuthorityMaterialV1,
        *,
        decision: PolicyDecision,
        request: PolicyDecisionInput,
        runner_binding_sha256: str,
        now: datetime,
    ) -> None:
        suffix = _suffix(material.effect_id)
        async with self._sessions() as session, session.begin():
            await _Repository(
                session,
                tenant_id=material.tenant_id,
                actor_user_id=self._actor_user_id,
                correlation_id=f"{self._correlation_prefix}-preio-{suffix}",
                owned_execution_enabled=self._owned_execution_enabled,
                child_lineage_verifier=self._child_lineage_verifier,
            ).commit_pre_io(
                material,
                decision=decision,
                request=request,
                runner_binding_sha256=runner_binding_sha256,
                now=now,
            )


class _Repository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
        owned_execution_enabled: bool = False,
        child_lineage_verifier: ChildLineageVerifier | None = None,
    ) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.actor_user_id = actor_user_id
        self.correlation_id = correlation_id
        self.owned_execution_enabled = owned_execution_enabled
        self.child_lineage_verifier = child_lineage_verifier

    async def read(
        self, command: EffectDispatchCommand, *, now: datetime
    ) -> DagAuthorityMaterialV1:
        await self._set_tenant()
        effects = metadata.tables["campaign_effects"]
        effect = (
            await self.session.execute(
                select(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == command.effect_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if (
            effect is None
            or effect["execution_run_id"] is None
            or effect["strategy_revision_id"] is not None
        ):
            raise DagEffectAuthorityConflict("dag_effect_execution_lineage_missing")
        run, node, receipt, reservation, engagement_id = await self._locked_lineage(
            execution_run_id=str(effect["execution_run_id"]),
            node_id=str(effect["node_id"]),
        )
        payload = effect["effect_intent_payload"]
        await assert_owned_execution_current(self.session, run, now=now, enabled=self.owned_execution_enabled,
                                             child_lineage_verifier=self.child_lineage_verifier)
        binding = payload.get("binding") if isinstance(payload, dict) else None
        if (
            not isinstance(payload, dict)
            or payload.get("schema_version")
            != "redagent.campaign-dag-effect-intent/v1"
            or payload.get("execution_run_id") != run["id"]
            or payload.get("node_id") != node["node_id"]
            or payload.get("node_sha256") != node["node_sha256"]
            or payload.get("target_id") != node["target_id"]
            or payload.get("capability_id") != node["capability_id"]
            or binding != asdict(command.binding)
            or canonical_planning_sha256(payload) != effect["effect_intent_sha256"]
        ):
            raise DagEffectAuthorityConflict("dag_effect_intent_binding_mismatch")
        if (
            command.tenant_id != self.tenant_id
            or command.principal_id != run["principal_id"]
            or command.engagement_id != engagement_id
            or command.target_id != node["target_id"]
            or command.effect_intent_sha256 != effect["effect_intent_sha256"]
            or command.envelope_sha256 != effect["envelope_sha256"]
        ):
            raise DagEffectAuthorityConflict("dag_effect_command_binding_mismatch")
        input_payload = run["input_payload"]
        admitted = _object(input_payload, "admission_receipt")
        if receipt["receipt_payload"] != admitted:
            raise DagEffectAuthorityConflict("dag_effect_admission_payload_mismatch")
        rate_claimed = int(run["rate_claimed_requests"])
        rate_window = run["rate_window_started_at"]
        if rate_window is None or rate_window <= now - timedelta(minutes=1):
            rate_claimed = 0
        return DagAuthorityMaterialV1(
            tenant_id=self.tenant_id,
            principal_id=str(run["principal_id"]),
            campaign_id=str(run["campaign_id"]),
            engagement_id=engagement_id,
            execution_run_id=str(run["id"]),
            node_id=str(node["node_id"]),
            node_sha256=str(node["node_sha256"]),
            target_id=str(node["target_id"]),
            effect_id=str(effect["effect_id"]),
            effect_intent_sha256=str(effect["effect_intent_sha256"]),
            envelope_sha256=str(effect["envelope_sha256"]),
            authority_sha256=str(run["authority_sha256"]),
            policy_bundle_revision=_text(admitted, "policy_bundle_revision"),
            policy_bundle_sha256=_text(admitted, "policy_bundle_sha256"),
            domain_sha256=str(run["domain_sha256"]),
            plan_sha256=str(run["plan_sha256"]),
            certificate_sha256=str(run["certificate_sha256"]),
            subset_proof_sha256=_text(admitted, "subset_proof_sha256"),
            admission_receipt_sha256=str(run["admission_receipt_sha256"]),
            post_residual_budget_sha256=_text(
                admitted, "post_residual_budget_sha256"
            ),
            reserved_budget_sha256=str(run["reserved_budget_sha256"]),
            reservation_id=str(run["reservation_id"]),
            reservation_state=str(reservation["reservation_state"]),
            reservation_lease_expires_at=reservation["lease_expires_at"],
            lifecycle_epoch=int(run["lifecycle_epoch"]),
            policy_revocation_epoch=int(run["policy_revocation_epoch"]),
            roe_revocation_epoch=int(run["roe_revocation_epoch"]),
            kill_switch_epoch=int(run["kill_switch_epoch"]),
            capability_id=str(node["capability_id"]),
            effect_class=_text(payload, "effect_class"),
            data_access_class=_text(payload, "data_access_class"),
            credential_class=_text(payload, "credential_class"),
            environment_class=str(node["environment"]),
            rate_limit=int(reservation["rate_per_minute"]),
            rate_claimed_requests=rate_claimed,
            concurrency_limit=int(reservation["concurrency"]),
            active_concurrency=int(run["active_concurrency"]),
            run_state=DagRunState(str(run["run_state"])),
            node_state=DagNodeState(str(node["node_state"])),
            effect_state=str(effect["effect_state"]),
        )

    async def observe_lifecycle(
        self,
        material: DagAuthorityMaterialV1,
        lifecycle: CampaignAuthorityLifecycleV2,
        *,
        now: datetime,
    ) -> None:
        _aware("dag_lifecycle_observed_now", now)
        await self._set_tenant()
        if (
            lifecycle.tenant_id != self.tenant_id
            or lifecycle.engagement_id != material.engagement_id
            or lifecycle.authority_sha256 != material.authority_sha256
        ):
            raise DagEffectAuthorityConflict("dag_lifecycle_binding_mismatch")
        runs = metadata.tables["campaign_execution_runs"]
        run = (
            await self.session.execute(
                select(runs)
                .where(
                    runs.c.tenant_id == self.tenant_id,
                    runs.c.id == material.execution_run_id,
                    runs.c.campaign_id == material.campaign_id,
                    runs.c.authority_sha256 == material.authority_sha256,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if run is None:
            raise DagEffectAuthorityConflict("dag_lifecycle_run_mismatch")
        table = metadata.tables["campaign_execution_authority_observations"]
        latest = (
            await self.session.execute(
                select(table)
                .where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.execution_run_id == material.execution_run_id,
                )
                .order_by(table.c.observation_sequence.desc())
                .limit(1)
                .with_for_update()
            )
        ).mappings().one_or_none()
        payload = json.loads(canonical_planning_bytes(lifecycle))
        digest = canonical_planning_sha256(payload)
        if latest is not None and (
            latest["lifecycle_sha256"] == digest
            and latest["observed_at"] == lifecycle.observed_at
            and latest["valid_until"] == lifecycle.valid_until
        ):
            return
        sequence = 1 if latest is None else int(latest["observation_sequence"]) + 1
        stable = hashlib.sha256(
            f"{material.execution_run_id}\0{sequence}\0{digest}".encode("utf-8")
        ).hexdigest()[:32]
        await self.session.execute(
            insert(table).values(
                id=f"dag-observation-{stable}",
                execution_run_id=material.execution_run_id,
                campaign_id=material.campaign_id,
                observation_sequence=sequence,
                authority_sha256=material.authority_sha256,
                lifecycle_epoch=lifecycle.lifecycle_epoch,
                policy_revocation_epoch=lifecycle.policy_revocation_epoch,
                roe_revocation_epoch=lifecycle.roe_revocation_epoch,
                kill_switch_epoch=lifecycle.kill_switch_epoch,
                lifecycle_state=lifecycle.state.value,
                lifecycle_sha256=digest,
                lifecycle_payload=payload,
                observed_at=lifecycle.observed_at,
                valid_until=lifecycle.valid_until,
                revoked_at=lifecycle.revoked_at,
                reason_code=lifecycle.reason_code,
                tenant_id=self.tenant_id,
                version=1,
                created_at=now,
                updated_at=now,
            )
        )

    async def commit_pre_io(
        self,
        material: DagAuthorityMaterialV1,
        *,
        decision: PolicyDecision,
        request: PolicyDecisionInput,
        runner_binding_sha256: str,
        now: datetime,
    ) -> None:
        _aware("dag_pre_io_now", now)
        await self._set_tenant()
        if (
            not isinstance(decision, PolicyDecision)
            or not isinstance(request, PolicyDecisionInput)
            or policy_input_hash(request) != decision.input_hash
            or request.tenant_id != self.tenant_id
            or request.resource_id != material.effect_id
            or request.attributes.get("campaign_runner_binding_sha256")
            != runner_binding_sha256
        ):
            raise DagEffectAuthorityConflict("dag_pre_io_policy_binding_mismatch")
        runs = metadata.tables["campaign_execution_runs"]
        current_run = (await self.session.execute(select(runs).where(
            runs.c.tenant_id == self.tenant_id, runs.c.id == material.execution_run_id
        ).with_for_update())).mappings().one()
        # CRITICAL: this locked check is after fresh policy and immediately before runner I/O.
        await assert_owned_execution_current(self.session, current_run, now=now, enabled=self.owned_execution_enabled,
                                             child_lineage_verifier=self.child_lineage_verifier)
        decision.assert_current(
            request, required_revision=material.policy_bundle_revision, now=now
        )
        if not decision.allowed:
            raise DagEffectAuthorityConflict("dag_pre_io_policy_denied")

        effects = metadata.tables["campaign_effects"]
        effect = (
            await self.session.execute(
                select(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == material.effect_id,
                    effects.c.execution_run_id == material.execution_run_id,
                    effects.c.node_id == material.node_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if effect is None or effect["effect_state"] != "dispatching":
            raise DagEffectAuthorityConflict("dag_pre_io_effect_not_dispatching")
        exact_replay = (
            effect["pre_io_policy_decision_id"] == decision.decision_id
            and effect["pre_io_policy_input_sha256"] == decision.input_hash
            and effect["pre_io_policy_valid_until"] == decision.valid_until
            and effect["pre_io_authorized_at"] == now
        )
        if exact_replay:
            return
        if any(
            effect[name] is not None
            for name in (
                "pre_io_policy_decision_id",
                "pre_io_policy_input_sha256",
                "pre_io_policy_valid_until",
                "pre_io_authorized_at",
            )
        ):
            raise DagEffectAuthorityConflict("dag_pre_io_replay_mismatch")

        runs = metadata.tables["campaign_execution_runs"]
        run = (
            await self.session.execute(
                select(runs)
                .where(
                    runs.c.tenant_id == self.tenant_id,
                    runs.c.id == material.execution_run_id,
                    runs.c.campaign_id == material.campaign_id,
                    runs.c.run_state == DagRunState.RUNNING.value,
                    runs.c.stop_requested.is_(False),
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        nodes = metadata.tables["campaign_execution_nodes"]
        node = (
            await self.session.execute(
                select(nodes)
                .where(
                    nodes.c.tenant_id == self.tenant_id,
                    nodes.c.execution_run_id == material.execution_run_id,
                    nodes.c.node_id == material.node_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        reservations = metadata.tables["campaign_budget_reservations"]
        reservation = (
            await self.session.execute(
                select(reservations)
                .where(
                    reservations.c.tenant_id == self.tenant_id,
                    reservations.c.id == material.reservation_id,
                    reservations.c.campaign_id == material.campaign_id,
                    reservations.c.reservation_state.in_(("reserved", "held")),
                    reservations.c.lease_expires_at > now,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        latest = await self._latest_lifecycle(material.execution_run_id)
        if run is None or node is None or reservation is None:
            raise DagEffectAuthorityConflict("dag_pre_io_current_state_mismatch")
        if (
            latest is None
            or latest["lifecycle_state"]
            != CampaignAuthorityLifecycleState.ACTIVE.value
            or latest["valid_until"] <= now
            or any(
                int(latest[name]) != int(run[name])
                for name in (
                    "lifecycle_epoch",
                    "policy_revocation_epoch",
                    "roe_revocation_epoch",
                    "kill_switch_epoch",
                )
            )
        ):
            raise DagEffectAuthorityConflict("dag_pre_io_lifecycle_not_current")
        rate_started = run["rate_window_started_at"]
        rate_claimed = int(run["rate_claimed_requests"])
        if rate_started is None or rate_started <= now - timedelta(minutes=1):
            rate_started = now
            rate_claimed = 0
        if (
            rate_claimed >= int(reservation["rate_per_minute"])
            or int(run["active_concurrency"]) >= int(reservation["concurrency"])
        ):
            raise DagEffectAuthorityConflict("dag_pre_io_capacity_exhausted")

        if reservation["reservation_state"] == "reserved":
            budget_owner = await transition_repository_for_run(
                self.session,
                run=run,
                actor_user_id=self.actor_user_id,
                correlation_id=self.correlation_id,
                now=now,
            )
            await budget_owner.transition_reservation(
                reservation_id=material.reservation_id,
                target=CampaignReservationState.HELD,
                effect_started=True,
                reconciliation_code="effect_started",
                now=now,
            )
        run_updated = await self.session.execute(
            update(runs)
            .where(
                runs.c.tenant_id == self.tenant_id,
                runs.c.id == material.execution_run_id,
                runs.c.version == run["version"],
            )
            .values(
                rate_window_started_at=rate_started,
                rate_claimed_requests=rate_claimed + 1,
                active_concurrency=runs.c.active_concurrency + 1,
                version=runs.c.version + 1,
                updated_at=now,
            )
        )
        if getattr(run_updated, "rowcount", None) != 1:
            raise DagEffectAuthorityConflict("dag_pre_io_run_conflict")
        effect_updated = await self.session.execute(
            update(effects)
            .where(
                effects.c.tenant_id == self.tenant_id,
                effects.c.effect_id == material.effect_id,
                effects.c.effect_state == "dispatching",
                effects.c.pre_io_policy_decision_id.is_(None),
            )
            .values(
                pre_io_policy_decision_id=decision.decision_id,
                pre_io_policy_input_sha256=decision.input_hash,
                pre_io_policy_valid_until=decision.valid_until,
                pre_io_authorized_at=now,
                version=effects.c.version + 1,
                updated_at=now,
            )
        )
        if getattr(effect_updated, "rowcount", None) != 1:
            raise DagEffectAuthorityConflict("dag_pre_io_effect_conflict")
        await self.session.execute(
            update(nodes)
            .where(
                nodes.c.tenant_id == self.tenant_id,
                nodes.c.execution_run_id == material.execution_run_id,
                nodes.c.node_id == material.node_id,
                nodes.c.version == node["version"],
            )
            .values(
                node_state=DagNodeState.DISPATCHING.value,
                version=nodes.c.version + 1,
                updated_at=now,
            )
        )

    async def _locked_lineage(
        self, *, execution_run_id: str, node_id: str
    ) -> tuple[
        Any,
        Any,
        Any,
        Any,
        str,
    ]:
        runs = metadata.tables["campaign_execution_runs"]
        run = (
            await self.session.execute(
                select(runs)
                .where(
                    runs.c.tenant_id == self.tenant_id,
                    runs.c.id == execution_run_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if run is None:
            raise DagEffectAuthorityConflict("dag_effect_run_missing")
        nodes = metadata.tables["campaign_execution_nodes"]
        node = (
            await self.session.execute(
                select(nodes)
                .where(
                    nodes.c.tenant_id == self.tenant_id,
                    nodes.c.execution_run_id == execution_run_id,
                    nodes.c.campaign_id == run["campaign_id"],
                    nodes.c.node_id == node_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        campaigns = metadata.tables["campaigns"]
        campaign = (
            await self.session.execute(
                select(campaigns.c.engagement_id)
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == run["campaign_id"],
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        receipts = metadata.tables["plan_admission_receipts"]
        receipt = (
            await self.session.execute(
                select(receipts)
                .where(
                    receipts.c.tenant_id == self.tenant_id,
                    receipts.c.id == run["admission_receipt_id"],
                    receipts.c.campaign_id == run["campaign_id"],
                    receipts.c.outcome == "admitted",
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        reservations = metadata.tables["campaign_budget_reservations"]
        reservation = (
            await self.session.execute(
                select(reservations)
                .where(
                    reservations.c.tenant_id == self.tenant_id,
                    reservations.c.id == run["reservation_id"],
                    reservations.c.campaign_id == run["campaign_id"],
                    reservations.c.plan_sha256 == run["plan_sha256"],
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if (
            node is None
            or campaign is None
            or receipt is None
            or reservation is None
        ):
            raise DagEffectAuthorityConflict("dag_effect_lineage_incomplete")
        budget = CampaignBudgetVectorV1(
            duration_seconds=int(reservation["duration_seconds"]),
            requests=int(reservation["requests"]),
            rate_per_minute=int(reservation["rate_per_minute"]),
            concurrency=int(reservation["concurrency"]),
            risk_micropoints=int(reservation["risk_micropoints"]),
            cost_microunits=int(reservation["cost_microunits"]),
            evidence_bytes=int(reservation["evidence_bytes"]),
            data_bytes=int(reservation["data_bytes"]),
        )
        if budget.budget_sha256 != run["reserved_budget_sha256"]:
            raise DagEffectAuthorityConflict("dag_effect_budget_binding_mismatch")
        return run, node, receipt, reservation, str(campaign["engagement_id"])

    async def _latest_lifecycle(self, execution_run_id: str):
        table = metadata.tables["campaign_execution_authority_observations"]
        return (
            await self.session.execute(
                select(table)
                .where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.execution_run_id == execution_run_id,
                )
                .order_by(table.c.observation_sequence.desc())
                .limit(1)
                .with_for_update()
            )
        ).mappings().one_or_none()

    async def _set_tenant(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )


def _object(parent: object, name: str) -> dict[str, object]:
    if not isinstance(parent, dict) or not isinstance(parent.get(name), dict):
        raise DagEffectAuthorityConflict("dag_effect_input_payload_invalid")
    return parent[name]


def _text(parent: object, name: str) -> str:
    if not isinstance(parent, dict) or not isinstance(parent.get(name), str):
        raise DagEffectAuthorityConflict("dag_effect_input_payload_invalid")
    return str(parent[name])


def _suffix(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]


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
