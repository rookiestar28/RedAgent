"""Child-only admission projection; generic reservation accounting remains unchanged."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Mapping

from sqlalchemy import select
from sqlalchemy.engine import RowMapping
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1, CampaignReservationState, PlanAdmissionReceiptV1
from redagent_platform.campaign_service.admission_repository import AdmissionReservationCommandV1, CampaignAdmissionRepository, _vector_from_row
from redagent_platform.campaign_service.approval_contracts import AutonomousCampaignPlanPreviewV1
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.application_repository import _verified_preview_from_payload
from redagent_platform.campaign_service.child_lineage import ChildLineageConflict, ChildLineageVerifier, VerifiedChildLineageV1
from redagent_platform.campaign_service.child_lineage import verify_settlement_time_projection
from redagent_platform.campaign_service.child_replan_contracts import CAPACITY_COOLDOWN_SECONDS, ChildReplanLineageV1, project_sequential_child_residual
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from redagent_platform.campaign_service.planning.serde import _decode_dataclass
from redagent_platform.persistence.models import metadata


_OwnerRow = Mapping[str, Any] | RowMapping


class CanonicalChildAdmissionRepository(CampaignAdmissionRepository):
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str, correlation_id: str,
                 preview: AutonomousCampaignPlanPreviewV1, verifier: ChildLineageVerifier | None, now: datetime) -> None:
        super().__init__(session, tenant_id=tenant_id, actor_user_id=actor_user_id, correlation_id=correlation_id)
        if preview.child_lineage_sha256 is None:
            raise ValueError("child_admission_lineage_required")
        self._preview, self._verifier, self._now = preview, verifier, now

    async def preview_residual(self, *, campaign_id: str, envelope_sha256: str,
                               authorized: CampaignBudgetVectorV1) -> CampaignBudgetVectorV1:
        if campaign_id != self._preview.campaign_id or envelope_sha256 != self._preview.authority_sha256:
            raise ChildLineageConflict("child_admission_budget_scope_mismatch")
        ledger = await self.lock_ledger(campaign_id=campaign_id, envelope_sha256=envelope_sha256,
                                       authorized=authorized, occurred_at=self._now)
        return await self.residual_for_locked_ledger(ledger)

    async def residual_for_locked_ledger(self, ledger: Mapping[str, object]) -> CampaignBudgetVectorV1:
        if self._verifier is None:
            raise ChildLineageConflict("child_lineage_verifier_unavailable")
        # CRITICAL: final admission reruns parent/backend proof under its budget lock before projecting only settled peak capacity.
        verified = await self._verifier.verify(tenant_id=self.tenant_id, campaign_id=self._preview.campaign_id,
            preview=self._preview, now=self._now, session=self.session)
        if (not isinstance(verified, VerifiedChildLineageV1) or verified.verified_at != self._now
                or verified.authority_sha256 != self._preview.authority_sha256
                or verified.signed_authority_sha256 != self._preview.signed_authority_sha256):
            raise ChildLineageConflict("child_admission_fresh_lineage_required")
        reservations = metadata.tables["campaign_budget_reservations"]
        rows = tuple((await self.session.execute(select(reservations).where(
            reservations.c.tenant_id == self.tenant_id, reservations.c.ledger_id == ledger["id"],
            reservations.c.reservation_state.in_(("reserved", "held", "consumed")),
        ).order_by(reservations.c.id).with_for_update())).mappings().all())
        parent = tuple(row for row in rows if row["id"] == verified.parent_reservation_id)
        if len(parent) != 1:
            raise ChildLineageConflict("child_admission_charged_parent_missing")
        return project_sequential_child_residual(authorized=_vector_from_row(ledger),
            parent_charge=_vector_from_row(parent[0]),
            other_charges=tuple(_vector_from_row(row) for row in rows if row["id"] != verified.parent_reservation_id),
            parent_completed_at=verified.parent_completed_at, capacity_available_at=verified.capacity_available_at,
            now=self._now)


def verify_child_transition_settlement(
    *, run: _OwnerRow, preview: AutonomousCampaignPlanPreviewV1,
    child: _OwnerRow, settlement: _OwnerRow, parent_run: _OwnerRow, now: datetime,
) -> VerifiedChildLineageV1:
    lineage = _decode_dataclass(ChildReplanLineageV1, child["lineage_payload"])
    payload = settlement["settlement_payload"]
    scope = (preview.tenant_id, preview.campaign_id)
    if (preview.execution_mode is not AutonomousCampaignMode.BOUNDED_REPLAN
            or any((row["tenant_id"], row.get("campaign_id", row.get("application_id"))) != scope
                   for row in (run, child, settlement, parent_run))
            or child["preview_id"] != preview.preview_id or child["preview_sha256"] != preview.preview_sha256
            or lineage.lineage_sha256 != preview.child_lineage_sha256 or lineage.lineage_sha256 != child["lineage_sha256"]
            or lineage.child_revision_sha256 != preview.plan_revision_sha256
            or lineage.settlement_sha256 != child["settlement_sha256"]
            or lineage.settlement_sha256 != settlement["settlement_sha256"]
            or canonical_planning_sha256(payload) != lineage.settlement_sha256
            or payload.get("schema_version") != "redagent.canonical-child-capacity-settlement/v1"
            or any(payload.get(field) != settlement[field] for field in (
                "tenant_id", "application_id", "parent_execution_run_id", "parent_run_version",
                "parent_reservation_id", "source_provenance_sha256", "parent_effect_receipt_sha256",
                "child_revision_sha256", "proposal_sha256"))
            or settlement["child_revision_sha256"] != lineage.child_revision_sha256
            or settlement["proposal_sha256"] != lineage.proposal_sha256
            or parent_run["id"] != lineage.parent_execution_run_id
            or parent_run["id"] != child["parent_execution_run_id"]
            or parent_run["id"] != settlement["parent_execution_run_id"]
            or parent_run["version"] != child["parent_run_version"]
            or parent_run["version"] != settlement["parent_run_version"]
            or parent_run["run_state"] not in {"completed", "contained"} or parent_run["active_concurrency"] != 0
            or parent_run["reservation_id"] != settlement["parent_reservation_id"]
            or parent_run["admission_receipt_sha256"] != lineage.parent_admission_receipt_sha256
            or payload.get("parent_admission_receipt_sha256") != parent_run["admission_receipt_sha256"]
            or run["reservation_id"] == parent_run["reservation_id"]
            or settlement["capacity_available_at"] != settlement["latest_effect_completed_at"] + timedelta(seconds=CAPACITY_COOLDOWN_SECONDS)
            or now < settlement["capacity_available_at"]):
        raise ChildLineageConflict("child_transition_settlement_binding_mismatch")
    verify_settlement_time_projection(payload=payload,
        latest_effect_completed_at=settlement["latest_effect_completed_at"],
        capacity_available_at=settlement["capacity_available_at"], settled_at=child["created_at"])
    return VerifiedChildLineageV1(parent_run["reservation_id"], parent_run["id"], parent_run["version"],
        lineage.settlement_sha256, preview.authority_sha256, preview.signed_authority_sha256,
        now, settlement["latest_effect_completed_at"], settlement["capacity_available_at"])


def child_transition_residual(
    *, authorized: CampaignBudgetVectorV1, rows: tuple[_OwnerRow, ...],
    verified: VerifiedChildLineageV1, child_reservation_id: str, now: datetime,
) -> CampaignBudgetVectorV1:
    parent = tuple(row for row in rows if row["id"] == verified.parent_reservation_id)
    if len(parent) != 1 or child_reservation_id == verified.parent_reservation_id:
        raise ChildLineageConflict("child_transition_charged_parent_missing")
    return project_sequential_child_residual(authorized=authorized, parent_charge=_vector_from_row(parent[0]),
        other_charges=tuple(_vector_from_row(row) for row in rows if row["id"] != verified.parent_reservation_id),
        parent_completed_at=verified.parent_completed_at, capacity_available_at=verified.capacity_available_at, now=now)


class _ChildSettlementTransitionRepository(CampaignAdmissionRepository):
    def __init__(self, session: AsyncSession, *, run: _OwnerRow, preview: AutonomousCampaignPlanPreviewV1,
                 actor_user_id: str, correlation_id: str, now: datetime) -> None:
        super().__init__(session, tenant_id=preview.tenant_id, actor_user_id=actor_user_id, correlation_id=correlation_id)
        self._run, self._preview, self._now = run, preview, now

    async def admit(self, command: AdmissionReservationCommandV1) -> PlanAdmissionReceiptV1:
        # CRITICAL: historical settlement is accounting only; new work must use the fresh child admission verifier.
        raise ChildLineageConflict("child_transition_new_admission_forbidden")

    async def create_reservation(self, *, ledger: Mapping[str, object], campaign_id: str, plan_sha256: str,
                                 request_sha256: str, idempotency_key: str, budget: CampaignBudgetVectorV1,
                                 lease_expires_at: datetime, occurred_at: datetime) -> str:
        raise ChildLineageConflict("child_transition_new_reservation_forbidden")

    async def transition_reservation(self, *, reservation_id: str, target: CampaignReservationState,
                                     effect_started: bool, reconciliation_code: str | None, now: datetime) -> CampaignReservationState:
        if reservation_id != self._run["reservation_id"] or now != self._now:
            raise ChildLineageConflict("child_transition_reservation_binding_mismatch")
        return await super().transition_reservation(reservation_id=reservation_id, target=target,
            effect_started=effect_started, reconciliation_code=reconciliation_code, now=now)

    async def residual_for_locked_ledger(self, ledger: Mapping[str, object]) -> CampaignBudgetVectorV1:
        if ledger["tenant_id"] != self.tenant_id or ledger["campaign_id"] != self._preview.campaign_id:
            raise ChildLineageConflict("child_transition_ledger_scope_mismatch")
        children, settlements, runs = (metadata.tables[name] for name in (
            "autonomous_campaign_child_replans", "campaign_child_capacity_settlements", "campaign_execution_runs"))
        child = (await self.session.execute(select(children).where(children.c.tenant_id == self.tenant_id,
            children.c.application_id == self._preview.campaign_id, children.c.preview_id == self._preview.preview_id))).mappings().one_or_none()
        if child is None:
            raise ChildLineageConflict("child_transition_owner_missing")
        settlement = (await self.session.execute(select(settlements).where(settlements.c.tenant_id == self.tenant_id,
            settlements.c.id == child["settlement_id"]))).mappings().one_or_none()
        # CRITICAL: bookkeeping preserves settled peaks after expiry; it never grants I/O, refreshes observation TTL or locks the parent after child locks.
        parent = (await self.session.execute(select(runs).where(runs.c.tenant_id == self.tenant_id,
            runs.c.id == child["parent_execution_run_id"]))).mappings().one_or_none()
        if settlement is None or parent is None:
            raise ChildLineageConflict("child_transition_settlement_owner_missing")
        verified = verify_child_transition_settlement(run=self._run, preview=self._preview,
            child=child, settlement=settlement, parent_run=parent, now=self._now)
        reservations = metadata.tables["campaign_budget_reservations"]
        rows = tuple((await self.session.execute(select(reservations).where(reservations.c.tenant_id == self.tenant_id,
            reservations.c.ledger_id == ledger["id"], reservations.c.reservation_state.in_(("reserved", "held", "consumed")))
            .order_by(reservations.c.id).with_for_update())).mappings().all())
        return child_transition_residual(authorized=_vector_from_row(ledger), rows=rows, verified=verified,
            child_reservation_id=str(self._run["reservation_id"]), now=self._now)


async def transition_repository_for_run(
    session: AsyncSession, *, run: _OwnerRow, actor_user_id: str, correlation_id: str, now: datetime,
) -> CampaignAdmissionRepository:
    starts = metadata.tables["autonomous_campaign_execution_starts"]
    start = (await session.execute(select(starts).where(starts.c.tenant_id == run["tenant_id"],
        starts.c.application_id == run["campaign_id"], starts.c.execution_run_id == run["id"]))).mappings().one_or_none()
    if start is not None:
        previews = metadata.tables["autonomous_campaign_plan_previews"]
        row = (await session.execute(select(previews).where(previews.c.tenant_id == run["tenant_id"],
            previews.c.application_id == run["campaign_id"], previews.c.id == start["preview_id"]))).mappings().one_or_none()
        if row is None:
            raise ChildLineageConflict("child_transition_preview_missing")
        preview = _verified_preview_from_payload(row["preview_payload"], str(row["preview_sha256"]))
        if preview.child_lineage_sha256 is not None:
            if (start["reservation_id"] != run["reservation_id"]
                    or start["admission_receipt_sha256"] != run["admission_receipt_sha256"]):
                raise ChildLineageConflict("child_transition_start_binding_mismatch")
            return _ChildSettlementTransitionRepository(session, run=run, preview=preview,
                actor_user_id=actor_user_id, correlation_id=correlation_id, now=now)
    return CampaignAdmissionRepository(session, tenant_id=str(run["tenant_id"]),
        actor_user_id=actor_user_id, correlation_id=correlation_id)
