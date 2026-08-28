"""Transaction-neutral PostgreSQL owner for campaign plan admission state."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import json
from typing import Any, Mapping, cast
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.admission_contracts import (
    PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
    AdmissionOutcome,
    CampaignBudgetVectorV1,
    CampaignReservationState,
    PlanAdmissionReceiptV1,
    assert_campaign_reservation_transition,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes
from redagent_platform.persistence.models import metadata
from redagent_platform.policy_service.contracts import (
    PolicyDecision,
    PolicyDecisionInput,
    policy_input_hash,
)


_VECTOR_FIELDS = (
    "duration_seconds",
    "requests",
    "rate_per_minute",
    "concurrency",
    "risk_micropoints",
    "cost_microunits",
    "evidence_bytes",
    "data_bytes",
)
_CHARGED_STATES = ("reserved", "held", "consumed")


class AdmissionConflict(RuntimeError):
    pass


@dataclass(frozen=True, slots=True, kw_only=True)
class AdmissionReservationCommandV1:
    campaign_id: str
    engagement_id: str
    signed_authority_sha256: str
    authority_sha256: str
    domain_sha256: str
    plan_sha256: str
    certificate_sha256: str
    validator_version: str
    validator_sha256: str
    subset_proof_sha256: str
    policy_bundle_sha256: str
    authorized_budget: CampaignBudgetVectorV1
    reserved_budget: CampaignBudgetVectorV1
    policy_request: PolicyDecisionInput
    policy_decision: PolicyDecision
    idempotency_key: str
    request_sha256: str
    lifecycle_epoch: int
    policy_revocation_epoch: int
    roe_revocation_epoch: int
    kill_switch_epoch: int
    issued_at: datetime
    lease_expires_at: datetime


class CampaignAdmissionRepository:
    """All methods participate in the caller-owned transaction."""

    def __init__(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        self.session = session
        self.tenant_id = tenant_id
        self.actor_user_id = actor_user_id
        self.correlation_id = correlation_id

    async def admit(self, command: AdmissionReservationCommandV1) -> PlanAdmissionReceiptV1:
        if not isinstance(command, AdmissionReservationCommandV1):
            raise ValueError("plan_admission_command_invalid")
        self._assert_command(command)
        await self._set_tenant()
        # CRITICAL: serialize replay, ledger creation, policy evidence, reservation, and receipt together.
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": f"campaign-budget:{self.tenant_id}:{command.campaign_id}"},
        )
        existing = await self.existing_receipt(
            campaign_id=command.campaign_id,
            idempotency_key=command.idempotency_key,
            request_sha256=command.request_sha256,
        )
        if existing is not None:
            return _receipt_from_payload(existing["receipt_payload"])

        ledger = await self.lock_ledger(
            campaign_id=command.campaign_id,
            envelope_sha256=command.authority_sha256,
            authorized=command.authorized_budget,
            occurred_at=command.issued_at,
        )
        residual = await self.residual_for_locked_ledger(ledger)
        if command.policy_request.attributes.get("campaign_residual_budget_sha256") != residual.budget_sha256:
            raise AdmissionConflict("campaign_budget_residual_changed")
        try:
            command.policy_decision.assert_current(
                command.policy_request,
                required_revision=command.policy_request.policy_reference,
                now=command.issued_at,
            )
        except ValueError as exc:
            raise AdmissionConflict("plan_admission_policy_stale") from exc
        if not command.policy_decision.allowed:
            raise AdmissionConflict("plan_admission_policy_denied")
        if not command.reserved_budget.fits_within(residual):
            raise AdmissionConflict("campaign_budget_exhausted")

        post_residual = residual.subtract(command.reserved_budget)
        reservation_id = await self.create_reservation(
            ledger=ledger,
            campaign_id=command.campaign_id,
            plan_sha256=command.plan_sha256,
            request_sha256=command.request_sha256,
            idempotency_key=command.idempotency_key,
            budget=command.reserved_budget,
            lease_expires_at=command.lease_expires_at,
            occurred_at=command.issued_at,
        )
        policy_row_id, policy_receipt_id = await self._persist_policy(command)
        receipt_id = f"admission-{uuid4().hex}"
        audit_id = f"audit-{uuid4().hex}"
        outbox_id = f"outbox-{uuid4().hex}"
        receipt = PlanAdmissionReceiptV1(
            schema_version=PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
            receipt_id=receipt_id,
            tenant_id=self.tenant_id,
            campaign_id=command.campaign_id,
            engagement_id=command.engagement_id,
            signed_authority_sha256=command.signed_authority_sha256,
            authority_sha256=command.authority_sha256,
            domain_sha256=command.domain_sha256,
            plan_sha256=command.plan_sha256,
            certificate_sha256=command.certificate_sha256,
            validator_version=command.validator_version,
            validator_sha256=command.validator_sha256,
            subset_proof_sha256=command.subset_proof_sha256,
            policy_decision_id=command.policy_decision.decision_id,
            policy_input_sha256=command.policy_decision.input_hash,
            policy_bundle_revision=command.policy_decision.bundle_revision,
            policy_bundle_sha256=command.policy_bundle_sha256,
            pre_residual_budget_sha256=residual.budget_sha256,
            post_residual_budget_sha256=post_residual.budget_sha256,
            reserved_budget=command.reserved_budget,
            reservation_id=reservation_id,
            idempotency_key=command.idempotency_key,
            request_sha256=command.request_sha256,
            lifecycle_epoch=command.lifecycle_epoch,
            policy_revocation_epoch=command.policy_revocation_epoch,
            roe_revocation_epoch=command.roe_revocation_epoch,
            kill_switch_epoch=command.kill_switch_epoch,
            issued_at=command.issued_at,
            expires_at=command.lease_expires_at,
            outcome=AdmissionOutcome.ADMITTED,
            denial_stage=None,
            reason_code="admitted",
            audit_id=audit_id,
            outbox_id=outbox_id,
        )
        payload = json.loads(canonical_planning_bytes(receipt))
        details = {
            "campaign_id": command.campaign_id,
            "plan_sha256": command.plan_sha256,
            "receipt_id": receipt_id,
            "receipt_sha256": receipt.receipt_sha256,
            "reservation_id": reservation_id,
            "policy_decision_id": command.policy_decision.decision_id,
            "outcome": "admitted",
        }
        owned = self._owned(command.issued_at)
        await self.session.execute(
            insert(metadata.tables["plan_admission_receipts"]).values(
                id=receipt_id,
                campaign_id=command.campaign_id,
                reservation_id=reservation_id,
                policy_decision_id=policy_row_id,
                policy_boundary_receipt_id=policy_receipt_id,
                outcome="admitted",
                reason_code="admitted",
                idempotency_key=command.idempotency_key,
                request_sha256=command.request_sha256,
                receipt_sha256=receipt.receipt_sha256,
                receipt_payload=payload,
                **owned,
            )
        )
        await self.session.execute(
            insert(metadata.tables["campaign_budget_events"]).values(
                id=f"budget-event-{uuid4().hex}",
                ledger_id=ledger["id"],
                reservation_id=reservation_id,
                campaign_id=command.campaign_id,
                event_type="campaign.plan.admitted.v1",
                previous_state=None,
                next_state="reserved",
                before_residual_sha256=residual.budget_sha256,
                after_residual_sha256=post_residual.budget_sha256,
                receipt_sha256=receipt.receipt_sha256,
                **owned,
            )
        )
        await self.session.execute(
            insert(metadata.tables["audit_events"]).values(
                id=audit_id,
                actor_user_id=self.actor_user_id,
                action="campaign.plan.admitted.v1",
                subject_type="campaign_plan",
                subject_id=command.campaign_id,
                correlation_id=self.correlation_id,
                details=details,
                **owned,
            )
        )
        await self.session.execute(
            insert(metadata.tables["outbox_events"]).values(
                id=outbox_id,
                event_type="campaign.plan.admitted.v1",
                aggregate_id=command.campaign_id,
                payload=details,
                published=False,
                **owned,
            )
        )
        return receipt

    async def lock_ledger(
        self,
        *,
        campaign_id: str,
        envelope_sha256: str,
        authorized: CampaignBudgetVectorV1,
        occurred_at: datetime,
    ) -> Mapping[str, object]:
        await self._set_tenant()
        # CRITICAL: the campaign lock must precede ledger creation/read or concurrent admits can mint siblings.
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": f"campaign-budget:{self.tenant_id}:{campaign_id}"},
        )
        ledgers = metadata.tables["campaign_budget_ledgers"]
        existing = (
            (
                await self.session.execute(
                    select(ledgers)
                    .where(
                        ledgers.c.tenant_id == self.tenant_id,
                        ledgers.c.campaign_id == campaign_id,
                    )
                    .with_for_update()
                )
            )
            .mappings()
            .one_or_none()
        )
        if existing is None:
            ledger_id = f"budget-ledger-{uuid4().hex}"
            await self.session.execute(
                insert(ledgers).values(
                    id=ledger_id,
                    campaign_id=campaign_id,
                    envelope_sha256=envelope_sha256,
                    **_vector_values(authorized),
                    **self._owned(occurred_at),
                )
            )
            row: Mapping[str, object] = {
                "id": ledger_id,
                "campaign_id": campaign_id,
                "envelope_sha256": envelope_sha256,
                **_vector_values(authorized),
            }
        else:
            row = dict(existing)
            if row["envelope_sha256"] != envelope_sha256 or _vector_from_row(row) != authorized:
                raise AdmissionConflict("campaign_budget_ledger_binding_mismatch")
        return row

    async def residual_for_locked_ledger(
        self,
        ledger: Mapping[str, object],
    ) -> CampaignBudgetVectorV1:
        reservations = metadata.tables["campaign_budget_reservations"]
        rows = (
            (
                await self.session.execute(
                    select(reservations).where(
                        reservations.c.tenant_id == self.tenant_id,
                        reservations.c.ledger_id == ledger["id"],
                        reservations.c.reservation_state.in_(_CHARGED_STATES),
                    )
                )
            )
            .mappings()
            .all()
        )
        charged = CampaignBudgetVectorV1(0, 0, 0, 0, 0, 0, 0, 0)
        for row in rows:
            charged = charged.add(_vector_from_row(row))
        return _vector_from_row(ledger).subtract(charged)

    async def preview_residual(
        self,
        *,
        campaign_id: str,
        envelope_sha256: str,
        authorized: CampaignBudgetVectorV1,
    ) -> CampaignBudgetVectorV1:
        await self._set_tenant()
        ledgers = metadata.tables["campaign_budget_ledgers"]
        existing = (
            (
                await self.session.execute(
                    select(ledgers).where(
                        ledgers.c.tenant_id == self.tenant_id,
                        ledgers.c.campaign_id == campaign_id,
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        if existing is None:
            return authorized
        row = dict(existing)
        if row["envelope_sha256"] != envelope_sha256 or _vector_from_row(row) != authorized:
            raise AdmissionConflict("campaign_budget_ledger_binding_mismatch")
        return await self.residual_for_locked_ledger(row)

    async def existing_receipt(
        self,
        *,
        campaign_id: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> Mapping[str, object] | None:
        await self._set_tenant()
        receipts = metadata.tables["plan_admission_receipts"]
        row = (
            (
                await self.session.execute(
                    select(receipts).where(
                        receipts.c.tenant_id == self.tenant_id,
                        receipts.c.campaign_id == campaign_id,
                        receipts.c.idempotency_key == idempotency_key,
                    )
                )
            )
            .mappings()
            .one_or_none()
        )
        if row is not None and row["request_sha256"] != request_sha256:
            # CRITICAL: an idempotency key is bound to exact canonical request bytes, never caller intent.
            raise AdmissionConflict("plan_admission_idempotency_mismatch")
        return None if row is None else dict(row)

    async def create_reservation(
        self,
        *,
        ledger: Mapping[str, object],
        campaign_id: str,
        plan_sha256: str,
        request_sha256: str,
        idempotency_key: str,
        budget: CampaignBudgetVectorV1,
        lease_expires_at: datetime,
        occurred_at: datetime,
    ) -> str:
        residual = await self.residual_for_locked_ledger(ledger)
        if not budget.fits_within(residual):
            raise AdmissionConflict("campaign_budget_exhausted")
        reservation_id = f"budget-reservation-{uuid4().hex}"
        await self.session.execute(
            insert(metadata.tables["campaign_budget_reservations"]).values(
                id=reservation_id,
                ledger_id=ledger["id"],
                campaign_id=campaign_id,
                plan_sha256=plan_sha256,
                request_sha256=request_sha256,
                idempotency_key=idempotency_key,
                reservation_state="reserved",
                lease_expires_at=lease_expires_at,
                effect_started=False,
                reconciliation_code=None,
                **_vector_values(budget),
                **self._owned(occurred_at),
            )
        )
        return reservation_id

    async def transition_reservation(
        self,
        *,
        reservation_id: str,
        target: CampaignReservationState,
        effect_started: bool,
        reconciliation_code: str | None,
        now: datetime,
    ) -> CampaignReservationState:
        await self._set_tenant()
        reservations = metadata.tables["campaign_budget_reservations"]
        locator = (
            await self.session.execute(
                select(reservations.c.campaign_id).where(
                    reservations.c.tenant_id == self.tenant_id,
                    reservations.c.id == reservation_id,
                )
            )
        ).one_or_none()
        if locator is None:
            raise AdmissionConflict("campaign_budget_reservation_missing")
        campaign_id = str(locator[0])
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": f"campaign-budget:{self.tenant_id}:{campaign_id}"},
        )
        row = (
            (
                await self.session.execute(
                    select(reservations)
                    .where(
                        reservations.c.tenant_id == self.tenant_id,
                        reservations.c.id == reservation_id,
                    )
                    .with_for_update()
                )
            )
            .mappings()
            .one()
        )
        current = CampaignReservationState(str(row["reservation_state"]))
        assert_campaign_reservation_transition(
            current,
            target,
            effect_started=effect_started,
            reconciliation_code=reconciliation_code,
            now=now,
            lease_expires_at=cast(datetime, row["lease_expires_at"]),
        )
        ledgers = metadata.tables["campaign_budget_ledgers"]
        ledger = (
            (
                await self.session.execute(
                    select(ledgers)
                    .where(
                        ledgers.c.tenant_id == self.tenant_id,
                        ledgers.c.id == row["ledger_id"],
                    )
                    .with_for_update()
                )
            )
            .mappings()
            .one()
        )
        before = await self.residual_for_locked_ledger(dict(ledger))
        updated = await self.session.execute(
            update(reservations)
            .where(
                reservations.c.tenant_id == self.tenant_id,
                reservations.c.id == reservation_id,
                reservations.c.version == row["version"],
            )
            .values(
                reservation_state=target.value,
                effect_started=effect_started,
                reconciliation_code=reconciliation_code,
                version=reservations.c.version + 1,
                updated_at=now,
            )
            .returning(reservations.c.id)
        )
        if updated.scalar_one_or_none() is None:
            raise AdmissionConflict("campaign_budget_reservation_version_conflict")
        after = await self.residual_for_locked_ledger(dict(ledger))
        event_id = f"budget-event-{uuid4().hex}"
        audit_id = f"audit-{uuid4().hex}"
        outbox_id = f"outbox-{uuid4().hex}"
        details = {
            "campaign_id": campaign_id,
            "reservation_id": reservation_id,
            "previous_state": current.value,
            "next_state": target.value,
            "reconciliation_code": reconciliation_code,
            "before_residual_sha256": before.budget_sha256,
            "after_residual_sha256": after.budget_sha256,
        }
        owned = self._owned(now)
        await self.session.execute(
            insert(metadata.tables["campaign_budget_events"]).values(
                id=event_id,
                ledger_id=row["ledger_id"],
                reservation_id=reservation_id,
                campaign_id=campaign_id,
                event_type=f"campaign.budget.{target.value}.v1",
                previous_state=current.value,
                next_state=target.value,
                before_residual_sha256=before.budget_sha256,
                after_residual_sha256=after.budget_sha256,
                receipt_sha256=None,
                **owned,
            )
        )
        await self.session.execute(
            insert(metadata.tables["audit_events"]).values(
                id=audit_id,
                actor_user_id=self.actor_user_id,
                action=f"campaign.budget.{target.value}.v1",
                subject_type="campaign_budget_reservation",
                subject_id=reservation_id,
                correlation_id=self.correlation_id,
                details=details,
                **owned,
            )
        )
        await self.session.execute(
            insert(metadata.tables["outbox_events"]).values(
                id=outbox_id,
                event_type=f"campaign.budget.{target.value}.v1",
                aggregate_id=campaign_id,
                payload=details,
                published=False,
                **owned,
            )
        )
        return target

    async def _set_tenant(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
            {"tenant": self.tenant_id},
        )

    def _assert_command(self, command: AdmissionReservationCommandV1) -> None:
        request = command.policy_request
        if (
            request.tenant_id != self.tenant_id
            or request.resource_id != command.campaign_id
            or request.action != "campaign.plan.admit"
            or request.boundary.value != "workflow"
            or policy_input_hash(request) != command.policy_decision.input_hash
            or request.attributes.get("campaign_authority_sha256") != command.authority_sha256
            or request.attributes.get("campaign_policy_bundle_sha256") != command.policy_bundle_sha256
            or request.attributes.get("campaign_domain_sha256") != command.domain_sha256
            or request.attributes.get("campaign_plan_sha256") != command.plan_sha256
            or request.attributes.get("campaign_certificate_sha256") != command.certificate_sha256
            or request.attributes.get("campaign_subset_proof_sha256") != command.subset_proof_sha256
        ):
            raise AdmissionConflict("plan_admission_command_binding_mismatch")

    async def _persist_policy(self, command: AdmissionReservationCommandV1) -> tuple[str, str]:
        decisions = metadata.tables["policy_decisions"]
        decision_row_id = f"policy-decision-{uuid4().hex}"
        await self.session.execute(
            insert(decisions).values(
                id=decision_row_id,
                opa_decision_id=command.policy_decision.decision_id,
                bundle_revision=command.policy_decision.bundle_revision,
                input_hash=command.policy_decision.input_hash,
                boundary=command.policy_request.boundary.value,
                action=command.policy_request.action,
                subject_id=command.policy_request.subject_id,
                resource_type=command.policy_request.resource_type,
                resource_id=command.policy_request.resource_id,
                resource_version=None,
                allowed=True,
                reason_code=command.policy_decision.reason_code,
                obligations=[item.value for item in command.policy_decision.obligations],
                issued_at=command.policy_decision.issued_at,
                valid_until=command.policy_decision.valid_until,
                correlation_id=command.policy_request.correlation_id,
                **self._owned(command.issued_at),
            )
        )
        policy_receipt_id = f"policy-receipt-{uuid4().hex}"
        await self.session.execute(
            insert(metadata.tables["policy_boundary_receipts"]).values(
                id=policy_receipt_id,
                decision_id=decision_row_id,
                boundary="workflow",
                aggregate_type="campaign_plan",
                aggregate_id=command.campaign_id,
                operation=f"campaign.plan.admit:{command.request_sha256[:32]}",
                input_hash=command.policy_decision.input_hash,
                enforcement_outcome="allowed",
                enforced_at=command.issued_at,
                **self._owned(command.issued_at),
            )
        )
        return decision_row_id, policy_receipt_id

    def _owned(self, occurred_at: datetime) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "version": 1,
            "created_at": occurred_at,
            "updated_at": occurred_at,
        }


class TransactionalCampaignAdmissionStore:
    """Short transactions around preview, exact replay, denial, and atomic admission."""

    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        *,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        self.session_factory = session_factory
        self.actor_user_id = actor_user_id
        self.correlation_id = correlation_id

    async def replay(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> PlanAdmissionReceiptV1 | None:
        async with self.session_factory() as session, session.begin():
            repo = self._repo(session, tenant_id)
            row = await repo.existing_receipt(
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
            )
            return None if row is None else _receipt_from_payload(row["receipt_payload"])

    async def preview_residual(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        envelope_sha256: str,
        authorized_budget: CampaignBudgetVectorV1,
    ) -> CampaignBudgetVectorV1:
        async with self.session_factory() as session, session.begin():
            return await self._repo(session, tenant_id).preview_residual(
                campaign_id=campaign_id,
                envelope_sha256=envelope_sha256,
                authorized=authorized_budget,
            )

    async def admit(self, command: AdmissionReservationCommandV1) -> PlanAdmissionReceiptV1:
        async with self.session_factory() as session, session.begin():
            return await self._repo(session, command.policy_request.tenant_id).admit(command)

    async def deny(self, **values: object) -> PlanAdmissionReceiptV1:
        context = values.get("context")
        if not isinstance(context, dict):
            raise ValueError("plan_admission_denial_context_invalid")
        tenant_id = str(context["tenant_id"])
        campaign_id = str(values["campaign_id"])
        idempotency_key = str(values["idempotency_key"])
        request_sha256 = str(values["request_sha256"])
        occurred_at = context["issued_at"]
        if not isinstance(occurred_at, datetime):
            raise ValueError("plan_admission_denial_time_invalid")
        async with self.session_factory() as session, session.begin():
            repo = self._repo(session, tenant_id)
            await repo._set_tenant()
            await session.execute(
                text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                {"scope": f"campaign-budget:{tenant_id}:{campaign_id}"},
            )
            existing = await repo.existing_receipt(
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
            )
            if existing is not None:
                return _receipt_from_payload(existing["receipt_payload"])

            policy_request = values.get("policy_request")
            policy_decision = values.get("policy_decision")
            policy_row_id: str | None = None
            policy_receipt_id: str | None = None
            if isinstance(policy_request, PolicyDecisionInput) and isinstance(policy_decision, PolicyDecision):
                policy_row_id, policy_receipt_id = await _persist_denied_policy(
                    session,
                    repo,
                    policy_request,
                    policy_decision,
                    campaign_id=campaign_id,
                    occurred_at=occurred_at,
                    request_sha256=request_sha256,
                )

            receipt_id = f"admission-{uuid4().hex}"
            audit_id = f"audit-{uuid4().hex}"
            outbox_id = f"outbox-{uuid4().hex}"
            pre_residual = None
            if isinstance(policy_request, PolicyDecisionInput):
                candidate = policy_request.attributes.get("campaign_residual_budget_sha256")
                pre_residual = candidate if isinstance(candidate, str) else None
            receipt = PlanAdmissionReceiptV1(
                schema_version=PLAN_ADMISSION_RECEIPT_SCHEMA_VERSION,
                receipt_id=receipt_id,
                tenant_id=tenant_id,
                campaign_id=campaign_id,
                engagement_id=str(context["engagement_id"]),
                signed_authority_sha256=str(context["signed_authority_sha256"]),
                authority_sha256=str(context["authority_sha256"]),
                domain_sha256=str(context["domain_sha256"]),
                plan_sha256=str(context["plan_sha256"]),
                certificate_sha256=str(context["certificate_sha256"]),
                validator_version=str(context["validator_version"]),
                validator_sha256=str(context["validator_sha256"]),
                subset_proof_sha256=str(context["subset_proof_sha256"]),
                policy_decision_id=(
                    policy_decision.decision_id if isinstance(policy_decision, PolicyDecision) else None
                ),
                policy_input_sha256=(
                    policy_decision.input_hash if isinstance(policy_decision, PolicyDecision) else None
                ),
                policy_bundle_revision=(
                    policy_decision.bundle_revision if isinstance(policy_decision, PolicyDecision) else None
                ),
                policy_bundle_sha256=str(context["policy_bundle_sha256"]),
                pre_residual_budget_sha256=pre_residual,
                post_residual_budget_sha256=None,
                reserved_budget=None,
                reservation_id=None,
                idempotency_key=idempotency_key,
                request_sha256=request_sha256,
                lifecycle_epoch=cast(int, context["lifecycle_epoch"]),
                policy_revocation_epoch=cast(int, context["policy_revocation_epoch"]),
                roe_revocation_epoch=cast(int, context["roe_revocation_epoch"]),
                kill_switch_epoch=cast(int, context["kill_switch_epoch"]),
                issued_at=occurred_at,
                expires_at=occurred_at + timedelta(minutes=5),
                outcome=AdmissionOutcome.DENIED,
                denial_stage=str(values["denial_stage"]),
                reason_code=str(values["reason_code"]),
                audit_id=audit_id,
                outbox_id=outbox_id,
            )
            payload = json.loads(canonical_planning_bytes(receipt))
            details = {
                "campaign_id": campaign_id,
                "plan_sha256": context["plan_sha256"],
                "receipt_id": receipt_id,
                "receipt_sha256": receipt.receipt_sha256,
                "denial_stage": values["denial_stage"],
                "reason_code": values["reason_code"],
                "outcome": "denied",
            }
            owned = repo._owned(occurred_at)
            await session.execute(
                insert(metadata.tables["plan_admission_receipts"]).values(
                    id=receipt_id,
                    campaign_id=campaign_id,
                    reservation_id=None,
                    policy_decision_id=policy_row_id,
                    policy_boundary_receipt_id=policy_receipt_id,
                    outcome="denied",
                    reason_code=values["reason_code"],
                    idempotency_key=idempotency_key,
                    request_sha256=request_sha256,
                    receipt_sha256=receipt.receipt_sha256,
                    receipt_payload=payload,
                    **owned,
                )
            )
            await session.execute(
                insert(metadata.tables["audit_events"]).values(
                    id=audit_id,
                    actor_user_id=self.actor_user_id,
                    action="campaign.plan.denied.v1",
                    subject_type="campaign_plan",
                    subject_id=campaign_id,
                    correlation_id=self.correlation_id,
                    details=details,
                    **owned,
                )
            )
            await session.execute(
                insert(metadata.tables["outbox_events"]).values(
                    id=outbox_id,
                    event_type="campaign.plan.denied.v1",
                    aggregate_id=campaign_id,
                    payload=details,
                    published=False,
                    **owned,
                )
            )
            return receipt

    def _repo(self, session: AsyncSession, tenant_id: str) -> CampaignAdmissionRepository:
        return CampaignAdmissionRepository(
            session,
            tenant_id=tenant_id,
            actor_user_id=self.actor_user_id,
            correlation_id=self.correlation_id,
        )


def _vector_values(vector: CampaignBudgetVectorV1) -> dict[str, int]:
    values = asdict(vector)
    values.pop("schema_version")
    return values


async def _persist_denied_policy(
    session: AsyncSession,
    repo: CampaignAdmissionRepository,
    request: PolicyDecisionInput,
    decision: PolicyDecision,
    *,
    campaign_id: str,
    occurred_at: datetime,
    request_sha256: str,
) -> tuple[str, str]:
    if decision.allowed:
        raise AdmissionConflict("plan_admission_denial_policy_allowed")
    decision.assert_current(request, required_revision=request.policy_reference, now=occurred_at)
    decision_row_id = f"policy-decision-{uuid4().hex}"
    await session.execute(
        insert(metadata.tables["policy_decisions"]).values(
            id=decision_row_id,
            opa_decision_id=decision.decision_id,
            bundle_revision=decision.bundle_revision,
            input_hash=decision.input_hash,
            boundary=request.boundary.value,
            action=request.action,
            subject_id=request.subject_id,
            resource_type=request.resource_type,
            resource_id=request.resource_id,
            resource_version=None,
            allowed=False,
            reason_code=decision.reason_code,
            obligations=[item.value for item in decision.obligations],
            issued_at=decision.issued_at,
            valid_until=decision.valid_until,
            correlation_id=request.correlation_id,
            **repo._owned(occurred_at),
        )
    )
    policy_receipt_id = f"policy-receipt-{uuid4().hex}"
    await session.execute(
        insert(metadata.tables["policy_boundary_receipts"]).values(
            id=policy_receipt_id,
            decision_id=decision_row_id,
            boundary="workflow",
            aggregate_type="campaign_plan",
            aggregate_id=campaign_id,
            operation=f"campaign.plan.admit:{request_sha256[:32]}",
            input_hash=decision.input_hash,
            enforcement_outcome="denied",
            enforced_at=occurred_at,
            **repo._owned(occurred_at),
        )
    )
    return decision_row_id, policy_receipt_id


def _vector_from_row(row: Any) -> CampaignBudgetVectorV1:
    return CampaignBudgetVectorV1(
        duration_seconds=int(row["duration_seconds"]),
        requests=int(row["requests"]),
        rate_per_minute=int(row["rate_per_minute"]),
        concurrency=int(row["concurrency"]),
        risk_micropoints=int(row["risk_micropoints"]),
        cost_microunits=int(row["cost_microunits"]),
        evidence_bytes=int(row["evidence_bytes"]),
        data_bytes=int(row["data_bytes"]),
    )


def _receipt_from_payload(payload: object) -> PlanAdmissionReceiptV1:
    if not isinstance(payload, dict):
        raise AdmissionConflict("plan_admission_receipt_payload_invalid")
    values = dict(payload)
    budget = values.get("reserved_budget")
    if isinstance(budget, dict):
        values["reserved_budget"] = CampaignBudgetVectorV1(**budget)
    values["outcome"] = AdmissionOutcome(values["outcome"])
    for name in ("issued_at", "expires_at"):
        value = values[name]
        if not isinstance(value, str):
            raise AdmissionConflict("plan_admission_receipt_payload_invalid")
        values[name] = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return PlanAdmissionReceiptV1(**values)
