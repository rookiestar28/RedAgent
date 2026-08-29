"""PostgreSQL append-only persistence for trust decisions and bounded replan lineage."""

from __future__ import annotations

from datetime import datetime
import json

from sqlalchemy import insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes
from redagent_platform.campaign_service.replanning_contracts import (
    AcceptedBoundedReplanV1,
    BoundedReplanProposalV1,
)
from redagent_platform.campaign_service.trusted_observations import (
    ObservationCandidateV1,
    ObservationPromotionDecisionV1,
)
from redagent_platform.persistence.models import metadata


class ReplanningPersistenceConflict(RuntimeError):
    """A replay or tenant-owned lineage binding did not match exactly."""


class CampaignReplanningRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str) -> None:
        self.session = session
        self.tenant_id = tenant_id

    async def append_promotion(
        self,
        *,
        campaign_id: str,
        candidate: ObservationCandidateV1,
        decision: ObservationPromotionDecisionV1,
        occurred_at: datetime,
    ) -> str:
        if (
            candidate.tenant_id != self.tenant_id
            or candidate.campaign_id != campaign_id
            or decision.candidate_sha256 != candidate.candidate_sha256
        ):
            raise ReplanningPersistenceConflict("observation_persistence_binding_mismatch")
        await self._set_tenant()
        decisions = metadata.tables["campaign_observation_decisions"]
        existing = (
            await self.session.execute(
                select(decisions.c.id, decisions.c.decision_sha256).where(
                    decisions.c.tenant_id == self.tenant_id,
                    decisions.c.campaign_id == campaign_id,
                    decisions.c.candidate_sha256 == candidate.candidate_sha256,
                )
            )
        ).mappings().one_or_none()
        if existing is not None:
            if existing["decision_sha256"] != decision.decision_sha256:
                raise ReplanningPersistenceConflict("observation_persistence_replay_conflict")
            return str(existing["id"])
        decision_id = f"observation-decision-{decision.decision_sha256[:40]}"
        owned = self._owned(occurred_at)
        await self.session.execute(
            insert(decisions).values(
                id=decision_id,
                campaign_id=campaign_id,
                candidate_sha256=candidate.candidate_sha256,
                decision_sha256=decision.decision_sha256,
                outcome=decision.outcome.value,
                reason_code=decision.reason_code,
                candidate_payload=_payload(candidate),
                decision_payload=_payload(decision),
                decided_at=decision.decided_at,
                **owned,
            )
        )
        trusted = decision.trusted_observation
        if trusted is not None:
            item = trusted.candidate
            await self.session.execute(
                insert(metadata.tables["trusted_campaign_observations"]).values(
                    id=f"trusted-observation-{trusted.observation_sha256[:40]}",
                    decision_id=decision_id,
                    campaign_id=campaign_id,
                    target_id=item.target_id,
                    fact_id=item.fact_id,
                    producer_kind=item.producer.kind.value,
                    producer_id=item.producer.producer_id,
                    producer_version=item.producer.producer_version,
                    observation_sha256=trusted.observation_sha256,
                    provenance_sha256=trusted.provenance_sha256,
                    source_result_sha256=item.source_result_sha256,
                    evidence_sha256=item.evidence_sha256,
                    trusted_payload=_payload(trusted),
                    observed_at=item.observed_at,
                    received_at=item.received_at,
                    expires_at=item.expires_at,
                    promoted_at=trusted.promoted_at,
                    **owned,
                )
            )
        return decision_id

    async def append_proposal(
        self,
        *,
        campaign_id: str,
        proposal: BoundedReplanProposalV1,
        occurred_at: datetime,
    ) -> str:
        child = proposal.child_revision
        if child.tenant_id != self.tenant_id:
            raise ReplanningPersistenceConflict("replan_persistence_tenant_mismatch")
        await self._set_tenant()
        table = metadata.tables["campaign_replan_proposals"]
        existing = (
            await self.session.execute(
                select(table.c.id, table.c.proposal_sha256).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.request_sha256 == proposal.request_sha256,
                )
            )
        ).mappings().one_or_none()
        if existing is not None:
            if existing["proposal_sha256"] != proposal.proposal_sha256:
                raise ReplanningPersistenceConflict("replan_persistence_replay_conflict")
            return str(existing["id"])
        existing_child = (
            await self.session.execute(
                select(table.c.proposal_sha256).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.child_revision_sha256 == child.revision_sha256,
                )
            )
        ).scalar_one_or_none()
        if existing_child is not None:
            # IMPORTANT: a new request ID cannot turn the same observation delta into another replan.
            raise ReplanningPersistenceConflict("replan_persistence_child_revision_conflict")
        proposal_id = f"replan-proposal-{proposal.proposal_sha256[:40]}"
        await self.session.execute(
            insert(table).values(
                id=proposal_id,
                campaign_id=campaign_id,
                request_sha256=proposal.request_sha256,
                proposal_sha256=proposal.proposal_sha256,
                parent_revision_id=proposal.parent_revision_id,
                parent_revision_sha256=proposal.parent_revision_sha256,
                parent_admission_receipt_id=proposal.parent_admission_receipt_id,
                parent_admission_receipt_sha256=proposal.parent_admission_receipt_sha256,
                child_revision_id=child.revision_id,
                child_revision_sha256=child.revision_sha256,
                observation_history_sha256=proposal.observation_history_sha256,
                residual_budget_sha256=proposal.residual_budget.budget_sha256,
                planned_budget_sha256=proposal.planned_budget.budget_sha256,
                certificate_sha256=proposal.validation_certificate.certificate_sha256,
                subset_proof_sha256=proposal.subset_proof.proof_sha256,
                search_receipt_sha256=proposal.search_receipt.receipt_sha256,
                replan_sequence=proposal.replan_sequence,
                lifecycle_epoch=proposal.lifecycle_epoch,
                policy_revocation_epoch=proposal.policy_revocation_epoch,
                roe_revocation_epoch=proposal.roe_revocation_epoch,
                kill_switch_epoch=proposal.kill_switch_epoch,
                proposal_payload=_payload(proposal),
                **self._owned(occurred_at),
            )
        )
        return proposal_id

    async def append_acceptance(
        self,
        *,
        campaign_id: str,
        proposal_id: str,
        accepted: AcceptedBoundedReplanV1,
        occurred_at: datetime,
    ) -> str:
        if accepted.proposal.child_revision.tenant_id != self.tenant_id:
            raise ReplanningPersistenceConflict("replan_acceptance_tenant_mismatch")
        await self._set_tenant()
        proposals = metadata.tables["campaign_replan_proposals"]
        persisted_proposal = (
            await self.session.execute(
                select(proposals.c.proposal_sha256).where(
                    proposals.c.tenant_id == self.tenant_id,
                    proposals.c.id == proposal_id,
                    proposals.c.campaign_id == campaign_id,
                )
            )
        ).scalar_one_or_none()
        # CRITICAL: an admission-bound child cannot be attached to a different persisted proposal.
        if persisted_proposal != accepted.proposal.proposal_sha256:
            raise ReplanningPersistenceConflict("replan_acceptance_proposal_binding_mismatch")
        table = metadata.tables["campaign_replan_acceptances"]
        existing = (
            await self.session.execute(
                select(table.c.id, table.c.accepted_replan_sha256).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.proposal_id == proposal_id,
                )
            )
        ).mappings().one_or_none()
        if existing is not None:
            if existing["accepted_replan_sha256"] != accepted.accepted_replan_sha256:
                raise ReplanningPersistenceConflict("replan_acceptance_replay_conflict")
            return str(existing["id"])
        acceptance_id = f"replan-acceptance-{accepted.accepted_replan_sha256[:40]}"
        await self.session.execute(
            insert(table).values(
                id=acceptance_id,
                proposal_id=proposal_id,
                campaign_id=campaign_id,
                admission_receipt_id=accepted.child_admission_receipt_id,
                admission_receipt_sha256=accepted.child_admission_receipt_sha256,
                reservation_id=accepted.reservation_id,
                accepted_replan_sha256=accepted.accepted_replan_sha256,
                acceptance_payload=_payload(accepted),
                **self._owned(occurred_at),
            )
        )
        return acceptance_id

    async def _set_tenant(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
            {"tenant": self.tenant_id},
        )

    def _owned(self, occurred_at: datetime) -> dict[str, object]:
        return {
            "tenant_id": self.tenant_id,
            "version": 1,
            "created_at": occurred_at,
            "updated_at": occurred_at,
        }


def _payload(value: object) -> object:
    return json.loads(canonical_planning_bytes(value))
