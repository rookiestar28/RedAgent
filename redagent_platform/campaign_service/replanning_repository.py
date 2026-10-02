"""PostgreSQL append-only persistence for trust decisions and bounded replan lineage."""

from __future__ import annotations

from datetime import datetime
import json

from sqlalchemy import insert, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.campaign_service.admission_contracts import AdmissionOutcome
from redagent_platform.campaign_service.admission_repository import (
    AdmissionConflict,
    _receipt_from_payload,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes
from redagent_platform.campaign_service.replanning_contracts import (
    AcceptedBoundedReplanV1,
    BoundedReplanProposalV1,
)
from redagent_platform.campaign_service.trusted_observations import (
    ObservationCandidateV1,
    ObservationPromotionDecisionV1,
    ObservationProducerKind,
    OwnedCompletionSourceV1,
)
from redagent_platform.persistence.models import metadata


class ReplanningPersistenceConflict(RuntimeError):
    """A replay or tenant-owned lineage binding did not match exactly."""


def _proposal_parent_admission_at(
    *, tenant_id: str, proposal: BoundedReplanProposalV1,
    occurred_at: datetime, source: OwnedCompletionSourceV1 | None,
) -> datetime:
    if source is None:
        return occurred_at
    if (not isinstance(source, OwnedCompletionSourceV1)
            or source.tenant_id != tenant_id or source.campaign_id != proposal.campaign_id
            or source.engagement_id != proposal.engagement_id
            or source.parent_revision_sha256 != proposal.parent_revision_sha256
            or source.plan_sha256 != proposal.parent_plan_sha256
            or source.domain_sha256 != proposal.parent_domain_sha256
            or source.authority_sha256 != proposal.parent_authority_sha256
            or any(getattr(source, name) != getattr(proposal, name) for name in (
                "lifecycle_epoch", "policy_revocation_epoch", "roe_revocation_epoch", "kill_switch_epoch"))
            or source.verified_at > occurred_at or source.effect_receipt.completed_at is None
            or source.effect_receipt.completed_at > occurred_at
            or len(proposal.trusted_observation_sha256s) != 1
            or proposal.invalidated_parent_node_ids != (source.node_id,)
            or len(proposal.retained_parent_node_ids) != 1
            or proposal.child_revision.node_count != 1 or proposal.replan_sequence != 1):
        raise ReplanningPersistenceConflict("replan_persistence_historical_parent_source_mismatch")
    # CRITICAL: only sealed terminal completion proves historical authorization; it never renews or transfers a parent grant.
    return source.effect_receipt.completed_at


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
        trusted = decision.trusted_observation
        if trusted is not None and trusted.candidate != candidate:
            raise ReplanningPersistenceConflict("observation_persistence_trusted_candidate_mismatch")
        await self._set_tenant()
        if trusted is not None and candidate.producer.kind is ObservationProducerKind.DAG_RUNNER_RESULT:
            effects = metadata.tables["campaign_effects"]
            nodes = metadata.tables["campaign_execution_nodes"]
            persisted_source = (
                await self.session.execute(
                    select(
                        effects.c.effect_receipt_sha256,
                        effects.c.effect_state,
                        effects.c.reconciliation_state,
                        effects.c.execution_run_id,
                        effects.c.node_id,
                        nodes.c.node_state,
                    ).select_from(
                        effects.join(
                            nodes,
                            (nodes.c.tenant_id == effects.c.tenant_id)
                            & (nodes.c.execution_run_id == effects.c.execution_run_id)
                            & (nodes.c.campaign_id == effects.c.campaign_id)
                            & (nodes.c.node_id == effects.c.node_id),
                        )
                    ).where(
                        effects.c.tenant_id == self.tenant_id,
                        effects.c.campaign_id == campaign_id,
                        effects.c.effect_id == trusted.source_record_id,
                        effects.c.execution_run_id == trusted.source_execution_run_id,
                        effects.c.node_id == trusted.source_node_id,
                    )
                )
            ).mappings().one_or_none()
            if (
                persisted_source is None
                or persisted_source["effect_receipt_sha256"] != candidate.source_result_sha256
                or persisted_source["effect_receipt_sha256"] != candidate.evidence_sha256
                or persisted_source["effect_state"] not in {"confirmed", "not_applied"}
                or persisted_source["reconciliation_state"]
                != persisted_source["effect_state"]
                or persisted_source["node_state"] != persisted_source["effect_state"]
            ):
                raise ReplanningPersistenceConflict("observation_persistence_source_receipt_mismatch")
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
                    source_record_id=trusted.source_record_id,
                    source_execution_run_id=trusted.source_execution_run_id,
                    source_node_id=trusted.source_node_id,
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
        parent_completion_source: OwnedCompletionSourceV1 | None = None,
    ) -> str:
        child = proposal.child_revision
        if (
            child.tenant_id != self.tenant_id
            or proposal.campaign_id != campaign_id
            or proposal.engagement_id != child.engagement_id
        ):
            raise ReplanningPersistenceConflict("replan_persistence_tenant_mismatch")
        await self._set_tenant()
        parent_admission_at = _proposal_parent_admission_at(
            tenant_id=self.tenant_id, proposal=proposal, occurred_at=occurred_at,
            source=parent_completion_source,
        )
        parent_receipt = await self._admission_receipt(
            receipt_id=proposal.parent_admission_receipt_id,
            campaign_id=campaign_id,
            receipt_sha256=proposal.parent_admission_receipt_sha256,
        )
        if (
            parent_receipt.outcome is not AdmissionOutcome.ADMITTED
            or parent_receipt.engagement_id != proposal.engagement_id
            or parent_receipt.plan_sha256 != proposal.parent_plan_sha256
            or parent_receipt.authority_sha256 != proposal.parent_authority_sha256
            or parent_receipt.domain_sha256 != proposal.parent_domain_sha256
            or parent_receipt.lifecycle_epoch != proposal.lifecycle_epoch
            or parent_receipt.policy_revocation_epoch != proposal.policy_revocation_epoch
            or parent_receipt.roe_revocation_epoch != proposal.roe_revocation_epoch
            or parent_receipt.kill_switch_epoch != proposal.kill_switch_epoch
            or not parent_receipt.issued_at <= parent_admission_at < parent_receipt.expires_at
            or (parent_completion_source is not None
                and parent_completion_source.effect_receipt.started_at < parent_receipt.issued_at)
        ):
            raise ReplanningPersistenceConflict("replan_persistence_parent_admission_mismatch")
        if parent_completion_source is not None:
            observations = metadata.tables["trusted_campaign_observations"]
            observation = (await self.session.execute(select(observations).where(
                observations.c.tenant_id == self.tenant_id,
                observations.c.campaign_id == campaign_id,
                observations.c.observation_sha256 == proposal.trusted_observation_sha256s[0],
            ))).mappings().one_or_none()
            source = parent_completion_source
            if (observation is None
                    or observation["source_execution_run_id"] != source.snapshot.execution_run_id
                    or observation["source_node_id"] != source.node_id
                    or observation["observed_at"] != source.effect_receipt.completed_at
                    or observation["source_result_sha256"] != source.effect_receipt.receipt_sha256
                    or observation["evidence_sha256"] != source.effect_receipt.receipt_sha256
                    or not observation["promoted_at"] <= occurred_at < observation["expires_at"]):
                raise ReplanningPersistenceConflict("replan_persistence_historical_parent_observation_mismatch")
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
                engagement_id=proposal.engagement_id,
                request_sha256=proposal.request_sha256,
                proposal_sha256=proposal.proposal_sha256,
                parent_revision_id=proposal.parent_revision_id,
                parent_revision_sha256=proposal.parent_revision_sha256,
                parent_plan_sha256=proposal.parent_plan_sha256,
                parent_authority_sha256=proposal.parent_authority_sha256,
                parent_domain_sha256=proposal.parent_domain_sha256,
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
        child_receipt = await self._admission_receipt(
            receipt_id=accepted.child_admission_receipt_id,
            campaign_id=campaign_id,
            receipt_sha256=accepted.child_admission_receipt_sha256,
        )
        proposal = accepted.proposal
        if (
            child_receipt.outcome is not AdmissionOutcome.ADMITTED
            or child_receipt.engagement_id != proposal.engagement_id
            or child_receipt.plan_sha256 != proposal.child_revision.candidate_plan.plan_sha256
            or child_receipt.authority_sha256 != proposal.child_revision.authority_sha256
            or child_receipt.domain_sha256 != proposal.child_revision.domain_sha256
            or child_receipt.certificate_sha256
            != proposal.validation_certificate.certificate_sha256
            or child_receipt.subset_proof_sha256 != proposal.subset_proof.proof_sha256
            or child_receipt.pre_residual_budget_sha256 != proposal.residual_budget.budget_sha256
            or child_receipt.reserved_budget != proposal.planned_budget
            or child_receipt.reservation_id != accepted.reservation_id
            or child_receipt.lifecycle_epoch != proposal.lifecycle_epoch
            or child_receipt.policy_revocation_epoch != proposal.policy_revocation_epoch
            or child_receipt.roe_revocation_epoch != proposal.roe_revocation_epoch
            or child_receipt.kill_switch_epoch != proposal.kill_switch_epoch
            or not child_receipt.issued_at <= occurred_at < child_receipt.expires_at
        ):
            raise ReplanningPersistenceConflict("replan_acceptance_admission_binding_mismatch")
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
                proposal_sha256=accepted.proposal.proposal_sha256,
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

    async def _admission_receipt(
        self,
        *,
        receipt_id: str,
        campaign_id: str,
        receipt_sha256: str,
    ):
        table = metadata.tables["plan_admission_receipts"]
        row = (
            await self.session.execute(
                select(table.c.receipt_sha256, table.c.receipt_payload).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == receipt_id,
                    table.c.campaign_id == campaign_id,
                )
            )
        ).mappings().one_or_none()
        if row is None or row["receipt_sha256"] != receipt_sha256:
            raise ReplanningPersistenceConflict("replan_persistence_admission_digest_mismatch")
        try:
            receipt = _receipt_from_payload(row["receipt_payload"])
        except (AdmissionConflict, KeyError, TypeError, ValueError) as exc:
            raise ReplanningPersistenceConflict("replan_persistence_admission_payload_invalid") from exc
        if receipt.receipt_sha256 != receipt_sha256:
            raise ReplanningPersistenceConflict("replan_persistence_admission_payload_digest_mismatch")
        return receipt

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
