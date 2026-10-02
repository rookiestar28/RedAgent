"""Fresh server-owned child lineage verification at every authority boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Mapping, Protocol, TYPE_CHECKING

from sqlalchemy import select, text

from redagent_platform.campaign_service.approval_contracts import (
    AutonomousCampaignApprovalContextProvider, AutonomousCampaignPlanPreviewV1,
)
from redagent_platform.campaign_service.authority_envelope import (
    TrustedCampaignApproverKeyV2, verify_signed_campaign_authority,
)
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.planning.contracts import FactValueV1, canonical_planning_sha256
from redagent_platform.campaign_service.planning.serde import _decode_dataclass
from redagent_platform.campaign_service.child_replan_contracts import (
    CAPACITY_COOLDOWN_SECONDS, ChildReplanLineageV1, prove_canonical_child_subset,
)
from redagent_platform.campaign_service.replanning_contracts import BoundedReplanProposalV1
from redagent_platform.campaign_service.trusted_observations import (
    OBSERVATION_HISTORY_SCHEMA_VERSION, ObservationCandidateV1, OwnedCompletionSourceV1,
    verify_completed_owned_node_observation_evidence,
)
from redagent_platform.persistence.models import metadata

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
    from redagent_platform.campaign_service.child_replan_store import ChildEvidenceBackend


class ChildLineageConflict(RuntimeError):
    """Current child lineage or its physical parent proof is unavailable or changed."""


def verify_settlement_time_projection(
    *, payload: Mapping[str, object], latest_effect_completed_at: datetime,
    capacity_available_at: datetime, settled_at: datetime,
) -> None:
    from redagent_platform.campaign_service.application_repository import _json_payload

    # CRITICAL: native JSON uses canonical UTC Z; direct isoformat comparison falsely rejects valid persisted settlement times.
    expected = _json_payload({"latest_effect_completed_at": latest_effect_completed_at,
                             "capacity_available_at": capacity_available_at, "settled_at": settled_at})
    if any(payload.get(name) != value for name, value in expected.items()):
        raise ChildLineageConflict("child_settlement_time_projection_mismatch")


def verify_observation_promotion_time(
    *, received_at: datetime, source_verified_at: object, promoted_at: object,
) -> None:
    from redagent_platform.campaign_service.application_repository import _json_payload

    # CRITICAL: promotion and sealed-source times must use the persistence codec, without refreshing the original observation clock.
    canonical_time = _json_payload({"at": received_at})["at"]
    if source_verified_at != canonical_time or promoted_at != canonical_time:
        raise ChildLineageConflict("child_observation_promotion_time_projection_mismatch")


@dataclass(frozen=True, slots=True)
class VerifiedChildLineageV1:
    parent_reservation_id: str
    parent_execution_run_id: str
    parent_run_version: int
    settlement_sha256: str
    authority_sha256: str
    signed_authority_sha256: str
    verified_at: datetime
    parent_completed_at: datetime
    capacity_available_at: datetime


class ChildLineageVerifier(Protocol):
    async def verify(self, *, tenant_id: str, campaign_id: str, preview: AutonomousCampaignPlanPreviewV1,
                     now: datetime, session: AsyncSession | None = None) -> VerifiedChildLineageV1: ...


async def require_current_child_lineage(*, preview: AutonomousCampaignPlanPreviewV1, tenant_id: str,
                                        campaign_id: str, now: datetime, verifier: ChildLineageVerifier | None,
                                        session: AsyncSession | None = None) -> VerifiedChildLineageV1 | None:
    if preview.child_lineage_sha256 is None:
        return None
    if verifier is None:
        raise ChildLineageConflict("child_lineage_verifier_unavailable")
    return await verifier.verify(tenant_id=tenant_id, campaign_id=campaign_id, preview=preview, now=now, session=session)


def verify_child_source_provenance(*, fresh_source: OwnedCompletionSourceV1, stored_payload: object,
                                   expected_sha256: str, now: datetime) -> None:
    from redagent_platform.campaign_service.application_repository import _json_payload

    if (not isinstance(fresh_source, OwnedCompletionSourceV1) or not isinstance(stored_payload, dict)
            or fresh_source.verified_at != now or now.tzinfo is None or now.utcoffset() is None):
        raise ChildLineageConflict("child_source_fresh_owner_required")
    stored_time = stored_payload.get("verified_at")
    if not isinstance(stored_time, str):
        raise ChildLineageConflict("child_source_original_time_invalid")
    original_at = datetime.fromisoformat(stored_time)
    completed_at = fresh_source.effect_receipt.completed_at
    if (original_at.tzinfo is None or original_at.utcoffset() is None or original_at > now
            or completed_at is None or original_at < completed_at
            or not completed_at <= now < completed_at + timedelta(seconds=120)):
        raise ChildLineageConflict("child_source_freshness_invalid")
    # CRITICAL: compare original immutable owners without resetting observation age or replacing the fresh verification clock.
    comparable = _json_payload(fresh_source)
    comparable["verified_at"] = stored_time
    if comparable != stored_payload or canonical_planning_sha256(stored_payload) != expected_sha256:
        raise ChildLineageConflict("child_source_immutable_owner_drift")


class PostgresChildLineageVerifier:
    def __init__(self, sessions: async_sessionmaker[AsyncSession], *, evidence_backend: ChildEvidenceBackend,
                 context_provider: AutonomousCampaignApprovalContextProvider,
                 trusted_keys: Mapping[str, TrustedCampaignApproverKeyV2],
                 actor_user_id: str = "redagent-child-verifier") -> None:
        self._sessions = sessions
        self._evidence_backend = evidence_backend
        self._provider = context_provider
        self._keys = dict(trusted_keys)
        self._actor = actor_user_id

    async def verify(self, *, tenant_id: str, campaign_id: str, preview: AutonomousCampaignPlanPreviewV1,
                     now: datetime, session: AsyncSession | None = None) -> VerifiedChildLineageV1:
        if (preview.tenant_id != tenant_id or preview.campaign_id != campaign_id
                or preview.execution_mode is not AutonomousCampaignMode.BOUNDED_REPLAN
                or preview.child_lineage_sha256 is None or now >= preview.expires_at):
            raise ChildLineageConflict("child_preview_binding_invalid")
        if session is not None:
            return await self._verify(session, tenant_id, campaign_id, preview, now)
        async with self._sessions() as owned_session, owned_session.begin():
            return await self._verify(owned_session, tenant_id, campaign_id, preview, now)

    async def _verify(self, session: AsyncSession, tenant_id: str, campaign_id: str,
                      preview: AutonomousCampaignPlanPreviewV1, now: datetime) -> VerifiedChildLineageV1:
        # Import at the boundary: DAG state owners use this port and must not form an import-time owner cycle.
        from redagent_platform.campaign_service.child_replan_store import load_completed_owned_parent
        from redagent_platform.campaign_service.admission import authority_budget, calculate_plan_budget
        from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1
        from redagent_platform.campaign_service.planning.owned_sequential import validate_owned_sequential_candidate_plan

        await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"), {"tenant_id": tenant_id})
        children = metadata.tables["autonomous_campaign_child_replans"]
        row = (await session.execute(select(children).where(
            children.c.tenant_id == tenant_id, children.c.application_id == campaign_id,
            children.c.preview_id == preview.preview_id,
        ))).mappings().one_or_none()
        if row is None or row["preview_sha256"] != preview.preview_sha256 or row["replan_sequence"] != 1:
            raise ChildLineageConflict("child_lineage_owner_missing")
        lineage = _decode_dataclass(ChildReplanLineageV1, row["lineage_payload"])
        if lineage.lineage_sha256 != row["lineage_sha256"] or lineage.lineage_sha256 != preview.child_lineage_sha256:
            raise ChildLineageConflict("child_lineage_digest_mismatch")
        for name in ("parent_execution_run_id", "parent_revision_sha256", "parent_admission_receipt_sha256",
                     "observation_history_sha256", "proposal_sha256", "settlement_sha256", "child_revision_sha256"):
            if getattr(lineage, name) != row[name]:
                raise ChildLineageConflict("child_lineage_projection_mismatch")
        if lineage.subset_proof_sha256 != row["strict_subset_proof_sha256"]:
            raise ChildLineageConflict("child_lineage_subset_digest_mismatch")
        context = await self._provider.read_current_approval_context(tenant_id=tenant_id, campaign_id=campaign_id)
        if context is None:
            raise ChildLineageConflict("child_current_context_missing")
        verify_signed_campaign_authority(context.signed_authority, context.authority_lifecycle,
                                        trusted_keys=self._keys, now=now)
        authority = context.signed_authority.authority
        if (context.tenant_id != tenant_id or context.campaign_id != campaign_id
                or context.signed_authority.signed_authority_sha256 != preview.signed_authority_sha256
                or authority.authority_sha256 != preview.authority_sha256
                or any(getattr(authority, field) != getattr(preview, field) for field in (
                    "lifecycle_epoch", "policy_revocation_epoch", "roe_revocation_epoch", "kill_switch_epoch"))):
            raise ChildLineageConflict("child_current_authority_drift")
        # CRITICAL: child owners already hold child/application locks; never acquire terminal parent locks afterward.
        parent = await load_completed_owned_parent(session, tenant_id=tenant_id, application_id=campaign_id,
            parent_execution_run_id=lineage.parent_execution_run_id, actor_user_id=self._actor,
            correlation_id="child-lineage-verification", evidence_backend=self._evidence_backend,
            now=now, authority=authority, lock_rows=False)
        settlements = metadata.tables["campaign_child_capacity_settlements"]
        settlement = (await session.execute(select(settlements).where(
            settlements.c.tenant_id == tenant_id, settlements.c.application_id == campaign_id,
            settlements.c.id == row["settlement_id"],
        ))).mappings().one_or_none()
        if settlement is None or settlement["settlement_sha256"] != lineage.settlement_sha256:
            raise ChildLineageConflict("child_settlement_owner_missing")
        payload = settlement["settlement_payload"]
        if canonical_planning_sha256(payload) != lineage.settlement_sha256:
            raise ChildLineageConflict("child_settlement_digest_mismatch")
        for field in ("tenant_id", "application_id", "parent_execution_run_id", "parent_run_version",
                      "parent_reservation_id", "source_provenance_sha256", "parent_effect_receipt_sha256",
                      "child_revision_sha256", "proposal_sha256"):
            if payload.get(field) != settlement[field]:
                raise ChildLineageConflict("child_settlement_projection_mismatch")
        verify_settlement_time_projection(payload=payload,
            latest_effect_completed_at=settlement["latest_effect_completed_at"],
            capacity_available_at=settlement["capacity_available_at"], settled_at=row["created_at"])
        completed_at = parent.source.effect_receipt.completed_at
        if (completed_at is None or settlement["latest_effect_completed_at"] != completed_at
                or settlement["capacity_available_at"] != completed_at + timedelta(seconds=CAPACITY_COOLDOWN_SECONDS)
                or now < settlement["capacity_available_at"]
                or settlement["parent_execution_run_id"] != lineage.parent_execution_run_id
                or settlement["parent_run_version"] != parent.source.snapshot.revision
                or row["parent_run_version"] != parent.source.snapshot.revision
                or settlement["parent_reservation_id"] != parent.admission_receipt.reservation_id
                or settlement["parent_admission_receipt_id"] != parent.admission_receipt.receipt_id
                or settlement["parent_effect_receipt_sha256"] != parent.source.effect_receipt.receipt_sha256
                or lineage.parent_revision_sha256 != parent.revision.revision_sha256
                or lineage.parent_admission_receipt_sha256 != parent.admission_receipt.receipt_sha256):
            raise ChildLineageConflict("child_settlement_parent_or_cooldown_drift")
        verify_child_source_provenance(fresh_source=parent.source,
            stored_payload=row["source_payload"].get("completion_source"),
            expected_sha256=settlement["source_provenance_sha256"], now=now)
        proposals = metadata.tables["campaign_replan_proposals"]
        proposal_row = (await session.execute(select(proposals).where(
            proposals.c.tenant_id == tenant_id, proposals.c.campaign_id == campaign_id,
            proposals.c.id == row["proposal_id"],
        ))).mappings().one_or_none()
        if proposal_row is None or proposal_row["proposal_sha256"] != lineage.proposal_sha256:
            raise ChildLineageConflict("child_proposal_owner_missing")
        proposal = _decode_dataclass(BoundedReplanProposalV1, proposal_row["proposal_payload"])
        if (proposal.proposal_sha256 != lineage.proposal_sha256 or proposal.replan_sequence != 1
                or proposal.child_revision.revision_sha256 != lineage.child_revision_sha256
                or preview.plan_revision_sha256 != lineage.child_revision_sha256
                or preview.plan_sha256 != proposal.child_revision.candidate_plan.plan_sha256
                or preview.certificate_sha256 != proposal.validation_certificate.certificate_sha256
                or proposal.observation_history_sha256 != lineage.observation_history_sha256
                or proposal.parent_revision_sha256 != parent.revision.revision_sha256
                or proposal.parent_plan_sha256 != parent.revision.candidate_plan.plan_sha256
                or proposal.parent_authority_sha256 != authority.authority_sha256
                or proposal.parent_domain_sha256 != parent.domain.domain_sha256
                or proposal.parent_admission_receipt_id != parent.admission_receipt.receipt_id
                or proposal.parent_admission_receipt_sha256 != parent.admission_receipt.receipt_sha256
                or proposal.validation_certificate.validated_at > now
                or preview.domain_sha256 != parent.domain.domain_sha256
                or preview.plan_budget != calculate_plan_budget(proposal.child_revision, parent.domain)
                or preview.authorized_budget != authority_budget(authority)):
            raise ChildLineageConflict("child_proposal_binding_mismatch")
        certificate = validate_owned_sequential_candidate_plan(proposal.child_revision.candidate_plan,
            parent.domain, authority, limits=ValidationLimitsV1(2, 1, 32),
            validated_at=proposal.validation_certificate.validated_at)
        if not certificate.admissible or certificate.certificate_sha256 != proposal.validation_certificate.certificate_sha256:
            raise ChildLineageConflict("child_validation_certificate_drift")
        needed = {action.capability_id for action in preview.actions}
        current_bindings = tuple(sorted((binding for binding in context.execution_bindings if binding.capability_id in needed),
                                        key=lambda binding: binding.capability_id))
        if current_bindings != preview.execution_bindings:
            raise ChildLineageConflict("child_current_execution_binding_drift")
        observations = metadata.tables["trusted_campaign_observations"]
        observation_rows = tuple((await session.execute(select(observations).where(
            observations.c.tenant_id == tenant_id, observations.c.campaign_id == campaign_id,
            observations.c.observation_sha256.in_(proposal.trusted_observation_sha256s),
        ).order_by(observations.c.observation_sha256))).mappings().all())
        if len(observation_rows) != 1 or len(proposal.trusted_observation_sha256s) != 1:
            raise ChildLineageConflict("child_single_completion_observation_required")
        observation = observation_rows[0]
        trusted_payload = observation["trusted_payload"]
        if canonical_planning_sha256(trusted_payload) != observation["observation_sha256"]:
            raise ChildLineageConflict("child_observation_digest_mismatch")
        candidate = _decode_dataclass(ObservationCandidateV1, trusted_payload["candidate"])
        verify_completed_owned_node_observation_evidence(candidate=candidate, source=parent.source,
            domain=parent.domain, revision=parent.revision, verified_at=now)
        original_provenance = canonical_planning_sha256(("redagent.owned-completion-observation/v1",
            candidate.candidate_sha256, settlement["source_provenance_sha256"], candidate.received_at))
        verify_observation_promotion_time(received_at=candidate.received_at,
            source_verified_at=row["source_payload"]["completion_source"]["verified_at"],
            promoted_at=trusted_payload["promoted_at"])
        if (now >= candidate.expires_at or now - candidate.observed_at >= timedelta(seconds=120)
                or trusted_payload["provenance_sha256"] != original_provenance
                or trusted_payload["source_record_id"] != parent.source.effect_receipt.effect_id
                or trusted_payload["source_execution_run_id"] != lineage.parent_execution_run_id
                or trusted_payload["source_node_id"] != parent.source.node_id):
            raise ChildLineageConflict("child_observation_provenance_or_age_drift")
        history_payload = {"schema_version": OBSERVATION_HISTORY_SCHEMA_VERSION,
                           "trusted_observations": [trusted_payload], "conflicted_fact_keys": []}
        if canonical_planning_sha256(history_payload) != lineage.observation_history_sha256:
            raise ChildLineageConflict("child_observation_history_mismatch")
        proof = prove_canonical_child_subset(parent=parent.revision, child=proposal.child_revision,
            domain=parent.domain, completed_parent_node_ids=(parent.source.node_id,),
            observed_values=(FactValueV1(candidate.fact_id, candidate.value),),
            observation_history_sha256=lineage.observation_history_sha256)
        if (proof.proof_sha256 != lineage.subset_proof_sha256
                or canonical_planning_sha256(row["strict_subset_proof_payload"]) != proof.proof_sha256):
            raise ChildLineageConflict("child_strict_subset_proof_mismatch")
        return VerifiedChildLineageV1(str(settlement["parent_reservation_id"]), lineage.parent_execution_run_id,
            parent.source.snapshot.revision, lineage.settlement_sha256, authority.authority_sha256,
            context.signed_authority.signed_authority_sha256, now, completed_at, settlement["capacity_available_at"])
