"""Canonical read-only parent intake; caller owns the surrounding child transaction."""

from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta
import hashlib
import json
from typing import Any, Protocol

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.admission_contracts import PlanAdmissionReceiptV1
from redagent_platform.campaign_service.admission_repository import CampaignAdmissionRepository, _receipt_from_payload, _vector_from_row
from redagent_platform.campaign_service.admission import authority_budget
from redagent_platform.campaign_service.authority_envelope import CampaignAuthorityEnvelopeV2
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignLifecycle, AutonomousCampaignMode
from redagent_platform.campaign_service.operator_scope import assert_operator_scope_current
from redagent_platform.campaign_service.application_repository import (
    _assert_actor_binding, _json_payload, _plan_preview_result_from_payload, _plan_preview_result_payload,
    _record_lifecycle_event, _state_from_row, _successor_state, _verified_preview_from_payload,
)
from redagent_platform.campaign_service.approval_contracts import AutonomousCampaignPlanPreviewResultV1
from redagent_platform.campaign_service.child_replan_contracts import (
    CHILD_LINEAGE_SCHEMA_VERSION, CAPACITY_COOLDOWN_SECONDS, ChildReplanLineageV1,
    PrepareAutonomousCampaignChildV1, project_sequential_child_residual,
)
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.dag_execution_activity_store import _snapshot
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION, DagNodeState, DagWorkflowInputV1, dag_workflow_request_sha256,
)
from redagent_platform.campaign_service.execution import ReconciliationState
from redagent_platform.campaign_service.planning.contracts import CapabilityIdentityV1, PlanValidationCertificateV1, PlanningDomainV1, ValidationLimitsV1, canonical_planning_sha256
from redagent_platform.campaign_service.planning.owned_sequential import OWNED_SEQUENTIAL_PLANNER_SHA256, OWNED_SEQUENTIAL_VALIDATOR_SHA256, validate_owned_sequential_candidate_plan
from redagent_platform.campaign_service.planning.search_contracts import AttackPathDagRevisionV1
from redagent_platform.campaign_service.planning.serde import _decode_dataclass, parse_attack_path_dag_revision, parse_planning_domain
from redagent_platform.campaign_service.repository import CampaignRepository, _effect_receipt_contract
from redagent_platform.campaign_service.replanning_repository import CampaignReplanningRepository
from redagent_platform.campaign_service.trusted_observations import OwnedCompletionSourceV1, _OWNED_COMPLETION_SOURCE_TOKEN
from redagent_platform.evidence_service.contracts import ObjectVerification, StoredObjectVersion
from redagent_platform.evidence_service.service import _stored_from_artifact
from redagent_platform.finding_operations.contracts import FindingOccurrenceInput
from redagent_platform.finding_operations.repository import _digest
from redagent_platform.persistence.models import metadata
from redagent_platform.runner_service.campaign_result import parse_normalized_adapter_finding, report_safe_payload_matches


class ChildParentConflict(RuntimeError):
    """An exact parent owner, terminal result or immutable report could not be proved."""


class ChildEvidenceBackend(Protocol):
    def verify_exact(self, stored: StoredObjectVersion) -> ObjectVerification: ...

    def get_exact(self, object_key: str, version_id: str) -> bytes: ...


@dataclass(frozen=True, slots=True)
class CompletedOwnedParentV1:
    source: OwnedCompletionSourceV1
    domain: PlanningDomainV1
    revision: AttackPathDagRevisionV1
    admission_receipt: PlanAdmissionReceiptV1


class PostgresCanonicalChildReplanStore:
    """Own one observation/proposal/settlement/lineage/preview transaction per application."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession], *, evidence_backend: ChildEvidenceBackend) -> None:
        self._sessions = sessions
        self._evidence_backend = evidence_backend

    async def stage_child(self, command: PrepareAutonomousCampaignChildV1, *, read_context: Any,
                          build_preview: Any, trusted_keys: Any) -> AutonomousCampaignPlanPreviewResultV1:
        from redagent_platform.campaign_service.child_replan_service import prepare_canonical_child_proposal
        from redagent_platform.campaign_service.authority_envelope import verify_signed_campaign_authority

        if not isinstance(command, PrepareAutonomousCampaignChildV1):
            raise ValueError("canonical_child_command_invalid")
        request_sha = canonical_planning_sha256((command.tenant_id, command.campaign_id, command.actor_user_id,
                                                command.expected_revision, command.idempotency_key))
        async with self._sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"), {"tenant_id": command.tenant_id})
            await _assert_actor_binding(session, tenant_id=command.tenant_id, actor_user_id=command.actor_user_id)
            await session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                                  {"scope": f"canonical-child:{command.tenant_id}:{command.campaign_id}"})
            children = metadata.tables["autonomous_campaign_child_replans"]
            existing = (await session.execute(select(children).where(
                children.c.tenant_id == command.tenant_id, children.c.application_id == command.campaign_id,
            ))).mappings().one_or_none()
            if existing is not None:
                if existing["request_sha256"] != request_sha or existing["idempotency_key"] != command.idempotency_key:
                    raise ChildParentConflict("canonical_child_limit_exhausted")
                return _plan_preview_result_from_payload(existing["source_payload"]["stage_result"], replayed=True)
            starts = metadata.tables["autonomous_campaign_execution_starts"]
            parent_run_id = (await session.execute(select(starts.c.execution_run_id).where(
                starts.c.tenant_id == command.tenant_id, starts.c.application_id == command.campaign_id,
                starts.c.start_state == "execution_queued",
            ).order_by(starts.c.created_at.desc()).limit(1))).scalar_one_or_none()
            if parent_run_id is None:
                raise ChildParentConflict("child_parent_start_missing")
            context = await read_context(tenant_id=command.tenant_id, campaign_id=command.campaign_id)
            if context is None:
                raise ChildParentConflict("canonical_child_current_context_missing")
            verify_signed_campaign_authority(context.signed_authority, context.authority_lifecycle,
                                            trusted_keys=trusted_keys, now=command.occurred_at)
            parent = await load_completed_owned_parent(session, tenant_id=command.tenant_id,
                application_id=command.campaign_id, parent_execution_run_id=str(parent_run_id),
                actor_user_id=command.actor_user_id, correlation_id=command.correlation_id,
                evidence_backend=self._evidence_backend, now=command.occurred_at,
                authority=context.signed_authority.authority)
            applications = metadata.tables["autonomous_campaign_applications"]
            app_row = (await session.execute(select(applications).where(
                applications.c.tenant_id == command.tenant_id, applications.c.id == command.campaign_id,
            ).with_for_update())).mappings().one()
            current = _state_from_row(app_row)
            await assert_operator_scope_current(session, tenant_id=command.tenant_id, campaign_id=command.campaign_id)
            if (current.mode is not AutonomousCampaignMode.BOUNDED_REPLAN
                    or current.aggregate_revision != command.expected_revision
                    or current.target_id != parent.source.target_id
                    or current.lifecycle_state not in {AutonomousCampaignLifecycle.EVIDENCE_PENDING,
                                                       AutonomousCampaignLifecycle.FAILED_CONTAINED}):
                raise ChildParentConflict("canonical_child_parent_application_state_mismatch")
            now = command.occurred_at
            completed_at, parent_reserved = parent.source.effect_receipt.completed_at, parent.admission_receipt.reserved_budget
            if completed_at is None or parent_reserved is None:
                raise ChildParentConflict("canonical_child_confirmed_parent_budget_required")
            available_at = completed_at + timedelta(seconds=CAPACITY_COOLDOWN_SECONDS)
            budget = CampaignAdmissionRepository(session, tenant_id=command.tenant_id,
                actor_user_id=command.actor_user_id, correlation_id=command.correlation_id)
            ledger = await budget.lock_ledger(campaign_id=command.campaign_id,
                envelope_sha256=parent.source.authority_sha256,
                authorized=authority_budget(context.signed_authority.authority), occurred_at=now)
            # CRITICAL: reread the real charged rows under the same admission budget lock; settlement never refunds cumulative work.
            await _assert_parent_admission_owners(session, command.tenant_id, command.campaign_id,
                                                 parent.admission_receipt, {"admission_receipt_id": parent.admission_receipt.receipt_id,
                                                 "reserved_budget_sha256": parent_reserved.budget_sha256})
            reservations = metadata.tables["campaign_budget_reservations"]
            charges = tuple((await session.execute(select(reservations).where(
                reservations.c.tenant_id == command.tenant_id, reservations.c.ledger_id == ledger["id"],
                reservations.c.reservation_state.in_(("reserved", "held", "consumed")),
            ).order_by(reservations.c.id).with_for_update())).mappings().all())
            parent_charges = tuple(row for row in charges if row["id"] == parent.admission_receipt.reservation_id)
            if len(parent_charges) != 1:
                raise ChildParentConflict("canonical_child_charged_parent_missing")
            residual = project_sequential_child_residual(authorized=authority_budget(context.signed_authority.authority),
                parent_charge=_vector_from_row(parent_charges[0]),
                other_charges=tuple(_vector_from_row(row) for row in charges if row["id"] != parent.admission_receipt.reservation_id),
                parent_completed_at=completed_at, capacity_available_at=available_at, now=now)
            prepared = prepare_canonical_child_proposal(command=command, parent=parent, context=context,
                residual_budget=residual, consumed_replans=0, trusted_keys=trusted_keys)
            proposal = prepared.proposal
            owner = CampaignReplanningRepository(session, tenant_id=command.tenant_id)
            await owner.append_promotion(campaign_id=command.campaign_id, candidate=prepared.candidate,
                                         decision=prepared.promotion, occurred_at=now)
            proposal_id = await owner.append_proposal(campaign_id=command.campaign_id, proposal=proposal,
                occurred_at=now, parent_completion_source=parent.source)
            settlement_payload = {
                "schema_version": "redagent.canonical-child-capacity-settlement/v1", "tenant_id": command.tenant_id,
                "application_id": command.campaign_id, "parent_execution_run_id": str(parent_run_id),
                "parent_run_version": parent.source.snapshot.revision, "parent_reservation_id": parent.admission_receipt.reservation_id,
                "parent_admission_receipt_sha256": parent.admission_receipt.receipt_sha256,
                "source_provenance_sha256": parent.source.provenance_sha256,
                "parent_effect_receipt_sha256": parent.source.effect_receipt.receipt_sha256,
                "latest_effect_completed_at": parent.source.effect_receipt.completed_at,
                "capacity_available_at": available_at, "settled_at": now,
                "charged_rows_sha256": canonical_planning_sha256(tuple(dict(row) for row in charges)),
                "child_revision_sha256": proposal.child_revision.revision_sha256, "proposal_sha256": proposal.proposal_sha256,
                "residual_budget_sha256": residual.budget_sha256,
            }
            settlement_sha = canonical_planning_sha256(settlement_payload)
            settlement_id = "child-capacity-" + settlement_sha[:32]
            lineage = ChildReplanLineageV1(schema_version=CHILD_LINEAGE_SCHEMA_VERSION,
                parent_execution_run_id=str(parent_run_id), parent_revision_sha256=parent.revision.revision_sha256,
                parent_admission_receipt_sha256=parent.admission_receipt.receipt_sha256,
                observation_history_sha256=proposal.observation_history_sha256, proposal_sha256=proposal.proposal_sha256,
                subset_proof_sha256=prepared.strict_subset.proof_sha256, settlement_sha256=settlement_sha,
                child_revision_sha256=proposal.child_revision.revision_sha256)
            preview = build_preview(command, current, context, parent, prepared)
            if (preview.execution_mode is not AutonomousCampaignMode.BOUNDED_REPLAN
                    or preview.plan_revision_sha256 != lineage.child_revision_sha256
                    or preview.application_revision != command.expected_revision + 2):
                raise ChildParentConflict("canonical_child_preview_binding_mismatch")
            preview = replace(preview, child_lineage_sha256=lineage.lineage_sha256)
            owned = {"tenant_id": command.tenant_id, "version": 1, "created_at": now, "updated_at": now}
            await session.execute(insert(metadata.tables["campaign_child_capacity_settlements"]).values(
                id=settlement_id, application_id=command.campaign_id, parent_execution_run_id=str(parent_run_id),
                parent_run_version=parent.source.snapshot.revision, parent_reservation_id=parent.admission_receipt.reservation_id,
                parent_admission_receipt_id=parent.admission_receipt.receipt_id,
                source_provenance_sha256=parent.source.provenance_sha256,
                parent_effect_receipt_sha256=parent.source.effect_receipt.receipt_sha256,
                latest_effect_completed_at=parent.source.effect_receipt.completed_at, capacity_available_at=available_at,
                child_revision_sha256=lineage.child_revision_sha256, proposal_id=proposal_id, proposal_sha256=proposal.proposal_sha256,
                settlement_sha256=settlement_sha, settlement_payload=_json_payload(settlement_payload), **owned))
            await session.execute(insert(metadata.tables["autonomous_campaign_plan_previews"]).values(
                id=preview.preview_id, application_id=command.campaign_id, application_revision=preview.application_revision,
                contract_version=preview.schema_version, preview_sha256=preview.preview_sha256,
                preview_payload=_json_payload(preview), created_by_user_id=command.actor_user_id, expires_at=preview.expires_at, **owned))
            validated = _successor_state(current, lifecycle_state=AutonomousCampaignLifecycle.PLAN_VALIDATED,
                                         aggregate_revision=current.aggregate_revision + 1, occurred_at=now)
            awaiting = _successor_state(current, lifecycle_state=AutonomousCampaignLifecycle.AWAITING_APPROVAL,
                                        aggregate_revision=current.aggregate_revision + 2, occurred_at=now)
            changed = await session.execute(update(applications).where(
                applications.c.tenant_id == command.tenant_id, applications.c.id == command.campaign_id,
                applications.c.aggregate_revision == command.expected_revision,
            ).values(lifecycle_state=awaiting.lifecycle_state.value, aggregate_revision=awaiting.aggregate_revision,
                     version=applications.c.version + 2, updated_at=now, attention_reason=None))
            if getattr(changed, "rowcount", None) != 1:
                raise ChildParentConflict("canonical_child_application_cas_conflict")
            events = []
            for state, previous, event_type in (
                (validated, current.lifecycle_state, "autonomous_campaign.child.validated.v1"),
                (awaiting, validated.lifecycle_state, "autonomous_campaign.child.awaiting_approval.v1"),
            ):
                events.append(await _record_lifecycle_event(session, state=state, operation="prepare_child",
                    correlation_id=command.correlation_id, actor_user_id=command.actor_user_id, request_sha256=request_sha,
                    event_type=event_type, previous_state=previous,
                    event_payload={"preview_id": preview.preview_id, "preview_sha256": preview.preview_sha256,
                                   "lineage_sha256": lineage.lineage_sha256}, occurred_at=now))
            result = AutonomousCampaignPlanPreviewResultV1(application=awaiting, preview=preview,
                audit_ids=(events[0][0], events[1][0]), event_ids=(events[0][1], events[1][1]), replayed=False)
            await session.execute(insert(children).values(
                id="canonical-child-" + lineage.lineage_sha256[:32], application_id=command.campaign_id,
                request_sha256=request_sha, idempotency_key=command.idempotency_key,
                parent_execution_run_id=str(parent_run_id), parent_run_version=parent.source.snapshot.revision,
                parent_revision_sha256=lineage.parent_revision_sha256,
                parent_admission_receipt_sha256=lineage.parent_admission_receipt_sha256,
                observation_history_sha256=lineage.observation_history_sha256,
                proposal_id=proposal_id, proposal_sha256=proposal.proposal_sha256,
                strict_subset_proof_sha256=prepared.strict_subset.proof_sha256,
                strict_subset_proof_payload=_json_payload(prepared.strict_subset), settlement_id=settlement_id,
                settlement_sha256=settlement_sha, child_revision_sha256=lineage.child_revision_sha256,
                lineage_sha256=lineage.lineage_sha256, lineage_payload=_json_payload(lineage),
                source_payload={"completion_source": _json_payload(parent.source),
                                "stage_result": _plan_preview_result_payload(result)},
                preview_id=preview.preview_id, preview_sha256=preview.preview_sha256, replan_sequence=1, **owned))
            return result


async def load_completed_owned_parent(
    session: AsyncSession, *, tenant_id: str, application_id: str, parent_execution_run_id: str,
    actor_user_id: str, correlation_id: str, evidence_backend: ChildEvidenceBackend, now: datetime,
    authority: CampaignAuthorityEnvelopeV2 | None = None,
    lock_rows: bool = True,
) -> CompletedOwnedParentV1:
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("child_parent_time_invalid")
    await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"), {"tenant_id": tenant_id})
    runs, nodes, effects = (metadata.tables[name] for name in ("campaign_execution_runs", "campaign_execution_nodes", "campaign_effects"))
    if type(lock_rows) is not bool:
        raise ValueError("child_parent_lock_mode_invalid")
    # CRITICAL: staging locks parent before application; downstream child gates use terminal reads and final drift checks.
    run_query = select(runs).where(
        runs.c.tenant_id == tenant_id, runs.c.id == parent_execution_run_id, runs.c.campaign_id == application_id,
    )
    run = (await session.execute(run_query.with_for_update() if lock_rows else run_query)).mappings().one_or_none()
    if run is None:
        raise ChildParentConflict("child_parent_run_missing")
    if not isinstance(authority, CampaignAuthorityEnvelopeV2) or authority.authority_sha256 != run["authority_sha256"]:
        raise ChildParentConflict("child_parent_current_authority_required")
    if (run["run_state"] not in {"completed", "contained"} or run["active_concurrency"] != 0
            or run["completed_at"] is None or run["completed_at"] > now):
        raise ChildParentConflict("child_parent_terminal_cleanup_required")
    applications = metadata.tables["autonomous_campaign_applications"]
    app = (await session.execute(select(applications).where(
        applications.c.tenant_id == tenant_id, applications.c.id == application_id,
    ))).mappings().one_or_none()
    if app is None or app["mode"] != AutonomousCampaignMode.BOUNDED_REPLAN.value:
        raise ChildParentConflict("child_parent_bounded_application_required")
    starts = metadata.tables["autonomous_campaign_execution_starts"]
    start = (await session.execute(select(starts).where(
        starts.c.tenant_id == tenant_id, starts.c.application_id == application_id,
        starts.c.execution_run_id == parent_execution_run_id, starts.c.start_state == "execution_queued",
    ))).mappings().one_or_none()
    if start is None or start["workflow_run_id"] is None:
        raise ChildParentConflict("child_parent_start_binding_missing")
    for key in ("input_sha256", "authority_sha256", "domain_sha256", "plan_sha256", "certificate_sha256",
                "admission_receipt_sha256", "reserved_budget_sha256", "reservation_id", "admission_receipt_id",
                "lifecycle_epoch", "policy_revocation_epoch", "roe_revocation_epoch", "kill_switch_epoch"):
        if run[key] != start[key]:
            raise ChildParentConflict("child_parent_start_binding_mismatch")
    payload = run["input_payload"]
    if not isinstance(payload, dict) or canonical_planning_sha256(payload) != run["input_sha256"]:
        raise ChildParentConflict("child_parent_input_digest_mismatch")
    workflow = DagWorkflowInputV1(DAG_EXECUTION_SCHEMA_VERSION, tenant_id, parent_execution_run_id,
                                  str(run["input_sha256"]), str(run["plan_sha256"]), 2, int(run["max_transitions"]))
    if dag_workflow_request_sha256(workflow) != run["request_sha256"] or workflow.max_transitions > 32:
        raise ChildParentConflict("child_parent_workflow_binding_mismatch")
    revision = parse_attack_path_dag_revision(payload["revision"])
    domain = parse_planning_domain(payload["domain"])
    admission = _receipt_from_payload(payload["admission_receipt"])
    _assert_parent_certificate(payload.get("certificate"), revision=revision, domain=domain, authority=authority,
                               admission=admission, expected_sha256=str(run["certificate_sha256"]))
    if (revision.revision_sha256 != canonical_planning_sha256(payload["revision"])
            or revision.domain_sha256 != domain.domain_sha256 or revision.domain_sha256 != run["domain_sha256"]
            or revision.candidate_plan.plan_sha256 != run["plan_sha256"] or revision.authority_sha256 != run["authority_sha256"]
            or revision.tenant_id != tenant_id or revision.planner_sha256 != OWNED_SEQUENTIAL_PLANNER_SHA256
            or admission.receipt_sha256 != run["admission_receipt_sha256"]
            or admission.validator_sha256 != OWNED_SEQUENTIAL_VALIDATOR_SHA256
            or admission.certificate_sha256 != run["certificate_sha256"]
            or admission.reservation_id != run["reservation_id"]
            or len(revision.candidate_plan.nodes) != 2):
        raise ChildParentConflict("child_parent_closed_plan_binding_mismatch")
    await _assert_parent_admission_owners(session, tenant_id, application_id, admission, run)
    preview_table = metadata.tables["autonomous_campaign_plan_previews"]
    preview_row = (await session.execute(select(preview_table).where(
        preview_table.c.tenant_id == tenant_id, preview_table.c.application_id == application_id,
        preview_table.c.id == start["preview_id"],
    ))).mappings().one_or_none()
    if preview_row is None:
        raise ChildParentConflict("child_parent_preview_missing")
    preview = _verified_preview_from_payload(preview_row["preview_payload"], str(preview_row["preview_sha256"]))
    if (preview.execution_mode is not AutonomousCampaignMode.BOUNDED_REPLAN
            or preview.plan_revision_sha256 != revision.revision_sha256
            or canonical_planning_sha256(preview.execution_bindings) != canonical_planning_sha256(payload.get("execution_bindings"))):
        raise ChildParentConflict("child_parent_preview_binding_mismatch")
    node_query = select(nodes).where(
        nodes.c.tenant_id == tenant_id, nodes.c.execution_run_id == parent_execution_run_id,
        nodes.c.campaign_id == application_id,
    ).order_by(nodes.c.node_order)
    node_rows = tuple((await session.execute(node_query.with_for_update() if lock_rows else node_query)).mappings().all())
    if len(node_rows) != 2 or any(row["node_state"] not in {"confirmed", "contained", "skipped"} for row in node_rows):
        raise ChildParentConflict("child_parent_no_inflight_nodes_required")
    effect_query = select(effects).where(
        effects.c.tenant_id == tenant_id, effects.c.campaign_id == application_id,
        effects.c.execution_run_id == parent_execution_run_id,
    ).order_by(effects.c.id)
    effect_rows = tuple((await session.execute(effect_query.with_for_update() if lock_rows else effect_query)).mappings().all())
    if (len(effect_rows) != 1 or effect_rows[0]["node_id"] != revision.candidate_plan.nodes[0].node_id
            or effect_rows[0]["effect_state"] != "confirmed" or node_rows[0]["node_state"] != "confirmed"):
        raise ChildParentConflict("child_parent_one_confirmed_effect_required")
    for row, planned in zip(node_rows, revision.candidate_plan.nodes):
        if (row["node_id"] != planned.node_id or row["operator_id"] != planned.operator_id
                or row["target_id"] != planned.target_id or row["node_sha256"] != canonical_planning_sha256(planned)
                or row["arguments_sha256"] != canonical_planning_sha256(planned.arguments)):
            raise ChildParentConflict("child_parent_node_projection_mismatch")
    effect = effect_rows[0]
    receipt = _effect_receipt_contract(effect["effect_receipt_payload"])
    # CRITICAL: a terminal receipt proves historical authorized completion; it never renews or transfers the expired parent lease.
    if (receipt.completed_at is None or not admission.issued_at <= receipt.started_at <= receipt.completed_at < admission.expires_at
            or not start["issued_at"] <= receipt.started_at <= receipt.completed_at < start["expires_at"]
            or receipt.completed_at > now):
        raise ChildParentConflict("child_parent_completion_outside_authority_interval")
    if receipt.external_receipt_id is None or receipt.cleanup_receipt_id is None:
        raise ChildParentConflict("child_parent_effect_owners_required")
    if (receipt.reconciliation_state is not ReconciliationState.CONFIRMED
            or receipt.receipt_sha256 != effect["effect_receipt_sha256"] or receipt.effect_id != effect["effect_id"]
            or receipt.effect_intent_sha256 != effect["effect_intent_sha256"]
            or receipt.envelope_sha256 != run["authority_sha256"] or receipt.request_sha256 != effect["request_sha256"]
            or receipt.cleanup_receipt_id != effect["cleanup_receipt_id"]):
        raise ChildParentConflict("child_parent_effect_receipt_mismatch")
    intent = effect["effect_intent_payload"]
    if not isinstance(intent, dict) or canonical_planning_sha256(intent) != receipt.effect_intent_sha256:
        raise ChildParentConflict("child_parent_effect_intent_digest_mismatch")
    if any(intent.get(key) != value for key, value in (
        ("tenant_id", tenant_id), ("campaign_id", application_id), ("execution_run_id", parent_execution_run_id),
        ("node_id", node_rows[0]["node_id"]), ("node_sha256", node_rows[0]["node_sha256"]),
        ("target_id", node_rows[0]["target_id"]), ("effect_id", effect["effect_id"]),
        ("invocation_id", effect["invocation_id"]),
    )):
        raise ChildParentConflict("child_parent_effect_intent_scope_mismatch")
    binding = CapabilityBindingKeyV1(**intent["binding"])
    operator = next(op for op in domain.operators if op.operator_id == node_rows[0]["operator_id"])
    if not _capability_matches_binding(operator.capability, binding):
        raise ChildParentConflict("child_parent_full_capability_binding_mismatch")
    owners = await CampaignRepository(session, tenant_id=tenant_id, actor_user_id=actor_user_id,
                                       correlation_id=correlation_id).validate_trusted_effect_owners(
        effect_id=receipt.effect_id, external_receipt_id=receipt.external_receipt_id,
        evidence_ids=receipt.evidence_ids, cleanup_receipt_id=receipt.cleanup_receipt_id,
        require_complete_coverage=True, require_retest=False,
    )
    artifact, cleanup, imported = await _report_owners(session, tenant_id, receipt.external_receipt_id)
    report_hash = await _verify_report(session, evidence_backend, artifact, imported, binding.adapter_id)
    source = OwnedCompletionSourceV1(
        tenant_id=tenant_id, campaign_id=application_id, engagement_id=revision.engagement_id,
        target_id=revision.candidate_plan.nodes[0].target_id,
        authority_sha256=revision.authority_sha256, lifecycle_epoch=int(run["lifecycle_epoch"]),
        policy_revocation_epoch=int(run["policy_revocation_epoch"]), roe_revocation_epoch=int(run["roe_revocation_epoch"]),
        kill_switch_epoch=int(run["kill_switch_epoch"]), snapshot=_snapshot(run, node_rows),
        parent_revision_sha256=revision.revision_sha256, domain_sha256=domain.domain_sha256,
        plan_sha256=revision.candidate_plan.plan_sha256, node_id=str(node_rows[0]["node_id"]),
        persisted_node_state=DagNodeState.CONFIRMED, capability=operator.capability, effect_receipt=receipt,
        report_artifact_id=str(artifact["id"]), report_sha256=report_hash, report_size_bytes=int(artifact["size_bytes"]),
        evidence_owner_sha256=canonical_planning_sha256((dict(artifact), dict(imported), owners)),
        cleanup_owner_sha256=canonical_planning_sha256(dict(cleanup)), verified_at=now,
        _validation_token=_OWNED_COMPLETION_SOURCE_TOKEN,
    )
    if not lock_rows:
        final_run = (await session.execute(run_query)).mappings().one_or_none()
        final_nodes = tuple((await session.execute(node_query)).mappings().all())
        final_effects = tuple((await session.execute(effect_query)).mappings().all())
        # CRITICAL: terminal read-only intake must reject any owner drift during backend verification without reversing row-lock order.
        if (final_run is None or canonical_planning_sha256(dict(final_run)) != canonical_planning_sha256(dict(run))
                or canonical_planning_sha256(tuple(dict(row) for row in final_nodes)) != canonical_planning_sha256(tuple(dict(row) for row in node_rows))
                or canonical_planning_sha256(tuple(dict(row) for row in final_effects)) != canonical_planning_sha256(tuple(dict(row) for row in effect_rows))):
            raise ChildParentConflict("child_parent_terminal_owner_drift")
    return CompletedOwnedParentV1(source, domain, revision, admission)


def _capability_matches_binding(capability: CapabilityIdentityV1, binding: CapabilityBindingKeyV1) -> bool:
    # CRITICAL: binding adds semantics/projection fields; compare every capability field without requiring unlike schemas to be equal.
    return all(getattr(binding, name) == value for name, value in asdict(capability).items())


def _assert_parent_certificate(
    payload: object, *, revision: AttackPathDagRevisionV1, domain: PlanningDomainV1,
    authority: CampaignAuthorityEnvelopeV2, admission: PlanAdmissionReceiptV1, expected_sha256: str,
) -> None:
    try:
        certificate = _decode_dataclass(PlanValidationCertificateV1, payload)
        recomputed = validate_owned_sequential_candidate_plan(revision.candidate_plan, domain, authority,
            limits=ValidationLimitsV1(2, 1, 32), validated_at=certificate.validated_at)
    except (ValueError, TypeError) as exc:
        raise ChildParentConflict("child_parent_certificate_invalid") from exc
    if (not recomputed.admissible or certificate.certificate_sha256 != expected_sha256
            or certificate.certificate_sha256 != recomputed.certificate_sha256
            or admission.certificate_sha256 != expected_sha256
            or certificate.validated_at > admission.issued_at):
        raise ChildParentConflict("child_parent_certificate_binding_mismatch")


async def _assert_parent_admission_owners(
    session: AsyncSession, tenant_id: str, application_id: str, admission: PlanAdmissionReceiptV1, run: Any,
) -> None:
    receipts, reservations = (metadata.tables[name] for name in ("plan_admission_receipts", "campaign_budget_reservations"))
    persisted = (await session.execute(select(receipts).where(
        receipts.c.tenant_id == tenant_id, receipts.c.campaign_id == application_id,
        receipts.c.id == admission.receipt_id,
    ))).mappings().one_or_none()
    if (persisted is None or persisted["outcome"] != "admitted"
            or persisted["receipt_sha256"] != admission.receipt_sha256
            or _receipt_from_payload(persisted["receipt_payload"]) != admission
            or admission.tenant_id != tenant_id or admission.campaign_id != application_id
            or admission.receipt_id != run["admission_receipt_id"]
            or admission.reserved_budget is None or admission.reserved_budget.budget_sha256 != run["reserved_budget_sha256"]):
        raise ChildParentConflict("child_parent_admission_owner_mismatch")
    reservation = (await session.execute(select(reservations).where(
        reservations.c.tenant_id == tenant_id, reservations.c.campaign_id == application_id,
        reservations.c.id == admission.reservation_id,
    ))).mappings().one_or_none()
    if (reservation is None or reservation["reservation_state"] not in {"reserved", "held", "consumed"}
            or reservation["plan_sha256"] != admission.plan_sha256
            or reservation["request_sha256"] != admission.request_sha256
            or reservation["lease_expires_at"] != admission.expires_at
            or _vector_from_row(reservation) != admission.reserved_budget):
        raise ChildParentConflict("child_parent_reservation_owner_mismatch")


async def _report_owners(session: AsyncSession, tenant_id: str, execution_id: str) -> tuple[Any, Any, Any]:
    receipts, artifacts, imports = (metadata.tables[name] for name in ("runner_execution_receipts", "evidence_artifacts", "finding_import_sessions"))
    receipt = (await session.execute(select(receipts).where(
        receipts.c.tenant_id == tenant_id, receipts.c.execution_id == execution_id,
    ))).mappings().one()
    artifact = (await session.execute(select(artifacts).where(
        artifacts.c.tenant_id == tenant_id, artifacts.c.id == receipt["evidence_artifact_id"],
    ))).mappings().one()
    imported = (await session.execute(select(imports).where(
        imports.c.tenant_id == tenant_id, imports.c.run_id == execution_id,
    ))).mappings().one()
    return artifact, receipt, imported


async def _verify_report(session: AsyncSession, backend: ChildEvidenceBackend, artifact: Any,
                         imported: Any, adapter_id: str) -> str:
    if (artifact["artifact_class"] != "report_safe" or artifact["redaction_state"] != "report_safe"
            or artifact["content_type"] != "application/json" or not 1 <= artifact["size_bytes"] <= 1_048_576):
        raise ChildParentConflict("child_parent_report_owner_invalid")
    stored = _stored_from_artifact(dict(artifact))
    verification = backend.verify_exact(stored)
    if not verification.ok or verification.object_key != stored.object_key or verification.version_id != stored.version_id:
        raise ChildParentConflict("child_parent_report_backend_verification_failed")
    content = backend.get_exact(stored.object_key, stored.version_id)
    # CRITICAL: independently verify the bytes read after the backend check; metadata or a prior verification is not report truth.
    if not isinstance(content, bytes) or len(content) != stored.size_bytes or hashlib.sha256(content).hexdigest() != stored.content_sha256:
        raise ChildParentConflict("child_parent_report_bytes_mismatch")
    try:
        payload = json.loads(content)
        raw = payload.get("findings") if isinstance(payload, dict) else None
        if not isinstance(raw, list) or len(raw) > 100:
            raise ValueError("findings_shape_invalid")
        findings = tuple(parse_normalized_adapter_finding(item) for item in raw)
    except (ValueError, TypeError) as exc:
        raise ChildParentConflict("child_parent_report_payload_invalid") from exc
    if not report_safe_payload_matches(payload, adapter_id=adapter_id, findings=findings):
        raise ChildParentConflict("child_parent_report_semantics_mismatch")
    records = metadata.tables["finding_import_records"]
    rows = (await session.execute(select(records).where(
        records.c.tenant_id == artifact["tenant_id"], records.c.import_record_ref == imported["id"],
    ))).mappings().all()
    expected = {finding.source_record_id: _digest(asdict(FindingOccurrenceInput(
        **asdict(finding), evidence_id=str(artifact["id"]), evidence_sha256=stored.content_sha256,
        redaction_state="report_safe", observed_at=imported["imported_at"],
    ))) for finding in findings}
    if (len(expected) != len(findings) or len(rows) != len(expected) or len(rows) != imported["record_count"]
            or any(expected.get(row["source_record_id"]) != row["source_record_sha256"] for row in rows)):
        raise ChildParentConflict("child_parent_report_import_binding_mismatch")
    return stored.content_sha256
