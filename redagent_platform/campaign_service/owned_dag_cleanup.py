"""Execution-scoped stop observation for the fixed completed owned parent frontier."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.dag_execution_contracts import DagContainActivityInputV1
from redagent_platform.campaign_service.execution import ReconciliationState
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from redagent_platform.campaign_service.planning.owned_sequential import OWNED_SEQUENTIAL_PLANNER_SHA256
from redagent_platform.campaign_service.planning.serde import parse_attack_path_dag_revision, parse_planning_domain
from redagent_platform.campaign_service.registry import closed_execution_binding_for
from redagent_platform.campaign_service.repository import CampaignRepository, _effect_receipt_contract
from redagent_platform.persistence.models import metadata


class OwnedDagCleanupVerifier(Protocol):
    async def verify_in_session(self, session: AsyncSession, request: DagContainActivityInputV1,
                                run: Any, *, now: datetime) -> tuple[str, str]: ...


def validate_owned_stop_frontier(run: Any, nodes: tuple[Any, ...], effects: tuple[Any, ...]) -> Any:
    if run["run_state"] != "running" or run["active_concurrency"] != 0:
        raise ValueError("owned_stop_no_inflight_required")
    payload = run["input_payload"]
    if not isinstance(payload, dict) or canonical_planning_sha256(payload) != run["input_sha256"]:
        raise ValueError("owned_stop_input_binding_invalid")
    revision = parse_attack_path_dag_revision(payload["revision"])
    domain = parse_planning_domain(payload["domain"])
    operators = {operator.operator_id: operator for operator in domain.operators}
    planned = revision.candidate_plan.nodes
    if (revision.planner_sha256 != OWNED_SEQUENTIAL_PLANNER_SHA256 or len(planned) != 2
            or revision.candidate_plan.plan_sha256 != run["plan_sha256"] or len(nodes) != 2
            or revision.domain_sha256 != domain.domain_sha256
            or tuple(operators[node.operator_id].capability.capability_id for node in planned) != ("zap-controlled-runtime", "nuclei-trusted-runtime")
            or planned[0].target_id != planned[1].target_id):
        raise ValueError("owned_stop_closed_parent_required")
    for node, expected in zip(nodes, planned):
        if (node["node_id"] != expected.node_id or node["operator_id"] != expected.operator_id
                or node["target_id"] != expected.target_id or node["node_sha256"] != canonical_planning_sha256(expected)
                or node["arguments_sha256"] != canonical_planning_sha256(expected.arguments)):
            raise ValueError("owned_stop_node_binding_invalid")
    # CRITICAL: a dispatched/unknown second node or active work cannot be called contained from the first receipt.
    if (nodes[0]["node_state"] != "confirmed" or nodes[1]["node_state"] not in {"pending", "ready"}
            or len(effects) != 1 or effects[0]["node_id"] != planned[0].node_id
            or effects[0]["effect_state"] != "confirmed"):
        raise ValueError("owned_stop_completed_frontier_required")
    return effects[0]


class PostgresOwnedDagCleanupVerifier:
    def __init__(self, evidence_backend: Any) -> None:
        self._backend = evidence_backend

    async def verify_in_session(self, session: AsyncSession, request: DagContainActivityInputV1,
                                run: Any, *, now: datetime) -> tuple[str, str]:
        # Imported lazily: parent intake depends on the DAG owners, and only terminal intake may mint a trusted source.
        from redagent_platform.campaign_service.child_replan_store import _report_owners, _verify_report

        workflow = request.request
        applications = metadata.tables["autonomous_campaign_applications"]
        app = (await session.execute(select(applications).where(
            applications.c.tenant_id == workflow.tenant_id, applications.c.id == run["campaign_id"],
        ))).mappings().one_or_none()
        if app is None or app["mode"] != AutonomousCampaignMode.BOUNDED_REPLAN.value:
            raise ValueError("owned_stop_bounded_application_required")
        nodes, effects = (metadata.tables[name] for name in ("campaign_execution_nodes", "campaign_effects"))
        node_rows = tuple((await session.execute(select(nodes).where(
            nodes.c.tenant_id == workflow.tenant_id, nodes.c.execution_run_id == run["id"],
            nodes.c.campaign_id == run["campaign_id"],
        ).order_by(nodes.c.node_order).with_for_update())).mappings().all())
        effect_rows = tuple((await session.execute(select(effects).where(
            effects.c.tenant_id == workflow.tenant_id, effects.c.execution_run_id == run["id"],
            effects.c.campaign_id == run["campaign_id"],
        ).with_for_update())).mappings().all())
        effect = validate_owned_stop_frontier(run, node_rows, effect_rows)
        receipt = _effect_receipt_contract(effect["effect_receipt_payload"])
        if (receipt.reconciliation_state is not ReconciliationState.CONFIRMED
                or receipt.external_receipt_id is None or receipt.cleanup_receipt_id is None
                or receipt.receipt_sha256 != effect["effect_receipt_sha256"] or receipt.effect_id != effect["effect_id"]
                or receipt.envelope_sha256 != run["authority_sha256"] or receipt.request_sha256 != effect["request_sha256"]
                or receipt.cleanup_receipt_id != effect["cleanup_receipt_id"]
                or receipt.effect_intent_sha256 != effect["effect_intent_sha256"]
                or receipt.output_complete is not True or type(receipt.external_contact_count) is not int
                or receipt.external_contact_count != 0 or receipt.completed_at is None or receipt.completed_at > now):
            raise ValueError("owned_stop_receipt_invalid")
        intent = effect["effect_intent_payload"]
        if (not isinstance(intent, dict) or canonical_planning_sha256(intent) != receipt.effect_intent_sha256
                or any(intent.get(key) != value for key, value in (
                    ("tenant_id", workflow.tenant_id), ("campaign_id", run["campaign_id"]), ("execution_run_id", run["id"]),
                    ("node_id", node_rows[0]["node_id"]), ("node_sha256", node_rows[0]["node_sha256"]),
                    ("target_id", node_rows[0]["target_id"]), ("effect_id", effect["effect_id"]),
                    ("invocation_id", effect["invocation_id"])))):
            raise ValueError("owned_stop_intent_invalid")
        binding = CapabilityBindingKeyV1(**intent["binding"])
        closed = closed_execution_binding_for("zap-controlled-runtime")
        domain = parse_planning_domain(run["input_payload"]["domain"])
        capability = next(operator.capability for operator in domain.operators if operator.operator_id == node_rows[0]["operator_id"])
        if (any(getattr(binding, key) != value for key, value in asdict(closed).items() if key not in {"approval_tier", "requires_secret"})
                or any(getattr(binding, key) != value for key, value in asdict(capability).items())):
            raise ValueError("owned_stop_profile_invalid")
        await CampaignRepository(session, tenant_id=workflow.tenant_id, actor_user_id=request.stop.actor_user_id,
                                 correlation_id="owned-execution-stop-observation").validate_trusted_effect_owners(
            effect_id=receipt.effect_id, external_receipt_id=receipt.external_receipt_id,
            evidence_ids=receipt.evidence_ids, cleanup_receipt_id=receipt.cleanup_receipt_id,
            require_complete_coverage=True, require_retest=False)
        artifact, _, imported = await _report_owners(session, workflow.tenant_id, receipt.external_receipt_id)
        await _verify_report(session, self._backend, artifact, imported, "zap-service")
        return "contained", "owned_execution_terminal_cleanup_verified"
