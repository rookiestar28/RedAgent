"""Tenant-scoped server-truth projection for autonomous campaign operations."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
from typing import Any, Mapping

from sqlalchemy import or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker
from sqlalchemy.sql.elements import ColumnElement

from redagent_platform.campaign_service.admission_contracts import (
    AdmissionOutcome,
    CampaignBudgetVectorV1,
    PlanAdmissionReceiptV1,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from redagent_platform.campaign_service.status import CampaignStatusNotFound
from redagent_platform.persistence.models import metadata


OPERATIONS_SCHEMA_VERSION = "redagent.campaign-operations/v1"
_MAX_NODES = 100
_MAX_ROWS = 100
_MAX_JSON_BYTES = 1_000_000
_MAX_JSON_DEPTH = 32
_MAX_JSON_NODES = 10_000
_MAX_JSON_KEYS = 10_000
_MAX_JSON_KEY_LENGTH = 200
_BUDGET_UNITS = {
    "duration_seconds": "seconds",
    "requests": "requests",
    "rate_per_minute": "requests/minute",
    "concurrency": "concurrent operations",
    "risk_micropoints": "risk micropoints",
    "cost_microunits": "cost microunits",
    "evidence_bytes": "bytes",
    "data_bytes": "bytes",
}
_ACTIVE_RESERVATIONS = {"reserved", "held", "consumed"}
_ACTIVE_RUNS = {"start_pending", "running", "stopping", "reconciliation_required"}
_ADMISSION_OUTCOMES = {"admitted", "denied"}
_RESERVATION_STATES = {"reserved", "held", "consumed", "released", "expired"}
_RUN_STATES = _ACTIVE_RUNS | {
    "completed",
    "contained",
    "manual_review_required",
    "failed_before_io",
    "failed",
}
_NODE_STATES = {
    "pending",
    "ready",
    "reserved",
    "claimed",
    "dispatching",
    "reconciliation_required",
    "not_applied",
    "confirmed",
    "skipped",
    "contained",
    "manual_review_required",
    "failed",
}
_VALIDATION_RESULTS = {"valid", "invalid", "unknown"}
_CAPABILITY_LABELS = {
    "artifact-posture": "Artifact posture",
    "http-posture": "HTTP posture",
    "nuclei-trusted-runtime": "Nuclei trusted runtime",
    "zap-controlled-runtime": "ZAP controlled runtime",
}
_FACT_LABELS = {
    "authorized": "Authorized",
    "finding-count": "Finding count",
    "http_header_present": "HTTP header present",
    "posture-collected": "Posture collected",
    "owned.zap.passive.completed": "ZAP passive profile completed",
    "owned.nuclei.header.completed": "Nuclei header profile completed",
}
_PRODUCER_LABELS = {
    "dag_runner_result": "DAG runner result",
    "detection_correlation": "Detection correlation",
}
_AUDIT_ACTION_LABELS = {
    "campaign.dag.containment_recorded": "Campaign containment recorded",
    "campaign.dag.start.requested": "Campaign start requested",
    "campaign.dag.workflow_start_delivery_failed": "Campaign workflow start failed",
    "campaign.dag.workflow_started": "Campaign workflow started",
}


class CampaignOperationsProjectionInvalid(RuntimeError):
    """Persisted campaign material cannot be projected without unsafe inference."""


@dataclass(frozen=True, slots=True)
class CampaignOperationsSource:
    campaign: Mapping[str, Any]
    admission: Mapping[str, Any] | None = None
    ledger: Mapping[str, Any] | None = None
    reservations: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    execution: Mapping[str, Any] | None = None
    nodes: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    observations: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    proposals: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    audits: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)
    effects: tuple[Mapping[str, Any], ...] = field(default_factory=tuple)


class PostgresCampaignOperationsOwner:
    """Read accepted campaign stores under one exact tenant context."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self.sessions = sessions

    async def read(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        now: datetime,
    ) -> dict[str, Any]:
        _required("operations_tenant", tenant_id, 64)
        _required("operations_campaign", campaign_id, 64)
        _aware(now)
        async with self.sessions() as session, session.begin():
            # IMPORTANT: all component rows must come from one snapshot or a concurrent replan can
            # produce a mixed authority/plan/budget projection that never existed server-side.
            await session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
            # CRITICAL: every projection query must share the exact tenant RLS context; client-side
            # filtering would expose cross-tenant operational and evidence metadata.
            await session.execute(
                text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
                {"tenant_id": tenant_id},
            )
            source = await _read_source(
                session,
                tenant_id=tenant_id,
                campaign_id=campaign_id,
            )
        return project_campaign_operations(source, now=now)


async def _read_source(
    session: AsyncSession,
    *,
    tenant_id: str,
    campaign_id: str,
) -> CampaignOperationsSource:
    campaigns = metadata.tables["campaigns"]
    campaign = (
        (
            await session.execute(
                select(campaigns).where(
                    campaigns.c.tenant_id == tenant_id,
                    campaigns.c.id == campaign_id,
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if campaign is None:
        raise CampaignStatusNotFound("campaign_operations_not_found")
    campaign_row = dict(campaign)

    admission = await _latest(
        session,
        metadata.tables["plan_admission_receipts"],
        tenant_id=tenant_id,
        campaign_id=campaign_id,
    )
    ledger = await _single(
        session,
        metadata.tables["campaign_budget_ledgers"],
        tenant_id=tenant_id,
        campaign_id=campaign_id,
    )
    reservations = await _bounded_rows(
        session,
        metadata.tables["campaign_budget_reservations"],
        tenant_id=tenant_id,
        campaign_id=campaign_id,
        order_column="created_at",
    )
    execution = await _latest(
        session,
        metadata.tables["campaign_execution_runs"],
        tenant_id=tenant_id,
        campaign_id=campaign_id,
    )
    nodes: tuple[Mapping[str, Any], ...] = ()
    execution_id: str | None = None
    if execution is not None:
        execution_id = str(execution["id"])
        nodes = await _bounded_rows(
            session,
            metadata.tables["campaign_execution_nodes"],
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            extra=(metadata.tables["campaign_execution_nodes"].c.execution_run_id == execution_id),
            order_column="node_order",
        )
    observations = await _bounded_rows(
        session,
        metadata.tables["trusted_campaign_observations"],
        tenant_id=tenant_id,
        campaign_id=campaign_id,
        order_column="promoted_at",
        descending=True,
    )
    proposals = list(
        await _bounded_rows(
            session,
            metadata.tables["campaign_replan_proposals"],
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            order_column="replan_sequence",
        )
    )
    acceptances = metadata.tables["campaign_replan_acceptances"]
    acceptance_rows = (
        (
            await session.execute(
                select(acceptances.c.proposal_id)
                .where(
                    acceptances.c.tenant_id == tenant_id,
                    acceptances.c.campaign_id == campaign_id,
                )
                .limit(_MAX_ROWS + 1)
            )
        )
        .mappings()
        .all()
    )
    if len(acceptance_rows) > _MAX_ROWS:
        raise CampaignOperationsProjectionInvalid("operations_replan_acceptances_unbounded")
    accepted_ids = {str(row["proposal_id"]) for row in acceptance_rows}
    proposals = [{**row, "accepted": str(row["id"]) in accepted_ids} for row in proposals]

    effects = await _bounded_rows(
        session,
        metadata.tables["campaign_effects"],
        tenant_id=tenant_id,
        campaign_id=campaign_id,
        order_column="created_at",
    )
    audits_table = metadata.tables["audit_events"]
    subject_filter: ColumnElement[bool] = (audits_table.c.subject_type == "campaign") & (
        audits_table.c.subject_id == campaign_id
    )
    if execution_id is not None:
        subject_filter = or_(
            subject_filter,
            ((audits_table.c.subject_type == "campaign_execution") & (audits_table.c.subject_id == execution_id)),
        )
    audit_rows = (
        (
            await session.execute(
                select(audits_table)
                .where(audits_table.c.tenant_id == tenant_id, subject_filter)
                .order_by(audits_table.c.created_at.desc(), audits_table.c.id.desc())
                .limit(_MAX_ROWS + 1)
            )
        )
        .mappings()
        .all()
    )
    if len(audit_rows) > _MAX_ROWS:
        raise CampaignOperationsProjectionInvalid("operations_audits_unbounded")
    return CampaignOperationsSource(
        campaign=campaign_row,
        admission=admission,
        ledger=ledger,
        reservations=reservations,
        execution=execution,
        nodes=nodes,
        observations=observations,
        proposals=tuple(proposals),
        audits=tuple(dict(row) for row in audit_rows),
        effects=effects,
    )


async def _latest(
    session: AsyncSession,
    table: Any,
    *,
    tenant_id: str,
    campaign_id: str,
) -> Mapping[str, Any] | None:
    row = (
        (
            await session.execute(
                select(table)
                .where(table.c.tenant_id == tenant_id, table.c.campaign_id == campaign_id)
                .order_by(table.c.created_at.desc(), table.c.id.desc())
                .limit(1)
            )
        )
        .mappings()
        .one_or_none()
    )
    return dict(row) if row is not None else None


async def _single(
    session: AsyncSession,
    table: Any,
    *,
    tenant_id: str,
    campaign_id: str,
) -> Mapping[str, Any] | None:
    rows = (
        (
            await session.execute(
                select(table)
                .where(
                    table.c.tenant_id == tenant_id,
                    table.c.campaign_id == campaign_id,
                )
                .limit(2)
            )
        )
        .mappings()
        .all()
    )
    if len(rows) > 1:
        raise CampaignOperationsProjectionInvalid("operations_store_identity_ambiguous")
    return dict(rows[0]) if rows else None


async def _bounded_rows(
    session: AsyncSession,
    table: Any,
    *,
    tenant_id: str,
    campaign_id: str,
    order_column: str,
    descending: bool = False,
    extra: Any | None = None,
) -> tuple[Mapping[str, Any], ...]:
    clauses = [table.c.tenant_id == tenant_id, table.c.campaign_id == campaign_id]
    if extra is not None:
        clauses.append(extra)
    order = getattr(table.c, order_column)
    query = (
        select(table)
        .where(*clauses)
        .order_by(
            order.desc() if descending else order.asc(),
            table.c.id.asc(),
        )
        .limit(_MAX_ROWS + 1)
    )
    rows = (await session.execute(query)).mappings().all()
    if len(rows) > _MAX_ROWS:
        raise CampaignOperationsProjectionInvalid(f"operations_{table.name}_unbounded")
    return tuple(dict(row) for row in rows)


def project_campaign_operations(
    source: CampaignOperationsSource,
    *,
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(source, CampaignOperationsSource):
        raise CampaignOperationsProjectionInvalid("operations_source_invalid")
    _aware(now)
    if not isinstance(source.campaign, Mapping):
        raise CampaignOperationsProjectionInvalid("operations_campaign_row_invalid")
    for name in ("admission", "ledger", "execution"):
        value = getattr(source, name)
        if value is not None and not isinstance(value, Mapping):
            raise CampaignOperationsProjectionInvalid(f"operations_{name}_row_invalid")
    campaign_id = _required("operations_campaign", source.campaign.get("id"), 64)
    _bound("nodes", source.nodes, _MAX_NODES)
    for name in ("reservations", "observations", "proposals", "audits", "effects"):
        _bound(name, getattr(source, name), _MAX_ROWS)

    execution = source.execution
    input_payload = _mapping(execution.get("input_payload"), "operations_input_payload_invalid") if execution else {}
    _json_bound(input_payload, "operations_input_payload_unbounded")
    revision = _mapping(input_payload.get("revision"), "operations_revision_invalid", optional=True)
    candidate = _mapping(revision.get("candidate_plan"), "operations_candidate_plan_invalid", optional=True)
    plan_nodes = candidate.get("nodes", []) if candidate else []
    plan_edges = candidate.get("edges", []) if candidate else []
    if not isinstance(plan_nodes, list):
        raise CampaignOperationsProjectionInvalid("operations_plan_nodes_invalid")
    if not isinstance(plan_edges, list):
        raise CampaignOperationsProjectionInvalid("operations_plan_edges_invalid")
    if len(plan_nodes) > _MAX_NODES or len(plan_edges) > _MAX_NODES * 2:
        raise CampaignOperationsProjectionInvalid("operations_plan_unbounded")

    stored_nodes = {str(row.get("node_id")): row for row in source.nodes}
    if len(stored_nodes) != len(source.nodes):
        raise CampaignOperationsProjectionInvalid("operations_node_binding_invalid")
    labels: dict[str, str] = {}
    safe_nodes: list[dict[str, Any]] = []
    for index, item in enumerate(plan_nodes):
        node = _mapping(item, "operations_plan_node_invalid")
        node_id = _required("operations_plan_node", node.get("node_id"), 100)
        order = _integer(node.get("order"), "operations_plan_node_order_invalid")
        label = f"Step {index + 1}"
        labels[node_id] = label
        stored = stored_nodes.get(node_id, {})
        capability = stored.get("capability_id") or node.get("operator_id")
        safe_nodes.append(
            {
                "label": label,
                "capability": _capability_label(capability),
                "state": _required("operations_node_state", stored.get("node_state", "planned"), 32),
                "order": order,
            }
        )
    safe_edges: list[dict[str, str]] = []
    for item in plan_edges:
        edge = _mapping(item, "operations_plan_edge_invalid")
        source_label = labels.get(str(edge.get("source_node_id")))
        target_label = labels.get(str(edge.get("target_node_id")))
        if source_label is None or target_label is None:
            raise CampaignOperationsProjectionInvalid("operations_plan_edge_binding_invalid")
        safe_edges.append({"source": source_label, "target": target_label})

    certificate = _mapping(input_payload.get("certificate"), "operations_certificate_invalid", optional=True)
    admission_payload = _mapping(
        source.admission.get("receipt_payload") if source.admission else None,
        "operations_admission_payload_invalid",
        optional=True,
    )
    if admission_payload:
        _json_bound(admission_payload, "operations_admission_payload_unbounded")
    authority = _authority(source, admission_payload, now=now)
    validation = _validation(certificate)
    admission = _admission(source.admission)
    budget = _budget(source)
    execution_section = _execution(execution, source.nodes)
    observations = _observations(source.observations, now=now)
    revisions = _revisions(source.proposals)
    audits = _audits(source.audits)
    evidence = _evidence(source)
    version = _aggregate_version(source)
    return {
        "schema_version": OPERATIONS_SCHEMA_VERSION,
        "aggregate_version": version,
        "etag": f'"{campaign_id}:{version}"',
        "preparation_state": _preparation_state(source.admission, execution, authority_state=authority["state"]),
        "authority": authority,
        "plan": {
            "revision_label": "Current revision" if revision else "Unavailable",
            "parent_revision_present": bool(revision.get("parent_revision_id")) if revision else False,
            "nodes": safe_nodes,
            "edges": safe_edges,
        },
        "validation": validation,
        "admission": admission,
        "budget": budget,
        "execution": execution_section,
        "observations": observations,
        "revisions": revisions,
        "audit": audits,
        "evidence": evidence,
    }


def _authority(
    source: CampaignOperationsSource,
    payload: Mapping[str, Any],
    *,
    now: datetime,
) -> dict[str, Any]:
    execution = source.execution or {}
    if not source.admission and not execution:
        return {
            "state": "unavailable",
            "signed_authority_sha256": None,
            "authority_sha256": None,
            "lifecycle_epoch": None,
            "policy_revocation_epoch": None,
            "roe_revocation_epoch": None,
            "kill_switch_epoch": None,
            "expires_at": None,
        }
    if source.admission is None:
        raise CampaignOperationsProjectionInvalid("operations_authority_binding_invalid")
    outcome = _closed_value(
        source.admission.get("outcome"),
        _ADMISSION_OUTCOMES,
        "operations_admission_outcome_invalid",
    )
    selected_receipt = _typed_admission_receipt(payload)
    signed_authority_sha256 = selected_receipt.signed_authority_sha256
    authority_sha256 = selected_receipt.authority_sha256
    lifecycle_epoch = selected_receipt.lifecycle_epoch
    policy_revocation_epoch = selected_receipt.policy_revocation_epoch
    roe_revocation_epoch = selected_receipt.roe_revocation_epoch
    kill_switch_epoch = selected_receipt.kill_switch_epoch
    expires_at = selected_receipt.expires_at
    admission_receipt_sha256 = _digest_required(source.admission.get("receipt_sha256"))
    if (
        source.admission.get("id") != selected_receipt.receipt_id
        or outcome != selected_receipt.outcome.value
        or source.admission.get("reason_code") != selected_receipt.reason_code
        or admission_receipt_sha256 != selected_receipt.receipt_sha256
    ):
        raise CampaignOperationsProjectionInvalid("operations_authority_binding_mismatch")
    if execution:
        # CRITICAL: never render an admitted approval from a partial or cross-revision binding;
        # doing so makes unrelated persisted rows look like one current authority grant.
        if outcome != "admitted":
            raise CampaignOperationsProjectionInvalid("operations_authority_binding_mismatch")
        input_payload = _mapping(execution.get("input_payload"), "operations_authority_binding_mismatch")
        nested_payload = _mapping(
            input_payload.get("admission_receipt"),
            "operations_authority_binding_mismatch",
        )
        nested_receipt = _typed_admission_receipt(nested_payload)
        # CRITICAL: the immutable workflow input is an authority copy, not a display hint. Any
        # divergence can make a different receipt or expiry appear admitted after execution starts.
        if (
            nested_receipt != selected_receipt
            or nested_receipt.receipt_sha256 != admission_receipt_sha256
            or canonical_planning_sha256(input_payload) != execution.get("input_sha256")
        ):
            raise CampaignOperationsProjectionInvalid("operations_authority_binding_mismatch")
        reserved_budget = selected_receipt.reserved_budget
        if reserved_budget is None or selected_receipt.reservation_id is None:
            raise CampaignOperationsProjectionInvalid("operations_authority_binding_mismatch")
        expected = {
            "tenant_id": selected_receipt.tenant_id,
            "campaign_id": selected_receipt.campaign_id,
            "admission_receipt_id": selected_receipt.receipt_id,
            "reservation_id": selected_receipt.reservation_id,
            "signed_authority_sha256": signed_authority_sha256,
            "authority_sha256": authority_sha256,
            "domain_sha256": selected_receipt.domain_sha256,
            "plan_sha256": selected_receipt.plan_sha256,
            "certificate_sha256": selected_receipt.certificate_sha256,
            "lifecycle_epoch": lifecycle_epoch,
            "policy_revocation_epoch": policy_revocation_epoch,
            "roe_revocation_epoch": roe_revocation_epoch,
            "kill_switch_epoch": kill_switch_epoch,
            "admission_receipt_sha256": admission_receipt_sha256,
            "reserved_budget_sha256": reserved_budget.budget_sha256,
        }
        for name, value in expected.items():
            actual = execution.get(name)
            if actual != value or type(actual) is not type(value):
                raise CampaignOperationsProjectionInvalid("operations_authority_binding_mismatch")
    return {
        "state": "expired" if outcome == "admitted" and expires_at <= now else outcome,
        "signed_authority_sha256": signed_authority_sha256,
        "authority_sha256": authority_sha256,
        "lifecycle_epoch": lifecycle_epoch,
        "policy_revocation_epoch": policy_revocation_epoch,
        "roe_revocation_epoch": roe_revocation_epoch,
        "kill_switch_epoch": kill_switch_epoch,
        "expires_at": expires_at.astimezone(timezone.utc).isoformat(),
    }


def _typed_admission_receipt(payload: Mapping[str, Any]) -> PlanAdmissionReceiptV1:
    values = dict(payload)
    try:
        values["outcome"] = AdmissionOutcome(values.get("outcome"))
        values["issued_at"] = _as_datetime(values.get("issued_at"), "operations_authority_binding_invalid")
        values["expires_at"] = _as_datetime(
            values.get("expires_at"),
            "operations_authority_binding_invalid",
        )
        reserved = values.get("reserved_budget")
        if reserved is not None:
            values["reserved_budget"] = CampaignBudgetVectorV1(
                **dict(_mapping(reserved, "operations_authority_binding_invalid"))
            )
        return PlanAdmissionReceiptV1(**values)
    except (KeyError, TypeError, ValueError, CampaignOperationsProjectionInvalid) as exc:
        raise CampaignOperationsProjectionInvalid("operations_authority_binding_invalid") from exc


def _validation(certificate: Mapping[str, Any]) -> dict[str, Any]:
    if not certificate:
        return {"result": "unavailable", "reason": None, "counterexample_codes": []}
    counterexamples = certificate.get("counterexamples", [])
    if not isinstance(counterexamples, list) or len(counterexamples) > _MAX_ROWS:
        raise CampaignOperationsProjectionInvalid("operations_counterexamples_invalid")
    codes: list[str] = []
    for item in counterexamples:
        counterexample = _mapping(item, "operations_counterexample_invalid")
        codes.append(_required("operations_counterexample_code", counterexample.get("code"), 150))
    return {
        "result": _closed_value(
            certificate.get("result"),
            _VALIDATION_RESULTS,
            "operations_validation_result_invalid",
        ),
        "reason": _optional_text(certificate.get("bounded_reason"), 150),
        "counterexample_codes": codes,
    }


def _admission(row: Mapping[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {"outcome": "unavailable", "reason": None, "receipt_sha256": None}
    return {
        "outcome": _closed_value(
            row.get("outcome"),
            _ADMISSION_OUTCOMES,
            "operations_admission_outcome_invalid",
        ),
        "reason": _optional_text(row.get("reason_code"), 100),
        "receipt_sha256": _digest_required(row.get("receipt_sha256")),
    }


def _budget(source: CampaignOperationsSource) -> dict[str, Any]:
    if source.ledger is None and source.reservations:
        raise CampaignOperationsProjectionInvalid("operations_budget_ledger_missing")
    for reservation in source.reservations:
        _closed_value(
            reservation.get("reservation_state"),
            _RESERVATION_STATES,
            "operations_reservation_state_invalid",
        )
    dimensions: dict[str, dict[str, Any]] = {}
    for name, unit in _BUDGET_UNITS.items():
        authorized = _integer(source.ledger.get(name), f"operations_budget_{name}_invalid") if source.ledger else None
        committed = 0
        for reservation in source.reservations:
            if reservation.get("reservation_state") in _ACTIVE_RESERVATIONS:
                committed += _integer(reservation.get(name), f"operations_budget_{name}_invalid")
        if authorized is not None and committed > authorized:
            raise CampaignOperationsProjectionInvalid(f"operations_budget_{name}_overcommitted")
        dimensions[name] = {
            "authorized": authorized,
            "committed": committed if authorized is not None else None,
            "residual": authorized - committed if authorized is not None else None,
            "unit": unit,
        }
    return {"state": "available" if source.ledger else "unavailable", "dimensions": dimensions}


def _execution(
    row: Mapping[str, Any] | None,
    nodes: tuple[Mapping[str, Any], ...],
) -> dict[str, Any]:
    if row is None:
        return {
            "state": "unavailable",
            "transition_count": 0,
            "max_transitions": 0,
            "stop_requested": False,
            "terminal_reason": None,
            "frontier": {},
        }
    frontier: dict[str, int] = {}
    for node in nodes:
        state = _closed_value(
            node.get("node_state"),
            _NODE_STATES,
            "operations_node_state_invalid",
        )
        frontier[state] = frontier.get(state, 0) + 1
    state = _closed_value(
        row.get("run_state"),
        _RUN_STATES,
        "operations_execution_state_invalid",
    )
    transition_count = _integer(row.get("transition_count"), "operations_transition_count_invalid")
    max_transitions = _integer(row.get("max_transitions"), "operations_max_transitions_invalid")
    if max_transitions < 1 or max_transitions > 10_000:
        raise CampaignOperationsProjectionInvalid("operations_max_transitions_invalid")
    if transition_count > max_transitions:
        raise CampaignOperationsProjectionInvalid("operations_transition_count_exceeded")
    stop_requested = row.get("stop_requested")
    if type(stop_requested) is not bool:
        raise CampaignOperationsProjectionInvalid("operations_stop_requested_invalid")
    return {
        "state": state,
        "transition_count": transition_count,
        "max_transitions": max_transitions,
        "stop_requested": stop_requested,
        "terminal_reason": _optional_text(row.get("terminal_reason"), 100),
        "frontier": dict(sorted(frontier.items())),
    }


def _observations(rows: tuple[Mapping[str, Any], ...], *, now: datetime) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        expires = _as_datetime(row.get("expires_at"), "operations_observation_expiry_invalid")
        result.append(
            {
                "fact": _public_label(row.get("fact_id"), _FACT_LABELS),
                "producer_kind": _public_label(row.get("producer_kind"), _PRODUCER_LABELS),
                "observation_sha256": _digest_or_none(row.get("observation_sha256")),
                "provenance_sha256": _digest_or_none(row.get("provenance_sha256")),
                "freshness": "current" if expires > now else "expired",
            }
        )
    return result


def _revisions(rows: tuple[Mapping[str, Any], ...]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        payload = _mapping(row.get("proposal_payload"), "operations_replan_payload_invalid")
        _json_bound(payload, "operations_replan_payload_unbounded")
        invalidated = _list(payload.get("invalidated_parent_node_ids"), "operations_replan_invalidated_invalid")
        retained = _list(payload.get("retained_parent_node_ids"), "operations_replan_retained_invalid")
        substitutions = _list(payload.get("substitutions"), "operations_replan_substitutions_invalid")
        sequence = _integer(row.get("replan_sequence"), "operations_replan_sequence_invalid")
        accepted = row.get("accepted")
        if type(accepted) is not bool:
            raise CampaignOperationsProjectionInvalid("operations_replan_acceptance_invalid")
        result.append(
            {
                "label": f"Revision {sequence}",
                "state": "accepted" if accepted else "proposed",
                "proposal_sha256": _digest_or_none(row.get("proposal_sha256")),
                "invalidated_count": len(invalidated),
                "retained_count": len(retained),
                "substitution_count": len(substitutions),
            }
        )
    return result


def _audits(rows: tuple[Mapping[str, Any], ...]) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for index, row in enumerate(rows):
        details = _mapping(row.get("details"), "operations_audit_details_invalid")
        _json_bound(details, "operations_audit_details_unbounded")
        _required("operations_audit_correlation", row.get("correlation_id"), 100)
        result.append(
            {
                "action": _public_label(row.get("action"), _AUDIT_ACTION_LABELS),
                "occurred_at": _datetime_text(row.get("created_at")),
                "correlation_id": f"Event {index + 1}",
                "details_sha256": hashlib.sha256(
                    json.dumps(details, sort_keys=True, separators=(",", ":")).encode("utf-8")
                ).hexdigest(),
            }
        )
    return result


def _evidence(source: CampaignOperationsSource) -> dict[str, Any]:
    evidence_count = 0
    for row in source.effects:
        evidence_ids = row.get("evidence_ids")
        if not isinstance(evidence_ids, list) or len(evidence_ids) > _MAX_ROWS:
            raise CampaignOperationsProjectionInvalid("operations_effect_evidence_invalid")
        if any(not isinstance(item, str) or not item or len(item) > 100 for item in evidence_ids) or len(
            set(evidence_ids)
        ) != len(evidence_ids):
            raise CampaignOperationsProjectionInvalid("operations_effect_evidence_invalid")
        evidence_count += len(evidence_ids)
    cleanup_complete = bool(source.effects) and all(
        isinstance(row.get("cleanup_receipt_id"), str) and 0 < len(row["cleanup_receipt_id"]) <= 100
        for row in source.effects
    )
    terminal = source.campaign.get("terminal_receipt_sha256")
    return {
        "effect_count": len(source.effects),
        "evidence_count": evidence_count,
        "cleanup_state": "complete" if cleanup_complete else ("required" if source.effects else "unavailable"),
        "terminal_receipt_present": _digest_or_none(terminal) is not None,
        # CRITICAL: live rows are not a substitute for R161 retained-bundle and trust-anchor verification.
        "export_state": "unavailable_without_verified_bundle",
    }


def _aggregate_version(source: CampaignOperationsSource) -> int:
    rows = [source.campaign]
    rows.extend(row for row in (source.admission, source.ledger, source.execution) if row is not None)
    rows.extend(
        source.reservations + source.nodes + source.observations + source.proposals + source.audits + source.effects
    )
    return max(
        1,
        sum(max(1, _integer(row.get("version", 1), "operations_row_version_invalid")) for row in rows),
    )


def _preparation_state(
    admission: Mapping[str, Any] | None,
    execution: Mapping[str, Any] | None,
    *,
    authority_state: str,
) -> str:
    if admission is None and execution is None:
        return "not_prepared"
    if authority_state == "denied":
        return "denied"
    if execution is None:
        return authority_state
    state = _closed_value(
        execution.get("run_state"),
        _RUN_STATES,
        "operations_execution_state_invalid",
    )
    return "executing" if state in _ACTIVE_RUNS else "terminal"


def _mapping(value: Any, code: str, *, optional: bool = False) -> Mapping[str, Any]:
    if value is None and optional:
        return {}
    if not isinstance(value, Mapping):
        raise CampaignOperationsProjectionInvalid(code)
    return value


def _list(value: Any, code: str) -> list[Any]:
    if not isinstance(value, list) or len(value) > _MAX_ROWS:
        raise CampaignOperationsProjectionInvalid(code)
    return value


def _bound(name: str, rows: tuple[Mapping[str, Any], ...], maximum: int) -> None:
    if not isinstance(rows, tuple) or len(rows) > maximum:
        raise CampaignOperationsProjectionInvalid(f"operations_{name}_unbounded")
    if any(not isinstance(row, Mapping) for row in rows):
        raise CampaignOperationsProjectionInvalid(f"operations_{name}_invalid")


def _json_bound(value: Any, code: str) -> None:
    # CRITICAL: stored JSON is untrusted persistence input; implicit string conversion or recursive
    # traversal can leak internal objects or escape the typed fail-closed projection boundary.
    stack: list[tuple[Any, int]] = [(value, 0)]
    seen_containers: set[int] = set()
    node_count = 0
    key_count = 0
    while stack:
        current, depth = stack.pop()
        node_count += 1
        if depth > _MAX_JSON_DEPTH or node_count > _MAX_JSON_NODES:
            raise CampaignOperationsProjectionInvalid(code)
        if isinstance(current, Mapping):
            identity = id(current)
            if identity in seen_containers or len(current) > _MAX_JSON_KEYS:
                raise CampaignOperationsProjectionInvalid(code)
            seen_containers.add(identity)
            key_count += len(current)
            if key_count > _MAX_JSON_KEYS:
                raise CampaignOperationsProjectionInvalid(code)
            for key, child in current.items():
                if not isinstance(key, str) or not key or len(key) > _MAX_JSON_KEY_LENGTH:
                    raise CampaignOperationsProjectionInvalid(code)
                stack.append((child, depth + 1))
        elif isinstance(current, list):
            identity = id(current)
            if identity in seen_containers or len(current) > _MAX_JSON_NODES:
                raise CampaignOperationsProjectionInvalid(code)
            seen_containers.add(identity)
            stack.extend((child, depth + 1) for child in current)
        elif current is None or type(current) in {str, bool, int, float}:
            if type(current) is float and (current != current or current in {float("inf"), float("-inf")}):
                raise CampaignOperationsProjectionInvalid(code)
        else:
            raise CampaignOperationsProjectionInvalid(code)
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as exc:
        raise CampaignOperationsProjectionInvalid(code) from exc
    if len(encoded) > _MAX_JSON_BYTES:
        raise CampaignOperationsProjectionInvalid(code)


def _required(name: str, value: Any, maximum: int) -> str:
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CampaignOperationsProjectionInvalid(f"{name}_invalid")
    return value


def _optional_text(value: Any, maximum: int) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value or len(value) > maximum:
        raise CampaignOperationsProjectionInvalid("operations_optional_text_invalid")
    return value


def _integer(value: Any, code: str) -> int:
    if type(value) is not int or value < 0 or value > 10**18:
        raise CampaignOperationsProjectionInvalid(code)
    return value


def _optional_integer(value: Any) -> int | None:
    return None if value is None else _integer(value, "operations_integer_invalid")


def _digest_or_none(value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value):
        raise CampaignOperationsProjectionInvalid("operations_digest_invalid")
    return value


def _digest_required(value: Any) -> str:
    result = _digest_or_none(value)
    if result is None:
        raise CampaignOperationsProjectionInvalid("operations_digest_invalid")
    return result


def _as_datetime(value: Any, code: str) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, str):
        try:
            result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as exc:
            raise CampaignOperationsProjectionInvalid(code) from exc
    else:
        raise CampaignOperationsProjectionInvalid(code)
    if result.tzinfo is None or result.utcoffset() is None:
        raise CampaignOperationsProjectionInvalid(code)
    return result


def _datetime_text(value: Any) -> str | None:
    if value is None:
        return None
    return _as_datetime(value, "operations_datetime_invalid").astimezone(timezone.utc).isoformat()


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise CampaignOperationsProjectionInvalid("operations_now_invalid")


def _closed_value(value: Any, allowed: set[str], code: str) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise CampaignOperationsProjectionInvalid(code)
    return value


def _public_label(value: Any, labels: Mapping[str, str]) -> str:
    if not isinstance(value, str) or value not in labels:
        raise CampaignOperationsProjectionInvalid("operations_public_label_invalid")
    return labels[value]


def _capability_label(value: Any) -> str:
    return _public_label(value, _CAPABILITY_LABELS)
