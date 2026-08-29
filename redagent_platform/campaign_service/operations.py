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

from redagent_platform.campaign_service.status import CampaignStatusNotFound
from redagent_platform.persistence.models import metadata


OPERATIONS_SCHEMA_VERSION = "redagent.campaign-operations/v1"
_MAX_NODES = 100
_MAX_ROWS = 100
_MAX_JSON_BYTES = 1_000_000
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
    authority = _authority(source, admission_payload)
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
        "preparation_state": _preparation_state(source.admission, execution),
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


def _authority(source: CampaignOperationsSource, payload: Mapping[str, Any]) -> dict[str, Any]:
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
    outcome = (
        _required("operations_authority_state", source.admission.get("outcome"), 32)
        if source.admission
        else "unavailable"
    )
    return {
        "state": outcome,
        "signed_authority_sha256": _digest_or_none(
            execution.get("signed_authority_sha256") or payload.get("signed_authority_sha256")
        ),
        "authority_sha256": _digest_or_none(execution.get("authority_sha256") or payload.get("authority_sha256")),
        "lifecycle_epoch": _optional_integer(execution.get("lifecycle_epoch", payload.get("lifecycle_epoch"))),
        "policy_revocation_epoch": _optional_integer(
            execution.get("policy_revocation_epoch", payload.get("policy_revocation_epoch"))
        ),
        "roe_revocation_epoch": _optional_integer(
            execution.get("roe_revocation_epoch", payload.get("roe_revocation_epoch"))
        ),
        "kill_switch_epoch": _optional_integer(execution.get("kill_switch_epoch", payload.get("kill_switch_epoch"))),
        "expires_at": _datetime_text(payload.get("expires_at")),
    }


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
        "result": _required("operations_validation_result", certificate.get("result"), 32),
        "reason": _optional_text(certificate.get("bounded_reason"), 150),
        "counterexample_codes": codes,
    }


def _admission(row: Mapping[str, Any] | None) -> dict[str, Any]:
    if row is None:
        return {"outcome": "unavailable", "reason": None, "receipt_sha256": None}
    return {
        "outcome": _required("operations_admission_outcome", row.get("outcome"), 32),
        "reason": _optional_text(row.get("reason_code"), 100),
        "receipt_sha256": _digest_or_none(row.get("receipt_sha256")),
    }


def _budget(source: CampaignOperationsSource) -> dict[str, Any]:
    dimensions: dict[str, dict[str, Any]] = {}
    for name, unit in _BUDGET_UNITS.items():
        authorized = _optional_integer(source.ledger.get(name)) if source.ledger else None
        committed = 0
        for reservation in source.reservations:
            if reservation.get("reservation_state") in _ACTIVE_RESERVATIONS:
                committed += _integer(reservation.get(name), f"operations_budget_{name}_invalid")
        dimensions[name] = {
            "authorized": authorized,
            "committed": committed if authorized is not None else None,
            "residual": max(0, authorized - committed) if authorized is not None else None,
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
        state = _required("operations_node_state", node.get("node_state"), 32)
        frontier[state] = frontier.get(state, 0) + 1
    return {
        "state": _required("operations_execution_state", row.get("run_state"), 32),
        "transition_count": _integer(row.get("transition_count"), "operations_transition_count_invalid"),
        "max_transitions": _integer(row.get("max_transitions"), "operations_max_transitions_invalid"),
        "stop_requested": bool(row.get("stop_requested")),
        "terminal_reason": _optional_text(row.get("terminal_reason"), 100),
        "frontier": dict(sorted(frontier.items())),
    }


def _observations(rows: tuple[Mapping[str, Any], ...], *, now: datetime) -> list[dict[str, Any]]:
    result: list[dict[str, Any]] = []
    for row in rows:
        expires = _as_datetime(row.get("expires_at"), "operations_observation_expiry_invalid")
        result.append(
            {
                "fact": _human_label(row.get("fact_id")),
                "producer_kind": _required("operations_observation_producer", row.get("producer_kind"), 32),
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
    for row in rows:
        details = _mapping(row.get("details"), "operations_audit_details_invalid")
        _json_bound(details, "operations_audit_details_unbounded")
        result.append(
            {
                "action": _required("operations_audit_action", row.get("action"), 100),
                "occurred_at": _datetime_text(row.get("created_at")),
                "correlation_id": _required("operations_audit_correlation", row.get("correlation_id"), 100),
                "details_sha256": hashlib.sha256(
                    json.dumps(details, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
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
) -> str:
    if admission is None and execution is None:
        return "not_prepared"
    if admission is not None and admission.get("outcome") == "denied":
        return "denied"
    if execution is None:
        return "admitted"
    return "executing" if execution.get("run_state") in _ACTIVE_RUNS else "terminal"


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


def _json_bound(value: Mapping[str, Any], code: str) -> None:
    try:
        encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    except (TypeError, ValueError) as exc:
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


def _human_label(value: Any) -> str:
    return _required("operations_label", value, 150).replace("_", " ").replace("-", " ").capitalize()


def _capability_label(value: Any) -> str:
    source = _required("operations_capability", value, 150)
    if source == "http-posture":
        return "HTTP posture"
    return source.replace("_", " ").replace("-", " ").capitalize()
