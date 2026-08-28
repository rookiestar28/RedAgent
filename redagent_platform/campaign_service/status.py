"""Tenant-scoped canonical compat_123 campaign status projection."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
from typing import Protocol

from sqlalchemy import func, select

from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.repository import campaign_core_principal_is_active
from redagent_platform.persistence.models import metadata


_CAMPAIGN_STATES = frozenset({
    "dispatch_pending",
    "workflow_started",
    "contained",
    "completed",
})
_EFFECT_STATES = frozenset({
    "reserved",
    "claimed",
    "dispatching",
    "reconciliation_required",
    "not_applied",
    "confirmed",
    "compensated",
    "manual_review_required",
    "failed",
})
_RECONCILIATION_STATES = frozenset({
    "none",
    "reconciliation_required",
    "confirmed",
    "not_applied",
    "compensated",
    "manual_review_required",
})
_DELIVERY_STATES = frozenset({
    "pending",
    "claimed",
    "delivered",
    "reconciliation_required",
    "dead_letter",
})


class CampaignStatusNotFound(RuntimeError):
    pass


class CampaignCorePrincipalInactive(PermissionError):
    pass


class CampaignStatusOwner(Protocol):
    async def read(
        self, *, tenant_id: str, campaign_id: str
    ) -> "CampaignStatusV1": ...


@dataclass(frozen=True, slots=True)
class CampaignEffectStatusV1:
    capability_id: str
    state: str
    reconciliation_state: str
    evidence_count: int
    cleanup_complete: bool

    def __post_init__(self) -> None:
        if self.capability_id not in closed_execution_registry():
            raise ValueError("r123_status_capability_invalid")
        if self.state not in _EFFECT_STATES:
            raise ValueError("r123_status_effect_state_invalid")
        if self.reconciliation_state not in _RECONCILIATION_STATES:
            raise ValueError("r123_status_reconciliation_state_invalid")
        if isinstance(self.evidence_count, bool) or not 0 <= self.evidence_count <= 100:
            raise ValueError("r123_status_evidence_count_invalid")
        if not isinstance(self.cleanup_complete, bool):
            raise ValueError("r123_status_cleanup_state_invalid")


@dataclass(frozen=True, slots=True)
class CampaignStatusV1:
    schema_version: str
    campaign_id: str
    status: str
    aggregate_sequence: int
    replan_count: int
    attention_reason: str | None
    workflow_delivery_state: str
    workflow_reconciliation_state: str
    effects: tuple[CampaignEffectStatusV1, ...]
    terminal_receipt_present: bool

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r123-campaign-status/v1":
            raise ValueError("r123_status_schema_invalid")
        _identifier("r123_status_campaign", self.campaign_id, 64)
        if self.status not in _CAMPAIGN_STATES:
            raise ValueError("r123_status_campaign_state_invalid")
        if (
            isinstance(self.aggregate_sequence, bool)
            or self.aggregate_sequence < 1
            or isinstance(self.replan_count, bool)
            or not 0 <= self.replan_count <= 1
        ):
            raise ValueError("r123_status_revision_invalid")
        if self.attention_reason is not None:
            _identifier("r123_status_attention", self.attention_reason, 100)
        if self.workflow_delivery_state not in _DELIVERY_STATES:
            raise ValueError("r123_status_workflow_delivery_invalid")
        if self.workflow_reconciliation_state not in _RECONCILIATION_STATES:
            raise ValueError("r123_status_workflow_reconciliation_invalid")
        if not isinstance(self.effects, tuple) or len(self.effects) > 2:
            raise ValueError("r123_status_effect_inventory_invalid")
        if not isinstance(self.terminal_receipt_present, bool):
            raise ValueError("r123_status_terminal_receipt_invalid")


class PostgresCampaignStatusOwner:
    """Read a bounded projection from the existing canonical campaign/outbox/effect owners."""

    def __init__(self, sessions: object) -> None:
        self._sessions = sessions

    async def read(self, *, tenant_id: str, campaign_id: str) -> CampaignStatusV1:
        _identifier("r123_status_tenant", tenant_id, 64)
        _identifier("r123_status_campaign", campaign_id, 64)
        campaigns = metadata.tables["campaigns"]
        outbox = metadata.tables["outbox_events"]
        effects = metadata.tables["campaign_effects"]
        imports = metadata.tables["finding_import_sessions"]
        import_records = metadata.tables["finding_import_records"]
        occurrences = metadata.tables["finding_occurrences"]
        issues = metadata.tables["managed_issues"]
        retests = metadata.tables["finding_retests"]
        async with self._sessions() as session, session.begin():
            await session.execute(
                select(func.set_config("redagent.tenant_id", tenant_id, True))
            )
            campaign = (
                await session.execute(
                    select(
                        campaigns.c.id,
                        campaigns.c.status,
                        campaigns.c.aggregate_sequence,
                        campaigns.c.replan_count,
                        campaigns.c.attention_reason,
                        campaigns.c.terminal_receipt_sha256,
                    ).where(
                        campaigns.c.tenant_id == tenant_id,
                        campaigns.c.id == campaign_id,
                    )
                )
            ).mappings().one_or_none()
            if campaign is None:
                raise CampaignStatusNotFound("r123_campaign_status_not_found")
            workflow = (
                await session.execute(
                    select(
                        outbox.c.delivery_state,
                        outbox.c.reconciliation_state,
                    )
                    .where(
                        outbox.c.tenant_id == tenant_id,
                        outbox.c.aggregate_type == "campaign",
                        outbox.c.aggregate_id == campaign_id,
                        outbox.c.event_type == "workflow.start.requested.v1",
                        outbox.c.schema_revision == 2,
                    )
                    .order_by(outbox.c.aggregate_sequence.desc())
                    .limit(1)
                )
            ).mappings().one_or_none()
            if workflow is None:
                raise ValueError("r123_status_workflow_intent_missing")
            rows = (
                await session.execute(
                    select(
                        effects.c.effect_intent_payload,
                        effects.c.effect_state,
                        effects.c.reconciliation_state,
                        effects.c.evidence_ids,
                        effects.c.cleanup_receipt_id,
                    )
                    .where(
                        effects.c.tenant_id == tenant_id,
                        effects.c.campaign_id == campaign_id,
                    )
                    .order_by(effects.c.node_id)
                    .limit(3)
                )
            ).mappings().all()
        if len(rows) > 2:
            raise ValueError("r123_status_effect_inventory_invalid")
        projected_effects = tuple(_effect_status(row) for row in rows)
        return CampaignStatusV1(
            schema_version="redagent.r123-campaign-status/v1",
            campaign_id=str(campaign["id"]),
            status=str(campaign["status"]),
            aggregate_sequence=int(campaign["aggregate_sequence"]),
            replan_count=int(campaign["replan_count"]),
            attention_reason=(
                str(campaign["attention_reason"])
                if campaign["attention_reason"] is not None
                else None
            ),
            workflow_delivery_state=str(workflow["delivery_state"]),
            workflow_reconciliation_state=str(workflow["reconciliation_state"]),
            effects=projected_effects,
            terminal_receipt_present=campaign["terminal_receipt_sha256"] is not None,
        )


class PostgresCampaignCorePresentationOwner:
    """Compose operator and inspector views from existing campaign/finding owners."""

    def __init__(self, sessions: object) -> None:
        self._sessions = sessions

    async def list_campaigns(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        limit: int,
        cursor: str | None,
        now: datetime,
    ) -> dict[str, object]:
        offset = _campaign_core_offset(limit, cursor)
        campaigns = metadata.tables["campaigns"]
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, tenant_id)
            await _require_campaign_core_principal(
                session, tenant_id=tenant_id, principal_id=principal_id, now=now
            )
            rows = (
                await session.execute(
                    select(
                        campaigns.c.id,
                        campaigns.c.name,
                        campaigns.c.status,
                        campaigns.c.attention_reason,
                        campaigns.c.aggregate_sequence,
                    )
                    .where(campaigns.c.tenant_id == tenant_id)
                    .order_by(campaigns.c.updated_at.desc(), campaigns.c.id)
                    .offset(offset)
                    .limit(limit + 1)
                )
            ).mappings().all()
        selected = rows[:limit]
        return {
            "data": [
                {
                    "campaign_id": str(row["id"]),
                    "label": str(row["name"]),
                    "status": str(row["status"]),
                    "authority_state": (
                        "requires_attention"
                        if row["attention_reason"] is not None
                        else "current_at_last_resolution"
                    ),
                    "attention_reason": (
                        str(row["attention_reason"])
                        if row["attention_reason"] is not None else None
                    ),
                    "aggregate_sequence": int(row["aggregate_sequence"]),
                }
                for row in selected
            ],
            "page": {
                "limit": limit,
                "next_cursor": (
                    f"r124-cursor-{offset + limit}" if len(rows) > limit else None
                ),
            },
        }

    async def read_campaign(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        campaign_id: str,
        now: datetime,
    ) -> dict[str, object]:
        projection = await self._read_rows(
            tenant_id=tenant_id,
            principal_id=principal_id,
            campaign_id=campaign_id,
            now=now,
        )
        campaign = projection["campaign"]
        strategy = projection["strategy"]
        effects = projection["effects"]
        findings = projection["findings"]
        plan = strategy["plan_payload"]
        decision = strategy["decision_payload"]
        return {"data": {
            "campaign_id": str(campaign["id"]),
            "label": str(campaign["name"]),
            "status": str(campaign["status"]),
            "aggregate_sequence": int(campaign["aggregate_sequence"]),
            "etag": f'"{campaign_id}:{campaign["aggregate_sequence"]}"',
            "authority": {
                "state": (
                    "requires_attention"
                    if campaign["attention_reason"] is not None
                    else "current_at_last_resolution"
                ),
                "attention_reason": campaign["attention_reason"],
            },
            "context": {
                "schema": strategy["context_schema"],
                "coverage": "Canonical authority and two-capability snapshot",
                "freshness": "Resolved at campaign start; mutations recheck authority",
            },
            "decision": {
                "outcome": str(decision.get("outcome", "not_planned")),
                "reason": str(decision.get("reason", "no_decision_reason")),
                "candidates": _public_candidates(decision.get("candidates")),
            },
            "plan": _public_plan(plan),
            "effects": [_public_effect(row) for row in effects],
            "findings": findings,
            "recovery": _recovery_guidance(campaign, effects),
        }}

    async def inspect_campaign(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        campaign_id: str,
        now: datetime,
    ) -> dict[str, object]:
        projection = await self._read_rows(
            tenant_id=tenant_id,
            principal_id=principal_id,
            campaign_id=campaign_id,
            now=now,
        )
        campaign = projection["campaign"]
        strategy = projection["strategy"]
        return {"data": {
            "campaign_id": str(campaign["id"]),
            "engagement_id": str(campaign["engagement_id"]),
            "roe_version_id": str(campaign["roe_version_id"]),
            "workflow_id": str(campaign["workflow_id"]),
            "strategy_revision_id": str(strategy["strategy_revision_id"]),
            "context_sha256": str(strategy["context_sha256"]),
            "decision_sha256": str(strategy["decision_sha256"]),
            "plan_sha256": str(strategy["plan_sha256"]),
            "approval_receipt_id": str(strategy["approval_receipt_id"]),
            "approval_receipt_sha256": str(strategy["approval_receipt_sha256"]),
            "envelope_sha256": str(strategy["envelope_sha256"]),
            "terminal_receipt_sha256": campaign["terminal_receipt_sha256"],
        }}

    async def list_attention(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        limit: int,
        cursor: str | None,
        now: datetime,
    ) -> dict[str, object]:
        offset = _campaign_core_offset(limit, cursor)
        campaigns = metadata.tables["campaigns"]
        outbox = metadata.tables["outbox_events"]
        effects = metadata.tables["campaign_effects"]
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, tenant_id)
            await _require_campaign_core_principal(
                session, tenant_id=tenant_id, principal_id=principal_id, now=now
            )
            rows = (
                await session.execute(
                    select(
                        campaigns.c.id,
                        campaigns.c.name,
                        campaigns.c.attention_reason,
                        campaigns.c.updated_at,
                        outbox.c.delivery_state,
                        outbox.c.reconciliation_state.label("outbox_reconciliation"),
                        effects.c.effect_state,
                        effects.c.reconciliation_state.label("effect_reconciliation"),
                        effects.c.cleanup_receipt_id,
                        effects.c.failure_code,
                        effects.c.external_receipt_id,
                    )
                    .select_from(
                        campaigns.outerjoin(
                            outbox,
                            (outbox.c.tenant_id == campaigns.c.tenant_id)
                            & (outbox.c.aggregate_id == campaigns.c.id)
                            & (outbox.c.event_type == "workflow.start.requested.v1"),
                        ).outerjoin(
                            effects,
                            (effects.c.tenant_id == campaigns.c.tenant_id)
                            & (effects.c.campaign_id == campaigns.c.id),
                        )
                    )
                    .where(campaigns.c.tenant_id == tenant_id)
                    .order_by(campaigns.c.updated_at.desc(), campaigns.c.id)
                    .limit(501)
                )
            ).mappings().all()
            if len(rows) > 500:
                raise ValueError("r124_attention_inventory_unbounded")
            receipt_to_campaign = {
                str(row["external_receipt_id"]): (str(row["id"]), str(row["name"]))
                for row in rows if row["external_receipt_id"] is not None
            }
            finding_rows = []
            if receipt_to_campaign:
                finding_rows = (
                    await session.execute(
                        select(
                            imports.c.run_id,
                            issues.c.issue_state,
                            issues.c.disposition,
                            retests.c.coverage_state,
                            retests.c.result_state,
                        )
                        .select_from(
                            imports.join(
                                import_records,
                                import_records.c.import_record_ref == imports.c.id,
                            ).join(
                                occurrences,
                                occurrences.c.import_record_ref == import_records.c.id,
                            ).join(
                                issues,
                                issues.c.id == occurrences.c.issue_record_id,
                            ).outerjoin(
                                retests,
                                retests.c.issue_record_id == issues.c.id,
                            )
                        )
                        .where(
                            imports.c.tenant_id == tenant_id,
                            imports.c.run_id.in_(tuple(receipt_to_campaign)),
                        )
                        .order_by(imports.c.run_id, issues.c.id, retests.c.id)
                        .limit(501)
                    )
                ).mappings().all()
                if len(finding_rows) > 500:
                    raise ValueError("r124_attention_finding_inventory_unbounded")
        projected: list[dict[str, object]] = []
        seen: set[str] = set()
        for row in rows:
            category, reason, guidance = _attention_reason(row)
            campaign_key = str(row["id"])
            attention_key = f"{campaign_key}:{category}"
            if category is None or attention_key in seen:
                continue
            seen.add(attention_key)
            projected.append({
                "binding": "r124-attention-" + hashlib.sha256(
                    f"{tenant_id}\x1f{campaign_key}\x1f{category}".encode()
                ).hexdigest()[:32],
                "campaign_label": str(row["name"]),
                "category": category,
                "reason": reason,
                "next_safe_action": guidance,
                "occurred_at": row["updated_at"] or now,
            })
        for row in finding_rows:
            campaign = receipt_to_campaign.get(str(row["run_id"]))
            if campaign is None:
                continue
            campaign_key, campaign_label = campaign
            category, reason, guidance = _finding_attention_reason(row)
            attention_key = f"{campaign_key}:{category}"
            if category is None or attention_key in seen:
                continue
            seen.add(attention_key)
            projected.append({
                "binding": "r124-attention-" + hashlib.sha256(
                    f"{tenant_id}\x1f{campaign_key}\x1f{category}".encode()
                ).hexdigest()[:32],
                "campaign_label": campaign_label,
                "category": category,
                "reason": reason,
                "next_safe_action": guidance,
                "occurred_at": now,
            })
        projected.sort(key=_campaign_core_attention_sort_key)
        selected = projected[offset:offset + limit]
        return {
            "data": selected,
            "page": {
                "limit": limit,
                "next_cursor": (
                    f"r124-cursor-{offset + limit}"
                    if offset + limit < len(projected) else None
                ),
            },
        }

    async def _read_rows(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        campaign_id: str,
        now: datetime,
    ) -> dict[str, object]:
        _identifier("r124_presentation_tenant", tenant_id, 64)
        _identifier("r124_presentation_campaign", campaign_id, 64)
        campaigns = metadata.tables["campaigns"]
        strategies = metadata.tables["campaign_strategy_revisions"]
        effects = metadata.tables["campaign_effects"]
        imports = metadata.tables["finding_import_sessions"]
        import_records = metadata.tables["finding_import_records"]
        occurrences = metadata.tables["finding_occurrences"]
        issues = metadata.tables["managed_issues"]
        retests = metadata.tables["finding_retests"]
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, tenant_id)
            await _require_campaign_core_principal(
                session, tenant_id=tenant_id, principal_id=principal_id, now=now
            )
            campaign = (
                await session.execute(
                    select(campaigns).where(
                        campaigns.c.tenant_id == tenant_id,
                        campaigns.c.id == campaign_id,
                    )
                )
            ).mappings().one_or_none()
            if campaign is None:
                raise CampaignStatusNotFound("r124_campaign_not_found")
            strategy = (
                await session.execute(
                    select(strategies).where(
                        strategies.c.tenant_id == tenant_id,
                        strategies.c.id == campaign["current_strategy_revision_id"],
                    )
                )
            ).mappings().one_or_none()
            if strategy is None:
                raise ValueError("r124_strategy_projection_missing")
            effect_rows = (
                await session.execute(
                    select(effects).where(
                        effects.c.tenant_id == tenant_id,
                        effects.c.campaign_id == campaign_id,
                    ).order_by(effects.c.node_id).limit(3)
                )
            ).mappings().all()
            if len(effect_rows) > 2:
                raise ValueError("r124_effect_projection_unbounded")
            receipt_ids = [
                str(row["external_receipt_id"])
                for row in effect_rows if row["external_receipt_id"] is not None
            ]
            finding_rows = []
            if receipt_ids:
                finding_rows = (
                    await session.execute(
                        select(
                            issues.c.title,
                            issues.c.severity,
                            issues.c.disposition,
                            issues.c.owner_id,
                            issues.c.issue_state,
                            retests.c.coverage_state,
                            retests.c.result_state,
                        )
                        .select_from(
                            imports.join(
                                import_records,
                                import_records.c.import_record_ref == imports.c.id,
                            ).join(
                                occurrences,
                                occurrences.c.import_record_ref == import_records.c.id,
                            ).join(
                                issues,
                                issues.c.id == occurrences.c.issue_record_id,
                            ).outerjoin(
                                retests,
                                retests.c.issue_record_id == issues.c.id,
                            )
                        )
                        .where(
                            imports.c.tenant_id == tenant_id,
                            imports.c.run_id.in_(receipt_ids),
                        )
                        .order_by(issues.c.severity, issues.c.title)
                        .limit(101)
                    )
                ).mappings().all()
            if len(finding_rows) > 100:
                raise ValueError("r124_finding_projection_unbounded")
        return {
            "campaign": campaign,
            "strategy": strategy,
            "effects": effect_rows,
            "findings": [_public_finding(row) for row in finding_rows],
        }


def _effect_status(row: object) -> CampaignEffectStatusV1:
    payload = row["effect_intent_payload"]
    if not isinstance(payload, dict):
        raise ValueError("r123_status_effect_intent_invalid")
    evidence = row["evidence_ids"]
    if not isinstance(evidence, list) or len(evidence) > 100:
        raise ValueError("r123_status_evidence_inventory_invalid")
    return CampaignEffectStatusV1(
        capability_id=str(payload.get("capability_id", "")),
        state=str(row["effect_state"]),
        reconciliation_state=str(row["reconciliation_state"]),
        evidence_count=len(evidence),
        cleanup_complete=row["cleanup_receipt_id"] is not None,
    )


def _campaign_core_offset(limit: int, cursor: str | None) -> int:
    if isinstance(limit, bool) or not 1 <= limit <= 50:
        raise ValueError("r124_page_limit_invalid")
    if cursor is None:
        return 0
    prefix = "r124-cursor-"
    if not cursor.startswith(prefix) or not cursor[len(prefix):].isdigit():
        raise ValueError("r124_cursor_invalid")
    offset = int(cursor[len(prefix):])
    if offset > 100_000:
        raise ValueError("r124_cursor_invalid")
    return offset


async def _tenant_context(session: object, tenant_id: str) -> None:
    _identifier("r124_tenant", tenant_id, 64)
    await session.execute(
        select(func.set_config("redagent.tenant_id", tenant_id, True))
    )


def _public_effect(row: object) -> dict[str, object]:
    payload = row["effect_intent_payload"]
    if not isinstance(payload, dict):
        raise ValueError("r124_effect_intent_invalid")
    evidence = row["evidence_ids"]
    if not isinstance(evidence, list) or len(evidence) > 100:
        raise ValueError("r124_effect_evidence_invalid")
    return {
        "capability": _human_capability(payload.get("capability_id")),
        "state": str(row["effect_state"]),
        "reconciliation": str(row["reconciliation_state"]),
        "evidence_count": len(evidence),
        "cleanup_complete": row["cleanup_receipt_id"] is not None,
        "failure": row["failure_code"],
    }


def _public_candidates(value: object) -> list[dict[str, object]]:
    if not isinstance(value, list) or len(value) > 3:
        raise ValueError("r124_candidate_projection_invalid")
    projected: list[dict[str, object]] = []
    for candidate in value:
        if not isinstance(candidate, dict):
            raise ValueError("r124_candidate_projection_invalid")
        projected.append({
            "label": _human_capability(candidate.get("capability_id")),
            "eligible": candidate.get("eligible") is True,
            "reason": str(candidate.get("reason", "not_selected")),
        })
    return projected


def _public_plan(plan: object) -> dict[str, object]:
    if not isinstance(plan, dict):
        raise ValueError("r124_plan_projection_invalid")
    primary = plan.get("primary")
    if not isinstance(primary, dict):
        raise ValueError("r124_plan_projection_invalid")
    successor = plan.get("successor")
    successor_action = successor.get("action") if isinstance(successor, dict) else None
    if successor_action is not None and not isinstance(successor_action, dict):
        raise ValueError("r124_plan_projection_invalid")
    budget = primary.get("budget")
    if not isinstance(budget, dict):
        budget = {}
    evidence = primary.get("evidence_schemas")
    evidence_count = len(evidence) if isinstance(evidence, list) else 0
    return {
        "primary": _human_capability(primary.get("capability_id")),
        "successor": (
            _human_capability(successor_action.get("capability_id"))
            if isinstance(successor_action, dict) else None
        ),
        "successor_condition": (
            str(successor.get("condition")) if isinstance(successor, dict) else None
        ),
        "depth": int(plan.get("depth", 1)),
        "risk": (
            "Tier 1, data-only zero execution"
            if primary.get("capability_id") == "artifact-posture"
            else "Tier 1 passive, owned-loopback only"
        ),
        "cost": (
            f"At most {int(budget.get('max_operations', 2))} operations in "
            f"{int(budget.get('max_elapsed_seconds', 300))} seconds"
        ),
        "evidence": f"{evidence_count} reviewed evidence schema(s) expected",
        "cleanup": str(primary.get("cleanup", "Canonical cleanup receipt required")),
        "approval": str(primary.get("approval_class", "standing Tier 1 authority")),
    }


def _human_capability(value: object) -> str:
    return {
        "artifact-posture": "Repository snapshot posture assessment",
        "zap-controlled-runtime": "Primary web posture assessment",
        "nuclei-trusted-runtime": "Independent corroboration assessment",
    }.get(str(value), "Unavailable reviewed capability")


async def _require_campaign_core_principal(
    session: object,
    *,
    tenant_id: str,
    principal_id: str,
    now: datetime,
) -> None:
    if not await campaign_core_principal_is_active(
        session,
        tenant_id=tenant_id,
        principal_id=principal_id,
        now=now,
    ):
        raise CampaignCorePrincipalInactive("r124_principal_inactive")


def _campaign_core_attention_sort_key(item: dict[str, object]) -> tuple[float, str]:
    occurred_at = item["occurred_at"]
    if not isinstance(occurred_at, datetime):
        raise ValueError("r124_attention_occurred_at_invalid")
    return (-occurred_at.timestamp(), str(item["binding"]))


def _recovery_guidance(campaign: object, effects: list[object]) -> dict[str, object]:
    active = str(campaign["status"]) in {"dispatch_pending", "workflow_started"}
    incomplete_cleanup = any(
        row["effect_state"] in {"confirmed", "compensated"}
        and row["cleanup_receipt_id"] is None
        for row in effects
    )
    return {
        "stop_visible": active or incomplete_cleanup,
        "revoke_visible": active or incomplete_cleanup,
        "cleanup_required": incomplete_cleanup,
        "guidance": (
            "Request containment and wait for dual-control cleanup evidence."
            if active or incomplete_cleanup
            else "Review evidence, findings, residual risk, and retest state."
        ),
    }


def _public_finding(row: object) -> dict[str, object]:
    state = str(row["issue_state"])
    return {
        "title": str(row["title"]),
        "severity": str(row["severity"]),
        "disposition": str(row["disposition"]),
        # CRITICAL: public operator projection communicates assignment state, never identity IDs.
        "owner": "Assigned" if row["owner_id"] is not None else "Unassigned",
        "state": state,
        "residual_risk": (
            "Requires operator review"
            if state not in {"closed", "resolved"}
            else "Accepted or remediated"
        ),
        "retest": {
            "coverage": row["coverage_state"],
            "result": row["result_state"],
        },
    }


def _attention_reason(row: object) -> tuple[str | None, str, str]:
    if row["attention_reason"] is not None:
        reason = str(row["attention_reason"])
        return (
            _authority_attention_category(reason),
            reason,
            "Refresh current authority and follow the displayed governed recovery path.",
        )
    if row["delivery_state"] in {"reconciliation_required", "dead_letter"} or row[
        "outbox_reconciliation"
    ] not in {None, "none", "confirmed"}:
        return (
            "reconciliation",
            "workflow_delivery_requires_reconciliation",
            "Inspect the bounded receipt and do not redispatch an ambiguous effect.",
        )
    if row["effect_reconciliation"] not in {None, "none", "confirmed"}:
        return (
            "reconciliation",
            "effect_requires_reconciliation",
            "Use status lookup or manual review; automatic redispatch remains blocked.",
        )
    if row["failure_code"] is not None and "evidence" in str(row["failure_code"]):
        return (
            "evidence",
            str(row["failure_code"]),
            "Keep completion blocked and restore the canonical evidence boundary before retrying.",
        )
    if row["effect_state"] in {"confirmed", "compensated"} and row[
        "cleanup_receipt_id"
    ] is None:
        return (
            "cleanup_evidence",
            "cleanup_receipt_missing",
            "Keep successor work blocked until canonical cleanup evidence is accepted.",
        )
    return None, "", ""


def _authority_attention_category(reason: str) -> str:
    normalized = reason.lower()
    if "approval" in normalized:
        return "approval"
    if "denied" in normalized or "policy" in normalized:
        return "denial"
    if any(token in normalized for token in ("stale", "expired", "revoked", "authority")):
        return "stale_authority"
    if "evidence" in normalized:
        return "evidence"
    if "cleanup" in normalized:
        return "cleanup"
    return "authority"


def _finding_attention_reason(row: object) -> tuple[str | None, str, str]:
    if row["issue_state"] != "closed":
        return (
            "finding",
            "finding_requires_review",
            "Review disposition, ownership, residual risk, and the governed remediation path.",
        )
    if row["coverage_state"] != "complete" or row["result_state"] != "passed":
        return (
            "retest",
            "retest_incomplete_or_failed",
            "Keep closure blocked until a complete passing retest is recorded.",
        )
    return None, "", ""


def _identifier(name: str, value: object, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError(f"{name}_invalid")
