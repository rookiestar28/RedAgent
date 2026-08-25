"""PostgreSQL-authoritative compat_114 broker and structured-workbench state."""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.mcp_broker.contracts import InventoryItem, ServerRegistration
from redagent_platform.mcp_broker.inventory import ServerFreeze, inventory_sha256
from redagent_platform.persistence.models import metadata
from redagent_platform.workbench.contracts import WorkbenchItem, WorkbenchProposal, proposal_sha256


class McpWorkbenchRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _id(tenant_id)
        self.actor_user_id = _id(actor_user_id)
        self.correlation_id = _id(correlation_id)

    async def register_server(self, registration: ServerRegistration, *, transport_attestation_sha256: str,
                              occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"registration:{registration.registration_id}")
        if registration.tenant_id != self.tenant_id:
            raise ValueError("mcp_registration_tenant_mismatch")
        values = {"registration_id": registration.registration_id, "server_id": registration.server_id,
                  "protocol_version": registration.protocol_version, "transport_kind": registration.transport.value,
                  "transport_identity_sha256": registration.transport_identity_sha256,
                  "inventory_sha256": registration.inventory_sha256,
                  "risk_class": registration.risk_class, "data_class": registration.data_class,
                  "allowed_inventory_sha256": _digest(registration.allowed_item_names),
                  "registered_by": registration.registered_by, "reviewed_by": registration.reviewed_by,
                  "signature_sha256": registration.signature_sha256, "registration_state": "attested-fixture-only",
                  "issued_at": registration.issued_at, "expires_at": registration.expires_at}
        row = await self._immutable("mcp_server_registrations", {"registration_id": registration.registration_id},
                                    values, occurred_at, "registration")
        attestation = self._owned("transport", occurred_at) | {
            "registration_record_id": row["id"], "attestation_id": f"attestation-{registration.registration_id}",
            "transport_kind": registration.transport.value, "identity_sha256": registration.transport_identity_sha256,
            "authorization_profile_sha256": _sha(transport_attestation_sha256),
            "boundary_controls_sha256": _sha(transport_attestation_sha256), "transport_enabled": False,
            "attestation_state": "qualified-no-io", "attested_at": occurred_at}
        existing_attestation = await self._find("mcp_transport_attestations", {
            "attestation_id": attestation["attestation_id"],
        })
        if existing_attestation is None:
            await self.session.execute(insert(metadata.tables["mcp_transport_attestations"]).values(**attestation))
        await self._audit("mcp.server.registered", registration.registration_id,
                          {"inventory_sha256": registration.inventory_sha256, "transport_enabled": False}, occurred_at)
        return row

    async def store_inventory(self, *, registration_id: str, inventory_id: str, items: tuple[InventoryItem, ...],
                              occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"inventory:{inventory_id}")
        registration = await self._find("mcp_server_registrations", {"registration_id": registration_id})
        digest = inventory_sha256(items)
        if registration is None or registration["inventory_sha256"] != digest:
            raise ValueError("mcp_exact_registration_inventory_required")
        existing = await self._find("mcp_inventory_revisions", {"inventory_id": inventory_id, "inventory_revision": 1})
        if existing is not None:
            if existing["inventory_sha256"] != digest:
                raise ValueError("mcp_inventory_immutable")
            return existing
        row = self._owned("inventory", occurred_at) | {"registration_record_id": registration["id"],
            "inventory_id": _id(inventory_id), "inventory_revision": 1, "inventory_sha256": digest,
            "protocol_version": "2025-11-25", "inventory_state": "pinned", "observed_at": occurred_at}
        await self.session.execute(insert(metadata.tables["mcp_inventory_revisions"]).values(**row))
        for item in items:
            item_row = self._owned("item", occurred_at) | {"inventory_record_id": row["id"],
                "item_id": f"item-{hashlib.sha256(item.name.encode()).hexdigest()[:24]}", "item_name": item.name,
                "item_kind": item.item_kind.value, "description_sha256": item.description_sha256,
                "request_schema_sha256": item.input_schema_sha256, "result_schema_sha256": item.output_schema_sha256,
                "risk_class": item.risk_class, "data_class": item.data_class, "tool_mode": item.tool_mode,
                "item_state": "pinned"}
            await self.session.execute(insert(metadata.tables["mcp_inventory_items"]).values(**item_row))
        await self._audit("mcp.inventory.pinned", inventory_id, {"inventory_sha256": digest, "item_count": len(items)}, occurred_at)
        return row

    async def store_draft(self, proposal: WorkbenchProposal, *, created_by: str,
                          trust_items: tuple[WorkbenchItem, ...], occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"draft:{proposal.proposal_id}")
        if created_by == "" or not trust_items:
            raise ValueError("workbench_draft_context_required")
        existing = await self._find("workbench_campaign_drafts", {"draft_id": proposal.proposal_id})
        if existing is not None:
            if existing["proposal_sha256"] != proposal_sha256(proposal):
                raise ValueError("mcp_draft_immutable")
            return existing
        values = {"draft_id": proposal.proposal_id, "campaign_id": proposal.campaign_id,
                  "draft_revision": proposal.revision, "predecessor_draft_id": proposal.predecessor_proposal_id,
                  "proposal_sha256": proposal_sha256(proposal),
                  "authority_sha256": _digest((proposal.roe_version_id, proposal.policy_revision,
                                                proposal.policy_decision_id, proposal.target_ids)),
                  "draft_state": "awaiting_review", "created_by": _id(created_by), "expires_at": proposal.expires_at}
        row = await self._immutable("workbench_campaign_drafts", {"draft_id": proposal.proposal_id},
                                    values, occurred_at, "draft")
        for item in trust_items:
            item_row = self._owned("trust", occurred_at) | {"draft_record_id": row["id"], "item_id": item.item_id,
                "trust_lane": item.lane.value, "summary_sha256": _digest(item.summary),
                "provenance_sha256": item.provenance_sha256, "item_state": "visible-minimized"}
            await self.session.execute(insert(metadata.tables["workbench_trust_items"]).values(**item_row))
        disclosure = self._owned("disclosure", occurred_at) | {"draft_record_id": row["id"],
            "disclosure_id": f"disclosure-{hashlib.sha256(proposal.proposal_id.encode()).hexdigest()[:24]}",
            "sanitized_fields_sha256": _digest(proposal.sanitized_arguments),
            "target_scope_sha256": _digest(proposal.target_ids), "access_class": proposal.credential_class,
            "egress_class": proposal.egress_class, "side_effects_sha256": _digest(proposal.side_effects),
            "budget_sha256": proposal.budget_sha256, "disclosure_state": "review-required"}
        await self.session.execute(insert(metadata.tables["workbench_disclosures"]).values(**disclosure))
        await self._audit("workbench.draft.created", proposal.proposal_id,
                          {"proposal_sha256": values["proposal_sha256"], "trust_item_count": len(trust_items)}, occurred_at)
        return row

    async def create_successor_from_stored(
        self, *, predecessor_draft_id: str, successor_draft_id: str, plan_id: str,
        created_by: str, occurred_at: datetime,
    ) -> tuple[dict[str, object], dict[str, object]]:
        await self._context(); await self._lock(f"draft-successor:{predecessor_draft_id}")
        predecessor = await self._find("workbench_campaign_drafts", {"draft_id": predecessor_draft_id})
        if predecessor is None or predecessor["draft_state"] not in {"awaiting_review", "approved"}:
            raise ValueError("workbench_predecessor_not_editable")
        existing = await self._find("workbench_campaign_drafts", {"draft_id": successor_draft_id})
        successor_sha = _digest({"predecessor_proposal_sha256": predecessor["proposal_sha256"],
                                 "stored_plan_id": _id(plan_id), "successor_revision": int(predecessor["draft_revision"]) + 1})
        if existing is not None:
            if existing["proposal_sha256"] != successor_sha:
                raise ValueError("mcp_draft_immutable")
            return predecessor, existing
        successor = self._owned("draft", occurred_at) | {
            "draft_id": _id(successor_draft_id), "campaign_id": predecessor["campaign_id"],
            "draft_revision": int(predecessor["draft_revision"]) + 1,
            "predecessor_draft_id": predecessor_draft_id, "proposal_sha256": successor_sha,
            "authority_sha256": predecessor["authority_sha256"], "draft_state": "awaiting_review",
            "created_by": _id(created_by), "expires_at": occurred_at + timedelta(minutes=2),
        }
        await self.session.execute(insert(metadata.tables["workbench_campaign_drafts"]).values(**successor))
        disclosure = await self._find("workbench_disclosures", {"draft_record_id": predecessor["id"]})
        if disclosure is None:
            raise ValueError("workbench_predecessor_disclosure_missing")
        successor_disclosure = self._owned("disclosure", occurred_at) | {
            "draft_record_id": successor["id"],
            "disclosure_id": f"disclosure-{hashlib.sha256(successor_draft_id.encode()).hexdigest()[:24]}",
            "sanitized_fields_sha256": _digest({"plan_id": plan_id}),
            "target_scope_sha256": disclosure["target_scope_sha256"],
            "access_class": disclosure["access_class"], "egress_class": disclosure["egress_class"],
            "side_effects_sha256": disclosure["side_effects_sha256"],
            "budget_sha256": disclosure["budget_sha256"], "disclosure_state": "review-required",
        }
        await self.session.execute(insert(metadata.tables["workbench_disclosures"]).values(**successor_disclosure))
        await self.session.execute(update(metadata.tables["workbench_campaign_drafts"]).where(
            metadata.tables["workbench_campaign_drafts"].c.id == predecessor["id"],
        ).values(draft_state="superseded", version=int(predecessor["version"]) + 1, updated_at=occurred_at))
        await self.session.execute(update(metadata.tables["workbench_reviewer_decisions"]).where(
            metadata.tables["workbench_reviewer_decisions"].c.draft_record_id == predecessor["id"],
            metadata.tables["workbench_reviewer_decisions"].c.decision_state == "active",
        ).values(decision_state="invalidated-by-successor", version=metadata.tables["workbench_reviewer_decisions"].c.version + 1,
                 updated_at=occurred_at))
        lifecycle = self._owned("lifecycle", occurred_at) | {
            "draft_record_id": successor["id"], "event_id": f"successor-{uuid4().hex[:24]}",
            "event_kind": "successor_created", "from_state": str(predecessor["draft_state"]),
            "to_state": "awaiting_review", "event_sha256": _digest((predecessor_draft_id, successor_draft_id, successor_sha)),
            "occurred_at": occurred_at,
        }
        await self.session.execute(insert(metadata.tables["workbench_lifecycle_events"]).values(**lifecycle))
        await self._audit("workbench.draft.successor-created", successor_draft_id,
                          {"predecessor_draft_id": predecessor_draft_id, "proposal_sha256": successor_sha,
                           "approval_invalidated": True}, occurred_at)
        return predecessor, successor

    async def review_stored_draft(
        self, *, draft_id: str, decision_id: str, expected_proposal_sha256: str,
        decision: str, reviewer_id: str, occurred_at: datetime,
    ) -> tuple[dict[str, object], dict[str, object]]:
        await self._context(); await self._lock(f"draft-review:{draft_id}")
        draft = await self._find("workbench_campaign_drafts", {"draft_id": draft_id})
        if (draft is None or draft["draft_state"] != "awaiting_review"
            or draft["proposal_sha256"] != _sha(expected_proposal_sha256)
            or decision not in {"approve_exact", "deny"}):
            raise ValueError("workbench_exact_review_required")
        if decision == "approve_exact" and reviewer_id == draft["created_by"]:
            raise ValueError("workbench_review_separation_required")
        existing = await self._find("workbench_reviewer_decisions", {"decision_id": decision_id})
        if existing is not None:
            if existing["proposal_sha256"] != draft["proposal_sha256"] or existing["decision_kind"] != decision:
                raise ValueError("workbench_decision_immutable")
            return draft, existing
        row = self._owned("decision", occurred_at) | {
            "draft_record_id": draft["id"], "decision_id": _id(decision_id), "decision_kind": decision,
            "proposal_sha256": draft["proposal_sha256"], "actor_id": _id(reviewer_id),
            "rationale_sha256": _digest((decision, draft["proposal_sha256"])), "decision_state": "active",
            "decided_at": occurred_at,
        }
        await self.session.execute(insert(metadata.tables["workbench_reviewer_decisions"]).values(**row))
        next_state = "approved" if decision == "approve_exact" else "denied"
        await self.session.execute(update(metadata.tables["workbench_campaign_drafts"]).where(
            metadata.tables["workbench_campaign_drafts"].c.id == draft["id"],
        ).values(draft_state=next_state, version=int(draft["version"]) + 1, updated_at=occurred_at))
        await self._audit("workbench.draft.reviewed", draft_id,
                          {"decision": decision, "proposal_sha256": draft["proposal_sha256"]}, occurred_at)
        return draft | {"draft_state": next_state}, row

    async def freeze_registered_server(
        self, *, registration_id: str, expected_inventory_sha256: str, occurred_at: datetime,
    ) -> dict[str, object]:
        await self._context(); await self._lock(f"freeze:{registration_id}")
        registration = await self._find("mcp_server_registrations", {"registration_id": registration_id})
        if registration is None or registration["inventory_sha256"] != _sha(expected_inventory_sha256):
            raise ValueError("mcp_exact_inventory_freeze_required")
        decisions = metadata.tables["workbench_reviewer_decisions"]
        active_count = int(await self.session.scalar(select(text("count(*)")).select_from(decisions).where(
            decisions.c.tenant_id == self.tenant_id, decisions.c.decision_state == "active")) or 0)
        freeze = ServerFreeze(server_id=str(registration["server_id"]), frozen=True,
                              reason_code="operator_freeze", expected_inventory_sha256=expected_inventory_sha256,
                              observed_inventory_sha256=None, invalidated_approval_ids=tuple(f"active-{i}" for i in range(active_count)))
        row = await self.record_freeze(registration_id=registration_id, freeze=freeze, occurred_at=occurred_at)
        await self.session.execute(update(metadata.tables["mcp_server_registrations"]).where(
            metadata.tables["mcp_server_registrations"].c.id == registration["id"],
        ).values(registration_state="frozen", version=int(registration["version"]) + 1, updated_at=occurred_at))
        await self.session.execute(update(decisions).where(
            decisions.c.tenant_id == self.tenant_id, decisions.c.decision_state == "active",
        ).values(decision_state="invalidated-by-freeze", version=decisions.c.version + 1, updated_at=occurred_at))
        return row

    async def record_freeze(self, *, registration_id: str, freeze: ServerFreeze,
                            occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"freeze:{registration_id}")
        registration = await self._find("mcp_server_registrations", {"registration_id": registration_id})
        if registration is None or not freeze.frozen:
            raise ValueError("mcp_active_freeze_required")
        row = self._owned("freeze", occurred_at) | {"registration_record_id": registration["id"],
            "freeze_id": f"freeze-{uuid4().hex[:24]}", "reason_code": freeze.reason_code,
            "expected_inventory_sha256": freeze.expected_inventory_sha256,
            "observed_inventory_sha256": freeze.observed_inventory_sha256,
            "invalidated_approval_count": len(freeze.invalidated_approval_ids), "freeze_state": "active",
            "frozen_at": occurred_at}
        await self.session.execute(insert(metadata.tables["mcp_freeze_events"]).values(**row))
        await self._audit("mcp.server.frozen", registration_id,
                          {"reason_code": freeze.reason_code, "invalidated_approval_count": len(freeze.invalidated_approval_ids)}, occurred_at)
        return row

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context()
        result = {}
        for key, name in (("registrations", "mcp_server_registrations"), ("attestations", "mcp_transport_attestations"),
                          ("inventories", "mcp_inventory_revisions"), ("items", "mcp_inventory_items"),
                          ("freezes", "mcp_freeze_events"), ("drafts", "workbench_campaign_drafts"),
                          ("trust_items", "workbench_trust_items"), ("disclosures", "workbench_disclosures"),
                          ("decisions", "workbench_reviewer_decisions"), ("conclusions", "workbench_conclusions"),
                          ("lifecycle", "workbench_lifecycle_events"), ("qualifications", "mcp_qualification_receipts")):
            table = metadata.tables[name]
            rows = (await self.session.execute(select(table).where(table.c.tenant_id == self.tenant_id)
                                               .order_by(table.c.created_at.desc()).limit(100))).mappings().all()
            result[key] = [dict(row) for row in rows]
        return result

    async def _immutable(self, table_name: str, where: dict[str, object], values: dict[str, object],
                         occurred_at: datetime, prefix: str) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing:
            if any(existing[name] != value for name, value in values.items()):
                raise ValueError(f"mcp_{prefix}_immutable")
            return existing
        row = self._owned(prefix, occurred_at) | values
        await self.session.execute(insert(metadata.tables[table_name]).values(**row))
        return row

    async def _find(self, table_name: str, where: dict[str, object]) -> dict[str, object] | None:
        table = metadata.tables[table_name]
        clauses = [table.c.tenant_id == self.tenant_id] + [getattr(table.c, key) == value for key, value in where.items()]
        row = (await self.session.execute(select(table).where(*clauses))).mappings().one_or_none()
        return dict(row) if row else None

    def _owned(self, prefix: str, occurred_at: datetime) -> dict[str, object]:
        return {"id": f"r114-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id, "version": 1,
                "created_at": occurred_at, "updated_at": occurred_at}

    async def _context(self) -> None:
        await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
                                   {"scope": f"{self.tenant_id}:{scope}"})

    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        owned = {"tenant_id": self.tenant_id, "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", actor_user_id=self.actor_user_id, action=event,
            subject_type="mcp_workbench", subject_id=subject[:64], correlation_id=self.correlation_id,
            details=details, **owned))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", event_type=event, aggregate_id=subject[:64], payload=details,
            published=False, **owned))


def _id(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 200 or not all(char.isalnum() or char in "._:-" for char in value):
        raise ValueError("mcp_repository_identifier_invalid")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("mcp_repository_sha256_invalid")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
