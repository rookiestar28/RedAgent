"""PostgreSQL-authoritative compat_113 provider, proposal, approval, budget, and trace state."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.agent_kernel.approvals import ApprovalGrant, ProposalContext, proposal_sha256
from redagent_platform.agent_kernel.contracts import ModelBudget, ProjectedTool
from redagent_platform.persistence.models import metadata


class AgentKernelRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _id(tenant_id)
        self.actor_user_id = _id(actor_user_id)
        self.correlation_id = _id(correlation_id)

    async def certify_provider(
        self,
        *,
        provider_id: str,
        adapter_version: str,
        model_snapshot: str,
        settings_sha256: str,
        response_storage_enabled: bool,
        background_enabled: bool,
        provider_tracing_enabled: bool,
        occurred_at: datetime,
    ) -> dict[str, object]:
        await self._context()
        await self._lock(f"provider:{_id(provider_id)}")
        if response_storage_enabled or background_enabled or provider_tracing_enabled:
            raise ValueError("agent_provider_minimization_required")
        values = {
            "provider_id": _id(provider_id), "adapter_version": _id(adapter_version),
            "model_snapshot": _id(model_snapshot), "settings_sha256": _sha(settings_sha256),
            "response_storage_enabled": False, "background_enabled": False,
            "provider_tracing_enabled": False, "profile_state": "certified-no-storage",
        }
        row = await self._immutable("agent_provider_profiles", {
            "provider_id": provider_id, "adapter_version": adapter_version, "model_snapshot": model_snapshot,
        }, values, occurred_at, "provider")
        await self._audit("agent.provider.certified", provider_id, {"settings_sha256": settings_sha256, "storage": False}, occurred_at)
        return row

    async def register_tool(self, tool: ProjectedTool, *, occurred_at: datetime) -> dict[str, object]:
        await self._context()
        await self._lock(f"tool:{tool.fully_qualified_name}")
        values = {
            "tool_fqn": tool.fully_qualified_name, "projection_revision": 1,
            "source_capability_id": tool.source_capability_id,
            "source_capability_revision": tool.source_capability_revision,
            "source_capability_sha256": tool.source_capability_sha256,
            "adapter_id": tool.adapter_id, "adapter_version": tool.adapter_version,
            "input_schema_sha256": tool.input_schema_sha256,
            "result_schema_sha256": tool.output_schema_sha256,
            "description_sha256": tool.description_sha256, "network_class": tool.network_mode,
            "access_class": tool.credential_class, "approval_tier": tool.approval_tier,
            "budget_policy": asdict(tool.budget), "unsupported_features": list(tool.unsupported_features),
            "tool_state": "certified-proposal-only",
        }
        row = await self._immutable("agent_projected_tools", {"tool_fqn": tool.fully_qualified_name, "projection_revision": 1}, values, occurred_at, "tool")
        await self._audit("agent.tool.registered", tool.fully_qualified_name, {
            "source_capability_sha256": tool.source_capability_sha256, "input_schema_sha256": tool.input_schema_sha256,
        }, occurred_at)
        return row

    async def create_run(
        self,
        *,
        run_id: str,
        provider_id: str,
        campaign_id: str,
        operator_id: str,
        trusted_context_sha256: str,
        registry_sha256: str,
        budget: ModelBudget,
        started_at: datetime,
        expires_at: datetime,
    ) -> dict[str, object]:
        await self._context()
        await self._lock(f"run:{_id(run_id)}")
        existing = await self._find("agent_runs", {"run_id": run_id})
        if existing:
            return existing
        provider = await self._find("agent_provider_profiles", {"provider_id": provider_id, "profile_state": "certified-no-storage"})
        if provider is None or not started_at < expires_at:
            raise ValueError("agent_certified_provider_and_expiry_required")
        row = self._owned("run", started_at) | {
            "run_id": _id(run_id), "provider_record_id": provider["id"], "campaign_id": _id(campaign_id),
            "operator_id": _id(operator_id), "trusted_context_sha256": _sha(trusted_context_sha256),
            "registry_sha256": _sha(registry_sha256), "run_state": "awaiting_model",
            "cancel_requested": False, "failure_code": None, "started_at": started_at,
            "expires_at": expires_at, "completed_at": None,
        }
        await self.session.execute(insert(metadata.tables["agent_runs"]).values(**row))
        budget_row = self._owned("budget", started_at) | {
            "run_record_id": row["id"], "ledger_id": f"budget-{run_id}", "budget_sha256": _digest(asdict(budget)),
            "turn_count": 0, "tool_call_count": 0, "input_token_count": 0, "result_token_count": 0,
            "cost_microunits": 0, "result_bytes": 0, "elapsed_millis": 0, "ledger_state": "open",
        }
        await self.session.execute(insert(metadata.tables["agent_budget_ledgers"]).values(**budget_row))
        await self._audit("agent.run.created", run_id, {"registry_sha256": registry_sha256, "provider_id": provider_id}, started_at)
        return row

    async def store_proposal(
        self, *, run_id: str, call_id: str, proposal: ProposalContext, occurred_at: datetime,
    ) -> dict[str, object]:
        await self._context()
        await self._lock(f"proposal:{_id(proposal.proposal_id)}")
        if proposal.tenant_id != self.tenant_id:
            raise ValueError("agent_proposal_tenant_mismatch")
        run = await self._find("agent_runs", {"run_id": run_id})
        tool = await self._find("agent_projected_tools", {"tool_fqn": proposal.tool_fqn, "input_schema_sha256": proposal.tool_schema_sha256})
        if run is None or tool is None or run["registry_sha256"] != proposal.registry_sha256 or run["cancel_requested"]:
            raise ValueError("agent_exact_run_tool_required")
        values = {
            "run_record_id": run["id"], "tool_record_id": tool["id"], "proposal_id": proposal.proposal_id,
            "call_id": _id(call_id), "proposal_sha256": proposal_sha256(proposal),
            "argument_sha256": _digest(proposal.arguments), "target_sha256": _digest(proposal.target_ids),
            "side_effect_classes": list(proposal.side_effects), "roe_version_id": proposal.roe_version_id,
            "policy_revision": proposal.policy_revision, "policy_decision_id": proposal.policy_decision_id,
            "proposal_state": "awaiting_approval", "expires_at": proposal.expires_at,
        }
        row = await self._immutable("agent_proposals", {"proposal_id": proposal.proposal_id}, values, occurred_at, "proposal")
        await self._audit("agent.proposal.created", proposal.proposal_id, {
            "proposal_sha256": values["proposal_sha256"], "tool_fqn": proposal.tool_fqn,
        }, occurred_at)
        return row

    async def store_approval(
        self, *, grant: ApprovalGrant, proposal: ProposalContext, occurred_at: datetime,
    ) -> dict[str, object]:
        await self._context()
        await self._lock(f"approval:{_id(grant.approval_id)}")
        row = await self._find("agent_proposals", {"proposal_id": proposal.proposal_id})
        digest = proposal_sha256(proposal)
        if row is None or row["proposal_sha256"] != digest or grant.proposal_sha256 != digest or grant.approved_by == proposal.operator_id:
            raise ValueError("agent_exact_independent_approval_required")
        values = {
            "proposal_record_id": row["id"], "approval_id": grant.approval_id,
            "proposal_sha256": digest, "approved_by": grant.approved_by,
            "nonce_sha256": _digest(grant.nonce), "approval_state": "pending",
            "issued_at": grant.issued_at, "expires_at": grant.expires_at, "consumed_at": None, "revoked_at": None,
        }
        approval = await self._immutable("agent_approvals", {"approval_id": grant.approval_id}, values, occurred_at, "approval")
        await self._audit("agent.approval.stored", grant.approval_id, {"proposal_sha256": digest}, occurred_at)
        return approval

    async def consume_approval(
        self, *, approval_id: str, proposal: ProposalContext, now: datetime,
    ) -> dict[str, object]:
        await self._context()
        await self._lock(f"approval:{_id(approval_id)}")
        table = metadata.tables["agent_approvals"]
        approval = await self._find("agent_approvals", {"approval_id": approval_id})
        if approval is None:
            raise ValueError("agent_approval_not_found")
        if approval["approval_state"] != "pending" or approval["consumed_at"] is not None:
            raise ValueError("agent_approval_replayed")
        if not approval["issued_at"] <= now < approval["expires_at"] or approval["proposal_sha256"] != proposal_sha256(proposal):
            raise ValueError("agent_approval_invalid_or_expired")
        values = {"approval_state": "consumed", "consumed_at": now, "version": int(approval["version"]) + 1, "updated_at": now}
        await self.session.execute(update(table).where(table.c.id == approval["id"]).values(**values))
        await self._audit("agent.approval.consumed", approval_id, {"proposal_sha256": approval["proposal_sha256"]}, now)
        return approval | values

    async def approve_stored_proposal(
        self,
        *,
        proposal_id: str,
        approval_id: str,
        expected_proposal_sha256: str,
        approved_by: str,
        issued_at: datetime,
        expires_at: datetime,
    ) -> tuple[dict[str, object], dict[str, object]]:
        """Approve only a server-stored digest; raw model arguments are never rehydrated here."""
        await self._context()
        await self._lock(f"proposal-approval:{_id(proposal_id)}")
        proposal = await self._find("agent_proposals", {"proposal_id": proposal_id})
        if proposal is None or proposal["proposal_state"] != "awaiting_approval":
            raise ValueError("agent_proposal_not_approvable")
        run = await self._find("agent_runs", {"id": proposal["run_record_id"]})
        if (
            run is None
            or approved_by == run["operator_id"]
            or proposal["proposal_sha256"] != _sha(expected_proposal_sha256)
            or not issued_at < expires_at <= min(proposal["expires_at"], issued_at + timedelta(minutes=5))
        ):
            raise ValueError("agent_exact_independent_approval_required")
        approval = self._owned("approval", issued_at) | {
            "proposal_record_id": proposal["id"], "approval_id": _id(approval_id),
            "proposal_sha256": proposal["proposal_sha256"], "approved_by": _id(approved_by),
            "nonce_sha256": _digest(f"{approval_id}:{proposal['proposal_sha256']}"),
            "approval_state": "consumed", "issued_at": issued_at, "expires_at": expires_at,
            "consumed_at": issued_at, "revoked_at": None,
        }
        await self.session.execute(insert(metadata.tables["agent_approvals"]).values(**approval))
        proposal_values = {"proposal_state": "approved", "version": int(proposal["version"]) + 1, "updated_at": issued_at}
        await self.session.execute(update(metadata.tables["agent_proposals"]).where(
            metadata.tables["agent_proposals"].c.id == proposal["id"],
        ).values(**proposal_values))
        await self._audit("agent.proposal.approved", proposal_id, {
            "proposal_sha256": proposal["proposal_sha256"], "approval_id": approval_id,
        }, issued_at)
        return approval, proposal | proposal_values

    async def record_budget(self, *, run_id: str, occurred_at: datetime, **counters: object) -> dict[str, object]:
        await self._context()
        await self._lock(f"budget:{_id(run_id)}")
        run = await self._find("agent_runs", {"run_id": run_id})
        if run is None:
            raise ValueError("agent_run_not_found")
        ledger = await self._find("agent_budget_ledgers", {"run_record_id": run["id"]})
        if ledger is None:
            raise ValueError("agent_budget_not_found")
        allowed = {"turn_count", "tool_call_count", "input_token_count", "result_token_count", "cost_microunits", "result_bytes", "elapsed_millis", "ledger_state"}
        if set(counters) != allowed or any(isinstance(counters[name], bool) or not isinstance(counters[name], int) or int(counters[name]) < 0 for name in allowed - {"ledger_state"}) or counters["ledger_state"] not in {"within_budget", "exceeded", "cancelled"}:
            raise ValueError("agent_budget_counters_invalid")
        values = dict(counters) | {"version": int(ledger["version"]) + 1, "updated_at": occurred_at}
        table = metadata.tables["agent_budget_ledgers"]
        await self.session.execute(update(table).where(table.c.id == ledger["id"]).values(**values))
        return ledger | values

    async def append_trace(self, *, run_id: str, occurred_at: datetime, **values: object) -> dict[str, object]:
        await self._context()
        run = await self._find("agent_runs", {"run_id": run_id})
        if run is None:
            raise ValueError("agent_run_not_found")
        row = self._owned("trace", occurred_at) | {"run_record_id": run["id"], "occurred_at": occurred_at} | values
        await self.session.execute(insert(metadata.tables["agent_trace_envelopes"]).values(**row))
        return row

    async def cancel_run(self, *, run_id: str, expected_version: int, occurred_at: datetime) -> dict[str, object]:
        await self._context()
        await self._lock(f"run:{_id(run_id)}")
        run = await self._find("agent_runs", {"run_id": run_id})
        if run is None:
            raise ValueError("agent_run_not_found")
        if run["version"] != expected_version:
            raise ValueError("agent_run_version_conflict")
        values = {"run_state": "cancelled", "cancel_requested": True, "completed_at": occurred_at,
                  "version": int(run["version"]) + 1, "updated_at": occurred_at}
        await self.session.execute(update(metadata.tables["agent_runs"]).where(metadata.tables["agent_runs"].c.id == run["id"]).values(**values))
        await self._audit("agent.run.cancelled", run_id, {"provider_independent": True, "new_progression_blocked": True}, occurred_at)
        return run | values

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context()
        result: dict[str, list[dict[str, object]]] = {}
        for key, name in (
            ("providers", "agent_provider_profiles"), ("tools", "agent_projected_tools"),
            ("runs", "agent_runs"), ("steps", "agent_steps"), ("proposals", "agent_proposals"),
            ("approvals", "agent_approvals"), ("budgets", "agent_budget_ledgers"),
            ("memory", "agent_working_memory"), ("facts", "agent_reviewed_facts"),
            ("traces", "agent_trace_envelopes"), ("qualifications", "agent_qualification_receipts"),
        ):
            table = metadata.tables[name]
            rows = (await self.session.execute(select(table).where(table.c.tenant_id == self.tenant_id).order_by(table.c.created_at.desc()).limit(100))).mappings().all()
            result[key] = [dict(row) for row in rows]
        return result

    async def _immutable(self, table_name: str, where: dict[str, object], values: dict[str, object], occurred_at: datetime, prefix: str) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing:
            if any(existing[name] != value for name, value in values.items()):
                raise ValueError(f"agent_{prefix}_immutable")
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
        return {"id": f"agent-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id, "version": 1,
                "created_at": occurred_at, "updated_at": occurred_at}

    async def _context(self) -> None:
        await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {"scope": f"{self.tenant_id}:{scope}"})

    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        owned = {"tenant_id": self.tenant_id, "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", actor_user_id=self.actor_user_id, action=event,
            subject_type="agent_kernel", subject_id=subject[:64], correlation_id=self.correlation_id,
            details=details, **owned,
        ))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", event_type=event, aggregate_id=subject[:64],
            payload=details, published=False, **owned,
        ))


def _id(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 200 or not all(char.isalnum() or char in "._:-" for char in value):
        raise ValueError("agent_identifier_invalid")
    return value


def _sha(value: object) -> str:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise ValueError("agent_sha256_invalid")
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
