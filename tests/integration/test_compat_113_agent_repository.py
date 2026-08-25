from __future__ import annotations

from datetime import datetime, timedelta, timezone
import asyncio
import hashlib
import importlib
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.agent_kernel.approvals import ApprovalGrant, ProposalContext, proposal_sha256
from redagent_platform.agent_kernel.contracts import ModelBudget, ProjectedTool, ToolKind
from redagent_platform.persistence.database import load_database_settings


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 12, 3, 0, tzinfo=timezone.utc)


def _repository_class():
    try:
        return importlib.import_module("redagent_platform.agent_kernel.repository").AgentKernelRepository
    except ModuleNotFoundError:
        pytest.fail("compat_113 RED: PostgreSQL agent-kernel repository is not implemented")


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _budget() -> ModelBudget:
    return ModelBudget(max_turns=2, max_tool_calls=1, max_elapsed_seconds=20, max_input_tokens=1000,
                       max_output_tokens=250, max_cost_microunits=1000, max_result_bytes=1024)


def _tool() -> ProjectedTool:
    return ProjectedTool(
        fully_qualified_name="redagent.human-simulation-sink.propose.v1", tool_kind=ToolKind.PROPOSAL,
        description="Propose the certified owned sink campaign.", description_sha256="1" * 64,
        input_schema={"type": "object", "properties": {"campaign_id": {"type": "string"}},
                      "required": ["campaign_id"], "additionalProperties": False},
        input_schema_sha256="2" * 64, output_schema_sha256="3" * 64,
        source_capability_id="human-simulation-sink", source_capability_revision=1,
        source_capability_sha256="4" * 64, adapter_id="r112-owned-sink", adapter_version="1.0.0",
        network_mode="none", credential_class="none", approval_tier="high", budget=_budget(),
        unsupported_features=("arbitrary_command", "native_template", "plugin_loading", "human_delivery"),
    )


def _proposal(*, tenant_id: str) -> ProposalContext:
    return ProposalContext(
        proposal_id="proposal-r113-1", tenant_id=tenant_id, operator_id="operator-requester",
        campaign_id="campaign-r113-1", tool_fqn="redagent.human-simulation-sink.propose.v1",
        tool_schema_sha256="2" * 64, arguments={"campaign_id": "r112-sink-email-canary-v1"},
        target_ids=("owned-sink-1",), roe_version_id="roe-r113-1", policy_revision="r099-v1",
        policy_decision_id="decision-r113-allow", credential_class="none", egress_class="none",
        side_effects=("create_proposal_only",), budget=_budget(), registry_sha256="5" * 64,
        issued_at=NOW, expires_at=NOW + timedelta(minutes=2),
    )


def test_repository_persists_digest_only_lineage_exact_approval_budget_cancel_and_tenant_isolation() -> None:
    asyncio.run(_repository_scenario())


async def _repository_scenario() -> None:
    repository_class = _repository_class()
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url)
    factory = async_sessionmaker(engine, expire_on_commit=False)
    tenant = f"tenant-r113-{uuid4().hex[:12]}"
    try:
        async with factory.begin() as session:
            repository = repository_class(session, tenant_id=tenant, actor_user_id="operator-r113", correlation_id="corr-r113")
            provider = await repository.certify_provider(
                provider_id="deterministic-fake", adapter_version="1.0.0", model_snapshot="fake-script-v1",
                settings_sha256="6" * 64, response_storage_enabled=False, background_enabled=False,
                provider_tracing_enabled=False, occurred_at=NOW,
            )
            tool = await repository.register_tool(_tool(), occurred_at=NOW)
            run = await repository.create_run(
                run_id="run-r113-1", provider_id="deterministic-fake", campaign_id="campaign-r113-1",
                operator_id="operator-requester", trusted_context_sha256="7" * 64,
                registry_sha256="5" * 64, budget=_budget(), started_at=NOW,
                expires_at=NOW + timedelta(minutes=5),
            )
            proposal = _proposal(tenant_id=tenant)
            stored = await repository.store_proposal(run_id="run-r113-1", call_id="call-r113-1", proposal=proposal, occurred_at=NOW)
            assert stored["argument_sha256"] == _sha(proposal.arguments)
            assert "arguments" not in stored and "campaign_id" not in stored
            grant = ApprovalGrant.for_proposal(
                proposal, approval_id="approval-r113-1", approved_by="operator-reviewer",
                issued_at=NOW + timedelta(seconds=1), expires_at=NOW + timedelta(minutes=1), nonce="nonce-r113-1",
            )
            approval = await repository.store_approval(grant=grant, proposal=proposal, occurred_at=NOW + timedelta(seconds=1))
            consumed = await repository.consume_approval(
                approval_id="approval-r113-1", proposal=proposal, now=NOW + timedelta(seconds=2),
            )
            assert approval["nonce_sha256"] != grant.nonce and consumed["approval_state"] == "consumed"
            with pytest.raises(ValueError, match="agent_approval_replayed"):
                await repository.consume_approval(approval_id="approval-r113-1", proposal=proposal, now=NOW + timedelta(seconds=3))
            stored_approval, approved_proposal = await repository.approve_stored_proposal(
                proposal_id="proposal-r113-1", approval_id="approval-r113-api",
                expected_proposal_sha256=proposal_sha256(proposal), approved_by="operator-api-reviewer",
                issued_at=NOW + timedelta(seconds=4), expires_at=NOW + timedelta(minutes=1),
            )
            assert stored_approval["approval_state"] == "consumed"
            assert approved_proposal["proposal_state"] == "approved"
            budget = await repository.record_budget(
                run_id="run-r113-1", turn_count=1, tool_call_count=1, input_token_count=50,
                result_token_count=10, cost_microunits=25, result_bytes=128, elapsed_millis=500,
                ledger_state="within_budget", occurred_at=NOW + timedelta(seconds=2),
            )
            trace = await repository.append_trace(
                run_id="run-r113-1", trace_id="trace-r113-1", span_id="span-r113-1", parent_span_id=None,
                event_type="proposal.approved", trace_state="approved", input_sha256="8" * 64,
                output_sha256="9" * 64, policy_decision_id="decision-r113-allow",
                approval_id="approval-r113-1", evidence_id=None, error_code=None,
                occurred_at=NOW + timedelta(seconds=2),
            )
            cancelled = await repository.cancel_run(run_id="run-r113-1", expected_version=1, occurred_at=NOW + timedelta(seconds=3))
            dashboard = await repository.dashboard()
            assert provider["profile_state"] == "certified-no-storage"
            assert tool["tool_state"] == "certified-proposal-only"
            assert run["run_state"] == "awaiting_model" and budget["ledger_state"] == "within_budget"
            assert trace["event_type"] == "proposal.approved"
            assert cancelled["cancel_requested"] is True and cancelled["run_state"] == "cancelled"
            assert len(dashboard["runs"]) == len(dashboard["proposals"]) == 1
            assert len(dashboard["approvals"]) == 2
        async with factory.begin() as session:
            other = repository_class(session, tenant_id=f"other-{tenant}", actor_user_id="operator-r113", correlation_id="corr-r113-other")
            assert all(not rows for rows in (await other.dashboard()).values())
    finally:
        await engine.dispose()
