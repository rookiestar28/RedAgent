"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from datetime import (
    datetime,
    timedelta,
)
from fastapi import (
    Depends,
    Request,
    status,
)
import hashlib
from pathlib import Path
from redagent_platform.agent_kernel.approvals import ProposalContext
from redagent_platform.agent_kernel.promotion import verify_agent_kernel_promotion
from redagent_platform.agent_kernel.qualification import (
    build_projection_catalog,
    certified_capability_catalog,
    qualify_agent_kernel,
)
from redagent_platform.agent_kernel.repository import AgentKernelRepository
from redagent_platform.api.contracts import (
    ApiError,
    RequestGuard,
)
from redagent_platform.api.router_primitives import _now
from redagent_platform.api.schemas.agent import (
    AgentCancelRequest,
    AgentDashboardResponse,
    AgentProposalApproveRequest,
    AgentProposalResponse,
    AgentRunCreateRequest,
    AgentRunResponse,
    AgentRunStartResponse,
    AgentToolListResponse,
)
from redagent_platform.persistence.models import metadata
from sqlalchemy import select


# IMPORTANT: router modules are one level below api; promotion assets remain workspace-relative.
def _public_agent_tool(tool) -> dict[str, object]:
    budget = tool.budget
    return {
        "tool_fqn": tool.fully_qualified_name,
        "capability_id": tool.source_capability_id,
        "capability_revision": tool.source_capability_revision,
        "capability_sha256": tool.source_capability_sha256,
        "input_schema_sha256": tool.input_schema_sha256,
        "output_schema_sha256": tool.output_schema_sha256,
        "approval_tier": tool.approval_tier,
        "network_class": tool.network_mode,
        "access_class": tool.credential_class,
        "max_turns": budget.max_turns,
        "max_tool_calls": budget.max_tool_calls,
        "max_elapsed_seconds": budget.max_elapsed_seconds,
        "max_input_tokens": budget.max_input_tokens,
        "max_output_tokens": budget.max_output_tokens,
        "max_cost_microunits": budget.max_cost_microunits,
        "max_result_bytes": budget.max_result_bytes,
        "unsupported_features": list(tool.unsupported_features),
    }


def _public_agent_run(row: dict[str, object], provider_id: str) -> dict[str, object]:
    return {
        "run_id": row["run_id"],
        "campaign_id": row["campaign_id"],
        "provider_id": provider_id,
        "registry_sha256": row["registry_sha256"],
        "run_state": row["run_state"],
        "cancel_requested": row["cancel_requested"],
        "failure_code": row["failure_code"],
        "started_at": row["started_at"],
        "expires_at": row["expires_at"],
        "completed_at": row["completed_at"],
        "version": row["version"],
    }


def _public_agent_proposal(row: dict[str, object], run_id: str, tool_fqn: str) -> dict[str, object]:
    return {
        "proposal_id": row["proposal_id"],
        "run_id": run_id,
        "tool_fqn": tool_fqn,
        "proposal_sha256": row["proposal_sha256"],
        "argument_sha256": row["argument_sha256"],
        "target_sha256": row["target_sha256"],
        "side_effect_classes": row["side_effect_classes"],
        "roe_version_id": row["roe_version_id"],
        "policy_revision": row["policy_revision"],
        "policy_decision_id": row["policy_decision_id"],
        "proposal_state": row["proposal_state"],
        "expires_at": row["expires_at"],
        "version": row["version"],
    }


def _public_agent_approval(row: dict[str, object], proposal_id: str) -> dict[str, object]:
    return {
        "approval_id": row["approval_id"],
        "proposal_id": proposal_id,
        "proposal_sha256": row["proposal_sha256"],
        "approved_by": row["approved_by"],
        "approval_state": row["approval_state"],
        "issued_at": row["issued_at"],
        "expires_at": row["expires_at"],
        "consumed_at": row["consumed_at"],
        "revoked_at": row["revoked_at"],
        "version": row["version"],
    }


def _public_agent_budget(row: dict[str, object], run_id: str) -> dict[str, object]:
    return {
        "ledger_id": row["ledger_id"],
        "run_id": run_id,
        **{
            key: row[key]
            for key in (
                "turn_count",
                "tool_call_count",
                "input_token_count",
                "result_token_count",
                "cost_microunits",
                "result_bytes",
                "elapsed_millis",
                "ledger_state",
                "version",
            )
        },
    }


def _public_agent_trace(row: dict[str, object], run_id: str) -> dict[str, object]:
    return {
        "trace_id": row["trace_id"],
        "span_id": row["span_id"],
        "run_id": run_id,
        **{
            key: row[key]
            for key in (
                "event_type",
                "trace_state",
                "input_sha256",
                "output_sha256",
                "policy_decision_id",
                "approval_id",
                "evidence_id",
                "error_code",
                "occurred_at",
            )
        },
    }


def _require_agent_promotion(now: datetime):
    try:
        return verify_agent_kernel_promotion(Path(__file__).resolve().parents[3], now=now)
    except (OSError, ValueError) as exc:
        raise ApiError(
            503, "agent_kernel_promotion_unavailable", "The signed deterministic agent-kernel promotion is unavailable."
        ) from exc


def register_agent_tool_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard

    @app.get("/api/v1/agent/tools", operation_id="list_agent_tools", response_model=AgentToolListResponse)
    async def list_agent_tools(
        guard: RequestGuard = Depends(require_guard("job:read", safety_preserving=True)),
    ) -> dict:
        del guard
        _require_agent_promotion(_now())
        return {"data": [_public_agent_tool(tool) for tool in build_projection_catalog(certified_capability_catalog())]}


def register_agent_runtime_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.post(
        "/api/v1/agent/runs",
        operation_id="create_agent_run",
        response_model=AgentRunStartResponse,
        status_code=status.HTTP_202_ACCEPTED,
    )
    async def create_agent_run(
        payload: AgentRunCreateRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        _require_agent_promotion(_now())
        now = _now()
        qualification = qualify_agent_kernel()
        tools = build_projection_catalog(certified_capability_catalog())
        selected = next((tool for tool in tools if tool.fully_qualified_name == payload.tool_fqn), None)
        if selected is None:
            raise ApiError(404, "agent_tool_not_found", "The certified projected tool does not exist.")
        context_sha = hashlib.sha256(
            f"{guard.security.tenant_id}:{payload.campaign_id}:{payload.plan_id}".encode()
        ).hexdigest()
        try:
            async with session_scope(request) as session:
                repository = AgentKernelRepository(
                    session,
                    tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                )
                await repository.certify_provider(
                    provider_id="deterministic-fake",
                    adapter_version="1.0.0",
                    model_snapshot="fake-script-v1",
                    settings_sha256=str(qualification["provider_settings_sha256"]),
                    response_storage_enabled=False,
                    background_enabled=False,
                    provider_tracing_enabled=False,
                    occurred_at=now,
                )
                for tool in tools:
                    await repository.register_tool(tool, occurred_at=now)
                run = await repository.create_run(
                    run_id=payload.run_id,
                    provider_id="deterministic-fake",
                    campaign_id=payload.campaign_id,
                    operator_id=guard.security.subject,
                    trusted_context_sha256=context_sha,
                    registry_sha256=str(qualification["registry_sha256"]),
                    budget=selected.budget,
                    started_at=now,
                    expires_at=now + timedelta(minutes=5),
                )
                # IMPORTANT: derive bounded opaque IDs; prefixed user IDs can exceed persisted column limits.
                proposal_key = hashlib.sha256(payload.run_id.encode()).hexdigest()[:24]
                proposal = ProposalContext(
                    proposal_id=f"proposal-{proposal_key}",
                    tenant_id=guard.security.tenant_id,
                    operator_id=guard.security.subject,
                    campaign_id=payload.campaign_id,
                    tool_fqn=payload.tool_fqn,
                    tool_schema_sha256=selected.input_schema_sha256,
                    arguments={"plan_id": payload.plan_id},
                    target_ids=(payload.plan_id,),
                    roe_version_id="roe-r113-approved",
                    policy_revision="r099-v1",
                    policy_decision_id="r113-deterministic-policy-allow",
                    credential_class=selected.credential_class,
                    egress_class=selected.network_mode,
                    side_effects=("proposal_only",),
                    budget=selected.budget,
                    registry_sha256=str(qualification["registry_sha256"]),
                    issued_at=now,
                    expires_at=now + timedelta(minutes=2),
                )
                proposal_row = await repository.store_proposal(
                    run_id=payload.run_id, call_id=f"call-{proposal_key}", proposal=proposal, occurred_at=now
                )
        except ValueError as exc:
            raise ApiError(409, "agent_run_conflict", str(exc)) from exc
        return {
            "data": {
                "run": _public_agent_run(run, "deterministic-fake"),
                "proposal": _public_agent_proposal(proposal_row, payload.run_id, payload.tool_fqn),
            }
        }

    @app.post(
        "/api/v1/agent/proposals/{proposal_id}/approve",
        operation_id="approve_agent_proposal",
        response_model=AgentProposalResponse,
    )
    async def approve_agent_proposal(
        proposal_id: str,
        payload: AgentProposalApproveRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        now = _now()
        try:
            async with session_scope(request) as session:
                repository = AgentKernelRepository(
                    session,
                    tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                )
                _, proposal = await repository.approve_stored_proposal(
                    proposal_id=proposal_id,
                    approval_id=payload.approval_id,
                    expected_proposal_sha256=payload.expected_proposal_sha256,
                    approved_by=guard.security.subject,
                    issued_at=now,
                    expires_at=now + timedelta(minutes=2),
                )
                runs = metadata.tables["agent_runs"]
                tools = metadata.tables["agent_projected_tools"]
                run_id = await session.scalar(select(runs.c.run_id).where(runs.c.id == proposal["run_record_id"]))
                tool_fqn = await session.scalar(
                    select(tools.c.tool_fqn).where(tools.c.id == proposal["tool_record_id"])
                )
        except ValueError as exc:
            raise ApiError(409, "agent_approval_conflict", str(exc)) from exc
        return {"data": _public_agent_proposal(proposal, str(run_id), str(tool_fqn))}

    @app.post("/api/v1/agent/runs/{run_id}/cancel", operation_id="cancel_agent_run", response_model=AgentRunResponse)
    async def cancel_agent_run(
        run_id: str,
        payload: AgentCancelRequest,
        request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        try:
            async with session_scope(request) as session:
                repository = AgentKernelRepository(
                    session,
                    tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject,
                    correlation_id=guard.correlation_id,
                )
                run = await repository.cancel_run(
                    run_id=run_id, expected_version=payload.expected_version, occurred_at=_now()
                )
                providers = metadata.tables["agent_provider_profiles"]
                provider_id = await session.scalar(
                    select(providers.c.provider_id).where(providers.c.id == run["provider_record_id"])
                )
        except ValueError as exc:
            raise ApiError(409, "agent_cancel_conflict", str(exc)) from exc
        return {"data": _public_agent_run(run, str(provider_id))}

    @app.get("/api/v1/agent/dashboard", operation_id="get_agent_dashboard", response_model=AgentDashboardResponse)
    async def get_agent_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        async with session_scope(request) as session:
            data = await AgentKernelRepository(
                session,
                tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject,
                correlation_id=guard.correlation_id,
            ).dashboard()
        provider_by_record = {str(row["id"]): str(row["provider_id"]) for row in data["providers"]}
        run_by_record = {str(row["id"]): str(row["run_id"]) for row in data["runs"]}
        tool_by_record = {str(row["id"]): str(row["tool_fqn"]) for row in data["tools"]}
        proposal_by_record = {str(row["id"]): str(row["proposal_id"]) for row in data["proposals"]}
        tools = build_projection_catalog(certified_capability_catalog())
        return {
            "data": {
                "tools": [_public_agent_tool(tool) for tool in tools],
                "runs": [
                    _public_agent_run(row, provider_by_record[str(row["provider_record_id"])]) for row in data["runs"]
                ],
                "proposals": [
                    _public_agent_proposal(
                        row, run_by_record[str(row["run_record_id"])], tool_by_record[str(row["tool_record_id"])]
                    )
                    for row in data["proposals"]
                ],
                "approvals": [
                    _public_agent_approval(row, proposal_by_record[str(row["proposal_record_id"])])
                    for row in data["approvals"]
                ],
                "budgets": [
                    _public_agent_budget(row, run_by_record[str(row["run_record_id"])]) for row in data["budgets"]
                ],
                "traces": [
                    _public_agent_trace(row, run_by_record[str(row["run_record_id"])]) for row in data["traces"]
                ],
            }
        }
