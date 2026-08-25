"""Behavior-preserving domain route registration."""

from __future__ import annotations

from fastapi import APIRouter

from redagent_platform.api.dependencies import ApiDependencies

from redagent_platform.api._route_support import (
    ApiError,
    Depends,
    McpFreezeRequest,
    McpFreezeResponse,
    Path,
    Request,
    RequestGuard,
    WorkbenchDashboardResponse,
    WorkbenchDraftCreateRequest,
    WorkbenchDraftMutationResponse,
    WorkbenchReviewRequest,
    WorkbenchReviewResponse,
    WorkbenchSuccessorRequest,
    _now,
    _r114_fixture_draft_binding,
    _r114_matches_fixture_draft_binding,
    _r114_matches_fixture_successor_plan,
    hashlib,
    status,
    timedelta,
)

def _public_mcp_registration(row: dict[str, object]) -> dict[str, object]:
    return {key: row[key] for key in ("registration_id", "server_id", "protocol_version", "transport_kind",
        "inventory_sha256", "risk_class", "data_class", "registration_state", "issued_at", "expires_at", "version")}


def _public_mcp_attestation(row: dict[str, object], registration_id: str) -> dict[str, object]:
    return {"registration_id": registration_id} | {key: row[key] for key in ("attestation_id", "transport_kind",
        "identity_sha256", "authorization_profile_sha256", "boundary_controls_sha256", "transport_enabled",
        "attestation_state", "attested_at", "version")}


def _public_mcp_inventory(row: dict[str, object], registration_id: str) -> dict[str, object]:
    return {"registration_id": registration_id} | {key: row[key] for key in ("inventory_id", "inventory_revision",
        "inventory_sha256", "protocol_version", "inventory_state", "observed_at", "version")}


def _public_mcp_item(row: dict[str, object], inventory_id: str) -> dict[str, object]:
    return {"inventory_id": inventory_id} | {key: row[key] for key in ("item_id", "item_name", "item_kind",
        "description_sha256", "request_schema_sha256", "result_schema_sha256", "risk_class", "data_class",
        "tool_mode", "item_state", "version")}


def _public_mcp_freeze(row: dict[str, object], registration_id: str) -> dict[str, object]:
    return {"registration_id": registration_id} | {key: row[key] for key in ("freeze_id", "reason_code",
        "expected_inventory_sha256", "observed_inventory_sha256", "invalidated_approval_count", "freeze_state",
        "frozen_at", "version")}


def _public_workbench_draft(row: dict[str, object]) -> dict[str, object]:
    return {key: row[key] for key in ("draft_id", "campaign_id", "draft_revision", "predecessor_draft_id",
        "proposal_sha256", "authority_sha256", "draft_state", "created_by", "expires_at", "version")}


def _public_workbench_trust(row: dict[str, object], draft_id: str) -> dict[str, object]:
    return {"draft_id": draft_id} | {key: row[key] for key in ("item_id", "trust_lane", "summary_sha256",
        "provenance_sha256", "item_state", "version")}


def _public_workbench_disclosure(row: dict[str, object], draft_id: str) -> dict[str, object]:
    return {"draft_id": draft_id} | {key: row[key] for key in ("disclosure_id", "sanitized_fields_sha256",
        "target_scope_sha256", "access_class", "egress_class", "side_effects_sha256", "budget_sha256",
        "disclosure_state", "version")}


def _public_workbench_decision(row: dict[str, object], draft_id: str) -> dict[str, object]:
    return {"draft_id": draft_id} | {key: row[key] for key in ("decision_id", "decision_kind",
        "proposal_sha256", "actor_id", "rationale_sha256", "decision_state", "decided_at", "version")}


def _public_workbench_lifecycle(row: dict[str, object], draft_id: str) -> dict[str, object]:
    return {"draft_id": draft_id} | {key: row[key] for key in ("event_id", "event_kind", "from_state",
        "to_state", "event_sha256", "occurred_at", "version")}


def register_workbench_routes(app: APIRouter, dependencies: ApiDependencies) -> None:
    require_guard = dependencies.require_guard
    session_scope = dependencies.session_scope

    @app.get("/api/v1/workbench/dashboard", operation_id="get_workbench_dashboard",
             response_model=WorkbenchDashboardResponse)
    async def get_workbench_dashboard(
        request: Request,
        guard: RequestGuard = Depends(require_guard("audit:read", safety_preserving=True)),
    ) -> dict:
        from redagent_platform.mcp_broker.repository import McpWorkbenchRepository
        async with session_scope(request) as session:
            data = await McpWorkbenchRepository(session, tenant_id=guard.security.tenant_id,
                actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).dashboard()
        registration_by_record = {str(row["id"]): str(row["registration_id"]) for row in data["registrations"]}
        inventory_by_record = {str(row["id"]): str(row["inventory_id"]) for row in data["inventories"]}
        draft_by_record = {str(row["id"]): str(row["draft_id"]) for row in data["drafts"]}
        return {"data": {
            "binding_options": [_r114_fixture_draft_binding()],
            "registrations": [_public_mcp_registration(row) for row in data["registrations"]],
            "attestations": [_public_mcp_attestation(row, registration_by_record[str(row["registration_record_id"])]) for row in data["attestations"]],
            "inventories": [_public_mcp_inventory(row, registration_by_record[str(row["registration_record_id"])]) for row in data["inventories"]],
            "items": [_public_mcp_item(row, inventory_by_record[str(row["inventory_record_id"])]) for row in data["items"]],
            "freezes": [_public_mcp_freeze(row, registration_by_record[str(row["registration_record_id"])]) for row in data["freezes"]],
            "drafts": [_public_workbench_draft(row) for row in data["drafts"]],
            "trust_items": [_public_workbench_trust(row, draft_by_record[str(row["draft_record_id"])]) for row in data["trust_items"]],
            "disclosures": [_public_workbench_disclosure(row, draft_by_record[str(row["draft_record_id"])]) for row in data["disclosures"]],
            "decisions": [_public_workbench_decision(row, draft_by_record[str(row["draft_record_id"])]) for row in data["decisions"]],
            "lifecycle": [_public_workbench_lifecycle(row, draft_by_record[str(row["draft_record_id"])]) for row in data["lifecycle"]],
        }}

    @app.post("/api/v1/workbench/drafts", operation_id="create_workbench_draft",
              response_model=WorkbenchDraftMutationResponse, status_code=status.HTTP_202_ACCEPTED)
    async def create_workbench_draft(
        payload: WorkbenchDraftCreateRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        from redagent_platform.mcp_broker.bridge import project_fixture_tool
        from redagent_platform.mcp_broker.contracts import ServerRegistration, TransportKind
        from redagent_platform.mcp_broker.fixture import DeterministicMcpFixture
        from redagent_platform.mcp_broker.inventory import inventory_sha256
        from redagent_platform.mcp_broker.promotion import verify_mcp_promotion
        from redagent_platform.mcp_broker.repository import McpWorkbenchRepository
        from redagent_platform.workbench.contracts import TrustLane, WorkbenchItem, WorkbenchProposal, proposal_sha256
        now = _now(); fixture = DeterministicMcpFixture(); items = fixture.list_inventory()
        # CRITICAL: keep fixture identifiers server-owned; accepting caller-selected bindings widens the MCP boundary.
        if not _r114_matches_fixture_draft_binding(
            campaign_id=payload.campaign_id, plan_id=payload.plan_id,
            target_id=payload.target_id, tool_fqn=payload.tool_fqn,
        ):
            raise ApiError(409, "workbench_fixture_binding_required",
                           "The selected campaign, plan, target, and tool must match the fixture-only binding.")
        # IMPORTANT: this router is one level below api; promotion assets remain workspace-relative.
        promotion = verify_mcp_promotion(Path(__file__).resolve().parents[3], now=now)
        projection = project_fixture_tool(fixture, item_name="campaign.propose",
                                          expected_inventory_sha256=promotion.inventory_sha256)
        if payload.tool_fqn != projection.tool.fully_qualified_name:
            raise ApiError(409, "workbench_tool_not_pinned", "The selected tool is not in the signed R114 inventory.")
        registration_id = "r114-fixture-registration"
        registration = ServerRegistration(
            registration_id=registration_id, tenant_id=guard.security.tenant_id, server_id="redagent-fixture",
            protocol_version="2025-11-25", transport=TransportKind.IN_PROCESS,
            transport_identity_sha256=hashlib.sha256(b"r114-in-process-fixture").hexdigest(),
            inventory_sha256=inventory_sha256(items), risk_class="high", data_class="internal",
            allowed_item_names=tuple(item.name for item in items), registered_by="r114-system-administrator",
            reviewed_by="r114-security-reviewer", signature_sha256=promotion.manifest_sha256,
            issued_at=now, expires_at=now + timedelta(minutes=10),
        )
        proposal = WorkbenchProposal(
            proposal_id=payload.draft_id, campaign_id=payload.campaign_id, revision=1,
            predecessor_proposal_id=None, server_id="redagent-fixture",
            server_inventory_sha256=promotion.inventory_sha256, tool_fqn=payload.tool_fqn,
            tool_schema_sha256=projection.tool.input_schema_sha256,
            sanitized_arguments={"plan_id": payload.plan_id}, target_ids=(payload.target_id,),
            roe_version_id="roe-r114-approved", policy_revision="r099-v1",
            policy_decision_id="r114-deterministic-policy-allow", credential_class="none", egress_class="none",
            side_effects=("proposal_only",), disclosure_fields=("stored_plan_id",),
            budget_sha256=hashlib.sha256(repr(projection.tool.budget).encode()).hexdigest(), approval_id=None,
            issued_at=now, expires_at=now + timedelta(minutes=2),
        )
        trust_items = (
            WorkbenchItem(item_id=f"authority-{payload.draft_id}", lane=TrustLane.IMMUTABLE_AUTHORITY,
                          summary="ROE, policy, target, and inventory are digest-bound.", provenance_sha256="a" * 64),
            WorkbenchItem(item_id=f"suggestion-{payload.draft_id}", lane=TrustLane.AI_SUGGESTION,
                          summary="A proposal-only stored plan awaits independent review.", provenance_sha256="b" * 64),
            WorkbenchItem(item_id=f"external-{payload.draft_id}", lane=TrustLane.UNTRUSTED_EXTERNAL,
                          summary="MCP descriptions and results remain untrusted.", provenance_sha256="c" * 64),
        )
        try:
            async with session_scope(request) as session:
                repository = McpWorkbenchRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id)
                await repository.register_server(registration, transport_attestation_sha256=promotion.runtime_lock_sha256,
                                                 occurred_at=now)
                await repository.store_inventory(registration_id=registration_id, inventory_id="r114-fixture-inventory",
                                                  items=items, occurred_at=now)
                row = await repository.store_draft(proposal, created_by=guard.security.subject,
                                                   trust_items=trust_items, occurred_at=now)
        except ValueError as exc:
            raise ApiError(409, "workbench_draft_conflict", str(exc)) from exc
        return {"data": {"draft_id": row["draft_id"], "draft_state": row["draft_state"],
                         "proposal_sha256": proposal_sha256(proposal), "version": row["version"]}}

    @app.post("/api/v1/workbench/drafts/{draft_id}/successors", operation_id="create_workbench_successor",
              response_model=WorkbenchDraftMutationResponse, status_code=status.HTTP_202_ACCEPTED)
    async def create_workbench_successor(
        draft_id: str, payload: WorkbenchSuccessorRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        from redagent_platform.mcp_broker.repository import McpWorkbenchRepository
        if not _r114_matches_fixture_successor_plan(payload.plan_id):
            raise ApiError(409, "workbench_successor_binding_required",
                           "The successor must use the server-owned revised fixture plan.")
        try:
            async with session_scope(request) as session:
                _, successor = await McpWorkbenchRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).create_successor_from_stored(
                    predecessor_draft_id=draft_id, successor_draft_id=payload.successor_draft_id,
                    plan_id=payload.plan_id, created_by=guard.security.subject, occurred_at=_now())
        except ValueError as exc:
            raise ApiError(409, "workbench_successor_conflict", str(exc)) from exc
        return {"data": {"draft_id": successor["draft_id"], "predecessor_draft_id": draft_id,
                         "proposal_sha256": successor["proposal_sha256"], "draft_state": successor["draft_state"],
                         "approval_invalidated": True, "version": successor["version"]}}

    @app.post("/api/v1/workbench/drafts/{draft_id}/review", operation_id="review_workbench_draft",
              response_model=WorkbenchReviewResponse)
    async def review_workbench_draft(
        draft_id: str, payload: WorkbenchReviewRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:create", mutation=True)),
    ) -> dict:
        from redagent_platform.mcp_broker.repository import McpWorkbenchRepository
        try:
            async with session_scope(request) as session:
                draft, decision = await McpWorkbenchRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).review_stored_draft(
                    draft_id=draft_id, decision_id=payload.decision_id,
                    expected_proposal_sha256=payload.expected_proposal_sha256, decision=payload.decision,
                    reviewer_id=guard.security.subject, occurred_at=_now())
        except ValueError as exc:
            raise ApiError(409, "workbench_review_conflict", str(exc)) from exc
        return {"data": {"draft_id": draft_id, "decision_id": decision["decision_id"],
                         "decision": decision["decision_kind"], "proposal_sha256": decision["proposal_sha256"],
                         "draft_state": draft["draft_state"], "version": decision["version"]}}

    @app.post("/api/v1/mcp/servers/{registration_id}/freeze", operation_id="freeze_mcp_server",
              response_model=McpFreezeResponse)
    async def freeze_mcp_server(
        registration_id: str, payload: McpFreezeRequest, request: Request,
        guard: RequestGuard = Depends(require_guard("job:stop", mutation=True, safety_preserving=True)),
    ) -> dict:
        from redagent_platform.mcp_broker.repository import McpWorkbenchRepository
        try:
            async with session_scope(request) as session:
                freeze = await McpWorkbenchRepository(session, tenant_id=guard.security.tenant_id,
                    actor_user_id=guard.security.subject, correlation_id=guard.correlation_id).freeze_registered_server(
                    registration_id=registration_id, expected_inventory_sha256=payload.expected_inventory_sha256,
                    occurred_at=_now())
        except ValueError as exc:
            raise ApiError(409, "mcp_freeze_conflict", str(exc)) from exc
        return {"data": {"registration_id": registration_id,
                         "expected_inventory_sha256": freeze["expected_inventory_sha256"],
                         "freeze_state": freeze["freeze_state"],
                         "invalidated_approval_count": freeze["invalidated_approval_count"],
                         "version": freeze["version"]}}
