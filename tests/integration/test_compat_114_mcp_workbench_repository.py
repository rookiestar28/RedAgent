from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.mcp_broker.contracts import ServerRegistration, TransportKind
from redagent_platform.mcp_broker.fixture import DeterministicMcpFixture
from redagent_platform.mcp_broker.inventory import inventory_sha256
from redagent_platform.mcp_broker.repository import McpWorkbenchRepository
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.workbench.contracts import TrustLane, WorkbenchItem, WorkbenchProposal


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 12, 9, 0, tzinfo=timezone.utc)


def test_repository_persists_minimized_lineage_freeze_audit_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex
    tenant = f"tenant-r114-{suffix}"
    items = DeterministicMcpFixture().list_inventory()
    digest = inventory_sha256(items)
    registration = ServerRegistration(registration_id=f"registration-{suffix}", tenant_id=tenant,
        server_id="redagent-fixture", protocol_version="2025-11-25", transport=TransportKind.IN_PROCESS,
        transport_identity_sha256="1" * 64, inventory_sha256=digest, risk_class="high", data_class="internal",
        allowed_item_names=tuple(item.name for item in items), registered_by="admin-r114", reviewed_by="reviewer-r114",
        signature_sha256="2" * 64, issued_at=NOW, expires_at=NOW + timedelta(minutes=10))
    proposal = WorkbenchProposal(proposal_id=f"proposal-{suffix}", campaign_id=f"campaign-{suffix}", revision=1,
        predecessor_proposal_id=None, server_id="redagent-fixture", server_inventory_sha256=digest,
        tool_fqn="redagent.r114-mcp-fixture.propose.v1", tool_schema_sha256="3" * 64,
        sanitized_arguments={"plan_id": f"plan-{suffix}"}, target_ids=(f"target-{suffix}",),
        roe_version_id="roe-r114-approved", policy_revision="r099-v1", policy_decision_id="decision-r114-allow",
        credential_class="none", egress_class="none", side_effects=("proposal_only",),
        disclosure_fields=("stored_plan_id",), budget_sha256="4" * 64, approval_id=None,
        issued_at=NOW, expires_at=NOW + timedelta(minutes=2))
    trust = WorkbenchItem(item_id=f"trust-{suffix}", lane=TrustLane.UNTRUSTED_EXTERNAL,
                          summary="Minimized fixture campaign summary.", provenance_sha256="5" * 64)
    async with sessions() as session:
        async with session.begin():
            repo = McpWorkbenchRepository(session, tenant_id=tenant, actor_user_id="operator-r114",
                                          correlation_id=f"correlation-{suffix}")
            await repo.register_server(registration, transport_attestation_sha256="6" * 64, occurred_at=NOW)
            await repo.store_inventory(registration_id=registration.registration_id,
                                       inventory_id=f"inventory-{suffix}", items=items, occurred_at=NOW)
            await repo.store_draft(proposal, created_by="operator-r114", trust_items=(trust,), occurred_at=NOW)
            _, successor = await repo.create_successor_from_stored(
                predecessor_draft_id=proposal.proposal_id, successor_draft_id=f"successor-{suffix}",
                plan_id=f"plan-revised-{suffix}", created_by="operator-r114", occurred_at=NOW + timedelta(seconds=1),
            )
            reviewed, decision = await repo.review_stored_draft(
                draft_id=str(successor["draft_id"]), decision_id=f"decision-{suffix}",
                expected_proposal_sha256=str(successor["proposal_sha256"]), decision="approve_exact",
                reviewer_id="reviewer-r114", occurred_at=NOW + timedelta(seconds=2),
            )
            assert reviewed["draft_state"] == "approved" and decision["decision_state"] == "active"
            freeze = await repo.freeze_registered_server(
                registration_id=registration.registration_id, expected_inventory_sha256=digest,
                occurred_at=NOW + timedelta(seconds=3),
            )
            assert freeze["invalidated_approval_count"] == 1
            dashboard = await repo.dashboard()
            assert len(dashboard["registrations"]) == len(dashboard["freezes"]) == 1
            assert len(dashboard["drafts"]) == 2 and len(dashboard["decisions"]) == 1
            assert dashboard["decisions"][0]["decision_state"] == "invalidated-by-freeze"
            assert dashboard["attestations"][0]["transport_enabled"] is False
            assert set(dashboard["disclosures"][0]).isdisjoint({"token", "credential", "raw_evidence", "arguments"})
    async with sessions() as session:
        async with session.begin():
            other = await McpWorkbenchRepository(session, tenant_id=f"other-{suffix}", actor_user_id="other-r114",
                correlation_id=f"other-correlation-{suffix}").dashboard()
            assert all(not rows for rows in other.values())
    await engine.dispose()
