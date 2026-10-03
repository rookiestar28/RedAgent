"""Current native scope may not replace the target a human previewed."""

import asyncio
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import func, select, update

from redagent_platform.persistence.models import metadata
from redagent_platform.campaign_service.application_contracts import ApplicationBindingConflict
from redagent_platform.campaign_service.owned_execution import OwnedExecutionDenied
from redagent_platform.campaign_service.owned_execution_store import assert_owned_execution_current
from redagent_platform.campaign_service.admission_start_store import PostgresAutonomousCampaignAdmissionStartStore
from types import SimpleNamespace
from tests.integration.test_autonomous_campaign_operator_journey import normal_plan_fixture
from tests.integration.test_compat_124_campaign_core import _set_tenant


@pytest.mark.parametrize("phase", ["prepare", "approve"])
@pytest.mark.parametrize("drift", ["target_version", "target_value", "engagement", "roe_document"])
def test_normal_http_scope_drift_denies_new_gate_preserves_preview_and_revoke(monkeypatch, phase, drift):
    asyncio.run(_scenario(monkeypatch, phase, drift))


async def _scenario(monkeypatch, phase, drift):
    app, engine, sessions, source, headers = await normal_plan_fixture(monkeypatch)
    try:
        async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver",
        ) as client:
            engagements = (await client.get("/api/v1/campaign-core/options/engagements", headers=headers)).json()["data"]
            targets = (await client.get("/api/v1/campaign-core/options/targets", headers=headers,
                params={"engagement_binding": engagements[0]["binding"]})).json()["data"]
            risks = (await client.get("/api/v1/campaign-core/options/risk-profiles", headers=headers,
                params={"engagement_binding": engagements[0]["binding"], "target_binding": targets[0]["binding"]})).json()["data"]
            created = await client.post("/api/v1/autonomous-campaigns", headers={**headers,
                "Idempotency-Key": uuid4().hex}, json={"engagement_binding": engagements[0]["binding"],
                "target_binding": targets[0]["binding"], "objective": "Assess HTTP security posture",
                "risk_profile": risks[0]["binding"]})
            assert created.status_code == 201, created.text
            path = "/api/v1/autonomous-campaigns/" + created.json()["data"]["campaign_id"]
            original = (await client.get(path, headers=headers)).json()["data"]
            if phase == "approve":
                prepared = await client.post(path + "/prepare-plan", headers={**headers,
                    "Idempotency-Key": uuid4().hex, "If-Match": original["etag"]}, json={"expected_revision": 1})
                assert prepared.status_code == 201, prepared.text
                original = (await client.get(path, headers=headers)).json()["data"]
            async with sessions() as session, session.begin():
                await _set_tenant(session, source.tenant)
                table_name = "targets" if drift.startswith("target") else "engagements" if drift == "engagement" else "roe_versions"
                table = metadata.tables[table_name]
                changes = {"normalized_value": "http://127.0.0.1:59999"} if drift == "target_value" else (
                    {"document": {"scope": "changed"}} if drift == "roe_document" else {"version": table.c.version + 1})
                scope = table.c.id == source.target if drift.startswith("target") else (
                    table.c.id == source.engagement if drift == "engagement" else table.c.engagement_id == source.engagement)
                await session.execute(update(table).where(table.c.tenant_id == source.tenant, scope).values(**changes))
            current_response = await client.get(path, headers=headers)
            assert current_response.status_code == 200, current_response.text
            current = current_response.json()["data"]
            assert current["target_label"] == original["target_label"]
            assert "operator_native_source_changed" in current["attention"]
            assert current["preview"] == original["preview"]
            if phase == "prepare":
                denied = await client.post(path + "/prepare-plan", headers={**headers,
                    "Idempotency-Key": uuid4().hex, "If-Match": original["etag"]},
                    json={"expected_revision": original["aggregate_revision"]})
            else:
                denied = await client.post(path + "/plan-approval", headers={**headers,
                    "Idempotency-Key": uuid4().hex, "If-Match": original["preview_etag"]},
                    json={"preview_id": original["preview"]["preview_id"], "preview_sha256": original["preview"]["preview_sha256"]})
            assert denied.status_code == 409, denied.text
            # Use the same real native transaction at each downstream gate. No runner or mock
            # policy is needed: changed scope must be denied before reading admission/effect owners.
            campaign_id = created.json()["data"]["campaign_id"]
            async with sessions() as session, session.begin():
                await _set_tenant(session, source.tenant)
                applications = metadata.tables["autonomous_campaign_applications"]
                await session.execute(update(applications).where(applications.c.tenant_id == source.tenant,
                    applications.c.id == campaign_id).values(mode="owned_loopback_auto", lifecycle_state="APPROVED"))
                store = object.__new__(PostgresAutonomousCampaignAdmissionStartStore)
                store._command = SimpleNamespace(tenant_id=source.tenant, campaign_id=campaign_id)
                with pytest.raises(ApplicationBindingConflict, match="operator_native_source_changed"):
                    await store._lock_current_bundle(session)
                with pytest.raises(OwnedExecutionDenied, match="operator_native_source_changed"):
                    await assert_owned_execution_current(session, {"tenant_id": source.tenant, "campaign_id": campaign_id},
                        now=source.now, enabled=True)
                # This isolated rollback does not advance or mutate the actual HTTP application.
                await session.rollback()
            revoked = await client.post(path + "/revoke", headers={**headers,
                "Idempotency-Key": uuid4().hex, "If-Match": current["etag"]},
                json={"expected_revision": current["aggregate_revision"], "reason": "Operator revokes changed execution scope."})
            assert revoked.status_code == 202, revoked.text
        async with sessions() as session, session.begin():
            await _set_tenant(session, source.tenant)
            for name in ("autonomous_campaign_plan_approval_receipts", "autonomous_campaign_execution_starts", "campaign_effects", "campaign_budget_reservations"):
                table = metadata.tables[name]
                assert await session.scalar(select(func.count()).select_from(table).where(table.c.tenant_id == source.tenant)) == 0
    finally:
        await engine.dispose()
