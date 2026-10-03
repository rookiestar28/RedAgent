from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
from uuid import uuid4
from pathlib import Path

import httpx
import pytest

from redagent_platform.api.runtime import build_runtime_app
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.application_repository import PostgresAutonomousCampaignApplicationRepository
from redagent_platform.campaign_service.repository import PostgresCampaignCoreAuthorizedOptionOwner
from redagent_platform.campaign_service.operator_repository import PostgresAutonomousCampaignOperatorOwner
from redagent_platform.campaign_service.operator_service import AutonomousCampaignOperatorService
from redagent_platform.campaign_service.service import CampaignCoreService
from redagent_platform.campaign_service.status import PostgresCampaignCorePresentationOwner
from redagent_platform.orchestration.gateway import OrchestrationUnavailable
from tests.integration.test_autonomous_campaign_admission_start_repository import _prepare_approved_campaign
from tests.integration.test_autonomous_campaign_application_repository import NOW
from tests.integration.test_autonomous_campaign_operator_repository import _current_membership
from tests.unit.test_compat_124_campaign_service import Starter


class NativeFlagObserverGateway:
    def __init__(self, owner, values, *, fail=False):
        self.owner, self.values, self.fail = owner, values, fail
        self.calls = []

    async def stop_campaign_dag(self, workflow_id, request, *, run_id=None):
        status = await self.owner.read_status(**self.values)
        assert status["operations"]["execution"]["stop_requested"] is True
        assert request.actor_user_id == self.values["principal_id"]
        self.calls.append((workflow_id, run_id, request))
        if self.fail:
            raise OrchestrationUnavailable("injected-temporal-signal-unknown")


@pytest.mark.parametrize("signal_unknown", [False, True])
def test_normal_status_and_stop_retain_native_recovery_when_create_mode_and_policy_are_disabled(monkeypatch, signal_unknown):
    asyncio.run(_normal_recovery_scenario(monkeypatch, signal_unknown))


async def _normal_recovery_scenario(monkeypatch, signal_unknown):
    prepared = await _prepare_approved_campaign()
    try:
        actor = await _current_membership(prepared)
        started = await prepared.service.admit_and_queue(prepared.command)
        now = NOW + timedelta(minutes=2)
        values = dict(tenant_id=prepared.tenant, campaign_id=prepared.campaign, principal_id=actor, now=now)
        owner = PostgresAutonomousCampaignOperatorOwner(prepared.sessions)
        gateway = NativeFlagObserverGateway(owner, values, fail=signal_unknown)
        def factory(sessions):
            return AutonomousCampaignOperatorService(
                CampaignCoreService(PostgresCampaignCoreAuthorizedOptionOwner(sessions), Starter(), create_enabled=False,
                                    presentation=PostgresCampaignCorePresentationOwner(sessions)),
                AutonomousCampaignApplicationService(PostgresAutonomousCampaignApplicationRepository(sessions),
                                                     mode=AutonomousCampaignMode.DISABLED),
                native_owner=PostgresAutonomousCampaignOperatorOwner(sessions), stop_gateway=gateway, create_enabled=False,
            )
        root = Path(__file__).resolve().parents[2]
        app = build_runtime_app(root, env={
            "REDAGENT_DATABASE_URL_FILE": str(root / ".local/redagent/runtime/database-url"),
            "REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "disabled",
        }, test_issuer_enabled=True, autonomous_campaign_operator_service_factory=factory)
        app.state.policy_required = True
        app.state.policy_sdk = None
        monkeypatch.setattr("redagent_platform.campaign_service.operator_api._now", lambda: now)
        class FrozenDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return now
        monkeypatch.setattr("redagent_platform.campaign_service.api.datetime", FrozenDateTime)
        headers = {
            "X-RedAgent-Test-Subject": actor, "X-RedAgent-Test-Tenant": prepared.tenant,
            "X-RedAgent-Test-Permissions": "campaign:read,campaign:stop,campaign:revoke",
            "X-RedAgent-Policy-Reference": "policy:operator-recovery-test",
            "Idempotency-Key": f"stop-{uuid4().hex}",
        }
        path = f"/api/v1/autonomous-campaigns/{prepared.campaign}"
        async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver",
        ) as client:
            catalog = await client.get("/api/v1/campaign-core/campaigns", headers=headers)
            assert catalog.status_code == 200
            summary = catalog.json()["data"][0]
            assert summary["operator_kind"] == "canonical"
            assert summary["status"] == started.application.lifecycle_state.value
            assert summary["aggregate_sequence"] == started.application.aggregate_revision
            status = await client.get(path, headers=headers)
            assert status.status_code == 200
            data = status.json()["data"]
            assert data["mode"] == "plan_only" and data["preview_expired"] is True
            assert status.headers["etag"] == data["etag"]
            assert status.headers["cache-control"] == "no-store"
            body = {"expected_revision": data["aggregate_revision"], "reason": "Stop the exact current owned run"}
            denied = await client.post(path + "/stop", headers={**headers, "X-RedAgent-Test-Permissions": "campaign:read"}, json=body)
            assert denied.status_code == 403
            assert (await client.post(path + "/stop", headers=headers, json=body)).status_code == 422
            assert (await client.post(path + "/stop", headers={**headers, "If-Match": '"wrong-etag"'}, json=body)).status_code == 409
            assert gateway.calls == []
            stop_headers = {**headers, "If-Match": data["etag"]}
            stopped = await client.post(path + "/stop", headers=stop_headers, json=body)
            assert stopped.status_code == 202
            stopped_data = stopped.json()["data"]
            assert stopped_data["signal_status"] == ("unknown" if signal_unknown else "acknowledged")
            assert stopped_data["lifecycle_state"] == started.application.lifecycle_state.value
            assert stopped_data["stop_requested"] is True
            assert len(gateway.calls) == 1
            replayed = await client.post(path + "/stop", headers=stop_headers, json=body)
            assert replayed.status_code == 202 and replayed.json()["data"]["replayed"] is True
            assert replayed.json()["data"]["signal_status"] == "not_repeated"
            assert len(gateway.calls) == 1
            after = await client.get(path, headers=headers)
            assert "stop_requested" in after.json()["data"]["attention"]
            assert after.json()["data"]["result"]["cleanup_state"] != "complete"
            revoked = await client.post(path + "/revoke", headers={**headers,
                "Idempotency-Key": "revoke-after-stop", "If-Match": after.headers["etag"]},
                json={"expected_revision": after.json()["data"]["aggregate_revision"], "reason": "Revoke future owned execution authority"})
            assert revoked.status_code == 202
            assert revoked.json()["data"]["lifecycle_state"] == "REVOKED"
            assert len(gateway.calls) == 1
    finally:
        await prepared.engine.dispose()
