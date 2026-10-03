"""Normal HTTP intent/preview/decision journey with native PostgreSQL owners.

Only the identity issuer and signed authority source are synthetic. No service
create/stage/approve/admit call is used to seed the application under test.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, select

from redagent_platform.api.runtime import build_runtime_app
from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.application_repository import PostgresAutonomousCampaignApplicationRepository
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.approval_contracts import AutonomousCampaignApprovalContextV1
from redagent_platform.campaign_service.authority_envelope import (
    CampaignApproverRequirementV2, SignedCampaignAuthorityEnvelopeV2, sign_campaign_authority,
)
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.operator_contracts import AutonomousCampaignRootPlanMaterialV1
from redagent_platform.campaign_service.operator_repository import PostgresAutonomousCampaignOperatorOwner
from redagent_platform.campaign_service.operator_service import AutonomousCampaignOperatorService
from redagent_platform.campaign_service.planning.validation import VALIDATOR_SHA256, VALIDATOR_VERSION
from redagent_platform.campaign_service.repository import PostgresCampaignCoreAuthorizedOptionOwner
from redagent_platform.campaign_service.service import CampaignCoreService
from redagent_platform.campaign_service.status import PostgresCampaignCorePresentationOwner
from redagent_platform.persistence.models import metadata
from tests.integration import test_compat_124_campaign_core as native_fixture
from tests.unit.test_campaign_authority_envelope import lifecycle, trusted_key
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_planning_contracts import authority, domain, limits, operator, world


ROOT = Path(__file__).resolve().parents[2]


class NoLegacyStart:
    async def start_campaign(self, *args, **kwargs):
        raise AssertionError("normal canonical journey must not dispatch the legacy owner")


class SyntheticRootAuthoritySource:
    """Exact server-owned synthetic scope; this is not production qualification."""

    def __init__(self, tenant, engagement, target, actor, now):
        self.tenant, self.engagement, self.target, self.actor = tenant, engagement, target, actor
        self.now = now
        self.key = Ed25519PrivateKey.generate()
        self.contexts = {}
        self.reads = 0

    async def read_root_plan(self, *, application, now):
        assert (application.tenant_id, application.engagement_id, application.target_id) == (
            self.tenant, self.engagement, self.target,
        )
        self.reads += 1
        binding = closed_execution_registry()["zap-controlled-runtime@3"]
        capability = replace(operator().capability, capability_id=binding.capability_id,
            capability_revision=binding.capability_revision, adapter_id=binding.adapter_id,
            adapter_version=binding.adapter_version, profile_id=binding.profile_id,
            profile_revision=binding.profile_revision, profile_sha256=binding.profile_sha256,
            bundle_id=binding.bundle_id, bundle_revision=binding.bundle_revision, bundle_sha256=binding.bundle_sha256)
        current_domain = domain(operators=(operator(capability=capability),))
        envelope = authority(envelope_id="authority-" + application.campaign_id[-40:],
            tenant_id=self.tenant, engagement_id=self.engagement, target_ids=(self.target,),
            capability_ids=(binding.capability_id,), valid_from=self.now,
            expires_at=self.now + timedelta(seconds=60),
            required_approvers=(CampaignApproverRequirementV2(self.actor, "campaign-owner"),))
        signature = sign_campaign_authority(envelope, self.key, approver_id=self.actor,
            approver_role="campaign-owner", key_id="operator-fixture-key",
            approved_at=self.now, expires_at=self.now + timedelta(seconds=55))
        context = AutonomousCampaignApprovalContextV1(tenant_id=self.tenant,
            campaign_id=application.campaign_id, signed_authority=SignedCampaignAuthorityEnvelopeV2(envelope, (signature,)),
            authority_lifecycle=lifecycle(envelope, observed_at=self.now, valid_until=self.now + timedelta(seconds=58)))
        self.contexts[application.campaign_id] = context
        return AutonomousCampaignRootPlanMaterialV1(context, current_domain, world(), search_limits())

    async def read_current_approval_context(self, *, tenant_id, campaign_id):
        return self.contexts.get(campaign_id) if tenant_id == self.tenant else None


async def normal_plan_fixture(monkeypatch, *, now=None):
    now = now or native_fixture.NOW
    monkeypatch.setattr(native_fixture, "NOW", now)
    suffix = uuid4().hex[:16]
    tenant, actor, engagement, target, roe = (prefix + suffix for prefix in (
        "tenant-operator-", "actor-operator-", "eng-operator-", "target-operator-", "roe-operator-"))
    engine, sessions = native_fixture._database()
    await native_fixture._bootstrap(sessions, tenant=tenant, actor=actor, engagement=engagement, target=target, roe=roe)
    source = SyntheticRootAuthoritySource(tenant, engagement, target, actor, now)
    def factory(configured_sessions):
        application = AutonomousCampaignApplicationService(
            PostgresAutonomousCampaignApplicationRepository(configured_sessions), mode=AutonomousCampaignMode.PLAN_ONLY,
            approval_context_provider=source, trusted_approval_keys={"operator-fixture-key": trusted_key(
                source.key, key_id="operator-fixture-key", approver_id=actor)}, validation_limits=limits(),
            trusted_validator_version=VALIDATOR_VERSION, trusted_validator_sha256=VALIDATOR_SHA256)
        return AutonomousCampaignOperatorService(CampaignCoreService(
            PostgresCampaignCoreAuthorizedOptionOwner(configured_sessions), NoLegacyStart(),
            presentation=PostgresCampaignCorePresentationOwner(configured_sessions)), application,
            root_plan_source=source, validation_limits=limits(), native_owner=PostgresAutonomousCampaignOperatorOwner(configured_sessions))
    app = build_runtime_app(ROOT, env={"REDAGENT_DATABASE_URL_FILE": str(ROOT / ".local/redagent/runtime/database-url"),
        "REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "plan_only"}, test_issuer_enabled=True,
        autonomous_campaign_operator_service_factory=factory)
    monkeypatch.setattr("redagent_platform.campaign_service.operator_api._now", lambda: now)
    monkeypatch.setattr("redagent_platform.campaign_service.approval_api._now", lambda: now)
    class FixedDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return now
    monkeypatch.setattr("redagent_platform.campaign_service.api.datetime", FixedDateTime)
    headers = {"X-RedAgent-Test-Subject": actor, "X-RedAgent-Test-Tenant": tenant,
        "X-RedAgent-Test-Permissions": "campaign:read,campaign:create,campaign:approve,campaign:admit,campaign:stop,campaign:revoke",
        "X-RedAgent-Policy-Reference": "policy:synthetic-operator-journey"}
    return app, engine, sessions, source, headers


@pytest.mark.parametrize("decision", ["approval", "denial"])
def test_normal_plan_only_http_journey_is_atomic_replayable_and_has_zero_runner_io(monkeypatch, decision):
    asyncio.run(_plan_only_journey(monkeypatch, decision))


async def _plan_only_journey(monkeypatch, decision):
    app, engine, sessions, source, headers = await normal_plan_fixture(monkeypatch)
    try:
        async with app.router.lifespan_context(app), httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://testserver") as client:
            availability = await client.get("/api/v1/campaign-core/operator-availability", headers=headers)
            assert availability.status_code == 200 and availability.json()["data"]["create_available"]
            engagements = (await client.get("/api/v1/campaign-core/options/engagements", headers=headers)).json()["data"]
            targets = (await client.get("/api/v1/campaign-core/options/targets",
                params={"engagement_binding": engagements[0]["binding"]}, headers=headers)).json()["data"]
            risks = (await client.get("/api/v1/campaign-core/options/risk-profiles", headers=headers,
                params={"engagement_binding": engagements[0]["binding"], "target_binding": targets[0]["binding"]})).json()["data"]
            intent = {"engagement_binding": engagements[0]["binding"], "target_binding": targets[0]["binding"],
                "objective": "Assess HTTP security posture", "risk_profile": risks[0]["binding"]}
            create_headers = {**headers, "Idempotency-Key": "normal-intent-" + uuid4().hex}
            extra = await client.post("/api/v1/autonomous-campaigns", headers=create_headers, json={**intent, "mode": "owned_loopback_auto"})
            assert extra.status_code == 422
            assert (await client.post("/api/v1/autonomous-campaigns", headers={**create_headers,
                "X-RedAgent-Test-Permissions": "campaign:read"}, json=intent)).status_code == 403
            created = await client.post("/api/v1/autonomous-campaigns", headers=create_headers, json=intent)
            assert created.status_code == 201, created.text
            data = created.json()["data"]
            assert data["mode"] == "plan_only" and data["lifecycle_state"] == "INTENT_CREATED"
            assert (await client.post("/api/v1/autonomous-campaigns", headers=create_headers, json=intent)).json()["data"]["replayed"]
            path = "/api/v1/autonomous-campaigns/" + data["campaign_id"]
            prepare_headers = {**headers, "Idempotency-Key": "normal-prepare-" + uuid4().hex, "If-Match": data["etag"]}
            prepared = await client.post(path + "/prepare-plan", headers=prepare_headers, json={"expected_revision": 1})
            assert prepared.status_code == 201, prepared.text
            assert (await client.post(path + "/prepare-plan", headers=prepare_headers,
                json={"expected_revision": 1})).json()["data"] == prepared.json()["data"]
            assert source.reads == 1
            current = await client.get(path, headers=headers)
            assert current.status_code == 200, current.text
            status = current.json()["data"]
            assert status["lifecycle_state"] == "AWAITING_APPROVAL" and status["start"] is None
            assert status["operations"]["validation"]["result"] == "valid"
            assert status["operations"]["plan"]["nodes"][0]["capability"] == "ZAP controlled runtime"
            preview = status["preview"]
            body = {"preview_id": preview["preview_id"], "preview_sha256": preview["preview_sha256"]}
            if decision == "denial":
                body["reason_code"] = "operator_denied"
            decide_headers = {**headers, "Idempotency-Key": "normal-decision-" + uuid4().hex, "If-Match": status["preview_etag"]}
            decided = await client.post(path + "/plan-" + decision, headers=decide_headers, json=body)
            assert decided.status_code == 200, decided.text
            assert (await client.post(path + "/plan-" + decision, headers=decide_headers, json=body)).json()["data"]["replayed"]
            final = (await client.get(path, headers=headers)).json()["data"]
            assert final["lifecycle_state"] == ("APPROVED" if decision == "approval" else "DENIED")
            assert final["start"] is None and final["result"]["effect_count"] == 0
            assert final["result"]["export_state"] == "unavailable_without_verified_bundle"
            assert (await client.get(path, headers={**headers, "X-RedAgent-Test-Tenant": "tenant-other"})).status_code == 409
            catalog = (await client.get("/api/v1/campaign-core/campaigns", headers=headers)).json()["data"]
            assert catalog[0]["operator_kind"] == "canonical" and catalog[0]["status"] == final["lifecycle_state"]
            second = await client.post("/api/v1/autonomous-campaigns", headers={**headers,
                "Idempotency-Key": "another-normal-intent-" + uuid4().hex}, json=intent)
            assert second.status_code == 201, second.text
            assert second.json()["data"]["campaign_id"] != data["campaign_id"]
        async with sessions() as session, session.begin():
            await native_fixture._set_tenant(session, source.tenant)
            for name in ("campaign_execution_runs", "campaign_execution_nodes", "campaign_effects", "outbox_events",
                         "autonomous_campaign_execution_starts", "campaign_budget_reservations"):
                table = metadata.tables[name]
                query = select(func.count()).select_from(table).where(table.c.tenant_id == source.tenant)
                if name == "outbox_events":
                    query = query.where(table.c.aggregate_id == data["campaign_id"])
                assert await session.scalar(query) == 0, name
            for name, count in (("autonomous_campaign_applications", 2), ("campaigns", 2),
                                ("autonomous_campaign_plan_previews", 1), ("autonomous_campaign_plan_approval_receipts", 1)):
                table = metadata.tables[name]
                assert await session.scalar(select(func.count()).select_from(table).where(table.c.tenant_id == source.tenant)) == count
    finally:
        await engine.dispose()
