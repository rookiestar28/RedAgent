from __future__ import annotations

import asyncio
from datetime import datetime, timedelta
import hashlib
import os
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import insert
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.api.routers import nuclei as nuclei_routes
from redagent_platform.api.app import create_app
from redagent_platform.nuclei_service.artifact_promotion import verify_current_nuclei_artifact_promotion
from redagent_platform.nuclei_service.contracts import CURRENT_R105_TARGET_IMAGE_ID, R105_TARGET_SOURCE_SHA256, NucleiTargetBinding
from redagent_platform.nuclei_service.promotion import verify_current_nuclei_bundle_promotion
from redagent_platform.nuclei_service.repository import NucleiRepository
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime.fromisoformat("2026-10-02T11:58:19.928804+00:00") + timedelta(minutes=1)


def test_nuclei_profiles_compile_dashboard_permissions_and_closed_input(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(nuclei_routes, "_now", lambda: NOW)
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r105-api-{suffix}"
    actor = f"operator-r105-{suffix}"
    roe_id = f"roe-r105-{suffix}"
    decision_id = f"decision-r105-{suffix}"
    attestation_sha = "a" * 64
    promoted = verify_current_nuclei_bundle_promotion(
        manifest_bytes=(ROOT / "bundles/r105-nuclei/bundle-manifest-v3.json").read_bytes(),
        signature_bundle_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.sigstore.json").read_bytes(),
        public_key_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.pub").read_bytes(),
        template_bytes=(ROOT / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml").read_bytes(),
        certificate_bytes=(ROOT / "config/trust/r105-nuclei-user.crt").read_bytes(),
        qualification_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_RUNTIME_QUALIFICATION_V3.json").read_bytes(),
        now=NOW,
    )
    artifact_receipt, artifact_signature_sha = verify_current_nuclei_artifact_promotion(
        promotion_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.json").read_bytes(),
        signature_bundle_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.sigstore.json").read_bytes(),
        public_key_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_ARTIFACT_PROMOTION_V3.pub").read_bytes(),
        runtime_lock_bytes=(ROOT / "config/r105-nuclei-runtime-v3.json").read_bytes(),
        qualification_bytes=(ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_RUNTIME_QUALIFICATION_V3.json").read_bytes(),
        now=NOW,
    )
    target = NucleiTargetBinding(
        target_id="r105-owned-http-fixture", attestation_sha256=attestation_sha,
        endpoint="http://redagent-r105-gateway:8080", allowed_paths=("/nuclei/missing-header",),
        network_id="redagent-r105-gateway-target", non_production=True,
        issued_at=NOW, expires_at=NOW + timedelta(minutes=15),
    )
    try:
        async with sessions() as session, session.begin():
            await ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=actor,
                                         correlation_id=f"bootstrap-{suffix}").bootstrap_tenant(
                                             name="compat_105 Nuclei API", occurred_at=NOW)
            owned = {"tenant_id": tenant, "version": 1, "created_at": NOW, "updated_at": NOW}
            engagement_id = f"engagement-r105-{suffix}"
            await session.execute(insert(metadata.tables["engagements"]).values(
                id=engagement_id, name="compat_105 API fixture", owner_user_id=actor, **owned))
            await session.execute(insert(metadata.tables["roe_versions"]).values(
                id=roe_id, engagement_id=engagement_id, revision=1, status="approved",
                document={"target": "r105-owned-http-fixture"}, **owned))
            await session.execute(insert(metadata.tables["policy_decisions"]).values(
                id=f"policy-decision-{suffix}", opa_decision_id=decision_id,
                bundle_revision="r099-v1", input_hash="b" * 64, boundary="api",
                action="nuclei.plan.compile", subject_id=actor, resource_type="nuclei_profile",
                resource_id="nuclei-http-header-v1", resource_version=1, allowed=True,
                reason_code="r105_profile_approved", obligations=["owned_fixture_only"],
                issued_at=NOW, valid_until=NOW + timedelta(minutes=15),
                correlation_id=f"seed-{suffix}", **owned))
            repository = NucleiRepository(session, tenant_id=tenant, actor_user_id=actor,
                                          correlation_id=f"seed-r105-{suffix}")
            await repository.ensure_certified_foundation(
                bundle=promoted, artifact_signature_sha256=artifact_signature_sha,
                artifact_provenance_sha256=artifact_receipt.provenance_sha256,
                bundle_signature_sha256=hashlib.sha256((ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_BUNDLE_PROMOTION_V3.sigstore.json").read_bytes()).hexdigest(),
                occurred_at=NOW)
            await repository.register_target_attestation(
                attestation_id=f"attestation-r105-{suffix}", target=target,
                target_source_sha256=R105_TARGET_SOURCE_SHA256, target_image_id=CURRENT_R105_TARGET_IMAGE_ID,
                address_sha256="c" * 64, occurred_at=NOW)
    finally:
        await engine.dispose()

    app = create_app(database_settings=settings, test_issuer_enabled=True,
                     policy_provider=DeterministicFakePolicyProvider(revision="r099-v1"),
                     policy_required_revision="r099-v1")
    base = {"X-RedAgent-Test-Subject": actor, "X-RedAgent-Test-Tenant": tenant,
            "X-Correlation-ID": f"api-r105-{suffix}"}
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
                                     base_url="http://testserver") as client:
            profiles = await client.get("/api/v1/nuclei/profiles", headers={
                **base, "X-RedAgent-Test-Permissions": "job:read"})
            assert profiles.status_code == 200, profiles.text
            assert [row["profile_id"] for row in profiles.json()["data"]] == ["nuclei-http-header-v1"]
            payload = {
                "plan_id": f"plan-r105-{suffix}", "profile_id": "nuclei-http-header-v1",
                "bundle_id": "r105-http-header-bundle", "bundle_revision": 3,
                "target_id": "r105-owned-http-fixture", "target_attestation_sha256": attestation_sha,
                "policy_decision_id": decision_id, "policy_revision": "r099-v1",
                "roe_version_id": roe_id,
            }
            headers = {**base, "X-RedAgent-Test-Permissions": "job:create",
                       "X-RedAgent-Policy-Reference": "policy:compat_105:compile",
                       "X-RedAgent-ROE-Version": roe_id, "Idempotency-Key": f"compile-{suffix}"}
            compiled = await client.post("/api/v1/nuclei/plans", headers=headers, json=payload)
            assert compiled.status_code == 201, compiled.text
            assert compiled.json()["data"]["bundle_id"] == "r105-http-header-bundle"
            dashboard = await client.get("/api/v1/nuclei/dashboard", headers={
                **base, "X-RedAgent-Test-Permissions": "audit:read"})
            assert dashboard.status_code == 200, dashboard.text
            assert dashboard.json()["data"]["plans"][0]["plan_id"] == payload["plan_id"]
            assert dashboard.json()["data"]["profiles"][0]["bundle_revision"] == 3
            assert dashboard.json()["data"]["profiles"][0]["image_digest"] == profiles.json()["data"][0]["image_digest"]
            denied = await client.get("/api/v1/nuclei/profiles", headers={
                **base, "X-RedAgent-Test-Permissions": "audit:read"})
            assert denied.status_code == 403
            arbitrary = await client.post("/api/v1/nuclei/plans", headers={**headers,
                "X-Correlation-ID": f"api-r105-bad-{suffix}", "Idempotency-Key": f"bad-{suffix}"},
                json={**payload, "template_url": "https://example.com/template.yaml"})
            assert arbitrary.status_code == 422, arbitrary.text
