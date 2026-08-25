from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.network_service.compiler import compile_network_plan
from redagent_platform.network_service.contracts import (
    NetworkAuthorization,
    NetworkProfileId,
    NetworkProtocol,
    NetworkTargetBinding,
)
from redagent_platform.network_service.repository import NetworkRepository
from redagent_platform.network_service.provisioning import register_network_capability
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 11, 12, 0, tzinfo=timezone.utc)


def test_r107_foundation_target_plan_restart_visibility_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r107-{suffix}"
    actor = f"operator-r107-{suffix}"
    target = NetworkTargetBinding(
        target_set_id="r107-local-fixture",
        topology_sha256="a" * 64,
        route_sha256="b" * 64,
        literal_targets=("10.107.0.10",),
        allowed_ports=(8080, 8443),
        protocol=NetworkProtocol.TCP,
        network_id="redagent-r107-gateway-target",
        non_production=True,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=20),
    )
    authorization = NetworkAuthorization(
        tenant_id=tenant,
        policy_decision_id=f"decision-r107-{suffix}",
        policy_revision="r099-v1",
        roe_version_id=f"roe-r107-{suffix}",
        reservation_id=f"reservation-r107-{suffix}",
        topology_sha256=target.topology_sha256,
        approved_profile_ids=(NetworkProfileId.TCP_CONNECT_DISCOVERY,),
        approved_at=NOW,
        expires_at=NOW + timedelta(minutes=15),
    )
    compiled = compile_network_plan(
        profile_id=NetworkProfileId.TCP_CONNECT_DISCOVERY,
        authorization=authorization,
        target_binding=target,
        now=NOW,
    )
    try:
        async with sessions() as session, session.begin():
            await ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}",
            ).bootstrap_tenant(name="compat_107 network assessment", occurred_at=NOW)
            registered = await register_network_capability(
                session, workspace=ROOT, tenant_id=tenant, actor_user_id=actor,
                correlation_id=f"capability-{suffix}", occurred_at=NOW,
            )
            assert registered["capability_id"] == "network-assessment"
            assert registered["image_digest"].startswith("sha256:")
            repository = NetworkRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"network-{suffix}",
            )
            first = await repository.certify_foundation(
                artifact_sha256="c" * 64, sbom_sha256="d" * 64,
                license_review_sha256="e" * 64,
                vulnerability_review="accepted_no_critical", occurred_at=NOW,
            )
            replay = await repository.certify_foundation(
                artifact_sha256="c" * 64, sbom_sha256="d" * 64,
                license_review_sha256="e" * 64,
                vulnerability_review="accepted_no_critical", occurred_at=NOW,
            )
            assert replay["id"] == first["id"]
            await repository.register_target_binding(
                topology_id=f"topology-r107-{suffix}", target=target, occurred_at=NOW,
            )
            plan = await repository.store_plan(
                plan_id=f"plan-r107-{suffix}", compiled=compiled,
                target=target, authorization=authorization, occurred_at=NOW,
            )
            assert plan["plan_sha256"] == compiled.plan_sha256
            dashboard = await repository.dashboard()
            assert len(dashboard["profiles"]) == 1
            assert len(dashboard["plans"]) == 1
            assert dashboard["runs"] == []
            assert dashboard["target_options"][0]["target_set_id"] == "r107-local-fixture"
            assert dashboard["runner_options"] == []
            assert dashboard["job_options"] == []
            assert dashboard["reservation_options"] == []

        async with sessions() as session, session.begin():
            other_tenant = f"tenant-other-r107-{suffix}"
            await ControlPlaneRepository(
                session, tenant_id=other_tenant, actor_user_id=actor, correlation_id=f"other-{suffix}",
            ).bootstrap_tenant(name="Other compat_107 tenant", occurred_at=NOW)
            other = await NetworkRepository(
                session, tenant_id=other_tenant, actor_user_id=actor, correlation_id=f"other-{suffix}",
            ).dashboard()
            assert all(not rows for rows in other.values())
    finally:
        await engine.dispose()
