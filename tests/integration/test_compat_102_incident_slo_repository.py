from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.telemetry_service.incidents import IncidentAction
from redagent_platform.telemetry_service.operations import (
    IncidentRepository, ObservabilityRepositoryConflict, SloRepository,
)
from redagent_platform.telemetry_service.slo import SloObjective


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 11, 5, 0, tzinfo=timezone.utc)


def test_incident_lifecycle_and_slo_truth_are_durable_audited_and_idempotent() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r102ops-{suffix}"
    try:
        async with sessions() as session, session.begin():
            control = ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=f"operator-{suffix}",
                correlation_id=f"bootstrap-{suffix}",
            )
            await control.bootstrap_tenant(name="compat_102 Operations", occurred_at=NOW)

        async with sessions() as session, session.begin():
            incidents = IncidentRepository(
                session, tenant_id=tenant, actor_user_id=f"operator-{suffix}",
                correlation_id=f"incident-{suffix}",
            )
            opened = await incidents.open_incident(
                incident_id=f"incident-{suffix}", source_kind="containment",
                source_id=f"containment-{suffix}", severity="critical",
                reason_code="containment_incomplete", occurred_at=NOW,
            )
            replay = await incidents.open_incident(
                incident_id=f"incident-{suffix}", source_kind="containment",
                source_id=f"containment-{suffix}", severity="critical",
                reason_code="containment_incomplete", occurred_at=NOW,
            )
            assert replay["id"] == opened["id"]
            with pytest.raises(ObservabilityRepositoryConflict, match="incident_open_replay_mismatch"):
                await incidents.open_incident(
                    incident_id=f"incident-{suffix}", source_kind="alert",
                    source_id=f"alert-{suffix}", severity="critical",
                    reason_code="containment_incomplete", occurred_at=NOW,
                )

        actions = (
            (IncidentAction.ASSIGN, "dispatcher", "responder"),
            (IncidentAction.ACKNOWLEDGE, "responder", None),
            (IncidentAction.PRESERVE_EVIDENCE, "responder", None),
            (IncidentAction.VERIFY_CONTAINMENT, "verifier", None),
            (IncidentAction.MARK_CONTAINED, "responder", None),
            (IncidentAction.MARK_RECOVERED, "recovery", None),
            (IncidentAction.COMPLETE_REVIEW, "reviewer", None),
            (IncidentAction.CLOSE, "closer", None),
        )
        version = 1
        for index, (action, actor, assignee) in enumerate(actions, start=1):
            async with sessions() as session, session.begin():
                repository = IncidentRepository(
                    session, tenant_id=tenant, actor_user_id=f"{actor}-{suffix}",
                    correlation_id=f"action-{index}-{suffix}",
                )
                result = await repository.apply_action(
                    incident_id=f"incident-{suffix}", action_id=f"action-{index}-{suffix}",
                    action=action, expected_version=version, occurred_at=NOW + timedelta(seconds=index),
                    assignee_id=f"{assignee}-{suffix}" if assignee else None,
                )
                assert result["version"] == version + 1
                version += 1

        objective = SloObjective(
            objective_id="telemetry_export_availability", target_basis_points=9900,
            window_seconds=300,
        )
        async with sessions() as session, session.begin():
            slos = SloRepository(
                session, tenant_id=tenant, actor_user_id=f"slo-evaluator-{suffix}",
                correlation_id=f"slo-{suffix}",
            )
            definition = await slos.register_objective(
                objective, revision=1, metric_name="telemetry_export_failure", occurred_at=NOW,
            )
            evaluation = await slos.evaluate_ratio_window(
                definition_id=str(definition["id"]), window_start=NOW,
                window_end=NOW + timedelta(minutes=5), total=100, bad=5, missing=0,
                source_hash="a" * 64, occurred_at=NOW + timedelta(minutes=5),
            )
            assert evaluation["evaluation_state"] == "breaching"
            repeated = await slos.evaluate_ratio_window(
                definition_id=str(definition["id"]), window_start=NOW,
                window_end=NOW + timedelta(minutes=5), total=100, bad=5, missing=0,
                source_hash="a" * 64, occurred_at=NOW + timedelta(minutes=5),
            )
            assert repeated["id"] == evaluation["id"]
            dashboard = await slos.dashboard()
            assert dashboard["slo_state_counts"]["breaching"] == 1
            assert dashboard["open_alerts"] == 1

        async with sessions() as session, session.begin():
            incidents = metadata.tables["security_incidents"]
            timeline = metadata.tables["incident_timeline_events"]
            audit = metadata.tables["audit_events"]
            assert await session.scalar(select(func.count()).select_from(incidents).where(
                incidents.c.tenant_id == tenant, incidents.c.incident_state == "closed",
            )) == 1
            assert await session.scalar(select(func.count()).select_from(timeline).where(
                timeline.c.tenant_id == tenant,
            )) == 9
            assert await session.scalar(select(func.count()).select_from(audit).where(
                audit.c.tenant_id == tenant, audit.c.subject_type.in_(("incident", "slo")),
            )) >= 10
    finally:
        await engine.dispose()
