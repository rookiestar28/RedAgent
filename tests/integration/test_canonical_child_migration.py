from __future__ import annotations

import asyncio
from dataclasses import replace
import os
import importlib
from pathlib import Path
from uuid import uuid4

import pytest

from sqlalchemy import text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.application_repository import PostgresAutonomousCampaignApplicationRepository
from redagent_platform.persistence.database import load_database_settings
from tests.integration.test_autonomous_campaign_application_repository import _bootstrap, _create_command
from tests.integration.test_migrations import _alembic, _create_database, _drop_database


ROOT = Path(__file__).resolve().parents[2]


def test_postgres_child_schema_empty_rollback_rls_and_populated_bounded_mode_refusal():
    asyncio.run(_scenario())


async def _scenario():
    settings = load_database_settings(ROOT, env=os.environ)
    suffix = uuid4().hex
    name = "child_" + suffix
    url = settings.url.set(database=name)
    directory = ROOT / ".local/redagent/test-databases" / name
    directory.mkdir(parents=True, exist_ok=False)
    secret = directory / "database-url"
    secret.write_text(url.render_as_string(hide_password=False), encoding="utf-8")
    engine = create_async_engine(url)
    try:
        await _create_database(settings.url.set(database="postgres"), name)
        result = _alembic(secret, "upgrade", "head")
        assert result.returncode == 0, result.stderr
        rolled_back = _alembic(secret, "downgrade", "0032_owned_execution_mode")
        assert rolled_back.returncode == 0, rolled_back.stderr
        reapplied = _alembic(secret, "upgrade", "head")
        assert reapplied.returncode == 0, reapplied.stderr
        async with engine.begin() as connection:
            rows = (await connection.execute(text(
                "SELECT relname, relrowsecurity, relforcerowsecurity FROM pg_class "
                "WHERE relname IN ('campaign_child_capacity_settlements','autonomous_campaign_child_replans')"
            ))).all()
            assert len(rows) == 2 and all(row.relrowsecurity and row.relforcerowsecurity for row in rows)
            count = await connection.scalar(text(
                "SELECT count(*) FROM pg_trigger WHERE tgname IN "
                "('campaign_child_capacity_settlements_immutable','autonomous_campaign_child_replans_immutable')"
            ))
            assert count == 2
        sessions = async_sessionmaker(engine, expire_on_commit=False)
        tenant = "tenant-child-" + suffix
        actor, engagement, target = await _bootstrap(sessions, tenant=tenant, suffix=suffix)
        command = replace(_create_command(tenant=tenant, actor=actor, engagement=engagement,
                                         target=target, suffix=suffix), mode=AutonomousCampaignMode.BOUNDED_REPLAN)
        repository = PostgresAutonomousCampaignApplicationRepository(sessions)
        created = await repository.create_intent(command)
        assert created.application.mode is AutonomousCampaignMode.BOUNDED_REPLAN
        denied = _alembic(secret, "downgrade", "0032_owned_execution_mode")
        assert denied.returncode != 0 and "mode_before_child" in denied.stderr
        persisted = await repository.read(tenant_id=tenant, campaign_id=command.campaign_id)
        assert persisted is not None and persisted.mode is AutonomousCampaignMode.BOUNDED_REPLAN
        function = getattr(importlib.import_module("redagent_platform.campaign_service.child_replan_store"),
                           "load_completed_owned_parent", None)
        assert callable(function), "Canonical observation intake must read the actual tenant-owned parent"
        class NoBackendContact:
            def get_exact(self, *args):
                raise AssertionError("Missing/cross-tenant parent must deny before backend contact")

            def verify_exact(self, *args):
                raise AssertionError("Missing/cross-tenant parent must deny before backend contact")

        for scope in (tenant, "tenant-missing"):
            async with sessions() as session, session.begin():
                with pytest.raises(RuntimeError, match="child_parent_run_missing"):
                    await function(session, tenant_id=scope, application_id=command.campaign_id,
                                   parent_execution_run_id="missing-run", actor_user_id=actor,
                                   correlation_id="child-source-test", evidence_backend=NoBackendContact(),
                                   now=command.occurred_at)
        from redagent_platform.campaign_service.child_replan_contracts import CHILD_REQUEST_SCHEMA_VERSION, PrepareAutonomousCampaignChildV1
        store_type = getattr(importlib.import_module("redagent_platform.campaign_service.child_replan_store"),
                             "PostgresCanonicalChildReplanStore", None)
        assert store_type is not None, "Canonical staging requires one transaction-owned child store"

        async def no_context(**kwargs):
            raise AssertionError("An application without a parent must deny before context preparation")

        def no_preview(*args):
            raise AssertionError("An application without a parent cannot produce a preview")

        child_command = PrepareAutonomousCampaignChildV1(schema_version=CHILD_REQUEST_SCHEMA_VERSION,
            tenant_id=tenant, campaign_id=command.campaign_id, actor_user_id=actor, expected_revision=1,
            idempotency_key="child-without-parent", correlation_id="child-without-parent", occurred_at=command.occurred_at)
        with pytest.raises(RuntimeError, match="child_parent_start_missing"):
            await store_type(sessions, evidence_backend=NoBackendContact()).stage_child(
                child_command, read_context=no_context, build_preview=no_preview, trusted_keys={})
        async with engine.begin() as connection:
            revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
            assert revision == "0033_bounded_child_replanning"
    finally:
        await engine.dispose()
        await _drop_database(settings.url.set(database="postgres"), name)
        secret.unlink(missing_ok=True)
        directory.rmdir()
