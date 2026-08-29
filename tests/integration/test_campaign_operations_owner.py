from __future__ import annotations

import asyncio
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.campaign_service.operations import PostgresCampaignOperationsOwner
from redagent_platform.campaign_service.status import CampaignStatusNotFound
from redagent_platform.persistence.database import load_database_settings
from tests.integration.test_campaign_dag_execution_repository import _bootstrap
from tests.integration.test_migrations import _alembic, _create_database, _drop_database
from tests.unit.test_campaign_planning_contracts import NOW


ROOT = Path(__file__).resolve().parents[2]


def test_campaign_operations_owner_is_tenant_scoped_and_projects_legacy_state() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    suffix = uuid4().hex
    settings = load_database_settings(ROOT, env=os.environ)
    database_name = f"r162_{suffix}"
    test_url = settings.url.set(database=database_name)
    secret_dir = ROOT / ".local" / "redagent" / "test-databases" / database_name
    secret_file = secret_dir / "database-url"
    secret_dir.mkdir(parents=True, exist_ok=False)
    secret_file.write_text(
        f"{test_url.render_as_string(hide_password=False)}\n",
        encoding="utf-8",
    )
    try:
        await _create_database(settings.url.set(database="postgres"), database_name)
        upgraded = _alembic(secret_file, "upgrade", "head")
        assert upgraded.returncode == 0, upgraded.stderr
    except BaseException:
        await _drop_database(settings.url.set(database="postgres"), database_name)
        secret_file.unlink(missing_ok=True)
        secret_dir.rmdir()
        raise

    engine = create_async_engine(test_url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    tenant = f"tenant-operations-{suffix}"[:64]
    actor = f"user-operations-{suffix}"[:64]
    campaign = f"campaign-operations-{suffix}"[:64]
    engagement = f"eng-operations-{suffix}"[:64]
    owner = PostgresCampaignOperationsOwner(sessions)
    try:
        await _bootstrap(
            sessions,
            tenant=tenant,
            actor=actor,
            campaign=campaign,
            engagement=engagement,
            suffix=suffix,
        )

        projected = await owner.read(tenant_id=tenant, campaign_id=campaign, now=NOW)
        assert projected["preparation_state"] == "not_prepared"
        assert projected["evidence"]["export_state"] == "unavailable_without_verified_bundle"

        with pytest.raises(CampaignStatusNotFound, match="campaign_operations_not_found"):
            await owner.read(
                tenant_id=f"tenant-other-{suffix}"[:64],
                campaign_id=campaign,
                now=NOW,
            )
    finally:
        await engine.dispose()
        await _drop_database(settings.url.set(database="postgres"), database_name)
        secret_file.unlink(missing_ok=True)
        secret_dir.rmdir()
