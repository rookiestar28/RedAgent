"""Opt-in loopback PLAN_ONLY API for browser tests; never a runtime entrypoint."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone

import pytest
import uvicorn
from sqlalchemy import func, select

from redagent_platform.persistence.models import metadata
from tests.integration.test_autonomous_campaign_operator_journey import normal_plan_fixture
from tests.integration.test_compat_124_campaign_core import _set_tenant


async def serve():
    if os.environ.get("REDAGENT_OPERATOR_BROWSER_TEST") != "plan-only-v1":
        raise RuntimeError("explicit_plan_only_browser_opt_in_required")
    monkeypatch = pytest.MonkeyPatch()
    app, engine, sessions, source, headers = await normal_plan_fixture(monkeypatch, now=datetime.now(timezone.utc))
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=4311, log_level="warning"))

    @app.get("/__test_fixture__")
    async def fixture():
        return {"headers": headers, "scope": "synthetic-plan-only-native-postgres"}

    @app.get("/__test_fixture__/counts")
    async def counts():
        async with sessions() as session, session.begin():
            await _set_tenant(session, source.tenant)
            values = {}
            for name in ("campaign_execution_runs", "campaign_effects", "campaign_budget_reservations",
                         "autonomous_campaign_execution_starts", "autonomous_campaign_applications",
                         "autonomous_campaign_plan_previews", "autonomous_campaign_plan_approval_receipts"):
                table = metadata.tables[name]
                values[name] = await session.scalar(select(func.count()).select_from(table).where(table.c.tenant_id == source.tenant))
            return values

    @app.post("/__test_fixture__/stop")
    async def stop():
        server.should_exit = True
        return {"stopping": True}

    try:
        print(json.dumps({"server": "owned-plan-only-browser", "port": 4311}), flush=True)
        await server.serve()
    finally:
        await engine.dispose()
        monkeypatch.undo()


if __name__ == "__main__":
    asyncio.run(serve())
