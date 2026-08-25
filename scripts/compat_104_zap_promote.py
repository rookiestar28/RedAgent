#!/usr/bin/env python3
"""Verify and register the signed compat_104 artifact in the compat_100 registry."""

from __future__ import annotations

import argparse
import asyncio
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.zap_service.provisioning import register_zap_capability


IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")


async def _run(*, tenant_id: str, actor_user_id: str) -> dict[str, object]:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as session, session.begin():
            return await register_zap_capability(
                session, workspace=ROOT, tenant_id=tenant_id,
                actor_user_id=actor_user_id, correlation_id="r104-local-artifact-promotion",
                occurred_at=datetime.now(timezone.utc),
            )
    finally:
        await engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tenant-id", required=True)
    parser.add_argument("--actor-user-id", required=True)
    parser.add_argument("--confirm-r104-local-lab", action="store_true")
    args = parser.parse_args()
    if not args.confirm_r104_local_lab:
        parser.error("--confirm-r104-local-lab is required")
    if not IDENTIFIER.fullmatch(args.tenant_id) or not IDENTIFIER.fullmatch(args.actor_user_id):
        parser.error("tenant and actor IDs must be closed opaque identifiers")
    result = asyncio.run(_run(tenant_id=args.tenant_id, actor_user_id=args.actor_user_id))
    print(json.dumps({"ok": True, "action": "promote", **result}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
