from __future__ import annotations

import asyncio
import hashlib
import os
from pathlib import Path
from uuid import uuid4

import pytest

from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.persistence.database import load_database_settings
from tests.integration.test_autonomous_campaign_admission_start_repository import _prepare_approved_campaign
from tests.integration.test_migrations import _alembic, _create_database, _drop_database


ROOT = Path(__file__).resolve().parents[2]


def test_native_closed_two_node_root_still_requires_physical_terminal_parent_before_child():
    asyncio.run(_scenario())


async def _scenario():
    settings = load_database_settings(ROOT, env=os.environ)
    name = "child_root_" + uuid4().hex
    url = settings.url.set(database=name)
    directory = ROOT / ".local/redagent/test-databases" / name
    directory.mkdir(parents=True, exist_ok=False)
    secret = directory / "database-url"
    secret.write_text(url.render_as_string(hide_password=False), encoding="utf-8")
    saved = os.environ.get("REDAGENT_DATABASE_URL_FILE")
    prepared = None
    try:
        await _create_database(settings.url.set(database="postgres"), name)
        migrated = _alembic(secret, "upgrade", "head")
        assert migrated.returncode == 0, migrated.stderr
        os.environ["REDAGENT_DATABASE_URL_FILE"] = str(secret)
        prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.BOUNDED_REPLAN,
            validity_seconds=180, bounded_manifest_sha256s={"zap-controlled-runtime": "a" * 64, "nuclei-trusted-runtime": "b" * 64})
        admitted = await prepared.service.admit_and_queue(prepared.command)
        assert admitted.admission_receipt.outcome.value == "admitted"
        assert len(prepared.context.revision.candidate_plan.nodes) == 2
        assert admitted.admission_receipt.reserved_budget.rate_per_minute == 60
        from redagent_platform.zap_service.capability import build_zap_capability_manifest
        from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
        from tests.integration.test_owned_execution_live import _install_runner

        for factory in (build_zap_capability_manifest, build_nuclei_capability_manifest):
            capability = factory(platform="linux/amd64", artifact_receipt_id="owned-fixture-artifact")
            suffix = uuid4().hex
            await _install_runner(prepared, capability, suffix, prepared.command.occurred_at,
                class_identity="owned-closed-" + capability.capability_id,
                certificate_fingerprint=hashlib.sha256(("owned-fixture-certificate:" + suffix).encode()).hexdigest())
        from redagent_platform.campaign_service.child_replan_store import load_completed_owned_parent

        class NoBackend:
            def verify_exact(self, *args):
                raise AssertionError("nonterminal parent must deny before backend proof")

            def get_exact(self, *args):
                raise AssertionError("nonterminal parent must deny before backend proof")

        async with prepared.sessions() as session, session.begin():
            with pytest.raises(RuntimeError, match="terminal_cleanup"):
                await load_completed_owned_parent(session, tenant_id=prepared.tenant,
                    application_id=prepared.campaign, parent_execution_run_id=admitted.execution_run_id,
                    actor_user_id=prepared.command.actor_user_id, correlation_id="child-root-negative",
                    evidence_backend=NoBackend(), now=prepared.command.occurred_at,
                    authority=prepared.context.signed_authority.authority, lock_rows=False)
    finally:
        if prepared is not None:
            await prepared.engine.dispose()
        if saved is None:
            os.environ.pop("REDAGENT_DATABASE_URL_FILE", None)
        else:
            os.environ["REDAGENT_DATABASE_URL_FILE"] = saved
        await _drop_database(settings.url.set(database="postgres"), name)
        secret.unlink(missing_ok=True)
        directory.rmdir()
