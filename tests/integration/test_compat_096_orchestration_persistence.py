from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.identity.repository import IdentityRepository
from redagent_platform.orchestration.contracts import (
    ActivityCommand,
    CONTRACT_SCHEMA_VERSION,
    JobWorkflowInput,
    deterministic_job_workflow_id,
)
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.repository import (
    ActivityAuthorizationError,
    ControlPlaneRepository,
    IdempotencyConflict,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)


def test_postgres_workflow_admission_command_replay_sod_and_scope_revalidation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex
    tenant = f"tenant-r096-{suffix}"
    operator = f"operator-r096-{suffix}"
    approver = f"approver-r096-{suffix}"
    engagement = f"eng-r096-{suffix}"
    roe = f"roe-r096-{suffix}"
    job = f"job-r096-{suffix}"
    workflow_id = deterministic_job_workflow_id(tenant, job)
    try:
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=operator, correlation_id=f"bootstrap-{suffix}")
            await repo.bootstrap_tenant(name="compat_096 Tenant", occurred_at=NOW)
            await repo.bootstrap_user(user_id=operator, subject=operator, occurred_at=NOW)
            await repo.bootstrap_user(user_id=approver, subject=approver, occurred_at=NOW)
            await repo.create_engagement(engagement_id=engagement, name="compat_096 synthetic", owner_user_id=operator, idempotency_key=f"eng-{suffix}", occurred_at=NOW)
            created_roe = await repo.create_roe_version(
                roe_version_id=roe,
                engagement_id=engagement,
                revision=1,
                document={"active_testing": False},
                policy_reference_id=f"policy-ref-{suffix}",
                policy_name="r096-policy",
                policy_version="1",
                idempotency_key=f"roe-{suffix}",
                occurred_at=NOW,
            )
            await repo.approve_roe_version(
                roe_version_id=roe,
                approval_id=f"roe-approval-{suffix}",
                expected_version=int(created_roe.resource["version"]),
                idempotency_key=f"approve-roe-{suffix}",
                occurred_at=NOW,
            )
            identity = IdentityRepository(session, tenant_id=tenant, actor_user_id=operator, correlation_id=f"identity-{suffix}")
            await identity.provision_membership(user_id=operator, roles=("operator",), occurred_at=NOW)
            await identity.provision_membership(user_id=approver, roles=("approver",), occurred_at=NOW)
            await repo.create_job(
                job_id=job,
                engagement_id=engagement,
                roe_version_id=roe,
                request={
                    "capability": "synthetic-noop",
                    "approval_timeout_seconds": 3600,
                    "max_activity_attempts": 3,
                    "budget_reference": "budget:compat_096:1",
                },
                workflow_id=workflow_id,
                policy_reference="policy:compat_096:1",
                campaign_id=None,
                idempotency_key=f"job-{suffix}",
                occurred_at=NOW,
            )

        workflow_input = JobWorkflowInput(
            CONTRACT_SCHEMA_VERSION,
            tenant,
            job,
            engagement,
            roe,
            "policy:compat_096:1",
            1,
            3600,
            3,
        )
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id="redagent-workflow", correlation_id=f"admit-{suffix}")
            admitted = await repo.admit_workflow_job(workflow_input, workflow_run_id=f"run-{suffix}", occurred_at=NOW)
            assert admitted.state == "awaiting_approval" and admitted.revision == 2

        command = ActivityCommand(
            CONTRACT_SCHEMA_VERSION,
            tenant,
            job,
            f"command-{suffix}",
            "approve",
            approver,
            2,
            "policy:compat_096:1",
            "a" * 64,
        )
        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=approver, correlation_id=f"command-{suffix}")
            accepted = await repo.apply_workflow_command(command, occurred_at=NOW + timedelta(seconds=1))
            replayed = await repo.apply_workflow_command(command, occurred_at=NOW + timedelta(seconds=2))
            assert accepted.state == "ready" and accepted.revision == 3 and accepted.replayed is False
            assert replayed.state == "ready" and replayed.revision == 3 and replayed.replayed is True
            with pytest.raises(IdempotencyConflict, match="workflow_command_id_mismatch"):
                await repo.apply_workflow_command(
                    ActivityCommand(
                        CONTRACT_SCHEMA_VERSION,
                        tenant,
                        job,
                        command.command_id,
                        "approve",
                        approver,
                        2,
                        "policy:compat_096:1",
                        "b" * 64,
                    ),
                    occurred_at=NOW + timedelta(seconds=3),
                )

        async with sessions() as session, session.begin():
            repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=operator, correlation_id=f"sod-{suffix}")
            with pytest.raises(ActivityAuthorizationError, match="workflow_approver_role_required"):
                await repo.apply_workflow_command(
                    ActivityCommand(
                        CONTRACT_SCHEMA_VERSION,
                        tenant,
                        job,
                        f"bad-approve-{suffix}",
                        "approve",
                        operator,
                        3,
                        "policy:compat_096:1",
                        "c" * 64,
                    ),
                    occurred_at=NOW + timedelta(seconds=4),
                )
    finally:
        await engine.dispose()
