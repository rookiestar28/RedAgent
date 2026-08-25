from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.policy_service.boundaries import PolicyBoundarySDK
from redagent_platform.policy_service.enforcement import PolicyBoundaryEnforcer
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider
from redagent_platform.policy_service.repository import TransactionalPolicyDecisionRecorder
from redagent_platform.secret_service.broker import SecretLeaseBroker
from redagent_platform.secret_service.contracts import (
    LeaseIssueRequest,
    SecretReference,
    SecretReferenceKind,
    SecretReferenceStatus,
    WorkloadClient,
)
from redagent_platform.secret_service.fakes import AttestedFakeWorkload, DeterministicFakeSecretProvider
from redagent_platform.secret_service.repository import TransactionalSecretLeaseStore


NOW = datetime(2026, 7, 10, 12, 0, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[2]


def test_postgresql_issue_idempotency_rls_leak_boundary_and_revoke_pending() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r098-{suffix}"
    actor = f"operator-r098-{suffix}"
    engagement = f"engagement-r098-{suffix}"
    roe = f"roe-r098-{suffix}"
    job = f"job-r098-{suffix}"
    reference_id = f"reference-r098-{suffix}"
    client_id = f"client-r098-{suffix}"
    attestation = "a" * 64
    try:
        await _bootstrap(sessions, tenant, actor, engagement, roe, job, suffix)
        store = TransactionalSecretLeaseStore(sessions)
        await store.register_reference(
            SecretReference(
                tenant_id=tenant, reference_id=reference_id, engagement_id=engagement,
                owner_user_id=actor, kind=SecretReferenceKind.DYNAMIC_DATABASE,
                provider_alias="openbao-primary", role_reference="database-role-r098",
                allowed_capabilities=("synthetic-noop",), allowed_permissions=("read",),
                created_at=NOW, expires_at=NOW + timedelta(hours=1),
                rotation_due_at=NOW + timedelta(minutes=30), status=SecretReferenceStatus.ACTIVE,
                redaction_label="synthetic-database-reference",
            ),
            actor_user_id=actor, correlation_id=f"register-reference-{suffix}",
        )
        await store.register_workload(
            WorkloadClient(
                tenant_id=tenant, client_id=client_id, job_id=job, capability="synthetic-noop",
                attestation_fingerprint=attestation, expires_at=NOW + timedelta(hours=1), revoked_at=None,
            ),
            actor_user_id=actor, correlation_id=f"register-client-{suffix}", occurred_at=NOW,
        )

        provider = DeterministicFakeSecretProvider(seed=suffix)
        workload = AttestedFakeWorkload(client_id=client_id, attestation_fingerprint=attestation)
        policy = PolicyBoundarySDK(
            PolicyBoundaryEnforcer(
                DeterministicFakePolicyProvider(revision="synthetic-r099-v1"),
                TransactionalPolicyDecisionRecorder(sessions),
            ),
            required_revision="synthetic-r099-v1",
        )
        broker = SecretLeaseBroker(store, provider, workload, policy)
        request = _request(tenant, engagement, roe, job, reference_id, client_id, suffix)
        issued = await broker.issue(request, actor_user_id=actor, correlation_id=f"issue-{suffix}")
        replayed = await broker.issue(request, actor_user_id=actor, correlation_id=f"replay-{suffix}")
        assert issued.lease["lease_state"] == "active"
        assert issued.lease["expires_at"] == NOW + timedelta(seconds=300)
        assert replayed.replayed
        assert workload.delivery_count == 1
        assert provider.last_material is not None and provider.last_material.cleared

        renewal_request = _request(
            tenant, engagement, roe, job, reference_id, client_id, suffix,
            requested_at=NOW + timedelta(seconds=30),
        )
        renewed = await broker.renew(
            renewal_request, expected_version=1, actor_user_id=actor,
            correlation_id=f"renew-{suffix}",
        )
        assert renewed.lease["renewal_count"] == 1
        assert renewed.lease["version"] == 2
        revoked = await broker.revoke(
            tenant_id=tenant, lease_id=request.lease_id, expected_version=2,
            actor_user_id=actor, correlation_id=f"revoke-{suffix}",
            occurred_at=NOW + timedelta(seconds=60),
        )
        assert revoked.lease["lease_state"] == "revoked"
        duplicate = await broker.revoke(
            tenant_id=tenant, lease_id=request.lease_id, expected_version=2,
            actor_user_id=actor, correlation_id=f"revoke-replay-{suffix}",
            occurred_at=NOW + timedelta(seconds=61),
        )
        assert duplicate.replayed

        async with sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant})
            rows: list[dict[str, object]] = []
            for name in (
                "secret_references", "secret_workload_clients", "secret_lease_operations",
                "secret_leases", "secret_lease_events", "policy_decisions",
                "policy_boundary_receipts", "audit_events", "outbox_events",
            ):
                result = await session.execute(select(metadata.tables[name]).where(metadata.tables[name].c.tenant_id == tenant))
                rows.extend(dict(row) for row in result.mappings())
            rendered = json.dumps(rows, default=str, sort_keys=True)
            assert "R098-SYNTHETIC" not in rendered
            assert "password" not in rendered.lower()

        failing_provider = DeterministicFakeSecretProvider(seed=f"failure-{suffix}")
        failing_provider.fail_revoke = True
        mismatched_workload = AttestedFakeWorkload(client_id=client_id, attestation_fingerprint="b" * 64)
        failed_request = _request(
            tenant, engagement, roe, job, reference_id, client_id, f"failure-{suffix}", lease_id=f"lease-failure-{suffix}"
        )
        with pytest.raises(RuntimeError, match="secret_delivery_failed"):
            await SecretLeaseBroker(store, failing_provider, mismatched_workload, policy).issue(
                failed_request, actor_user_id=actor, correlation_id=f"failure-{suffix}"
            )
        async with sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant})
            state = await session.scalar(
                select(metadata.tables["secret_lease_operations"].c.operation_state).where(
                    metadata.tables["secret_lease_operations"].c.tenant_id == tenant,
                    metadata.tables["secret_lease_operations"].c.lease_id == failed_request.lease_id,
                )
            )
            assert state == "revoke_pending"

        role_name = f"r098_test_{suffix}"
        async with sessions() as session:
            transaction = await session.begin()
            try:
                # CRITICAL: the role identifier is generated exclusively from a hex UUID suffix.
                await session.execute(text(f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS'))
                await session.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
                await session.execute(text(f'GRANT SELECT ON secret_leases TO "{role_name}"'))
                await session.execute(text(f'SET LOCAL ROLE "{role_name}"'))
                await session.execute(
                    text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
                    {"tenant": f"other-r098-{suffix}"},
                )
                hidden = await session.scalar(
                    select(metadata.tables["secret_leases"].c.id).where(metadata.tables["secret_leases"].c.id == request.lease_id)
                )
                assert hidden is None
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


async def _bootstrap(sessions, tenant: str, actor: str, engagement: str, roe: str, job: str, suffix: str) -> None:
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}")
        await repo.bootstrap_tenant(name="compat_098 Secret Tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)
        await repo.create_engagement(
            engagement_id=engagement, name="compat_098 synthetic", owner_user_id=actor,
            idempotency_key=f"eng-{suffix}", occurred_at=NOW,
        )
        created = await repo.create_roe_version(
            roe_version_id=roe, engagement_id=engagement, revision=1,
            document={"active_testing": False}, policy_reference_id=f"policy-reference-{suffix}",
            policy_name="r098-policy", policy_version="1", idempotency_key=f"roe-{suffix}", occurred_at=NOW,
        )
        await repo.approve_roe_version(
            roe_version_id=roe, approval_id=f"approval-{suffix}", expected_version=int(created.resource["version"]),
            idempotency_key=f"approval-{suffix}", occurred_at=NOW,
        )
        await repo.create_job(
            job_id=job, engagement_id=engagement, roe_version_id=roe,
            request={
                "capability": "synthetic-noop", "approval_timeout_seconds": 3600,
                "max_activity_attempts": 3, "budget_reference": "budget:compat_098:fixture",
            },
            workflow_id=f"workflow-{suffix}", policy_reference="policy:compat_098:1", campaign_id=None,
            idempotency_key=f"job-{suffix}", occurred_at=NOW,
        )


def _request(
    tenant: str, engagement: str, roe: str, job: str, reference_id: str, client_id: str,
    suffix: str, *, lease_id: str | None = None, requested_at: datetime = NOW,
) -> LeaseIssueRequest:
    deadline = NOW + timedelta(hours=1)
    return LeaseIssueRequest(
        tenant_id=tenant, lease_id=lease_id or f"lease-r098-{suffix}", reference_id=reference_id,
        engagement_id=engagement, job_id=job, workload_client_id=client_id,
        capability="synthetic-noop", requested_permissions=("read",), requested_at=requested_at,
        ttl_seconds=600, job_deadline=deadline, policy_expires_at=deadline,
        roe_expires_at=deadline, policy_reference="policy:compat_098:1", roe_version_id=roe,
        idempotency_key=f"issue-r098-{suffix}",
    )
