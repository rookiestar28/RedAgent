from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from uuid import uuid4

import pytest
from sqlalchemy import func, insert, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.containment_service.contracts import (
    REQUIRED_CONTAINMENT_PHASES, ControlScope, ControlScopeKind, PhaseReceipt,
    QuotaDimension, QuotaPolicy,
    StopApproval, StopRequest, canonical_stop_hash,
)
from redagent_platform.containment_service.repository import ContainmentRepository, ContainmentRepositoryConflict
from redagent_platform.containment_service.reconciliation import ContainmentReconciler
from redagent_platform.containment_service.revocation import (
    AuthorityFacts, PersistentRevocationStopActivator, RevocationMonitor,
)
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = __import__("pathlib").Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 19, 0, tzinfo=timezone.utc)


def test_persistent_stop_sod_replay_atomic_quota_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r101-{suffix}"
    initiator = f"initiator-{suffix}"
    approver = f"approver-{suffix}"
    reviewer = f"reviewer-{suffix}"
    campaign = f"campaign-{suffix}"
    job_id = f"job-{suffix}"
    try:
        async with sessions() as session, session.begin():
            control = ControlPlaneRepository(session, tenant_id=tenant, actor_user_id=initiator, correlation_id=f"bootstrap-{suffix}")
            await control.bootstrap_tenant(name="compat_101 Tenant", occurred_at=NOW)
            await control.bootstrap_user(user_id=initiator, subject=initiator, occurred_at=NOW)
            await control.bootstrap_user(user_id=approver, subject=approver, occurred_at=NOW)
            await control.bootstrap_user(user_id=reviewer, subject=reviewer, occurred_at=NOW)
            engagement_id = f"engagement-{suffix}"
            roe_id = f"roe-{suffix}"
            await session.execute(insert(metadata.tables["engagements"]).values(
                id=engagement_id, name="compat_101 synthetic engagement", owner_user_id=initiator,
                tenant_id=tenant, version=1, created_at=NOW, updated_at=NOW,
            ))
            await session.execute(insert(metadata.tables["roe_versions"]).values(
                id=roe_id, engagement_id=engagement_id, revision=1, status="approved",
                document={}, tenant_id=tenant, version=1, created_at=NOW, updated_at=NOW,
            ))
            await session.execute(insert(metadata.tables["jobs"]).values(
                id=job_id, engagement_id=engagement_id, roe_version_id=roe_id,
                created_by_user_id=initiator, campaign_id=None, status="running", request={},
                policy_reference="policy:r101-v1", workflow_id=f"workflow-{suffix}", workflow_run_id=f"run-{suffix}",
                orchestration_state="stop_requested", orchestration_revision=4,
                current_gate="containment_owned_by_r101", failure_code=None, retry_count=0,
                dispatch_blocked=True, stop_requested=True, tenant_id=tenant,
                version=1, created_at=NOW, updated_at=NOW,
            ))

        request = StopRequest(
            schema_version="1.0", stop_id=f"stop-{suffix}", tenant_id=tenant,
            scope=ControlScope(ControlScopeKind.CAMPAIGN, campaign), initiated_by=initiator,
            reason="Synthetic campaign emergency stop", requested_at=NOW,
            expected_version=1, idempotency_key=f"stop-request-{suffix}",
        )
        async with sessions() as session, session.begin():
            repository = ContainmentRepository(session, tenant_id=tenant, actor_user_id=initiator, correlation_id=f"stop-{suffix}")
            pending = await repository.request_stop(request)
            replay = await repository.request_stop(request)
            assert pending["control_state"] == "pending_approval"
            assert replay["id"] == pending["id"]
            mutated = StopRequest(**{**request.__dict__, "reason": "Mutated reason"})
            with pytest.raises(ContainmentRepositoryConflict, match="containment_request_idempotency_mismatch"):
                await repository.request_stop(mutated)

        same_actor = StopApproval(
            approval_id=f"approval-same-{suffix}", stop_id=request.stop_id, tenant_id=tenant,
            approver_user_id=initiator, request_hash=canonical_stop_hash(request),
            approved_at=NOW + timedelta(seconds=1), expected_version=1,
        )
        async with sessions() as session, session.begin():
            repository = ContainmentRepository(session, tenant_id=tenant, actor_user_id=initiator, correlation_id=f"approve-bad-{suffix}")
            with pytest.raises(ContainmentRepositoryConflict, match="stop_approval_separation_required"):
                await repository.approve_stop(same_actor)

        approval = StopApproval(
            approval_id=f"approval-{suffix}", stop_id=request.stop_id, tenant_id=tenant,
            approver_user_id=approver, request_hash=canonical_stop_hash(request),
            approved_at=NOW + timedelta(seconds=2), expected_version=1,
        )
        async with sessions() as session, session.begin():
            repository = ContainmentRepository(session, tenant_id=tenant, actor_user_id=approver, correlation_id=f"approve-{suffix}")
            active = await repository.approve_stop(approval)
            assert active["control_state"] == "active"
            assert active["approved_by_user_id"] == approver

        async with sessions() as session, session.begin():
            repository = ContainmentRepository(session, tenant_id=tenant, actor_user_id=approver, correlation_id=f"phases-{suffix}")
            action = await repository.begin_action(
                control_id=str(active["id"]), job_id=job_id,
                runner_registration_id=None, occurred_at=NOW + timedelta(seconds=3),
            )
            for phase in REQUIRED_CONTAINMENT_PHASES:
                receipt = PhaseReceipt(
                    phase=phase, state="verified", reason_code=f"{phase.value}_verified",
                    occurred_at=NOW + timedelta(seconds=3), duration_ms=1,
                )
                first_receipt = await repository.record_phase(str(action["id"]), receipt)
                replayed_receipt = await repository.record_phase(str(action["id"]), receipt)
                assert replayed_receipt["id"] == first_receipt["id"]
            completed = await repository.complete_action(
                str(action["id"]), occurred_at=NOW + timedelta(seconds=4),
            )
            assert completed["outcome"] == "contained"
            assert not completed["residual_risks"]
            replayed_completion = await repository.complete_action(
                str(action["id"]), occurred_at=NOW + timedelta(seconds=5),
            )
            assert replayed_completion == completed
            assessed_events = await session.scalar(select(func.count()).select_from(
                metadata.tables["audit_events"]
            ).where(
                metadata.tables["audit_events"].c.tenant_id == tenant,
                metadata.tables["audit_events"].c.action == "containment.action.assessed",
                metadata.tables["audit_events"].c.subject_id == job_id,
            ))
            assert assessed_events == 1

        async with sessions() as session, session.begin():
            current_control_version = await session.scalar(select(
                metadata.tables["containment_controls"].c.version
            ).where(
                metadata.tables["containment_controls"].c.tenant_id == tenant,
                metadata.tables["containment_controls"].c.id == active["id"],
            ))
            assert current_control_version == 2, active
            repository = ContainmentRepository(
                session, tenant_id=tenant, actor_user_id=reviewer,
                correlation_id=f"recover-{suffix}",
            )
            recovered = await repository.recover_control(
                control_id=str(active["id"]), review_id=f"review-{suffix}",
                expected_version=2, occurred_at=NOW + timedelta(seconds=5),
            )
            replayed_recovery = await repository.recover_control(
                control_id=str(active["id"]), review_id=f"review-{suffix}",
                expected_version=2, occurred_at=NOW + timedelta(seconds=5),
            )
            assert recovered["control_state"] == "recovered"
            assert replayed_recovery["control_id"] == recovered["control_id"]

        overdue_request = StopRequest(
            schema_version="1.0", stop_id=f"overdue-{suffix}", tenant_id=tenant,
            scope=ControlScope(ControlScopeKind.JOB, job_id), initiated_by=initiator,
            reason="Synthetic overdue acknowledgement", requested_at=NOW,
            expected_version=1, idempotency_key=f"overdue-request-{suffix}",
        )
        async with sessions() as session, session.begin():
            repository = ContainmentRepository(
                session, tenant_id=tenant, actor_user_id=initiator,
                correlation_id=f"overdue-{suffix}",
            )
            await repository.request_stop(overdue_request)
        async with sessions() as session, session.begin():
            reconciler = ContainmentReconciler(ContainmentRepository(
                session, tenant_id=tenant, actor_user_id="redagent-reconciler",
                correlation_id=f"reconcile-{suffix}",
            ))
            first_reconcile = await reconciler.reconcile(occurred_at=NOW + timedelta(seconds=11))
            second_reconcile = await reconciler.reconcile(occurred_at=NOW + timedelta(seconds=12))
            assert first_reconcile.incidents_opened == 1
            assert second_reconcile.incidents_opened == 0

        policy = QuotaPolicy(
            policy_id=f"quota-{suffix}", tenant_id=tenant, revision=1,
            dimension=QuotaDimension.OPERATIONS,
            scope=ControlScope(ControlScopeKind.CAMPAIGN, campaign), hard_limit=10,
            window_seconds=60, active_from=NOW - timedelta(minutes=1),
            active_until=NOW + timedelta(hours=1), extension_name=None,
        )
        async with sessions() as session, session.begin():
            quota = ContainmentRepository(session, tenant_id=tenant, actor_user_id=initiator, correlation_id=f"quota-{suffix}")
            stored = await quota.register_quota_policy(policy, occurred_at=NOW)
            extension_rows = []
            for extension_name in ("model_tokens", "connector_messages"):
                extension_rows.append(await quota.register_quota_policy(QuotaPolicy(
                    policy_id=f"quota-extension-{suffix}", tenant_id=tenant, revision=1,
                    dimension=QuotaDimension.EXTENSION,
                    scope=ControlScope(ControlScopeKind.CAMPAIGN, campaign), hard_limit=100,
                    window_seconds=60, active_from=NOW - timedelta(minutes=1),
                    active_until=NOW + timedelta(hours=1), extension_name=extension_name,
                ), occurred_at=NOW))
            assert extension_rows[0]["id"] != extension_rows[1]["id"]

        async def reserve(operation_id: str):
            async with sessions() as session, session.begin():
                quota = ContainmentRepository(session, tenant_id=tenant, actor_user_id=initiator, correlation_id=operation_id)
                return await quota.reserve_quota(
                    policy_record_id=str(stored["id"]), operation_id=operation_id,
                    requested=6, occurred_at=NOW + timedelta(seconds=3),
                )

        first, second = await asyncio.gather(reserve(f"reserve-a-{suffix}"), reserve(f"reserve-b-{suffix}"))
        assert sum(result.decision.allowed for result in (first, second)) == 1
        denied = next(result for result in (first, second) if not result.decision.allowed)
        assert denied.decision.reason_code == "hard_quota_exceeded"
        assert denied.containment_control_id is not None

        async with sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant})
            reservations = metadata.tables["quota_reservations"]
            reservation_id = await session.scalar(select(reservations.c.reservation_id).where(
                reservations.c.tenant_id == tenant,
            ))
            assert reservation_id is not None

        async with sessions() as session, session.begin():
            quota = ContainmentRepository(session, tenant_id=tenant, actor_user_id=initiator, correlation_id=f"adjust-{suffix}")
            consumed = await quota.adjust_quota(
                reservation_id=str(reservation_id), operation_id=f"consume-{suffix}",
                operation_kind="consume", amount=2, occurred_at=NOW + timedelta(seconds=4),
            )
            replayed = await quota.adjust_quota(
                reservation_id=str(reservation_id), operation_id=f"consume-{suffix}",
                operation_kind="consume", amount=2, occurred_at=NOW + timedelta(seconds=4),
            )
            released = await quota.adjust_quota(
                reservation_id=str(reservation_id), operation_id=f"release-{suffix}",
                operation_kind="release", amount=2, occurred_at=NOW + timedelta(seconds=5),
            )
            assert consumed.allowed and replayed == consumed
            assert released.allowed and released.remaining_reserved == 2

        async with sessions() as session, session.begin():
            quota = ContainmentRepository(session, tenant_id=tenant, actor_user_id=initiator, correlation_id=f"expire-{suffix}")
            assert await quota.expire_quota_reservations(occurred_at=NOW + timedelta(seconds=61)) == 1

        async with sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant})
            usage = metadata.tables["quota_usage"]
            assert await session.scalar(select(func.sum(usage.c.reserved_amount)).where(usage.c.tenant_id == tenant)) == 0
            assert await session.scalar(select(func.sum(usage.c.consumed_amount)).where(usage.c.tenant_id == tenant)) == 2
            operations = metadata.tables["quota_operations"]
            assert await session.scalar(select(func.count()).select_from(operations).where(operations.c.tenant_id == tenant)) == 5
            denied_control = await session.scalar(select(operations.c.containment_control_id).where(
                operations.c.tenant_id == tenant, operations.c.decision == "denied",
            ))
            assert denied_control is not None
            controls = metadata.tables["containment_controls"]
            assert await session.scalar(select(func.count()).select_from(controls).where(controls.c.tenant_id == tenant)) == 3

        signaled: list[tuple[str, str]] = []

        async def facts(job: str, occurred_at: datetime) -> AuthorityFacts:
            return AuthorityFacts(
                tenant_id=tenant, job_id=job,
                authorization_current=True, roe_current=True,
                policy_current=False, credential_current=True,
                checked_at=occurred_at, invalidated_at=occurred_at - timedelta(seconds=1),
            )

        async def signal(current: AuthorityFacts, control: dict[str, object], reason: str) -> None:
            signaled.append((str(control["id"]), reason))

        propagated = await RevocationMonitor(
            facts, PersistentRevocationStopActivator(sessions, signal),
        ).reconcile((job_id,), occurred_at=NOW + timedelta(minutes=3))
        assert propagated[0].within_slo and propagated[0].reason_code == "policy_revoked"
        assert len(signaled) == 1

        async with sessions() as session, session.begin():
            role_name = f"r101_test_{suffix}"
            # CRITICAL: role identifier is generated exclusively from a hex UUID suffix.
            await session.execute(text(f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS'))
            await session.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
            await session.execute(text(f'GRANT SELECT ON containment_controls TO "{role_name}"'))
            await session.execute(text(f'SET LOCAL ROLE "{role_name}"'))
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": f"other-{suffix}"})
            controls = metadata.tables["containment_controls"]
            assert await session.scalar(select(func.count()).select_from(controls)) == 0
    finally:
        await engine.dispose()
