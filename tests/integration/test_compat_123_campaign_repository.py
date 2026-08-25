from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.campaign_service.repository import (
    EffectReservationCommand,
    R123CampaignRepository,
    R123ClaimConflict,
    R123RecordConflict,
    StartCampaignCommand,
)
from redagent_platform.campaign_service.relay_runtime import (
    PostgresWorkflowRelayRepository,
)
from redagent_platform.campaign_service.activity_coordinator import R123ActivityCoordinator
from redagent_platform.campaign_service.activity_store import (
    PostgresActivityContainmentOwner,
    PostgresCampaignActivityStateOwner,
)
from redagent_platform.campaign_service.lineage import (
    CampaignTerminalLineageV1,
    NodeTerminalLineageV1,
)
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.execution import (
    EffectReceiptV1,
    ReconciliationState,
)
from redagent_platform.campaign_service.resolver import (
    CampaignContextResolver,
    CanonicalAuthoritySnapshot,
)
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.status import PostgresR123CampaignStatusOwner
from redagent_platform.campaign_service.service import (
    AuthorityRecheck,
    EffectDispatchCommand,
    PostgresEffectResultOwner,
    PostgresManifestV2Issuer,
)
from redagent_platform.finding_operations.contracts import (
    CoverageState,
    FindingOccurrenceInput,
    ImportBatch,
)
from redagent_platform.finding_operations.repository import FindingOperationsRepository
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.evidence_service.service import EvidenceService
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.runner_service.contracts import canonical_capability_sha256
from redagent_platform.runner_service.identity import PeerCertificateIdentity
from redagent_platform.runner_service.compat_123_lifecycle import PostgresRunnerLifecycleOwner
from redagent_platform.runner_service.compat_123_result import (
    AdapterResultMaterialV1,
    PostgresAdapterResultWriter,
)
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from redagent_platform.runner_service.compat_123_dispatch import (
    AdapterTerminalReceipt,
    R123AdapterRequest,
)
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    R123ContainActivityCommand,
    R123DispatchActivityCommand,
    R123ReconcileActivityCommand,
)


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 24, 1, 0, tzinfo=timezone.utc)


class StaticAuthorityProvider:
    def __init__(self, snapshot: CanonicalAuthoritySnapshot) -> None:
        self.snapshot = snapshot

    async def read_current_authority(self, request):
        return self.snapshot


class StaticRunnerIdentityOwner:
    def __init__(self, identity: PeerCertificateIdentity) -> None:
        self.identity = identity
        self.calls = []

    async def read_current_identity(self, **values):
        self.calls.append(values)
        return self.identity


def test_r123_atomic_start_and_tenant_scoped_workflow_relay() -> None:
    asyncio.run(_atomic_start_and_relay_scenario())


def test_r123_start_rollback_leaves_no_partial_campaign_lineage() -> None:
    asyncio.run(_rollback_scenario())


def test_r123_status_projection_reads_canonical_campaign_outbox_and_effect_state() -> None:
    asyncio.run(_status_projection_scenario())


def test_r123_postgres_activity_owner_replays_without_duplicate_dispatch() -> None:
    asyncio.run(_activity_owner_replay_scenario())


def test_r123_postgres_activity_owner_reconstructs_exact_ambiguous_effect_lookup() -> None:
    asyncio.run(_activity_reconciliation_material_scenario())


def test_r123_campaign_stop_requires_r101_dual_control_before_containment() -> None:
    asyncio.run(_activity_containment_owner_scenario())


class _AllowedActivitySafety:
    async def check(self, **values):
        return True, True


class _ContainmentOwner:
    def __init__(self) -> None:
        self.calls = 0

    async def contain(self, **values):
        self.calls += 1
        return "contained", "stop_contained"


class _ConfirmedEffectCoordinator:
    def __init__(self) -> None:
        self.calls = []

    async def dispatch(self, command, *, now):
        self.calls.append(command)
        return {"state": "confirmed"}


async def _activity_containment_owner_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-stop-{suffix}"
    actor_id = f"user-r123-stop-{suffix}"
    campaign_id = f"campaign-r123-stop-{suffix}"
    owner = PostgresActivityContainmentOwner(sessions)
    values = {
        "tenant_id": tenant_id,
        "campaign_id": campaign_id,
        "signal_id": f"signal-r123-{suffix}",
        "actor_user_id": actor_id,
        "reason_sha256": "f" * 64,
        "now": NOW,
        "correlation_id": f"contain-r123-{suffix}",
    }
    try:
        await _bootstrap(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=f"eng-r123-stop-{suffix}",
            target_id=f"target-r123-stop-{suffix}",
            roe_id=f"roe-r123-stop-{suffix}",
        )

        first = await owner.contain(**values)
        replay = await owner.contain(**values)

        assert first == replay == (
            "manual_review_required",
            "campaign_stop_pending_dual_control",
        )
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            controls = metadata.tables["containment_controls"]
            rows = (
                await session.execute(
                    select(controls).where(controls.c.tenant_id == tenant_id)
                )
            ).mappings().all()
            assert len(rows) == 1
            assert rows[0]["scope_kind"] == "campaign"
            assert rows[0]["scope_id"] == campaign_id
            assert rows[0]["control_state"] == "pending_approval"
    finally:
        await engine.dispose()


async def _atomic_start_and_relay_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-{suffix}"
    actor_id = f"user-r123-{suffix}"
    engagement_id = f"eng-r123-{suffix}"
    target_id = f"target-r123-{suffix}"
    roe_id = f"roe-r123-{suffix}"
    campaign_id = f"campaign-r123-{suffix}"
    strategy_record_id = f"strategy-record-{suffix}"
    strategy_revision_id = f"strategy-r123-{suffix}"
    workflow_id = f"redagent-r123-{suffix}"
    command = _command(
        campaign_id=campaign_id,
        engagement_id=engagement_id,
        target_id=target_id,
        roe_id=roe_id,
        strategy_record_id=strategy_record_id,
        strategy_revision_id=strategy_revision_id,
        workflow_id=workflow_id,
    )
    try:
        await _bootstrap(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
        )
        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"corr-{suffix}",
            )
            result = await repo.start_campaign(command, occurred_at=NOW)
        assert result.aggregate_sequence == 1
        assert result.workflow_id == workflow_id

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            assert await _count(session, "campaigns", tenant_id) == 1
            assert await _count(session, "campaign_strategy_revisions", tenant_id) == 1
            assert await _count(session, "audit_events", tenant_id) == 5
            assert await _count(session, "outbox_events", tenant_id) == 5
            campaigns = metadata.tables["campaigns"]
            row = (
                await session.execute(
                    select(campaigns).where(
                        campaigns.c.tenant_id == tenant_id,
                        campaigns.c.id == campaign_id,
                    )
                )
            ).mappings().one()
            assert row["current_strategy_revision_id"] == strategy_record_id
            assert row["aggregate_sequence"] == 1

        async with sessions() as session, session.begin():
            other = R123CampaignRepository(
                session,
                tenant_id=f"other-{suffix}",
                actor_user_id=f"other-user-{suffix}",
                correlation_id=f"other-corr-{suffix}",
            )
            assert await other.claim_workflow_starts(
                claim_owner="relay-other",
                now=NOW,
                lease_seconds=30,
                limit=10,
            ) == []

        relay_repo = PostgresWorkflowRelayRepository(
            sessions,
            tenant_id=tenant_id,
            actor_user_id=actor_id,
            correlation_prefix=f"relay-runtime-{suffix[:12]}",
        )
        claimed = await relay_repo.claim_workflow_starts(
            claim_owner="relay-r123",
            now=NOW,
            lease_seconds=30,
            limit=10,
        )
        assert len(claimed) == 1
        assert claimed[0].attempt_count == 1
        assert claimed[0].payload["workflow_id"] == workflow_id
        event_id = claimed[0].event_id

        with pytest.raises(R123ClaimConflict, match="outbox_claim_conflict"):
            await relay_repo.acknowledge_workflow_start(
                event_id=event_id,
                claim_owner="relay-wrong",
                workflow_run_id=f"run-{suffix}",
                occurred_at=NOW + timedelta(seconds=1),
            )

        acknowledged = await relay_repo.acknowledge_workflow_start(
            event_id=event_id,
            claim_owner="relay-r123",
            workflow_run_id=f"run-{suffix}",
            occurred_at=NOW + timedelta(seconds=1),
        )
        assert acknowledged.aggregate_sequence == 2

        effect_id = f"effect-{suffix}"
        invocation_id = f"invocation-{suffix}"
        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-reserve-{suffix}",
            )
            reserved = await repo.reserve_effect(
                EffectReservationCommand(
                    effect_record_id=f"effect-record-{suffix}",
                    effect_id=effect_id,
                    campaign_id=campaign_id,
                    strategy_record_id=strategy_record_id,
                    node_id="node-zap",
                    invocation_id=invocation_id,
                    effect_intent_sha256="a" * 64,
                    effect_intent_payload={"capability_id": "zap-controlled-runtime@2"},
                    envelope_sha256="8" * 64,
                ),
                occurred_at=NOW + timedelta(seconds=2),
            )
            assert reserved.effect_state == "reserved"
            assert reserved.claim_version == 0
            assert reserved.aggregate_sequence == 3

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-claim-{suffix}",
            )
            claimed_effect = await repo.claim_effect(
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                expected_claim_version=0,
                now=NOW + timedelta(seconds=3),
                lease_seconds=30,
            )
            assert claimed_effect.effect_state == "claimed"
            assert claimed_effect.claim_version == 1
            with pytest.raises(R123ClaimConflict, match="effect_claim_conflict"):
                await repo.claim_effect(
                    effect_id=effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=0,
                    now=NOW + timedelta(seconds=3),
                    lease_seconds=30,
                )

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-manifest-context-{suffix}",
            )
            context = await repo.read_effect_manifest_context(
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                now=NOW + timedelta(seconds=3),
            )
            assert context.campaign_id == campaign_id
            assert context.strategy_revision_id == strategy_revision_id
            assert context.invocation_id == invocation_id
            assert context.claim_version == 1

        async with sessions() as session, session.begin():
            control = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-job-{suffix}",
            )
            job = await control.create_r123_runner_job(
                campaign_id=campaign_id,
                strategy_revision_id=strategy_revision_id,
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                capability_id="zap-controlled-runtime",
                envelope_sha256="8" * 64,
                occurred_at=NOW + timedelta(seconds=3),
            )
            replayed_job = await control.create_r123_runner_job(
                campaign_id=campaign_id,
                strategy_revision_id=strategy_revision_id,
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                capability_id="zap-controlled-runtime",
                envelope_sha256="8" * 64,
                occurred_at=NOW + timedelta(seconds=3),
            )
            assert job.replayed is False and replayed_job.replayed is True
            assert replayed_job.resource["job_id"] == job.resource["job_id"]
            assert job.resource["request"] == {
                "schema_version": "redagent.r123-runner-job/v1",
                "capability_id": "zap-controlled-runtime",
                "strategy_revision_id": strategy_revision_id,
                "effect_id": effect_id,
                "envelope_sha256": "8" * 64,
            }
            with pytest.raises(ValueError, match="r123_runner_job_capability_denied"):
                await control.create_r123_runner_job(
                    campaign_id=campaign_id,
                    strategy_revision_id=strategy_revision_id,
                    effect_id=effect_id,
                    claim_owner="runner-relay-r123",
                    capability_id="synthetic-conformance",
                    envelope_sha256="8" * 64,
                    occurred_at=NOW + timedelta(seconds=3),
                )

        capability = await _bootstrap_manifest_issuer_authority(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            suffix=suffix,
        )
        binding = CapabilityBindingKeyV1(
            schema_version="redagent.r119-capability-binding/v1",
            capability_id="zap-controlled-runtime",
            capability_revision=2,
            execution_manifest_sha256=canonical_capability_sha256(capability),
            adapter_id="zap-service",
            adapter_version="2.17.0-r104.2",
            profile_id="zap-passive-v1",
            profile_revision=1,
            profile_sha256=closed_execution_registry()[
                "zap-controlled-runtime@2"
            ].profile_sha256,
            bundle_id=None,
            bundle_revision=None,
            bundle_sha256=None,
            semantics_revision=1,
            semantics_sha256="b" * 64,
            normalized_output_sha256="c" * 64,
            projection_revision=1,
            projection_sha256="d" * 64,
        )
        authority_snapshot = _authority_snapshot(
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
            target_sha256=hashlib.sha256(json.dumps({
                "target_id": target_id,
                "revision": 1,
                "target_type": "url",
                "normalized_value": "http://127.0.0.1:41731",
            }, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
        )
        issuer = PostgresManifestV2Issuer(
            sessions,
            resolver=CampaignContextResolver(StaticAuthorityProvider(authority_snapshot)),
            tenant_id=tenant_id,
            actor_user_id=actor_id,
            signing_key=Ed25519PrivateKey.generate(),
            signing_key_id="r123-integration-key",
        )
        dispatch_command = EffectDispatchCommand(
            tenant_id=tenant_id,
            principal_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            effect_id=effect_id,
            invocation_id=invocation_id,
            effect_intent_sha256="a" * 64,
            envelope_sha256="8" * 64,
            expected_claim_version=0,
            expected_dispatch_attempt=0,
            expected_dispatch_generation=0,
            claim_owner="runner-relay-r123",
            binding=binding,
        )
        signed_v2 = await issuer.issue(
            dispatch_command,
            authority=AuthorityRecheck(
                True,
                "allowed",
                "runner-r123",
                "spiffe://redagent.test/runner/compat_123",
            ),
            now=NOW + timedelta(seconds=3),
        )
        replayed_v2 = await issuer.issue(
            dispatch_command,
            authority=AuthorityRecheck(
                True,
                "allowed",
                "runner-r123",
                "spiffe://redagent.test/runner/compat_123",
            ),
            now=NOW + timedelta(seconds=3),
        )
        assert replayed_v2 == signed_v2
        assert signed_v2.manifest.capability_id == "zap-controlled-runtime"
        assert signed_v2.manifest.v1.job_id == job.resource["job_id"]

        identity_owner = StaticRunnerIdentityOwner(
            PeerCertificateIdentity(
                runner_id="runner-r123",
                spiffe_id="spiffe://redagent.test/runner/compat_123",
                certificate_fingerprint="a" * 64,
                certificate_serial=f"issuer-{suffix}",
                not_before=NOW - timedelta(minutes=1),
                not_after=NOW + timedelta(minutes=10),
            )
        )
        lifecycle = PostgresRunnerLifecycleOwner(
            sessions,
            identity_owner,
            actor_user_id=actor_id,
        )
        runner_request = R123AdapterRequest(
            tenant_id=tenant_id,
            capability_id=binding.capability_id,
            capability_revision=binding.capability_revision,
            adapter_id=binding.adapter_id,
            adapter_version=binding.adapter_version,
            profile_id=binding.profile_id,
            profile_revision=binding.profile_revision,
            profile_sha256=binding.profile_sha256,
            bundle_id=binding.bundle_id,
            bundle_revision=binding.bundle_revision,
            bundle_sha256=binding.bundle_sha256,
            invocation_id=invocation_id,
            effect_id=effect_id,
            envelope_sha256=dispatch_command.envelope_sha256,
            manifest_v2_sha256=signed_v2.manifest_sha256,
        )
        runner_handle = await lifecycle.begin(
            runner_request,
            occurred_at=NOW + timedelta(seconds=3),
        )
        assert identity_owner.calls[0]["runner_id"] == "runner-r123"

        result_writer = PostgresAdapterResultWriter(
            sessions,
            EvidenceService(
                sessions,
                LocalAppendOnlyBackend(
                    ROOT / ".tmp" / "r123-result-writer" / suffix,
                    profile="synthetic-local",
                ),
            ),
            actor_user_id=actor_id,
            kms_reference="kms:compat_123:synthetic",
            retention_days=1,
        )
        lifecycle_receipt = await result_writer.persist(
            AdapterResultMaterialV1(
                request=runner_request,
                report_safe_content=b'{"findings":[],"schema":"redagent.r123-result/v1"}',
                findings=(),
                coverage_state=CoverageState.PARTIAL,
                cleanup_receipt_id=f"lifecycle-cleanup-{suffix}",
                observed_at=NOW + timedelta(seconds=4),
            )
        )
        assert await lifecycle.complete(
            runner_request,
            runner_handle,
            lifecycle_receipt,
            occurred_at=NOW + timedelta(seconds=5),
        ) == lifecycle_receipt
        assert not any(runner_handle.lease_token)
        assert await result_writer.lookup(
            runner_request,
            cleanup_receipt_id=f"lifecycle-cleanup-{suffix}",
        ) == lifecycle_receipt

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-dispatch-{suffix}",
            )
            dispatching = await repo.mark_effect_dispatching(
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                expected_claim_version=1,
                request_sha256="b" * 64,
                runner_id="runner-r123",
                workload_identity="spiffe://redagent.test/runner/compat_123",
                occurred_at=NOW + timedelta(seconds=4),
            )
            assert dispatching.effect_state == "dispatching"
            assert dispatching.dispatch_attempt == 1
            assert dispatching.claim_version == 2

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-ambiguous-{suffix}",
            )
            ambiguous = await repo.record_effect_ambiguity(
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                expected_claim_version=2,
                failure_code="adapter_receipt_commit_unknown",
                occurred_at=NOW + timedelta(seconds=5),
            )
            assert ambiguous.effect_state == "reconciliation_required"
            assert ambiguous.redispatch_permitted is False
            with pytest.raises(R123ClaimConflict, match="effect_claim_conflict"):
                await repo.claim_effect(
                    effect_id=effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=ambiguous.claim_version,
                    now=NOW + timedelta(seconds=6),
                    lease_seconds=30,
                )

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-lookup-outage-{suffix}",
            )
            lookup_retry = await repo.record_effect_lookup_unavailable(
                effect_id=effect_id,
                expected_claim_version=ambiguous.claim_version,
                failure_code="adapter_status_lookup_unavailable",
                occurred_at=NOW + timedelta(seconds=6),
            )
            assert lookup_retry.effect_state == "reconciliation_required"
            assert lookup_retry.redispatch_permitted is False

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-reconcile-{suffix}",
            )
            not_applied_receipt = EffectReceiptV1(
                schema_version="redagent.r123-effect-receipt/v1",
                effect_id=effect_id,
                effect_intent_sha256="a" * 64,
                envelope_sha256="8" * 64,
                dispatch_attempt=1,
                dispatch_generation=1,
                runner_id="runner-r123",
                workload_identity="spiffe://redagent.test/runner/compat_123",
                request_sha256="b" * 64,
                started_at=NOW + timedelta(seconds=4),
                completed_at=NOW + timedelta(seconds=7),
                adapter_accepted=False,
                external_status="not_applied",
                external_receipt_id=f"status-not-applied-{suffix}",
                evidence_ids=(f"evidence-{suffix}",),
                cleanup_receipt_id=f"cleanup-not-applied-{suffix}",
                output_complete=True,
                external_contact_count=0,
                reconciliation_state=ReconciliationState.NOT_APPLIED,
                reconciliation_evidence_ids=(f"evidence-{suffix}",),
                redispatch_permitted=True,
                failure_code=None,
            )
            reconciled = await repo.record_effect_not_applied(
                effect_id=effect_id,
                expected_claim_version=lookup_retry.claim_version,
                receipt_sha256=not_applied_receipt.receipt_sha256,
                receipt_payload=not_applied_receipt.canonical_payload,
                occurred_at=NOW + timedelta(seconds=7),
            )
            replayed_not_applied = await repo.record_effect_not_applied(
                effect_id=effect_id,
                expected_claim_version=lookup_retry.claim_version,
                receipt_sha256=not_applied_receipt.receipt_sha256,
                receipt_payload=not_applied_receipt.canonical_payload,
                occurred_at=NOW + timedelta(seconds=7),
            )
            assert replayed_not_applied == reconciled
            assert reconciled.effect_state == "not_applied"
            assert reconciled.redispatch_permitted is True
            effects = metadata.tables["campaign_effects"]
            proof = (
                await session.execute(
                    select(effects).where(
                        effects.c.tenant_id == tenant_id,
                        effects.c.effect_id == effect_id,
                    )
                )
            ).mappings().one()
            assert proof["next_retry_at"] == NOW + timedelta(seconds=8)
            assert proof["effect_receipt_sha256"] == not_applied_receipt.receipt_sha256
            assert proof["effect_receipt_payload"] == not_applied_receipt.canonical_payload
            assert proof["external_receipt_id"] == f"status-not-applied-{suffix}"
            assert proof["cleanup_receipt_id"] == f"cleanup-not-applied-{suffix}"
            assert proof["evidence_ids"] == [f"evidence-{suffix}"]

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-reclaim-{suffix}",
            )
            with pytest.raises(R123ClaimConflict, match="effect_claim_conflict"):
                await repo.claim_effect(
                    effect_id=effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=reconciled.claim_version,
                    now=NOW + timedelta(seconds=7, milliseconds=500),
                    lease_seconds=30,
                )
            reclaimed_effect = await repo.claim_effect(
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                expected_claim_version=reconciled.claim_version,
                now=NOW + timedelta(seconds=8),
                lease_seconds=30,
            )
            assert reclaimed_effect.effect_state == "claimed"
            assert reclaimed_effect.dispatch_attempt == 1

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-redispatch-{suffix}",
            )
            redispatching = await repo.mark_effect_dispatching(
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                expected_claim_version=reclaimed_effect.claim_version,
                request_sha256="c" * 64,
                runner_id="runner-r123",
                workload_identity="spiffe://redagent.test/runner/compat_123",
                occurred_at=NOW + timedelta(seconds=9),
            )
            assert redispatching.dispatch_attempt == 2
            effects = metadata.tables["campaign_effects"]
            redispatch_row = (
                await session.execute(
                    select(effects).where(
                        effects.c.tenant_id == tenant_id,
                        effects.c.effect_id == effect_id,
                    )
                )
            ).mappings().one()
            assert redispatch_row["effect_receipt_sha256"] is None
            assert redispatch_row["effect_receipt_payload"] is None
            assert redispatch_row["external_receipt_id"] is None
            assert redispatch_row["evidence_ids"] == []
            assert redispatch_row["cleanup_receipt_id"] is None
            assert redispatch_row["reconciliation_state"] == "none"

        receipt_payload = {
            "schema_version": "redagent.r123-effect-receipt/v1",
            "effect_id": effect_id,
            "effect_intent_sha256": "a" * 64,
            "envelope_sha256": "8" * 64,
            "dispatch_attempt": 2,
            "dispatch_generation": 2,
            "runner_id": "runner-r123",
            "workload_identity": "spiffe://redagent.test/runner/compat_123",
            "request_sha256": "c" * 64,
            "started_at": (NOW + timedelta(seconds=9)).isoformat().replace("+00:00", "Z"),
            "completed_at": (NOW + timedelta(seconds=10)).isoformat().replace("+00:00", "Z"),
            "adapter_accepted": True,
            "external_status": "confirmed",
            "external_receipt_id": f"adapter-receipt-{suffix}",
            "evidence_ids": [f"evidence-terminal-{suffix}"],
            "cleanup_receipt_id": f"cleanup-terminal-{suffix}",
            "output_complete": True,
            "external_contact_count": 0,
            "reconciliation_state": "confirmed",
            "reconciliation_evidence_ids": [f"evidence-terminal-{suffix}"],
            "redispatch_permitted": False,
            "failure_code": None,
        }
        receipt_sha256 = hashlib.sha256(
            json.dumps(
                receipt_payload,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=True,
            ).encode("utf-8")
        ).hexdigest()
        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-confirm-{suffix}",
            )
            with pytest.raises(ValueError, match="effect_receipt_payload_invalid"):
                await repo.record_effect_receipt(
                    effect_id=effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=redispatching.claim_version,
                    receipt_sha256="d" * 64,
                    receipt_payload=receipt_payload,
                    occurred_at=NOW + timedelta(seconds=10),
                )
            drifted_payload = {
                **receipt_payload,
                "workload_identity": "spiffe://redagent.test/runner/other",
            }
            drifted_sha256 = hashlib.sha256(
                json.dumps(
                    drifted_payload,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=True,
                ).encode("utf-8")
            ).hexdigest()
            with pytest.raises(R123ClaimConflict, match="effect_receipt_claim_conflict"):
                await repo.record_effect_receipt(
                    effect_id=effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=redispatching.claim_version,
                    receipt_sha256=drifted_sha256,
                    receipt_payload=drifted_payload,
                    occurred_at=NOW + timedelta(seconds=10),
                )
            confirmed = await repo.record_effect_receipt(
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                expected_claim_version=redispatching.claim_version,
                receipt_sha256=receipt_sha256,
                receipt_payload=receipt_payload,
                occurred_at=NOW + timedelta(seconds=10),
            )
            replay = await repo.record_effect_receipt(
                effect_id=effect_id,
                claim_owner="runner-relay-r123",
                expected_claim_version=redispatching.claim_version,
                receipt_sha256=receipt_sha256,
                receipt_payload=receipt_payload,
                occurred_at=NOW + timedelta(seconds=10),
            )
            assert confirmed.effect_state == "confirmed"
            assert replay == confirmed
            assert confirmed.redispatch_permitted is False

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-terminal-{suffix}",
            )
            with pytest.raises(R123ClaimConflict, match="effect_claim_conflict"):
                await repo.claim_effect(
                    effect_id=effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=confirmed.claim_version,
                    now=NOW + timedelta(seconds=11),
                    lease_seconds=30,
                )

        lineage = CampaignTerminalLineageV1(
            schema_version="redagent.r123-terminal-lineage/v1",
            tenant_id=tenant_id,
            campaign_id=campaign_id,
            strategy_revision_id=strategy_revision_id,
            objective_sha256="1" * 64,
            resolved_envelope_sha256="8" * 64,
            context_snapshot_sha256="2" * 64,
            decision_sha256="3" * 64,
            plan_sha256="4" * 64,
            approval_receipt_id=f"approval-{campaign_id}",
            approval_receipt_sha256="6" * 64,
            outbox_event_id=event_id,
            workflow_id=workflow_id,
            workflow_run_id=f"run-{suffix}",
            nodes=(
                NodeTerminalLineageV1(
                    node_id="node-zap",
                    capability_id="zap-controlled-runtime",
                    capability_revision=2,
                    effect_id=effect_id,
                        effect_receipt_sha256=receipt_sha256,
                    execution_receipt_id=f"adapter-receipt-{suffix}",
                    evidence_ids=(f"evidence-terminal-{suffix}",),
                    finding_import_id=f"import-{suffix}",
                    finding_issue_ids=(f"issue-{suffix}",),
                    no_finding_coverage=False,
                    retest_receipt_ids=(f"retest-{suffix}",),
                    cleanup_receipt_id=f"cleanup-terminal-{suffix}",
                    reconciliation_state="confirmed",
                ),
            ),
            stop_or_replan_receipt_id=f"stop-{suffix}",
            residual_risk_receipt_id=f"residual-{suffix}",
            campaign_cleanup_receipt_id=f"campaign-cleanup-{suffix}",
            terminal_reason="objective_satisfied",
        )
        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"terminal-missing-owner-{suffix}",
            )
            with pytest.raises(
                R123RecordConflict, match="campaign_terminal_evidence_owner_mismatch"
            ):
                await repo.finalize_campaign(
                    lineage,
                    expected_aggregate_sequence=3,
                    occurred_at=NOW + timedelta(seconds=12),
                )
            with pytest.raises(
                R123RecordConflict, match="effect_trusted_execution_owner_mismatch"
            ):
                await repo.validate_trusted_effect_owners(
                    effect_id=effect_id,
                    external_receipt_id=f"adapter-receipt-{suffix}",
                    evidence_ids=(f"evidence-terminal-{suffix}",),
                    cleanup_receipt_id=f"cleanup-terminal-{suffix}",
                )

        issue_id = await _bootstrap_terminal_owner_rows(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            roe_id=roe_id,
            campaign_id=campaign_id,
            suffix=suffix,
        )
        lineage = replace(
            lineage,
            nodes=(replace(lineage.nodes[0], finding_issue_ids=(issue_id,)),),
        )
        async with sessions() as session, session.begin():
            trusted = await R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-trusted-owner-{suffix}",
            ).validate_trusted_effect_owners(
                effect_id=effect_id,
                external_receipt_id=f"adapter-receipt-{suffix}",
                evidence_ids=(f"evidence-terminal-{suffix}",),
                cleanup_receipt_id=f"cleanup-terminal-{suffix}",
            )
            assert trusted.finding_issue_ids == (issue_id,)
            assert trusted.retest_receipt_ids == (f"retest-{suffix}",)
            assert trusted.no_finding_coverage is False
            imports = metadata.tables["finding_import_sessions"]
            await session.execute(
                update(imports)
                .where(
                    imports.c.tenant_id == tenant_id,
                    imports.c.run_id == f"adapter-receipt-{suffix}",
                )
                .values(adapter_id="nuclei-service")
            )
            with pytest.raises(
                R123RecordConflict, match="effect_trusted_finding_import_mismatch"
            ):
                await R123CampaignRepository(
                    session,
                    tenant_id=tenant_id,
                    actor_user_id=actor_id,
                    correlation_id=f"effect-trusted-adapter-drift-{suffix}",
                ).validate_trusted_effect_owners(
                    effect_id=effect_id,
                    external_receipt_id=f"adapter-receipt-{suffix}",
                    evidence_ids=(f"evidence-terminal-{suffix}",),
                    cleanup_receipt_id=f"cleanup-terminal-{suffix}",
                )
            await session.execute(
                update(imports)
                .where(
                    imports.c.tenant_id == tenant_id,
                    imports.c.run_id == f"adapter-receipt-{suffix}",
                )
                .values(adapter_id="zap-service")
            )
            await session.execute(
                update(imports)
                .where(
                    imports.c.tenant_id == tenant_id,
                    imports.c.run_id == f"adapter-receipt-{suffix}",
                )
                .values(coverage_state="partial")
            )
            with pytest.raises(
                R123RecordConflict, match="effect_trusted_finding_import_mismatch"
            ):
                await R123CampaignRepository(
                    session,
                    tenant_id=tenant_id,
                    actor_user_id=actor_id,
                    correlation_id=f"effect-trusted-partial-default-{suffix}",
                ).validate_trusted_effect_owners(
                    effect_id=effect_id,
                    external_receipt_id=f"adapter-receipt-{suffix}",
                    evidence_ids=(f"evidence-terminal-{suffix}",),
                    cleanup_receipt_id=f"cleanup-terminal-{suffix}",
                    require_retest=False,
                )
            partial = await R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-trusted-partial-observation-{suffix}",
            ).validate_trusted_effect_owners(
                effect_id=effect_id,
                external_receipt_id=f"adapter-receipt-{suffix}",
                evidence_ids=(f"evidence-terminal-{suffix}",),
                cleanup_receipt_id=f"cleanup-terminal-{suffix}",
                require_complete_coverage=False,
                require_retest=False,
            )
            assert partial.coverage_state == "partial"
            assert partial.no_finding_coverage is False
            await session.execute(
                update(imports)
                .where(
                    imports.c.tenant_id == tenant_id,
                    imports.c.run_id == f"adapter-receipt-{suffix}",
                )
                .values(coverage_state="complete")
            )
        trusted_receipt = AdapterTerminalReceipt(
            invocation_id=invocation_id,
            effect_id=effect_id,
            state="confirmed",
            external_receipt_id=f"adapter-receipt-{suffix}",
            evidence_ids=(f"evidence-terminal-{suffix}",),
            cleanup_receipt_id=f"cleanup-terminal-{suffix}",
            output_complete=True,
            external_contact_count=0,
            failure_code=None,
        )
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            retests = metadata.tables["finding_retests"]
            await session.execute(
                update(retests)
                .where(retests.c.retest_id == f"retest-{suffix}")
                .values(result_state="failed")
            )
        assert await PostgresEffectResultOwner(
            sessions,
            tenant_id=tenant_id,
            actor_user_id=actor_id,
            correlation_prefix="r123-result-owner",
        ).finalize(
            dispatch_command,
            trusted_receipt,
            now=NOW + timedelta(seconds=11),
        ) == trusted_receipt
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            await session.execute(
                update(metadata.tables["campaign_effects"])
                .where(
                    metadata.tables["campaign_effects"].c.tenant_id == tenant_id,
                    metadata.tables["campaign_effects"].c.effect_id == effect_id,
                )
                .values(effect_state="reconciliation_required")
            )
        reconciliation_owner = PostgresEffectResultOwner(
            sessions,
            tenant_id=tenant_id,
            actor_user_id=actor_id,
            correlation_prefix="r123-reconciliation-owner",
        )
        with pytest.raises(
            R123RecordConflict,
            match="effect_trusted_owner_state_invalid",
        ):
            await reconciliation_owner.finalize(
                dispatch_command,
                trusted_receipt,
                now=NOW + timedelta(seconds=11),
            )
        assert await reconciliation_owner.finalize(
            dispatch_command,
            trusted_receipt,
            now=NOW + timedelta(seconds=11),
            reconciliation=True,
        ) == trusted_receipt
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            await session.execute(
                update(metadata.tables["campaign_effects"])
                .where(
                    metadata.tables["campaign_effects"].c.tenant_id == tenant_id,
                    metadata.tables["campaign_effects"].c.effect_id == effect_id,
                )
                .values(effect_state="confirmed")
            )
        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"effect-terminal-retest-{suffix}",
            )
            with pytest.raises(
                R123RecordConflict, match="effect_trusted_retest_owner_mismatch"
            ):
                await repo.validate_trusted_effect_owners(
                    effect_id=effect_id,
                    external_receipt_id=f"adapter-receipt-{suffix}",
                    evidence_ids=(f"evidence-terminal-{suffix}",),
                    cleanup_receipt_id=f"cleanup-terminal-{suffix}",
                )
            await session.execute(
                update(metadata.tables["finding_retests"])
                .where(
                    metadata.tables["finding_retests"].c.retest_id
                    == f"retest-{suffix}"
                )
                .values(result_state="passed")
            )
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"terminal-unsafe-owner-{suffix}",
            )
            artifacts = metadata.tables["evidence_artifacts"]
            await session.execute(
                update(artifacts)
                .where(artifacts.c.id == f"evidence-terminal-{suffix}")
                .values(artifact_class="raw", redaction_state="raw")
            )
            with pytest.raises(
                R123RecordConflict, match="campaign_terminal_evidence_not_report_safe"
            ):
                await repo.finalize_campaign(
                    lineage,
                    expected_aggregate_sequence=3,
                    occurred_at=NOW + timedelta(seconds=12),
                )
            await session.execute(
                update(artifacts)
                .where(artifacts.c.id == f"evidence-terminal-{suffix}")
                .values(artifact_class="report_safe", redaction_state="report_safe")
            )

            receipts = metadata.tables["runner_execution_receipts"]
            await session.execute(
                update(receipts)
                .where(receipts.c.execution_id == f"adapter-receipt-{suffix}")
                .values(outcome="failed")
            )
            with pytest.raises(
                R123RecordConflict, match="campaign_terminal_execution_owner_mismatch"
            ):
                await repo.finalize_campaign(
                    lineage,
                    expected_aggregate_sequence=3,
                    occurred_at=NOW + timedelta(seconds=12),
                )
            await session.execute(
                update(receipts)
                .where(receipts.c.execution_id == f"adapter-receipt-{suffix}")
                .values(outcome="succeeded")
            )

            imports = metadata.tables["finding_import_sessions"]
            await session.execute(
                update(imports)
                .where(imports.c.import_id == f"import-{suffix}")
                .values(coverage_state="partial")
            )
            with pytest.raises(
                R123RecordConflict, match="campaign_terminal_finding_import_mismatch"
            ):
                await repo.finalize_campaign(
                    lineage,
                    expected_aggregate_sequence=3,
                    occurred_at=NOW + timedelta(seconds=12),
                )
            await session.execute(
                update(imports)
                .where(imports.c.import_id == f"import-{suffix}")
                .values(coverage_state="complete")
            )

            retests = metadata.tables["finding_retests"]
            await session.execute(
                update(retests)
                .where(retests.c.retest_id == f"retest-{suffix}")
                .values(result_state="failed")
            )
            with pytest.raises(
                R123RecordConflict, match="campaign_terminal_retest_owner_mismatch"
            ):
                await repo.finalize_campaign(
                    lineage,
                    expected_aggregate_sequence=3,
                    occurred_at=NOW + timedelta(seconds=12),
                )
            await session.execute(
                update(retests)
                .where(retests.c.retest_id == f"retest-{suffix}")
                .values(result_state="passed")
            )
        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"terminal-{suffix}",
            )
            terminal = await repo.finalize_campaign(
                lineage,
                expected_aggregate_sequence=3,
                occurred_at=NOW + timedelta(seconds=12),
            )
            replayed_terminal = await repo.finalize_campaign(
                lineage,
                expected_aggregate_sequence=3,
                occurred_at=NOW + timedelta(seconds=12),
            )
            assert terminal.aggregate_sequence == 4 and terminal.replayed is False
            assert replayed_terminal.replayed is True
            assert replayed_terminal.terminal_receipt_sha256 == terminal.terminal_receipt_sha256

        # Exercise terminal ambiguity branches in a savepoint so accepted lineage stays unchanged.
        async with sessions() as session, session.begin():
            nested = await session.begin_nested()
            try:
                repo = R123CampaignRepository(
                    session,
                    tenant_id=tenant_id,
                    actor_user_id=actor_id,
                    correlation_id=f"reconciliation-terminal-{suffix}",
                )
                reconciled_effect_id = f"effect-reconciled-{suffix}"
                await repo.reserve_effect(
                    EffectReservationCommand(
                        effect_record_id=f"effect-record-reconciled-{suffix}",
                        effect_id=reconciled_effect_id,
                        campaign_id=campaign_id,
                        strategy_record_id=strategy_record_id,
                        node_id=f"node-reconciled-{suffix}",
                        invocation_id=f"invocation-reconciled-{suffix}",
                        effect_intent_sha256="a" * 64,
                        effect_intent_payload={"capability_id": "zap-controlled-runtime"},
                        envelope_sha256="8" * 64,
                    ),
                    occurred_at=NOW + timedelta(seconds=40),
                )
                claimed = await repo.claim_effect(
                    effect_id=reconciled_effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=0,
                    now=NOW + timedelta(seconds=41),
                    lease_seconds=30,
                )
                dispatching = await repo.mark_effect_dispatching(
                    effect_id=reconciled_effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=claimed.claim_version,
                    request_sha256="d" * 64,
                    runner_id="runner-r123",
                    workload_identity="spiffe://redagent.test/runner/compat_123",
                    occurred_at=NOW + timedelta(seconds=42),
                )
                ambiguous_reconciled = await repo.record_effect_ambiguity(
                    effect_id=reconciled_effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=dispatching.claim_version,
                    failure_code="adapter_receipt_commit_unknown",
                    occurred_at=NOW + timedelta(seconds=43),
                )
                reconciled_receipt = EffectReceiptV1(
                    schema_version="redagent.r123-effect-receipt/v1",
                    effect_id=reconciled_effect_id,
                    effect_intent_sha256="a" * 64,
                    envelope_sha256="8" * 64,
                    dispatch_attempt=1,
                    dispatch_generation=1,
                    runner_id="runner-r123",
                    workload_identity="spiffe://redagent.test/runner/compat_123",
                    request_sha256="d" * 64,
                    started_at=NOW + timedelta(seconds=42),
                    completed_at=NOW + timedelta(seconds=44),
                    adapter_accepted=True,
                    external_status="confirmed",
                    external_receipt_id=f"adapter-reconciled-{suffix}",
                    evidence_ids=(f"evidence-reconciled-{suffix}",),
                    cleanup_receipt_id=f"cleanup-reconciled-{suffix}",
                    output_complete=True,
                    external_contact_count=0,
                    reconciliation_state=ReconciliationState.CONFIRMED,
                    reconciliation_evidence_ids=(f"evidence-reconciled-{suffix}",),
                    redispatch_permitted=False,
                    failure_code=None,
                )
                reconciled_confirmed = await repo.record_effect_receipt(
                    effect_id=reconciled_effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=ambiguous_reconciled.claim_version,
                    receipt_sha256=reconciled_receipt.receipt_sha256,
                    receipt_payload=reconciled_receipt.canonical_payload,
                    occurred_at=NOW + timedelta(seconds=44),
                )
                assert reconciled_confirmed.effect_state == "confirmed"

                manual_effect_id = f"effect-manual-{suffix}"
                await repo.reserve_effect(
                    EffectReservationCommand(
                        effect_record_id=f"effect-record-manual-{suffix}",
                        effect_id=manual_effect_id,
                        campaign_id=campaign_id,
                        strategy_record_id=strategy_record_id,
                        node_id=f"node-manual-{suffix}",
                        invocation_id=f"invocation-manual-{suffix}",
                        effect_intent_sha256="b" * 64,
                        effect_intent_payload={"capability_id": "nuclei-trusted-runtime"},
                        envelope_sha256="8" * 64,
                    ),
                    occurred_at=NOW + timedelta(seconds=45),
                )
                claimed_manual = await repo.claim_effect(
                    effect_id=manual_effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=0,
                    now=NOW + timedelta(seconds=46),
                    lease_seconds=30,
                )
                dispatching_manual = await repo.mark_effect_dispatching(
                    effect_id=manual_effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=claimed_manual.claim_version,
                    request_sha256="e" * 64,
                    runner_id="runner-r123",
                    workload_identity="spiffe://redagent.test/runner/compat_123",
                    occurred_at=NOW + timedelta(seconds=47),
                )
                ambiguous_manual = await repo.record_effect_ambiguity(
                    effect_id=manual_effect_id,
                    claim_owner="runner-relay-r123",
                    expected_claim_version=dispatching_manual.claim_version,
                    failure_code="adapter_receipt_commit_unknown",
                    occurred_at=NOW + timedelta(seconds=48),
                )
                retry_lookup = await repo.record_effect_lookup_unavailable(
                    effect_id=manual_effect_id,
                    expected_claim_version=ambiguous_manual.claim_version,
                    failure_code="adapter_status_lookup_unavailable",
                    occurred_at=NOW + timedelta(seconds=49),
                )
                manual = await repo.record_effect_lookup_unavailable(
                    effect_id=manual_effect_id,
                    expected_claim_version=retry_lookup.claim_version,
                    failure_code="adapter_status_lookup_unavailable",
                    occurred_at=NOW + timedelta(seconds=50),
                )
                assert manual.effect_state == "manual_review_required"
                assert manual.redispatch_permitted is False
                effects = metadata.tables["campaign_effects"]
                audits = metadata.tables["audit_events"]
                evidence_ids = await session.scalar(
                    select(effects.c.reconciliation_evidence_ids).where(
                        effects.c.tenant_id == tenant_id,
                        effects.c.effect_id == manual_effect_id,
                    )
                )
                assert isinstance(evidence_ids, list) and len(evidence_ids) == 1
                assert await session.scalar(
                    select(func.count()).select_from(audits).where(
                        audits.c.tenant_id == tenant_id,
                        audits.c.id == evidence_ids[0],
                        audits.c.action
                        == "campaign.r123.effect_manual_review_required",
                    )
                ) == 1
            finally:
                await nested.rollback()

        async with sessions() as session, session.begin():
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"reclaim-{suffix}",
            )
            assert await repo.claim_workflow_starts(
                claim_owner="relay-r123",
                now=NOW + timedelta(seconds=31),
                lease_seconds=30,
                limit=10,
            ) == []
    finally:
        await engine.dispose()


async def _bootstrap_terminal_owner_rows(
    sessions,
    *,
    tenant_id: str,
    actor_id: str,
    engagement_id: str,
    roe_id: str,
    campaign_id: str,
    suffix: str,
) -> str:
    job_id = f"job-r123-{suffix}"
    evidence_id = f"evidence-terminal-{suffix}"
    execution_id = f"adapter-receipt-{suffix}"
    retest_id = f"retest-{suffix}"
    owned = {
        "tenant_id": tenant_id,
        "version": 1,
        "created_at": NOW + timedelta(seconds=10),
        "updated_at": NOW + timedelta(seconds=10),
    }
    async with sessions() as session, session.begin():
        control = ControlPlaneRepository(
            session,
            tenant_id=tenant_id,
            actor_user_id=actor_id,
            correlation_id=f"terminal-job-{suffix}",
        )
        await control.create_job(
            job_id=job_id,
            engagement_id=engagement_id,
            roe_version_id=roe_id,
            request={
                "capability": "zap-controlled-runtime",
                "approval_timeout_seconds": 300,
                "max_activity_attempts": 1,
                "budget_reference": "budget:compat_123:owned-loopback",
            },
            workflow_id=f"job-workflow-{suffix}",
            policy_reference="policy:compat_123:owned-loopback",
            campaign_id=campaign_id,
            idempotency_key=f"terminal-job-{suffix}",
            occurred_at=NOW + timedelta(seconds=10),
        )
        await session.execute(
            insert(metadata.tables["evidence_artifacts"]).values(
                id=evidence_id,
                engagement_id=engagement_id,
                job_id=job_id,
                producer_id=actor_id,
                object_key=f"compat_123/{suffix}/report-safe.json",
                object_version_id="version-1",
                content_sha256="e" * 64,
                provider_checksum="e" * 64,
                size_bytes=64,
                content_type="application/json",
                artifact_class="report_safe",
                classification="internal",
                redaction_state="report_safe",
                retention_mode="GOVERNANCE",
                retain_until=NOW + timedelta(days=1),
                legal_hold=False,
                kms_reference="kms:compat_123:synthetic",
                attestation_hash="f" * 64,
                policy_reference="policy:compat_123:owned-loopback",
                quarantine_reason=None,
                finalized_at=NOW + timedelta(seconds=10),
                **owned,
            )
        )

        runner_class_id = f"runner-class-{suffix}"
        registration_id = f"runner-registration-{suffix}"
        manifest_id = f"runner-manifest-{suffix}"
        lease_id = f"runner-lease-{suffix}"
        await session.execute(
            insert(metadata.tables["runner_classes"]).values(
                id=runner_class_id,
                class_id="r123-loopback-runner",
                class_revision=1,
                environment="local-conformance",
                network_plane="owned-loopback",
                isolation_tier="container",
                runtime_name="docker",
                sandbox_profile_id="r123-closed-v1",
                policy_revision="r123-v1",
                resource_limits={"timeout_seconds": 300},
                credential_classes=["none"],
                evidence_schemas=["redagent.r123-terminal/v1"],
                class_status="active",
                author_user_id=actor_id,
                reviewer_user_id=f"reviewer-{suffix}",
                **owned,
            )
        )
        await session.execute(
            insert(metadata.tables["runner_registrations"]).values(
                id=registration_id,
                runner_id=f"runner-r123-{suffix}",
                runner_class_record_id=runner_class_id,
                environment="local-conformance",
                network_plane="owned-loopback",
                spiffe_id=f"spiffe://redagent.test/runner/{suffix}",
                certificate_fingerprint="a" * 64,
                certificate_serial=f"serial-{suffix}",
                adapter_allowlist=["zap-service@2.17.0-r104.2"],
                image_allowlist=["sha256:" + "b" * 64],
                required_policy_revision="r123-v1",
                generation=1,
                attestation_sha256="c" * 64,
                registration_state="active",
                registered_at=NOW,
                expires_at=NOW + timedelta(hours=1),
                revoked_at=None,
                last_seen_at=NOW + timedelta(seconds=10),
                **owned,
            )
        )
        await session.execute(
            insert(metadata.tables["runner_job_manifests"]).values(
                id=manifest_id,
                manifest_id=f"manifest-r123-{suffix}",
                job_id=job_id,
                runner_registration_id=registration_id,
                idempotency_key=f"manifest-r123-{suffix}",
                request_hash="1" * 64,
                manifest_document={"schema_version": "redagent.runner-manifest/v2"},
                manifest_sha256="2" * 64,
                signature_sha256="3" * 64,
                signing_key_id="r123-test-key",
                capability_id="zap-controlled-runtime",
                capability_revision=2,
                capability_sha256="4" * 64,
                image_digest="sha256:" + "b" * 64,
                artifact_receipt_id=f"artifact-receipt-{suffix}",
                policy_revision="r123-v1",
                policy_decision_id=f"policy-decision-{suffix}",
                nonce_hash="5" * 64,
                manifest_state="completed",
                issued_at=NOW,
                expires_at=NOW + timedelta(minutes=10),
                **owned,
            )
        )
        await session.execute(
            insert(metadata.tables["runner_pull_leases"]).values(
                id=lease_id,
                manifest_id=manifest_id,
                runner_registration_id=registration_id,
                claim_id=f"claim-{suffix}",
                lease_token_hash="6" * 64,
                runner_generation=1,
                manifest_sha256="2" * 64,
                lease_state="completed",
                claimed_at=NOW + timedelta(seconds=1),
                last_heartbeat_at=NOW + timedelta(seconds=9),
                expires_at=NOW + timedelta(minutes=5),
                finalized_at=NOW + timedelta(seconds=10),
                failure_code=None,
                **owned,
            )
        )
        await session.execute(
            insert(metadata.tables["runner_execution_receipts"]).values(
                id=f"runner-receipt-{suffix}",
                lease_id=lease_id,
                evidence_artifact_id=evidence_id,
                execution_id=execution_id,
                outcome="succeeded",
                final_phase="cleanup",
                policy_decision_id=f"policy-decision-{suffix}",
                evidence_sha256="e" * 64,
                cleanup_completed=True,
                residual_risk=None,
                completed_at=NOW + timedelta(seconds=10),
                **owned,
            )
        )

        findings = FindingOperationsRepository(
            session,
            tenant_id=tenant_id,
            actor_user_id=actor_id,
            correlation_id=f"terminal-finding-{suffix}",
        )
        imported = await findings.import_batch(
            ImportBatch(
                import_id=f"import-{suffix}",
                tenant_id=tenant_id,
                adapter_id="zap-service",
                run_id=execution_id,
                coverage_state=CoverageState.COMPLETE,
                comparable_baseline_run_id=None,
                records=(
                    FindingOccurrenceInput(
                        source_record_id=f"source-{suffix}",
                        tool="zap",
                        tool_version="2.17.0",
                        rule_id="10001",
                        rule_version="1",
                        database_version="compat_104",
                        title="Synthetic loopback finding",
                        resource_identity="http://127.0.0.1:41731",
                        location="/synthetic",
                        severity="low",
                        confidence="high",
                        taxonomy_ids=("CWE-200",),
                        control_ids=("RA-5",),
                        evidence_id=evidence_id,
                        evidence_sha256="e" * 64,
                        redaction_state="report_safe",
                        observed_at=NOW + timedelta(seconds=10),
                    ),
                ),
                imported_at=NOW + timedelta(seconds=10),
            )
        )
        issue_id = str(imported["issue_ids"][0])
        await findings.request_retest(
            issue_id=issue_id,
            retest_id=retest_id,
            baseline_run_id=execution_id,
            occurred_at=NOW + timedelta(seconds=10),
        )
        await findings.complete_retest(
            retest_id=retest_id,
            retest_run_id=f"retest-run-{suffix}",
            coverage_state="complete",
            result_state="passed",
            occurred_at=NOW + timedelta(seconds=11),
        )
        return issue_id


async def _bootstrap_manifest_issuer_authority(
    sessions,
    *,
    tenant_id: str,
    actor_id: str,
    suffix: str,
):
    capability = build_zap_capability_manifest(
        platform="linux/amd64",
        artifact_receipt_id=f"artifact-r123-{suffix}",
    )
    owned = {
        "tenant_id": tenant_id,
        "version": 1,
        "created_at": NOW,
        "updated_at": NOW,
    }
    async with sessions() as session, session.begin():
        await _set_tenant(session, tenant_id)
        runner_class_id = f"issuer-class-{suffix}"
        registration_id = f"issuer-registration-{suffix}"
        await session.execute(
            insert(metadata.tables["runner_classes"]).values(
                id=runner_class_id,
                class_id="r123-closed-runner",
                class_revision=1,
                environment="local-conformance",
                network_plane="owned-loopback",
                isolation_tier="container",
                runtime_name="docker",
                sandbox_profile_id=capability.sandbox_profile_id,
                policy_revision="policy-r123-v1",
                resource_limits=asdict(capability.limits),
                credential_classes=["none"],
                evidence_schemas=list(capability.evidence_schema),
                class_status="active",
                author_user_id=actor_id,
                reviewer_user_id=f"reviewer-{suffix}",
                **owned,
            )
        )
        await session.execute(
            insert(metadata.tables["runner_registrations"]).values(
                id=registration_id,
                runner_id="runner-r123",
                runner_class_record_id=runner_class_id,
                environment="local-conformance",
                network_plane="owned-loopback",
                spiffe_id="spiffe://redagent.test/runner/compat_123",
                certificate_fingerprint="a" * 64,
                certificate_serial=f"issuer-{suffix}",
                adapter_allowlist=["zap-service:2.17.0-r104.2"],
                image_allowlist=[capability.image_digest],
                required_policy_revision="policy-r123-v1",
                generation=1,
                attestation_sha256="b" * 64,
                registration_state="active",
                registered_at=NOW,
                expires_at=NOW + timedelta(minutes=10),
                revoked_at=None,
                last_seen_at=NOW,
                **owned,
            )
        )
        await session.execute(
            insert(metadata.tables["execution_capability_manifests"]).values(
                id=f"issuer-capability-{suffix}",
                capability_id=capability.capability_id,
                capability_revision=capability.revision,
                adapter_id=capability.adapter_id,
                adapter_version=capability.adapter_version,
                image_digest=capability.image_digest,
                input_schema_id=capability.input_schema_id,
                supported_modes=list(capability.supported_modes),
                phases=list(capability.phases),
                sandbox_profile_id=capability.sandbox_profile_id,
                network_mode=capability.network_mode.value,
                credential_class=capability.credential_class.value,
                evidence_schema=list(capability.evidence_schema),
                unsupported_features=list(capability.unsupported_features),
                resource_limits=asdict(capability.limits),
                artifact_receipt_id=capability.artifact_receipt_id,
                manifest_sha256=canonical_capability_sha256(capability),
                reviewed_by_user_id=capability.reviewed_by,
                capability_status=capability.status,
                **owned,
            )
        )
    return capability


def _authority_snapshot(
    *,
    tenant_id: str,
    actor_id: str,
    engagement_id: str,
    target_id: str,
    roe_id: str,
    target_sha256: str,
) -> CanonicalAuthoritySnapshot:
    return CanonicalAuthoritySnapshot(
        tenant_id=tenant_id,
        principal_id=actor_id,
        engagement_id=engagement_id,
        engagement_version=1,
        roe_version_id=roe_id,
        roe_revision=1,
        roe_sha256="1" * 64,
        roe_status="approved",
        roe_revocation_epoch=1,
        policy_decision_id=f"policy-decision-{tenant_id}",
        policy_revision="policy-r123-v1",
        policy_sha256="2" * 64,
        policy_status="allowed",
        policy_revocation_epoch=1,
        target_id=target_id,
        target_revision=1,
        target_sha256=target_sha256,
        target_value="http://127.0.0.1:41731",
        target_resolution_mode="owned-loopback",
        credential_class="none",
        credential_reference=None,
        quota_reference="quota-r123",
        quota_available=True,
        runner_id="runner-r123",
        runner_workload_identity="spiffe://redagent.test/runner/compat_123",
        runner_ready=True,
        reservation_id="reservation-r123",
        lease_id="lease-r123",
        lease_expires_at=NOW + timedelta(minutes=5),
        stop_requested=False,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=2),
    )


async def _activity_owner_replay_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-act-{suffix}"
    actor_id = f"user-r123-act-{suffix}"
    engagement_id = f"eng-r123-act-{suffix}"
    target_id = f"target-r123-act-{suffix}"
    roe_id = f"roe-r123-act-{suffix}"
    campaign_id = f"campaign-r123-act-{suffix}"
    strategy_record_id = f"strategy-record-act-{suffix}"
    strategy_revision_id = f"strategy-r123-act-{suffix}"
    workflow_id = f"redagent-r123-act-{suffix}"
    workflow_request_sha256 = "9" * 64
    bindings = [_activity_binding("zap-controlled-runtime"), _activity_binding("nuclei-trusted-runtime")]
    base = _command(
        campaign_id=campaign_id,
        engagement_id=engagement_id,
        target_id=target_id,
        roe_id=roe_id,
        strategy_record_id=strategy_record_id,
        strategy_revision_id=strategy_revision_id,
        workflow_id=workflow_id,
    )
    command = replace(
        base,
        context_payload={
            "tenant_id": tenant_id,
            "target_id": target_id,
            "bindings": [asdict(item) for item in bindings],
        },
        plan_payload={
            "schema_version": "redagent.r121-plan-revision/v1",
            "depth": 1,
            "primary": {"capability_id": "zap-controlled-runtime"},
            "successor": None,
        },
        workflow_request_sha256=workflow_request_sha256,
    )
    containment = _ContainmentOwner()
    effect = _ConfirmedEffectCoordinator()
    owner = PostgresCampaignActivityStateOwner(
        sessions,
        safety_gate=_AllowedActivitySafety(),
        containment_owner=containment,
    )
    coordinator = R123ActivityCoordinator(owner, effect)
    reconcile_command = R123ReconcileActivityCommand(
        CONTRACT_SCHEMA_VERSION,
        tenant_id,
        campaign_id,
        strategy_revision_id,
        command.envelope_sha256,
        workflow_request_sha256,
        1,
        False,
    )
    try:
        await _bootstrap(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
        )
        async with sessions() as session, session.begin():
            await R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"activity-start-{suffix}",
            ).start_campaign(command, occurred_at=NOW)

        first = await coordinator.reconcile(
            reconcile_command,
            occurred_at=NOW + timedelta(seconds=1),
            correlation_id=f"activity-reconcile-{suffix}",
        )
        replay = await coordinator.reconcile(
            reconcile_command,
            occurred_at=NOW + timedelta(seconds=2),
            correlation_id=f"activity-reconcile-{suffix}",
        )
        assert first == replay
        assert first.outcome == "dispatch_once" and first.revision == 2

        dispatch_command = R123DispatchActivityCommand(
            CONTRACT_SCHEMA_VERSION,
            tenant_id,
            campaign_id,
            strategy_revision_id,
            first.node_id or "",
            first.effect_id or "",
            command.envelope_sha256,
            first.revision,
        )
        dispatched = await coordinator.dispatch(
            dispatch_command,
            occurred_at=NOW + timedelta(seconds=3),
            correlation_id=f"activity-dispatch-{suffix}",
        )
        dispatch_replay = await coordinator.dispatch(
            dispatch_command,
            occurred_at=NOW + timedelta(seconds=4),
            correlation_id=f"activity-dispatch-{suffix}",
        )
        assert dispatched == dispatch_replay
        assert dispatched.state == "dispatched" and dispatched.revision == 3
        assert len(effect.calls) == 1
        assert effect.calls[0].principal_id == actor_id
        assert effect.calls[0].binding == bindings[0]

        contain_command = R123ContainActivityCommand(
            CONTRACT_SCHEMA_VERSION,
            tenant_id,
            campaign_id,
            strategy_revision_id,
            f"stop-{suffix}",
            actor_id,
            "f" * 64,
            dispatched.revision,
        )
        contained = await coordinator.contain(
            contain_command,
            occurred_at=NOW + timedelta(seconds=5),
            correlation_id=f"activity-contain-{suffix}",
        )
        contain_replay = await coordinator.contain(
            contain_command,
            occurred_at=NOW + timedelta(seconds=6),
            correlation_id=f"activity-contain-{suffix}",
        )
        assert contained == contain_replay
        assert contained.state == "contained" and contained.revision == 4
        assert containment.calls == 1

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            assert await _count(session, "campaign_effects", tenant_id) == 1
            campaign = await session.scalar(
                select(metadata.tables["campaigns"].c.aggregate_sequence).where(
                    metadata.tables["campaigns"].c.tenant_id == tenant_id,
                    metadata.tables["campaigns"].c.id == campaign_id,
                )
            )
            assert campaign == 4
    finally:
        await engine.dispose()


async def _activity_reconciliation_material_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-rec-{suffix}"
    actor_id = f"user-r123-rec-{suffix}"
    engagement_id = f"eng-r123-rec-{suffix}"
    target_id = f"target-r123-rec-{suffix}"
    roe_id = f"roe-r123-rec-{suffix}"
    campaign_id = f"campaign-r123-rec-{suffix}"
    strategy_record_id = f"strategy-record-rec-{suffix}"
    strategy_revision_id = f"strategy-r123-rec-{suffix}"
    workflow_id = f"redagent-r123-rec-{suffix}"
    workflow_request_sha256 = "7" * 64
    manifest_v2_sha256 = "6" * 64
    bindings = [
        _activity_binding("zap-controlled-runtime"),
        _activity_binding("nuclei-trusted-runtime"),
    ]
    base = _command(
        campaign_id=campaign_id,
        engagement_id=engagement_id,
        target_id=target_id,
        roe_id=roe_id,
        strategy_record_id=strategy_record_id,
        strategy_revision_id=strategy_revision_id,
        workflow_id=workflow_id,
    )
    start = replace(
        base,
        context_payload={
            "tenant_id": tenant_id,
            "target_id": target_id,
            "bindings": [asdict(item) for item in bindings],
        },
        plan_payload={
            "schema_version": "redagent.r121-plan-revision/v1",
            "depth": 1,
            "primary": {"capability_id": "zap-controlled-runtime"},
            "successor": None,
        },
        workflow_request_sha256=workflow_request_sha256,
    )
    owner = PostgresCampaignActivityStateOwner(
        sessions,
        safety_gate=_AllowedActivitySafety(),
        containment_owner=_ContainmentOwner(),
    )
    coordinator = R123ActivityCoordinator(owner, _ConfirmedEffectCoordinator())
    reconcile_command = R123ReconcileActivityCommand(
        CONTRACT_SCHEMA_VERSION,
        tenant_id,
        campaign_id,
        strategy_revision_id,
        start.envelope_sha256,
        workflow_request_sha256,
        1,
        False,
    )
    try:
        await _bootstrap(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
        )
        async with sessions() as session, session.begin():
            await R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"activity-rec-start-{suffix}",
            ).start_campaign(start, occurred_at=NOW)

        reserved = await coordinator.reconcile(
            reconcile_command,
            occurred_at=NOW + timedelta(seconds=1),
            correlation_id=f"activity-rec-reserve-{suffix}",
        )
        dispatch_command = R123DispatchActivityCommand(
            CONTRACT_SCHEMA_VERSION,
            tenant_id,
            campaign_id,
            strategy_revision_id,
            reserved.node_id or "",
            reserved.effect_id or "",
            start.envelope_sha256,
            reserved.revision,
        )
        dispatch_material = await owner.read_dispatch(
            dispatch_command,
            now=NOW + timedelta(seconds=2),
            correlation_id=f"activity-rec-read-{suffix}",
        )
        effect_command = dispatch_material.effect_command
        binding = effect_command.binding
        request = R123AdapterRequest(
            tenant_id=tenant_id,
            capability_id=binding.capability_id,
            capability_revision=binding.capability_revision,
            adapter_id=binding.adapter_id,
            adapter_version=binding.adapter_version,
            profile_id=binding.profile_id,
            profile_revision=binding.profile_revision,
            profile_sha256=binding.profile_sha256,
            bundle_id=binding.bundle_id,
            bundle_revision=binding.bundle_revision,
            bundle_sha256=binding.bundle_sha256,
            invocation_id=effect_command.invocation_id,
            effect_id=effect_command.effect_id,
            envelope_sha256=effect_command.envelope_sha256,
            manifest_v2_sha256=manifest_v2_sha256,
        )
        request_sha256 = hashlib.sha256(
            json.dumps(asdict(request), sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()

        async with sessions() as session, session.begin():
            control = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"activity-rec-job-{suffix}",
            )
            job = await control.create_job(
                job_id=f"job-r123-rec-{suffix}",
                engagement_id=engagement_id,
                roe_version_id=roe_id,
                request={
                    "capability": "zap-controlled-runtime",
                    "approval_timeout_seconds": 300,
                    "max_activity_attempts": 1,
                    "budget_reference": "budget:compat_123:owned-loopback",
                },
                workflow_id=f"job-workflow-rec-{suffix}",
                policy_reference="policy:compat_123:owned-loopback",
                campaign_id=campaign_id,
                idempotency_key=f"activity-rec-job-{suffix}",
                occurred_at=NOW + timedelta(seconds=2),
            )
            await session.execute(
                update(metadata.tables["jobs"])
                .where(
                    metadata.tables["jobs"].c.tenant_id == tenant_id,
                    metadata.tables["jobs"].c.id == job.resource["job_id"],
                )
                .values(
                    strategy_revision_id=strategy_record_id,
                    node_id=reserved.node_id,
                    effect_id=reserved.effect_id,
                    envelope_sha256=start.envelope_sha256,
                    manifest_v2_sha256=manifest_v2_sha256,
                )
            )
            repo = R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"activity-rec-ambiguous-{suffix}",
            )
            claimed = await repo.claim_effect(
                effect_id=effect_command.effect_id,
                claim_owner=effect_command.claim_owner,
                expected_claim_version=effect_command.expected_claim_version,
                now=NOW + timedelta(seconds=2),
                lease_seconds=30,
            )
            dispatching = await repo.mark_effect_dispatching(
                effect_id=effect_command.effect_id,
                claim_owner=effect_command.claim_owner,
                expected_claim_version=claimed.claim_version,
                request_sha256=request_sha256,
                runner_id="runner-r123",
                workload_identity="spiffe://redagent.test/runner/compat_123",
                occurred_at=NOW + timedelta(seconds=3),
            )

        recovered_revision = await owner.commit_dispatch(
            dispatch_command,
            dispatch_material,
            state="reconciliation_required",
            failure_code="adapter_acceptance_ambiguous",
            now=NOW + timedelta(seconds=4),
            correlation_id=f"activity-rec-crash-recovery-{suffix}",
        )
        assert recovered_revision == reserved.revision + 1
        async with sessions() as session, session.begin():
            ambiguity_replay = await R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"activity-rec-ambiguity-replay-{suffix}",
            ).record_effect_ambiguity(
                effect_id=effect_command.effect_id,
                claim_owner=effect_command.claim_owner,
                expected_claim_version=dispatching.claim_version,
                failure_code="adapter_receipt_commit_unknown",
                occurred_at=NOW + timedelta(seconds=4),
            )
            assert ambiguity_replay.claim_version == dispatching.claim_version + 1
        reconcile_after_recovery = replace(
            reconcile_command,
            revision=recovered_revision,
        )
        material = await owner.read_reconcile(
            reconcile_after_recovery,
            now=NOW + timedelta(seconds=5),
            correlation_id=f"activity-rec-reconstruct-{suffix}",
        )
        reconstructed = material.effect_reconciliation
        assert reconstructed is not None
        assert reconstructed.request == request
        assert reconstructed.request_sha256 == request_sha256
        assert reconstructed.effect_command.expected_claim_version == (
            dispatching.claim_version + 1
        )
        assert reconstructed.effect_command.expected_dispatch_attempt == 1
        assert reconstructed.effect_command.expected_dispatch_generation == 1
        assert reconstructed.runner_id == "runner-r123"
        assert reconstructed.workload_identity == "spiffe://redagent.test/runner/compat_123"
        assert reconstructed.started_at == NOW + timedelta(seconds=3)
    finally:
        await engine.dispose()


def _activity_binding(capability_id: str) -> CapabilityBindingKeyV1:
    closed = closed_execution_registry()[f"{capability_id}@2"]
    return CapabilityBindingKeyV1(
        schema_version="redagent.r119-capability-binding/v1",
        capability_id=capability_id,
        capability_revision=2,
        execution_manifest_sha256=("a" if capability_id.startswith("zap") else "b") * 64,
        adapter_id=closed.adapter_id,
        adapter_version=closed.adapter_version,
        profile_id=closed.profile_id,
        profile_revision=closed.profile_revision,
        profile_sha256=closed.profile_sha256,
        bundle_id=closed.bundle_id,
        bundle_revision=closed.bundle_revision,
        bundle_sha256=closed.bundle_sha256,
        semantics_revision=1,
        semantics_sha256="c" * 64,
        normalized_output_sha256="d" * 64,
        projection_revision=1,
        projection_sha256="e" * 64,
    )


async def _rollback_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-rollback-{suffix}"
    actor_id = f"user-r123-rollback-{suffix}"
    engagement_id = f"eng-r123-rollback-{suffix}"
    target_id = f"target-r123-rollback-{suffix}"
    roe_id = f"roe-r123-rollback-{suffix}"
    campaign_id = f"campaign-r123-rollback-{suffix}"
    try:
        await _bootstrap(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
        )
        with pytest.raises(RuntimeError, match="force rollback"):
            async with sessions() as session, session.begin():
                repo = R123CampaignRepository(
                    session,
                    tenant_id=tenant_id,
                    actor_user_id=actor_id,
                    correlation_id=f"rollback-{suffix}",
                )
                await repo.start_campaign(
                    _command(
                        campaign_id=campaign_id,
                        engagement_id=engagement_id,
                        target_id=target_id,
                        roe_id=roe_id,
                        strategy_record_id=f"strategy-record-{suffix}",
                        strategy_revision_id=f"strategy-r123-{suffix}",
                        workflow_id=f"redagent-r123-{suffix}",
                    ),
                    occurred_at=NOW,
                )
                raise RuntimeError("force rollback")
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            assert await _count(session, "campaigns", tenant_id) == 0
            assert await _count(session, "campaign_strategy_revisions", tenant_id) == 0
            assert await session.scalar(
                select(func.count())
                .select_from(metadata.tables["outbox_events"])
                .where(
                    metadata.tables["outbox_events"].c.tenant_id == tenant_id,
                    metadata.tables["outbox_events"].c.aggregate_id == campaign_id,
                )
            ) == 0
    finally:
        await engine.dispose()


async def _status_projection_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-status-{suffix}"
    actor_id = f"user-r123-status-{suffix}"
    engagement_id = f"eng-r123-status-{suffix}"
    target_id = f"target-r123-status-{suffix}"
    roe_id = f"roe-r123-status-{suffix}"
    campaign_id = f"campaign-r123-status-{suffix}"
    strategy_record_id = f"strategy-record-status-{suffix}"
    try:
        await _bootstrap(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
        )
        async with sessions() as session, session.begin():
            await R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"status-start-{suffix}",
            ).start_campaign(
                _command(
                    campaign_id=campaign_id,
                    engagement_id=engagement_id,
                    target_id=target_id,
                    roe_id=roe_id,
                    strategy_record_id=strategy_record_id,
                    strategy_revision_id=f"strategy-r123-status-{suffix}",
                    workflow_id=f"redagent-r123-status-{suffix}",
                ),
                occurred_at=NOW,
            )

        initial = await PostgresR123CampaignStatusOwner(sessions).read(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
        )
        assert initial.status == "dispatch_pending"
        assert initial.aggregate_sequence == 1
        assert initial.workflow_delivery_state == "pending"
        assert initial.workflow_reconciliation_state == "none"
        assert initial.effects == ()
        assert initial.terminal_receipt_present is False

        async with sessions() as session, session.begin():
            await R123CampaignRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"status-effect-{suffix}",
            ).reserve_effect(
                EffectReservationCommand(
                    effect_record_id=f"effect-record-status-{suffix}",
                    effect_id=f"effect-status-{suffix}",
                    campaign_id=campaign_id,
                    strategy_record_id=strategy_record_id,
                    node_id="node-zap",
                    invocation_id=f"invocation-status-{suffix}",
                    effect_intent_sha256="a" * 64,
                    effect_intent_payload={"capability_id": "zap-controlled-runtime@2"},
                    envelope_sha256="8" * 64,
                ),
                occurred_at=NOW + timedelta(seconds=1),
            )

        projected = await PostgresR123CampaignStatusOwner(sessions).read(
            tenant_id=tenant_id,
            campaign_id=campaign_id,
        )
        assert projected.aggregate_sequence == 2
        assert projected.effects[0].capability_id == "zap-controlled-runtime@2"
        assert projected.effects[0].state == "reserved"
        assert projected.effects[0].reconciliation_state == "none"
        assert projected.effects[0].evidence_count == 0
        assert projected.effects[0].cleanup_complete is False
    finally:
        await engine.dispose()


def _command(**ids: str) -> StartCampaignCommand:
    return StartCampaignCommand(
        **ids,
        name="compat_123 owned-loopback qualification",
        intent_sha256="1" * 64,
        context_schema="redagent.r119-context/v1",
        context_sha256="2" * 64,
        context_payload={"target_id": ids["target_id"]},
        decision_schema="redagent.r121-strategy-receipt/v1",
        decision_sha256="3" * 64,
        decision_payload={"outcome": "planned"},
        plan_revision=1,
        replan_count=0,
        plan_sha256="4" * 64,
        plan_payload={"nodes": ["node-zap"]},
        proposal_ceiling_sha256="5" * 64,
        approval_receipt_id=f"approval-{ids['campaign_id']}",
        approval_receipt_revision=1,
        approval_receipt_sha256="6" * 64,
        envelope_core_sha256="7" * 64,
        envelope_sha256="8" * 64,
        workflow_request_sha256="9" * 64,
    )


async def _bootstrap(
    sessions,
    *,
    tenant_id: str,
    actor_id: str,
    engagement_id: str,
    target_id: str,
    roe_id: str,
) -> None:
    async with sessions() as session, session.begin():
        repo = ControlPlaneRepository(
            session,
            tenant_id=tenant_id,
            actor_user_id=actor_id,
            correlation_id=f"bootstrap-{tenant_id}",
        )
        await repo.bootstrap_tenant(name="compat_123 tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=actor_id, subject=actor_id, occurred_at=NOW)
        await repo.create_engagement(
            engagement_id=engagement_id,
            name="compat_123 engagement",
            owner_user_id=actor_id,
            idempotency_key=f"eng-{engagement_id}",
            occurred_at=NOW,
        )
        await repo.create_target(
            target_id=target_id,
            engagement_id=engagement_id,
            target_type="url",
            normalized_value="http://127.0.0.1:41731",
            idempotency_key=f"target-{target_id}",
            occurred_at=NOW,
        )
        await repo.create_roe_version(
            roe_version_id=roe_id,
            engagement_id=engagement_id,
            revision=1,
            document={"scope": ["http://127.0.0.1:41731"], "active_testing": True},
            policy_reference_id=f"policy-{roe_id}",
            policy_name="r123-owned-loopback",
            policy_version="1",
            idempotency_key=f"roe-{roe_id}",
            occurred_at=NOW,
        )
        await repo.approve_roe_version(
            roe_version_id=roe_id,
            approval_id=f"approval-{roe_id}",
            expected_version=1,
            idempotency_key=f"approve-{roe_id}",
            occurred_at=NOW,
        )


def _database():
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


async def _set_tenant(session, tenant_id: str) -> None:
    await session.execute(select(func.set_config("redagent.tenant_id", tenant_id, True)))


async def _count(session, table_name: str, tenant_id: str) -> int:
    table = metadata.tables[table_name]
    value = await session.scalar(
        select(func.count()).select_from(table).where(table.c.tenant_id == tenant_id)
    )
    return int(value or 0)
