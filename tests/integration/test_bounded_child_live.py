"""Opt-in fixed owned-profile parent/child proof with synthetic campaign authority.

The native PostgreSQL, Temporal, OPA, runner, cleanup and report owners are real.
This does not qualify the normal operator API/UI or grant production authority.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import pytest
from sqlalchemy import func, select, text, update
from temporalio.client import Client
from temporalio.worker import Replayer, Worker

from redagent_platform.campaign_service.application_contracts import ApplicationPlanInvalid, AutonomousCampaignMode
from redagent_platform.campaign_service.application_repository import _json_payload
from redagent_platform.campaign_service.application_service import AutonomousCampaignApplicationService
from redagent_platform.campaign_service.approval_contracts import PLAN_APPROVE_SCHEMA_VERSION, ApproveAutonomousCampaignPlanV1
from redagent_platform.campaign_service.child_lineage import PostgresChildLineageVerifier
from redagent_platform.campaign_service.child_replan_contracts import CHILD_REQUEST_SCHEMA_VERSION, PrepareAutonomousCampaignChildV1
from redagent_platform.campaign_service.child_replan_store import PostgresCanonicalChildReplanStore, load_completed_owned_parent
from redagent_platform.campaign_service.activity_store import PostgresActivityContainmentOwner
from redagent_platform.campaign_service.admission_start_relay import AutonomousCampaignStartBridgeRelay
from redagent_platform.campaign_service.admission_start_relay_store import PostgresAutonomousCampaignStartBridgeRelayRepository
from redagent_platform.campaign_service.composition import build_runner_owned_campaign_dispatcher
from redagent_platform.campaign_service.dag_composition import build_dag_execution_temporal_activities
from redagent_platform.campaign_service.dag_execution_activity import DagActivityAction, DagActivityMaterialV1
from redagent_platform.campaign_service.dag_execution_contracts import DAG_EXECUTION_SCHEMA_VERSION, DagExecutionSnapshotV1, DagRunState, DagStopSignalV1, deterministic_dag_workflow_id
from redagent_platform.campaign_service.dag_lifecycle_store import PostgresDagLifecycleOwner
from redagent_platform.campaign_service.dag_policy import DagPolicyDecisionAdapter
from redagent_platform.campaign_service.owned_dag_cleanup import PostgresOwnedDagCleanupVerifier
from redagent_platform.campaign_service.dag_relay import DagWorkflowRelay
from redagent_platform.campaign_service.dag_relay_store import PostgresDagWorkflowRelayRepository
from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1
from redagent_platform.campaign_service.planning.owned_sequential import OWNED_SEQUENTIAL_VALIDATOR_VERSION, OWNED_SEQUENTIAL_VALIDATOR_SHA256
from redagent_platform.campaign_service.planning.serde import _decode_dataclass
from redagent_platform.campaign_service.replanning_contracts import BoundedReplanProposalV1
from redagent_platform.campaign_service.resolver import CampaignContextResolver
from redagent_platform.campaign_service.runtime import PostgresRunnerIdentityOwner, _verify_current_zap, _verify_current_nuclei
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.evidence_service.service import EvidenceService, _stored_from_artifact
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from redagent_platform.runner_service.contracts import canonical_capability_sha256
from redagent_platform.orchestration.admission_start_workflow import AutonomousCampaignStartBridgeWorkflow
from redagent_platform.orchestration.admission_start_gateway import AutonomousCampaignStartBridgeTemporalGateway
from redagent_platform.orchestration.dag_execution_gateway import DagExecutionTemporalStartGateway
from redagent_platform.orchestration.dag_execution_workflow import CampaignDagExecutionWorkflow
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.policy_service.providers import OpaPolicyDecisionProvider
from scripts import opa_conformance
from tests.integration.test_autonomous_campaign_admission_start_repository import _prepare_approved_campaign, _admission_service
from tests.integration.test_autonomous_campaign_application_repository import _set_tenant
from tests.integration.test_autonomous_campaign_plan_approval_repository import _ApprovalContextProvider
from tests.integration.test_campaign_dag_execution_repository import _AuthorityProvider, _authority_snapshot
from tests.integration.test_owned_execution_live import _ObservedDispatcher, _install_runner
from tests.integration.test_migrations import _alembic, _create_database, _drop_database


ROOT = Path(__file__).resolve().parents[2]
LIVE = os.environ.get("REDAGENT_CHILD_REPLAN_LIVE_TEST") == "owned-child-v1"


class _ObservedLineageVerifier:
    def __init__(self, owner):
        self.owner = owner

    async def verify(self, **kwargs):
        try:
            return await self.owner.verify(**kwargs)
        except (ValueError, RuntimeError) as exc:
            code = str(exc)
            print(json.dumps({"child_lineage_guard": type(exc).__name__,
                              "code": code if re.fullmatch(r"[a-z][a-z0-9_]{0,150}", code) else "opaque_failure"}), flush=True)
            raise


class _ObservedCoordinatorBoundary:
    """Observe native phases without replacing their decisions or transitions."""

    def __init__(self, owner, boundary):
        self.owner, self.boundary = owner, boundary

    def __getattr__(self, phase):
        native = getattr(self.owner, phase)

        async def observe(*args, **kwargs):
            try:
                result = await native(*args, **kwargs)
            except Exception as exc:
                pending, visited = [exc], set()
                while pending and len(visited) < 8:
                    error = pending.pop()
                    if id(error) in visited:
                        continue
                    visited.add(id(error))
                    reason = str(error)
                    print(json.dumps({"native_boundary": self.boundary, "phase": phase,
                        "type": type(error).__name__, "code": reason if re.fullmatch(
                            r"[A-Za-z][A-Za-z0-9_.:-]{0,199}", reason) else "opaque_failure"}), flush=True)
                    pending.extend(item for item in (error.__cause__, error.__context__) if item is not None)
                raise
            if phase == "recheck":
                print(json.dumps({"native_boundary": self.boundary, "phase": phase,
                    "allowed": result.allowed, "reason": result.reason}), flush=True)
            if phase == "ambiguity":
                print(json.dumps({"native_boundary": self.boundary, "phase": phase,
                    "reason": kwargs["failure_code"]}), flush=True)
            return result

        return observe


@pytest.mark.skipif(not LIVE, reason="requires explicit fixed owned-profile parent/child authority")
def test_real_owned_parent_to_fresh_strict_subset_child(monkeypatch):
    from redagent_platform.zap_service.campaign_transport import ZapDockerTransport

    original_run = ZapDockerTransport._run

    def measured_run(self, command, **kwargs):
        started = time.monotonic()
        try:
            return original_run(self, command, **kwargs)
        finally:
            print(json.dumps({"owned_runtime_command": list(command[:2]),
                              "elapsed_seconds": round(time.monotonic() - started, 3),
                              "timeout_seconds": kwargs.get("timeout")}), flush=True)

    monkeypatch.setattr(ZapDockerTransport, "_run", measured_run)
    with opa_conformance.opa_fixture_lease():
        assert opa_conformance._provision()["ok"]
        try:
            asyncio.run(_isolated_scenario(monkeypatch))
        finally:
            opa_conformance._scoped_cleanup()


class _StopBeforeSecondEffect:
    def __init__(self, delegate, remaining_node_id):
        self.delegate, self.remaining_node_id = delegate, remaining_node_id
        self.ready, self.release = asyncio.Event(), asyncio.Event()

    async def prepare(self, request, *, now):
        snapshot = await self.delegate.snapshot(request, now=now)
        if snapshot.current_node_id == self.remaining_node_id:
            # Actual native snapshot only: pause before prepare can create a second effect, then use the normal Workflow stop signal.
            self.ready.set()
            await self.release.wait()
            return DagActivityMaterialV1(DagActivityAction.WAIT, snapshot, None, None)
        return await self.delegate.prepare(request, now=now)

    async def snapshot(self, request, *, now):
        return await self.delegate.snapshot(request, now=now)


class _ObservedCleanupVerifier(PostgresOwnedDagCleanupVerifier):
    async def verify_in_session(self, session, request, run, *, now):
        try:
            return await super().verify_in_session(session, request, run, now=now)
        except (ValueError, RuntimeError, KeyError, TypeError) as error:
            code = str(error)
            print(json.dumps({"owned_cleanup_guard": type(error).__name__,
                              "code": code if code.replace("_", "").isalnum() else "opaque_failure"}), flush=True)
            raise


async def _isolated_scenario(monkeypatch):
    settings = load_database_settings(ROOT, env=os.environ)
    name = "owned_child_" + uuid4().hex
    directory = ROOT / ".local/redagent/test-databases" / name
    directory.mkdir(parents=True, exist_ok=False)
    secret = directory / "database-url"
    secret.write_text(settings.url.set(database=name).render_as_string(hide_password=False), encoding="utf-8")
    previous = os.environ.get("REDAGENT_DATABASE_URL_FILE")
    prepared = None
    try:
        await _create_database(settings.url.set(database="postgres"), name)
        migrated = _alembic(secret, "upgrade", "head")
        assert migrated.returncode == 0, migrated.stderr
        os.environ["REDAGENT_DATABASE_URL_FILE"] = str(secret)
        now = datetime.now(timezone.utc)
        zap_artifact, _ = _verify_current_zap(ROOT, now=now)
        nuclei_artifact, _, _ = _verify_current_nuclei(ROOT, now=now)
        zap = build_zap_capability_manifest(platform="linux/amd64", artifact_receipt_id=zap_artifact.receipt_id)
        nuclei = build_nuclei_capability_manifest(platform="linux/amd64", artifact_receipt_id=nuclei_artifact.receipt_id)
        prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.BOUNDED_REPLAN,
            now=now - timedelta(seconds=5), validity_seconds=180, policy_revision="r099-v1",
            bounded_manifest_sha256s={zap.capability_id: canonical_capability_sha256(zap),
                                     nuclei.capability_id: canonical_capability_sha256(nuclei)})
        backend = LocalAppendOnlyBackend(ROOT / ".tmp/owned-child-evidence" / name, profile="synthetic-local")
        provider = _ApprovalContextProvider(prepared.approval_context)
        lineage = _ObservedLineageVerifier(PostgresChildLineageVerifier(prepared.sessions, evidence_backend=backend,
            context_provider=provider, trusted_keys=prepared.trusted_keys, actor_user_id=prepared.command.actor_user_id))
        # CRITICAL: fixture provisioning belongs before admission; consuming a live policy lease for setup can time out authorized execution.
        runner_suffixes = {}
        for capability in (zap, nuclei):
            suffix = uuid4().hex
            runner_suffixes[capability.capability_id] = suffix
            await _install_runner(prepared, capability, suffix, datetime.now(timezone.utc),
                class_identity="owned-closed-" + capability.capability_id,
                certificate_fingerprint=hashlib.sha256(("owned-fixture-certificate:" + suffix).encode()).hexdigest())
        dispatcher = _ObservedDispatcher(build_runner_owned_campaign_dispatcher(ROOT, prepared.sessions,
            runner_identity_owner=PostgresRunnerIdentityOwner(prepared.sessions), evidence_service=EvidenceService(prepared.sessions, backend),
            actor_user_id=prepared.command.actor_user_id, kms_reference="kms:redagent:synthetic-local", owned_execution=True))
        client = await Client.connect("127.0.0.1:62001")
        async with httpx.AsyncClient(timeout=5) as http:
            policy = OpaPolicyDecisionProvider(http, endpoint=opa_conformance.opa_endpoint(), token_source=lambda: opa_conformance.APP_TOKEN)
            root_service = _admission_service(sessions=prepared.sessions, repository=prepared.repository,
                context_provider=prepared.context_provider, context=prepared.context, trusted_keys=prepared.trusted_keys,
                policy_provider=policy, lease_seconds=300, owned_sequential=True, child_lineage_verifier=lineage)
            root, parent_history = await _execute(prepared, zap, backend, lineage, client, policy, stop_before_second=True,
                runner_suffix=runner_suffixes[zap.capability_id], dispatcher=dispatcher,
                admit=lambda: root_service.admit_and_queue(replace(prepared.command, occurred_at=datetime.now(timezone.utc))))
            async with prepared.sessions() as session, session.begin():
                parent = await load_completed_owned_parent(session, tenant_id=prepared.tenant, application_id=prepared.campaign,
                    parent_execution_run_id=root.execution_run_id, actor_user_id=prepared.command.actor_user_id,
                    correlation_id="owned-child-parent-proof", evidence_backend=backend, now=datetime.now(timezone.utc),
                    authority=prepared.context.signed_authority.authority, lock_rows=False)
            completed_at = parent.source.effect_receipt.completed_at
            current = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
            assert current.lifecycle_state.value == "FAILED_CONTAINED"
            command = PrepareAutonomousCampaignChildV1(schema_version=CHILD_REQUEST_SCHEMA_VERSION,
                tenant_id=prepared.tenant, campaign_id=prepared.campaign, actor_user_id=prepared.command.actor_user_id,
                expected_revision=current.aggregate_revision, idempotency_key="owned-child-request", correlation_id="owned-child-correlation",
                occurred_at=datetime.now(timezone.utc))
            store = PostgresCanonicalChildReplanStore(prepared.sessions, evidence_backend=backend)
            application = AutonomousCampaignApplicationService(prepared.repository, mode=AutonomousCampaignMode.BOUNDED_REPLAN,
                approval_context_provider=provider, trusted_approval_keys=prepared.trusted_keys, validation_limits=ValidationLimitsV1(2, 1, 32),
                trusted_validator_version=OWNED_SEQUENTIAL_VALIDATOR_VERSION, trusted_validator_sha256=OWNED_SEQUENTIAL_VALIDATOR_SHA256,
                child_lineage_verifier=lineage, canonical_child_store=store)
            with pytest.raises(ApplicationPlanInvalid):
                await application.prepare_child(command)
            available_at = completed_at + timedelta(seconds=60)
            remaining = (available_at - datetime.now(timezone.utc)).total_seconds()
            assert 0 < remaining <= 60, "early cooldown denial must occur before the full real window"
            print("parent actual receipt and containment verified; waiting only its fixed 60-second capacity window", flush=True)
            await asyncio.sleep(remaining)
            command = replace(command, occurred_at=datetime.now(timezone.utc))
            await _terminal_drift_proof(prepared, root, backend, monkeypatch)
            print("actual terminal parent concurrent drift denial: PASS", flush=True)
            def fail_after_proposal_context(*args):
                raise RuntimeError("controlled_child_transaction_rollback")
            with pytest.raises(RuntimeError, match="controlled_child_transaction_rollback"):
                await store.stage_child(command, read_context=provider.read_current_approval_context,
                    build_preview=fail_after_proposal_context, trusted_keys=prepared.trusted_keys)
            async with prepared.sessions() as session, session.begin():
                await _set_tenant(session, prepared.tenant)
                for table_name in ("campaign_observation_decisions", "trusted_campaign_observations", "campaign_replan_proposals",
                                   "campaign_child_capacity_settlements", "autonomous_campaign_child_replans"):
                    table = metadata.tables[table_name]
                    assert await session.scalar(select(func.count()).select_from(table).where(table.c.tenant_id == prepared.tenant)) == 0
            print("actual child staging atomic rollback: PASS", flush=True)
            command = replace(command, occurred_at=datetime.now(timezone.utc))
            first, replay = await asyncio.gather(application.prepare_child(command), application.prepare_child(command))
            assert sorted((first.replayed, replay.replayed)) == [False, True]
            print("actual child same-key concurrency produced one child and one replay: PASS", flush=True)
            child_preview = first.preview
            assert child_preview.child_lineage_sha256 is not None and len(child_preview.actions) == 1
            assert child_preview.actions[0].capability_id == nuclei.capability_id
            with pytest.raises(ApplicationPlanInvalid):
                await application.prepare_child(replace(command, idempotency_key="another-child-request"))
            class MutatedReportRead:
                def verify_exact(self, stored):
                    return backend.verify_exact(stored)

                def get_exact(self, key, version):
                    return backend.get_exact(key, version) + b" "

            bad_verifier = PostgresChildLineageVerifier(prepared.sessions, evidence_backend=MutatedReportRead(),
                context_provider=provider, trusted_keys=prepared.trusted_keys)
            with pytest.raises(RuntimeError, match="report"):
                await bad_verifier.verify(tenant_id=prepared.tenant, campaign_id=prepared.campaign,
                    preview=child_preview, now=datetime.now(timezone.utc))
            await lineage.verify(tenant_id=prepared.tenant, campaign_id=prepared.campaign, preview=child_preview, now=datetime.now(timezone.utc))
            print("actual fresh child lineage and changed-report denial: PASS", flush=True)
            approval = await application.approve_plan(ApproveAutonomousCampaignPlanV1(schema_version=PLAN_APPROVE_SCHEMA_VERSION,
                tenant_id=prepared.tenant, campaign_id=prepared.campaign, preview_id=child_preview.preview_id,
                preview_sha256=child_preview.preview_sha256, actor_user_id=child_preview.required_approvers[0].principal_id,
                actor_permissions=("campaign:approve", "campaign:read"), policy_reference=prepared.command.policy_reference,
                expected_revision=child_preview.application_revision, idempotency_key="owned-child-approval",
                correlation_id="owned-child-approval-correlation", occurred_at=datetime.now(timezone.utc)))
            async with prepared.sessions() as session, session.begin():
                await _set_tenant(session, prepared.tenant)
                rows = metadata.tables["campaign_replan_proposals"]
                row = (await session.execute(select(rows).where(rows.c.tenant_id == prepared.tenant))).mappings().one()
                proposal = _decode_dataclass(BoundedReplanProposalV1, row["proposal_payload"])
            child_context = replace(prepared.context, revision=proposal.child_revision, certificate=proposal.validation_certificate)
            prepared.context_provider._context = child_context
            child_command = replace(prepared.command, approval_receipt_id=approval.receipt.receipt_id,
                approval_receipt_sha256=approval.receipt.receipt_sha256, expected_revision=approval.application.aggregate_revision,
                idempotency_key="owned-child-admission", correlation_id="owned-child-admission-correlation", occurred_at=datetime.now(timezone.utc))
            child_service = _admission_service(sessions=prepared.sessions, repository=prepared.repository,
                context_provider=prepared.context_provider, context=child_context, trusted_keys=prepared.trusted_keys,
                policy_provider=policy, lease_seconds=300, owned_sequential=True, child_lineage_verifier=lineage)
            child, child_history = await _execute(prepared, nuclei, backend, lineage, client, policy, stop_before_second=False,
                runner_suffix=runner_suffixes[nuclei.capability_id], dispatcher=dispatcher,
                admit=lambda: child_service.admit_and_queue(replace(child_command, occurred_at=datetime.now(timezone.utc))), previous_run=root)
            assert child.execution_run_id != root.execution_run_id
            assert child.admission_receipt.reservation_id != root.admission_receipt.reservation_id
            print("actual fresh child approval and distinct admission/reservation/start: PASS", flush=True)
            await _write_proof(prepared, root, child, backend, parent_history, child_history)
    finally:
        if prepared is not None:
            await prepared.engine.dispose()
        if previous is None:
            os.environ.pop("REDAGENT_DATABASE_URL_FILE", None)
        else:
            os.environ["REDAGENT_DATABASE_URL_FILE"] = previous
        await _drop_database(settings.url.set(database="postgres"), name)
        secret.unlink(missing_ok=True)
        directory.rmdir()
        print("disposable child database and secret pointer cleaned", flush=True)


async def _terminal_drift_proof(prepared, root, backend, monkeypatch):
    import redagent_platform.campaign_service.child_replan_store as owner
    original = owner._verify_report
    async def drift_after_report(*args):
        result = await original(*args)
        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            runs = metadata.tables["campaign_execution_runs"]
            await session.execute(update(runs).where(runs.c.tenant_id == prepared.tenant, runs.c.id == root.execution_run_id)
                                  .values(version=runs.c.version + 1))
        return result
    with monkeypatch.context() as scoped:
        scoped.setattr(owner, "_verify_report", drift_after_report)
        async with prepared.sessions() as session, session.begin():
            with pytest.raises(RuntimeError, match="terminal_owner_drift"):
                await load_completed_owned_parent(session, tenant_id=prepared.tenant, application_id=prepared.campaign,
                    parent_execution_run_id=root.execution_run_id, actor_user_id=prepared.command.actor_user_id,
                    correlation_id="terminal-drift-proof", evidence_backend=backend, now=datetime.now(timezone.utc),
                    authority=prepared.context.signed_authority.authority, lock_rows=False)


async def _execute(prepared, capability, backend, lineage, client, policy, *, stop_before_second, runner_suffix, dispatcher, admit, previous_run=None):
    now, suffix = datetime.now(timezone.utc), runner_suffix
    authority = prepared.context.signed_authority.authority
    async with prepared.sessions() as session, session.begin():
        await _set_tenant(session, prepared.tenant)
        campaigns, targets = metadata.tables["campaigns"], metadata.tables["targets"]
        campaign = (await session.execute(select(campaigns).where(campaigns.c.id == prepared.campaign))).mappings().one()
        target = (await session.execute(select(targets).where(targets.c.id == authority.target_ids[0]))).mappings().one()
    authority_provider = _AuthorityProvider(None)
    activities = build_dag_execution_temporal_activities(sessions=prepared.sessions, resolver=CampaignContextResolver(authority_provider),
        lifecycle=PostgresDagLifecycleOwner(prepared.sessions), policy=DagPolicyDecisionAdapter(policy), dispatcher=dispatcher,
        containment=PostgresActivityContainmentOwner(prepared.sessions), signing_key=Ed25519PrivateKey.generate(), signing_key_id="owned-child-test-key",
        owned_execution_enabled=True, actor_user_id=prepared.command.actor_user_id, child_lineage_verifier=lineage,
        owned_cleanup_verifier=_ObservedCleanupVerifier(backend))
    coordinator = activities._application._coordinator
    coordinator._authority = _ObservedCoordinatorBoundary(coordinator._authority, "effect_authority")
    coordinator._store = _ObservedCoordinatorBoundary(coordinator._store, "effect_transition")
    stopper = None
    if stop_before_second:
        stopper = _StopBeforeSecondEffect(activities._state, prepared.context.revision.candidate_plan.nodes[1].node_id)
        activities._state = stopper
    queue = "owned-child-" + suffix
    handle = None
    async with Worker(client, task_queue=queue, workflows=[AutonomousCampaignStartBridgeWorkflow, CampaignDagExecutionWorkflow],
                          activities=[activities.reconcile, activities.dispatch, activities.contain]):
        try:
            # CRITICAL: worker startup is fixture preparation, before the unchanged fresh OPA-clipped admission lease begins.
            admitted = await admit()
            assert admitted.execution_run_id is not None, admitted.admission_receipt.reason_code
            if previous_run is not None:
                assert admitted.execution_run_id != previous_run.execution_run_id
                assert admitted.admission_receipt.reservation_id != previous_run.admission_receipt.reservation_id
            now = datetime.now(timezone.utc)
            authority_provider.snapshot = replace(_authority_snapshot(tenant=prepared.tenant, actor=prepared.command.actor_user_id,
                engagement=authority.engagement_id, target_id=authority.target_ids[0], reservation_id=admitted.admission_receipt.reservation_id, suffix=suffix),
                target_value=target["normalized_value"], target_sha256=hashlib.sha256(json.dumps({"target_id": target["id"], "revision": 1,
                    "target_type": "url", "normalized_value": target["normalized_value"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                roe_version_id=campaign["roe_version_id"], roe_sha256=authority.roe_sha256, roe_revocation_epoch=authority.roe_revocation_epoch,
                policy_revision=authority.policy_revision, policy_sha256=authority.policy_bundle_sha256, policy_revocation_epoch=authority.policy_revocation_epoch,
                runner_id=f"owned-runner-{suffix}", runner_workload_identity=f"spiffe://redagent.test/runner/{suffix}",
                lease_expires_at=admitted.admission_receipt.expires_at, observed_at=now, expires_at=admitted.admission_receipt.expires_at)
            bridge = PostgresAutonomousCampaignStartBridgeRelayRepository(prepared.sessions, tenant_id=prepared.tenant,
                actor_user_id=prepared.command.actor_user_id, correlation_prefix="owned-child-bridge", child_lineage_verifier=lineage)
            claim = (await bridge.claim_admission_start_bridges(claim_owner="owned-child-bridge", now=datetime.now(timezone.utc), lease_seconds=30, limit=1))[0]
            await AutonomousCampaignStartBridgeRelay(repository=bridge,
                gateway=AutonomousCampaignStartBridgeTemporalGateway(client, task_queue=queue)).deliver(claim, now=datetime.now(timezone.utc))
            relay = PostgresDagWorkflowRelayRepository(prepared.sessions, tenant_id=prepared.tenant,
                actor_user_id=prepared.command.actor_user_id, correlation_prefix="owned-child-relay")
            claim = (await relay.claim_dag_workflow_starts(claim_owner="owned-child-dag", now=datetime.now(timezone.utc), lease_seconds=30, limit=1))[0]
            await DagWorkflowRelay(repository=relay, gateway=DagExecutionTemporalStartGateway(client, task_queue=queue)).deliver(claim, now=datetime.now(timezone.utc))
            handle = client.get_workflow_handle(deterministic_dag_workflow_id(prepared.tenant, admitted.execution_run_id), result_type=DagExecutionSnapshotV1)
            if stopper is not None:
                ready = asyncio.create_task(stopper.ready.wait())
                terminal = asyncio.create_task(handle.result())
                try:
                    done, _ = await asyncio.wait((ready, terminal), timeout=90, return_when=asyncio.FIRST_COMPLETED)
                    if terminal in done:
                        early_result = terminal.result()
                        pytest.fail(json.dumps({"unexpected_parent_terminal": early_result.state.value,
                                                "dispatch_failures": dispatcher.failures}))
                    assert ready in done, "parent never reached the actual second-node frontier"
                finally:
                    ready.cancel()
                    terminal.cancel()
                    await asyncio.gather(ready, terminal, return_exceptions=True)
                await handle.signal("stop", DagStopSignalV1(DAG_EXECUTION_SCHEMA_VERSION, "owned-child-frontier-stop",
                    prepared.command.actor_user_id, hashlib.sha256(b"controlled-stop-after-real-owned-parent-result").hexdigest()))
                stopper.release.set()
            result = await asyncio.wait_for(handle.result(), timeout=120)
            expected = DagRunState.CONTAINED if stop_before_second else DagRunState.COMPLETED
            assert result.state is expected, json.dumps({"state": result.state.value, "dispatch_failures": dispatcher.failures})
            history = await handle.fetch_history()
        finally:
            if handle is not None:
                await _execution_diagnostics(prepared, admitted.execution_run_id)
            if stopper is not None:
                stopper.release.set()
            if handle is not None:
                description = await handle.describe()
                if description.status.name == "RUNNING":
                    await handle.signal("stop", DagStopSignalV1(DAG_EXECUTION_SCHEMA_VERSION, "owned-child-final-cleanup",
                        prepared.command.actor_user_id, hashlib.sha256(b"owned-child-final-cleanup").hexdigest()))
                    await asyncio.wait_for(handle.result(), timeout=120)
    await Replayer(workflows=[CampaignDagExecutionWorkflow]).replay_workflow(history)
    return admitted, history


async def _execution_diagnostics(prepared, run_id):
    async with prepared.sessions() as session, session.begin():
        await _set_tenant(session, prepared.tenant)
        for name, columns in (
            ("campaign_effects", ("id", "effect_state", "failure_code", "reconciliation_state", "external_status", "created_at", "updated_at", "claim_expires_at")),
            ("runner_job_manifests", ("id", "manifest_state", "issued_at", "expires_at")),
            ("runner_pull_leases", ("id", "lease_state", "created_at", "expires_at")),
        ):
            table = metadata.tables[name]
            rows = (await session.execute(select(*(table.c[column] for column in columns))
                                          .where(table.c.tenant_id == prepared.tenant))).mappings().all()
            print(json.dumps({"owner_table": name, "requested_run_id": run_id, "inventory_scope": "disposable_tenant",
                              "time_projections": _json_payload({"rows": [dict(row) for row in rows]})["rows"]}), flush=True)
        waits = (await session.execute(text("SELECT state, wait_event_type, wait_event, cardinality(pg_blocking_pids(pid)) AS blockers FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()"))).mappings().all()
        print(json.dumps({"database_waits": [dict(row) for row in waits]}), flush=True)


async def _write_proof(prepared, parent, child, backend, parent_history, child_history):
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    async with prepared.sessions() as session, session.begin():
        await _set_tenant(session, prepared.tenant)
        effects = metadata.tables["campaign_effects"]
        rows = tuple((await session.execute(select(effects).where(effects.c.tenant_id == prepared.tenant))).mappings().all())
        assert len(rows) == 2 and {row["execution_run_id"] for row in rows} == {parent.execution_run_id, child.execution_run_id}
        for row in rows:
            receipt = row["effect_receipt_payload"]
            assert row["effect_state"] == "confirmed" and row["dispatch_attempt"] == row["dispatch_generation"] == 1
            assert receipt["external_contact_count"] == 0 and receipt["output_complete"] and receipt["cleanup_receipt_id"]
        artifacts = metadata.tables["evidence_artifacts"]
        artifact_rows = tuple((await session.execute(select(artifacts).where(artifacts.c.tenant_id == prepared.tenant))).mappings().all())
        assert artifact_rows
        for row in artifact_rows:
            verification = backend.verify_exact(_stored_from_artifact(dict(row)))
            assert verification.ok, verification.reason
        owners = {}
        for name in ("autonomous_campaign_child_replans", "campaign_child_capacity_settlements", "campaign_replan_proposals",
                     "trusted_campaign_observations", "campaign_observation_decisions", "campaign_budget_reservations",
                     "campaign_budget_ledgers", "campaign_budget_events",
                     "autonomous_campaign_applications", "autonomous_campaign_application_events",
                     "autonomous_campaign_plan_previews", "autonomous_campaign_plan_approval_receipts",
                     "autonomous_campaign_execution_starts", "plan_admission_receipts",
                     "campaign_execution_runs", "campaign_execution_nodes", "campaign_execution_authority_observations",
                     "runner_job_manifests", "runner_pull_leases", "runner_lifecycle_events", "runner_execution_receipts",
                     "finding_import_sessions", "finding_import_records"):
            table = metadata.tables[name]
            owners[name] = [dict(row) for row in (await session.execute(select(table).where(table.c.tenant_id == prepared.tenant))).mappings().all()]
        assert len(owners["autonomous_campaign_child_replans"]) == len(owners["campaign_child_capacity_settlements"]) == 1
        current = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
        assert current.lifecycle_state.value == "EVIDENCE_PENDING"
        proof_root = ROOT / ".tmp/owned-child-proofs"
        proof_root.mkdir(parents=True, exist_ok=True)
        parent_history_sha = _write_history_bytes(proof_root / (child.execution_run_id + "-parent-history.json"), parent_history)
        child_history_sha = _write_history_bytes(proof_root / (child.execution_run_id + "-child-history.json"), child_history)
        proof = {"schema_version": "redagent.owned-child-composition-proof/v1",
            "authority_kind": "synthetic-campaign-authority-with-real-local-owners", "normal_api_ui_qualified": False,
            "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
            "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
            "tracked_candidate_dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True).strip()),
            "tenant_id": prepared.tenant, "campaign_id": prepared.campaign,
            "campaign_state": current.lifecycle_state.value,
            "evidence_backend_root": backend.root.relative_to(ROOT).as_posix(),
            "synthetic_signed_authority": _json_payload(prepared.context.signed_authority),
            "synthetic_authority_lifecycle": _json_payload(prepared.context.authority_lifecycle),
            "synthetic_public_approval_keys": [{"key_id": key.key_id, "approver_id": key.approver_id,
                "allowed_roles": list(key.allowed_roles),
                "public_key_hex": key.public_key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex()}
                for key in prepared.trusted_keys.values()],
            "parent_run_id": parent.execution_run_id, "child_run_id": child.execution_run_id,
            "parent_admission": _json_payload(parent.admission_receipt), "child_admission": _json_payload(child.admission_receipt),
            "effects": [dict(row) for row in rows], "artifacts": [dict(row) for row in artifact_rows], "owners": owners,
            "parent_history_sha256": parent_history_sha,
            "child_history_sha256": child_history_sha, "temporal_replay": "PASS"}
        path = proof_root / (child.execution_run_id + ".json")
        path.write_bytes((json.dumps(_json_payload(proof), sort_keys=True, indent=2) + "\n").encode())
        print(json.dumps({"proof": path.name, "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                          "parent_run": parent.execution_run_id, "child_run": child.execution_run_id, "dispatches": 2,
                          "external_contacts": 0, "replay": "PASS"}), flush=True)


def _write_history_bytes(path, history):
    # CRITICAL: hash and persist the same UTF-8 bytes; Windows text newline conversion breaks offline evidence integrity.
    serialized = history.to_json().encode("utf-8")
    path.write_bytes(serialized)
    return hashlib.sha256(serialized).hexdigest()
