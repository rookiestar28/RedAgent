"""Explicit synthetic-authority composition with real local execution owners.

This is a bounded composition test. The resolver snapshot is a signed-test-context fixture;
it does not qualify the normal API/UI, canonical lab bootstrap or a production environment.
"""

from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
import pytest
from sqlalchemy import insert, select
from temporalio.client import Client
from temporalio.worker import Replayer, Worker

from redagent_platform.campaign_service.application_contracts import AutonomousCampaignMode
from redagent_platform.campaign_service.admission_start_relay import AutonomousCampaignStartBridgeRelay
from redagent_platform.campaign_service.composition import build_runner_owned_campaign_dispatcher
from redagent_platform.campaign_service.dag_composition import build_dag_execution_temporal_activities
from redagent_platform.campaign_service.dag_lifecycle_store import PostgresDagLifecycleOwner
from redagent_platform.campaign_service.dag_policy import DagPolicyDecisionAdapter
from redagent_platform.campaign_service.dag_relay import DagWorkflowRelay
from redagent_platform.campaign_service.dag_relay_store import PostgresDagWorkflowRelayRepository
from redagent_platform.campaign_service.dag_execution_contracts import DagRunState, DagExecutionSnapshotV1, deterministic_dag_workflow_id
from redagent_platform.campaign_service.resolver import CampaignContextResolver
from redagent_platform.campaign_service.runtime import PostgresRunnerIdentityOwner, _verify_current_zap, _verify_current_nuclei
from redagent_platform.campaign_service.activity_store import PostgresActivityContainmentOwner
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.evidence_service.service import EvidenceService, _stored_from_artifact
from redagent_platform.nuclei_service.capability import build_nuclei_capability_manifest
from redagent_platform.zap_service.capability import build_zap_capability_manifest
from redagent_platform.runner_service.contracts import canonical_capability_sha256
from redagent_platform.orchestration.admission_start_workflow import AutonomousCampaignStartBridgeWorkflow
from redagent_platform.orchestration.admission_start_gateway import AutonomousCampaignStartBridgeTemporalGateway
from redagent_platform.orchestration.dag_execution_gateway import DagExecutionTemporalStartGateway
from redagent_platform.orchestration.dag_execution_workflow import CampaignDagExecutionWorkflow
from redagent_platform.persistence.models import metadata
from redagent_platform.policy_service.providers import OpaPolicyDecisionProvider
from scripts import opa_conformance
from tests.integration.test_autonomous_campaign_admission_start_repository import _prepare_approved_campaign, _admission_service
from tests.integration.test_autonomous_campaign_admission_start_relay_repository import _repository
from tests.integration.test_autonomous_campaign_application_repository import _set_tenant
from tests.integration.test_campaign_dag_execution_repository import _AuthorityProvider, _authority_snapshot


ROOT = Path(__file__).resolve().parents[2]
LIVE = os.environ.get("REDAGENT_OWNED_EXECUTION_LIVE_TEST") == "owned-loopback-v1"


class _ObservedDispatcher:
    def __init__(self, delegate):
        self.delegate = delegate
        self.failures = []

    async def dispatch(self, request):
        try:
            return await self.delegate.dispatch(request)
        except Exception as exc:
            # Keep the original safe guard code when the coordinator persists generic ambiguity.
            pending = [exc]
            visited = set()
            while pending and len(visited) < 8:
                error = pending.pop()
                if id(error) in visited:
                    continue
                visited.add(id(error))
                reason = str(error)
                self.failures.append((type(error).__name__, reason if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,199}", reason) else "opaque_failure"))
                pending.extend(item for item in (error.__cause__, error.__context__) if item is not None)
            raise

    async def lookup(self, request):
        return await self.delegate.lookup(request)


class _ObservedResultBoundary:
    """Delegate canonical owners unchanged and expose only their safe guard codes."""
    def __init__(self, delegate, failures):
        self.delegate = delegate
        self.failures = failures

    def __getattr__(self, name):
        return getattr(self.delegate, name)

    async def _observe(self, phase, command, **kwargs):
        try:
            return await getattr(self.delegate, phase)(command, **kwargs)
        except Exception as exc:
            reason = str(exc)
            self.failures.append({"phase": phase, "type": type(exc).__name__,
                "code": reason if re.fullmatch(r"[A-Za-z][A-Za-z0-9_.:-]{0,199}", reason) else "opaque_failure"})
            raise

    async def finalize(self, command, receipt, **kwargs):
        return await self._observe("finalize", command, receipt=receipt, **kwargs)

    async def confirm(self, command, **kwargs):
        return await self._observe("confirm", command, **kwargs)


@pytest.mark.skipif(not LIVE, reason="requires explicit owned-loopback composition authority")
def test_real_owned_execution_from_approved_application_to_durable_evidence():
    with opa_conformance.opa_fixture_lease():
        assert opa_conformance._provision()["ok"]
        try:
            asyncio.run(_both_capabilities())
        finally:
            opa_conformance._scoped_cleanup()


async def _both_capabilities():
    client = await Client.connect("127.0.0.1:62001")
    async with httpx.AsyncClient(timeout=5) as http:
        provider = OpaPolicyDecisionProvider(http, endpoint=opa_conformance.opa_endpoint(), token_source=lambda: opa_conformance.APP_TOKEN)
        for capability_key in ("zap-controlled-runtime@3", "nuclei-trusted-runtime@3"):
            await _scenario(client, provider, capability_key)


async def _scenario(client, policy_provider, capability_key):
    now = datetime.now(timezone.utc)
    if capability_key.startswith("zap"):
        artifact, _ = _verify_current_zap(ROOT, now=now)
        capability = build_zap_capability_manifest(platform="linux/amd64", artifact_receipt_id=artifact.receipt_id)
    else:
        artifact, _, _ = _verify_current_nuclei(ROOT, now=now)
        capability = build_nuclei_capability_manifest(platform="linux/amd64", artifact_receipt_id=artifact.receipt_id)
    prepared = await _prepare_approved_campaign(mode=AutonomousCampaignMode.OWNED_LOOPBACK_AUTO,
        capability_key=capability_key, capability_manifest_sha256=canonical_capability_sha256(capability),
        now=now - timedelta(seconds=5), validity_seconds=300, policy_revision="r099-v1")
    suffix = uuid4().hex
    try:
        service = _admission_service(sessions=prepared.sessions, repository=prepared.repository,
            context_provider=prepared.context_provider, context=prepared.context,
            trusted_keys=prepared.trusted_keys, policy_provider=policy_provider, lease_seconds=300)
        admitted = await service.admit_and_queue(prepared.command)
        assert admitted.execution_run_id is not None, admitted.admission_receipt.reason_code
        await _install_runner(prepared, capability, suffix, now)
        authority = prepared.context.signed_authority.authority
        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            campaigns = metadata.tables["campaigns"]
            campaign = (await session.execute(select(campaigns).where(campaigns.c.id == prepared.campaign))).mappings().one()
            targets = metadata.tables["targets"]
            target = (await session.execute(select(targets).where(targets.c.id == authority.target_ids[0]))).mappings().one()
        snapshot = replace(_authority_snapshot(tenant=prepared.tenant, actor=prepared.command.actor_user_id,
            engagement=authority.engagement_id, target_id=authority.target_ids[0], reservation_id=admitted.admission_receipt.reservation_id, suffix=suffix),
            target_value=target["normalized_value"], target_sha256=hashlib.sha256(json.dumps({"target_id": target["id"], "revision": 1, "target_type": "url", "normalized_value": target["normalized_value"]}, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
            roe_version_id=campaign["roe_version_id"], roe_sha256=authority.roe_sha256, roe_revocation_epoch=authority.roe_revocation_epoch,
            policy_revision=authority.policy_revision, policy_sha256=authority.policy_bundle_sha256, policy_revocation_epoch=authority.policy_revocation_epoch,
            runner_id=f"owned-runner-{suffix}", runner_workload_identity=f"spiffe://redagent.test/runner/{suffix}",
            lease_expires_at=admitted.admission_receipt.expires_at, observed_at=now,
            expires_at=admitted.admission_receipt.expires_at)
        resolver = CampaignContextResolver(_AuthorityProvider(snapshot))
        backend = LocalAppendOnlyBackend(ROOT / ".tmp/owned-execution-evidence" / suffix, profile="synthetic-local")
        dispatcher = _ObservedDispatcher(build_runner_owned_campaign_dispatcher(ROOT, prepared.sessions,
            runner_identity_owner=PostgresRunnerIdentityOwner(prepared.sessions),
            evidence_service=EvidenceService(prepared.sessions, backend), actor_user_id=prepared.command.actor_user_id,
            kms_reference="kms:redagent:synthetic-local", owned_execution=True))
        activities = build_dag_execution_temporal_activities(sessions=prepared.sessions, resolver=resolver,
            lifecycle=PostgresDagLifecycleOwner(prepared.sessions), policy=DagPolicyDecisionAdapter(policy_provider),
            dispatcher=dispatcher, containment=PostgresActivityContainmentOwner(prepared.sessions),
            signing_key=Ed25519PrivateKey.generate(), signing_key_id="owned-test-key", owned_execution_enabled=True,
            actor_user_id=prepared.command.actor_user_id)
        owner_failures = []
        coordinator = activities._application._coordinator
        coordinator._result_owner = _ObservedResultBoundary(coordinator._result_owner, owner_failures)
        coordinator._store = _ObservedResultBoundary(coordinator._store, owner_failures)
        queue = f"owned-execution-{suffix}"
        async with Worker(client, task_queue=queue, workflows=[AutonomousCampaignStartBridgeWorkflow, CampaignDagExecutionWorkflow],
                          activities=[activities.reconcile, activities.dispatch, activities.contain]):
            bridge = _repository(prepared)
            claim = (await bridge.claim_admission_start_bridges(claim_owner="owned-live-bridge", now=datetime.now(timezone.utc), lease_seconds=30, limit=1))[0]
            await AutonomousCampaignStartBridgeRelay(repository=bridge,
                gateway=AutonomousCampaignStartBridgeTemporalGateway(client, task_queue=queue)).deliver(claim, now=datetime.now(timezone.utc))
            relay = PostgresDagWorkflowRelayRepository(prepared.sessions, tenant_id=prepared.tenant, actor_user_id=prepared.command.actor_user_id, correlation_prefix="owned-live-relay")
            claim = (await relay.claim_dag_workflow_starts(claim_owner="owned-live-dag", now=datetime.now(timezone.utc), lease_seconds=30, limit=1))[0]
            await DagWorkflowRelay(repository=relay, gateway=DagExecutionTemporalStartGateway(client, task_queue=queue)).deliver(claim, now=datetime.now(timezone.utc))
            handle = client.get_workflow_handle(deterministic_dag_workflow_id(prepared.tenant, admitted.execution_run_id), result_type=DagExecutionSnapshotV1)
            result = await asyncio.wait_for(handle.result(), timeout=180)
            assert result.state is DagRunState.COMPLETED, json.dumps({"state": result.state.value, "execution_run_id": result.execution_run_id, "failures": dispatcher.failures, "owner_failures": owner_failures})
            history = await handle.fetch_history()
        await Replayer(workflows=[CampaignDagExecutionWorkflow]).replay_workflow(history)
        current = await prepared.repository.read(tenant_id=prepared.tenant, campaign_id=prepared.campaign)
        assert current.lifecycle_state.value == "EVIDENCE_PENDING"
        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            effects = metadata.tables["campaign_effects"]
            effect = (await session.execute(select(effects).where(effects.c.execution_run_id == admitted.execution_run_id))).mappings().one()
            assert effect["effect_state"] == "confirmed"
            assert effect["dispatch_attempt"] == effect["dispatch_generation"] == 1
            assert effect["effect_receipt_payload"]["external_contact_count"] == 0
            assert effect["cleanup_receipt_id"] and effect["evidence_ids"]
            assert effect["effect_receipt_payload"]["output_complete"]
            artifacts = metadata.tables["evidence_artifacts"]
            rows = (await session.execute(select(artifacts).where(
                artifacts.c.tenant_id == prepared.tenant, artifacts.c.id.in_(effect["evidence_ids"]),
            ))).mappings().all()
            assert len(rows) == len(effect["evidence_ids"]) > 0
            for row in rows:
                stored = _stored_from_artifact(dict(row))
                verification = backend.verify_exact(stored)
                assert verification.ok, verification.reason
            proof = {
                "schema": "redagent.owned-execution-composition-proof/v1",
                "authority_kind": "explicit-synthetic-authority-with-real-local-owners",
                "normal_api_ui_qualified": False,
                "source_revision": subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                "source_tree": subprocess.check_output(["git", "rev-parse", "HEAD^{tree}"], cwd=ROOT, text=True).strip(),
                "tracked_candidate_dirty": bool(subprocess.check_output(["git", "status", "--porcelain", "--untracked-files=no"], cwd=ROOT, text=True).strip()),
                "capability_key": capability_key,
                "execution_run_id": admitted.execution_run_id,
                "tenant_id": prepared.tenant,
                "campaign_id": prepared.campaign,
                "workflow_id": handle.id,
                "workflow_run_id": history.events[0].workflow_execution_started_event_attributes.original_execution_run_id,
                "workflow_state": result.state.value,
                "campaign_state": current.lifecycle_state.value,
                "temporal_replay": "PASS",
                "history_sha256": hashlib.sha256(history.to_json().encode()).hexdigest(),
                "effect_id": effect["effect_id"],
                "dispatch_attempt": effect["dispatch_attempt"],
                "dispatch_generation": effect["dispatch_generation"],
                "effect_receipt": effect["effect_receipt_payload"],
                "artifacts": [{"id": row["id"], "sha256": row["content_sha256"],
                               "size_bytes": row["size_bytes"], "backend_verification": "PASS"} for row in rows],
            }
            proof_root = ROOT / ".tmp/owned-execution-proofs"
            proof_root.mkdir(parents=True, exist_ok=True)
            (proof_root / f"{admitted.execution_run_id}.json").write_text(
                json.dumps(proof, sort_keys=True, indent=2, default=str) + "\n", encoding="utf-8")
    finally:
        await prepared.engine.dispose()


async def _install_runner(prepared, capability, suffix, now):
    owned = {"tenant_id": prepared.tenant, "version": 1, "created_at": now, "updated_at": now}
    class_id = f"owned-class-{suffix}"
    registration_id = f"owned-registration-{suffix}"
    async with prepared.sessions() as session, session.begin():
        await _set_tenant(session, prepared.tenant)
        await session.execute(insert(metadata.tables["runner_classes"]).values(id=class_id,
            class_id="r123-closed-runner", class_revision=1, environment="local-conformance", network_plane="owned-loopback",
            isolation_tier="container", runtime_name="docker", sandbox_profile_id=capability.sandbox_profile_id,
            policy_revision="r099-v1", resource_limits=asdict(capability.limits), credential_classes=["none"],
            evidence_schemas=list(capability.evidence_schema), class_status="active", author_user_id=prepared.command.actor_user_id,
            reviewer_user_id="owned-fixture-reviewer", **owned))
        await session.execute(insert(metadata.tables["runner_registrations"]).values(id=registration_id,
            runner_id=f"owned-runner-{suffix}", runner_class_record_id=class_id, environment="local-conformance", network_plane="owned-loopback",
            spiffe_id=f"spiffe://redagent.test/runner/{suffix}", certificate_fingerprint="a" * 64, certificate_serial=suffix,
            adapter_allowlist=[f"{capability.adapter_id}:{capability.adapter_version}"], image_allowlist=[capability.image_digest],
            required_policy_revision="r099-v1", generation=1, attestation_sha256="b" * 64, registration_state="active",
            registered_at=now, expires_at=now + timedelta(minutes=10), revoked_at=None, last_seen_at=now, **owned))
        await session.execute(insert(metadata.tables["runner_identities"]).values(id=f"owned-identity-{suffix}",
            registration_id=registration_id, spiffe_id=f"spiffe://redagent.test/runner/{suffix}", certificate_fingerprint="a" * 64,
            certificate_serial=suffix, not_before=now, not_after=now + timedelta(minutes=10), identity_state="observed", observed_at=now, **owned))
        await session.execute(insert(metadata.tables["execution_capability_manifests"]).values(id=f"owned-capability-{suffix}",
            capability_id=capability.capability_id, capability_revision=capability.revision, adapter_id=capability.adapter_id,
            adapter_version=capability.adapter_version, image_digest=capability.image_digest, input_schema_id=capability.input_schema_id,
            supported_modes=list(capability.supported_modes), phases=list(capability.phases), sandbox_profile_id=capability.sandbox_profile_id,
            network_mode=capability.network_mode.value, credential_class=capability.credential_class.value, evidence_schema=list(capability.evidence_schema),
            unsupported_features=list(capability.unsupported_features), resource_limits=asdict(capability.limits), artifact_receipt_id=capability.artifact_receipt_id,
            manifest_sha256=canonical_capability_sha256(capability), reviewed_by_user_id=capability.reviewed_by, capability_status=capability.status, **owned))
