from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import httpx
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from temporalio.worker import Worker

from redagent_platform.api.app import create_app
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.evidence_service.contracts import (
    ArtifactClass,
    ArtifactWriteRequest,
    DataClassification,
    RetentionMode,
)
from redagent_platform.evidence_service.service import EvidenceService
from redagent_platform.identity.repository import IdentityRepository
from redagent_platform.orchestration.activities import WorkflowActivities
from redagent_platform.orchestration.config import TemporalSettings
from redagent_platform.orchestration.contracts import (
    CONTRACT_SCHEMA_VERSION,
    CommandAction,
    JobSnapshot,
    JobWorkflowInput,
    OperatorCommand,
    WorkflowState,
    deterministic_job_workflow_id,
)
from redagent_platform.orchestration.gateway import TemporalOrchestrationGateway, connect_temporal
from redagent_platform.orchestration.workflow import CampaignLifecycleWorkflow, JobLifecycleWorkflow
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.policy_service.boundaries import PolicyBoundarySDK
from redagent_platform.policy_service.enforcement import PolicyBoundaryEnforcer
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider
from redagent_platform.policy_service.repository import TransactionalPolicyDecisionRecorder
from redagent_platform.runner_service.contracts import (
    ArtifactVerificationReceipt,
    CredentialClass,
    ExecutionCapabilityManifest,
    IsolationTier,
    JobManifestDraft,
    NetworkMode,
    ResourceLimits,
    RunnerClassDefinition,
    RunnerRegistration,
    SandboxProfile,
    canonical_capability_sha256,
    sign_job_manifest,
)
from redagent_platform.runner_service.dispatch import SyntheticRunnerDispatcher
from redagent_platform.runner_service.identity import PeerCertificateIdentity
from redagent_platform.runner_service.persistent_backend import (
    PersistentRunnerBinding,
    PersistentSyntheticRunnerBackend,
)
from redagent_platform.runner_service.repository import RunnerRepository
from redagent_platform.runner_service.sdk import RunnerExecutionCoordinator, SyntheticConformanceAdapter
from redagent_platform.runner_service.secret_mailbox import EphemeralSecretMailbox
from redagent_platform.secret_service.broker import SecretLeaseBroker
from redagent_platform.secret_service.contracts import (
    LeaseIssueRequest,
    SecretReference,
    SecretReferenceKind,
    SecretReferenceStatus,
    WorkloadClient,
)
from redagent_platform.secret_service.fakes import DeterministicFakeSecretProvider
from redagent_platform.secret_service.repository import TransactionalSecretLeaseStore
from tests.integration.runtime_coordinates import persisted_temporal_target


ROOT = Path(__file__).resolve().parents[2]
IMAGE = "sha256:" + "a" * 64
POLICY_REVISION = "synthetic-r099-v1"


def test_postgresql_temporal_command_policy_secret_adapter_evidence_finalize_path() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    now = datetime.now(timezone.utc).replace(microsecond=0)
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant, actor = f"tenant-r100-cross-{suffix}", f"operator-r100-cross-{suffix}"
    approver = f"approver-r100-cross-{suffix}"
    engagement, roe, job = f"eng-r100-cross-{suffix}", f"roe-r100-cross-{suffix}", f"job-r100-cross-{suffix}"
    runner, reference, client = f"runner-r100-cross-{suffix}", f"reference-r100-cross-{suffix}", f"client-r100-cross-{suffix}"
    evidence_id, secret_lease_id = f"evidence-r100-cross-{suffix}", f"secret-lease-r100-cross-{suffix}"
    evidence_root = ROOT / ".tmp" / "r100-cross-boundary" / suffix
    key = Ed25519PrivateKey.generate()
    attestation = "3" * 64
    provider = DeterministicFakeSecretProvider(seed=suffix)
    adapter = SyntheticConformanceAdapter(require_secret=True)
    worker: Worker | None = None
    worker_task: asyncio.Task[None] | None = None
    try:
        await _bootstrap_control_plane(
            sessions, tenant, actor, approver, engagement, roe, job, suffix, now,
        )
        capability = _capability()
        registration = _registration(tenant, runner, now)
        identity = PeerCertificateIdentity(
            runner_id=runner, spiffe_id=registration.spiffe_id,
            certificate_fingerprint=registration.certificate_fingerprint,
            certificate_serial=registration.certificate_serial,
            not_before=now - timedelta(minutes=1), not_after=now + timedelta(minutes=10),
        )
        async with sessions() as session, session.begin():
            repository = RunnerRepository(
                session, tenant_id=tenant, actor_user_id=actor,
                correlation_id=f"runner-bootstrap-{suffix}",
            )
            runner_class = await repository.register_runner_class(
                _runner_class(), author_user_id="author-r100",
                reviewer_user_id="reviewer-r100", occurred_at=now,
            )
            await repository.register_artifact(_artifact(now), signature_sha256="6" * 64, occurred_at=now)
            await repository.register_capability(capability, occurred_at=now)
            registered = await repository.register_runner(
                registration, runner_class_record_id=str(runner_class["id"]),
                attestation_sha256="7" * 64, identity=identity, occurred_at=now,
            )

        policy = PolicyBoundarySDK(
            PolicyBoundaryEnforcer(
                DeterministicFakePolicyProvider(revision=POLICY_REVISION),
                TransactionalPolicyDecisionRecorder(sessions),
            ),
            required_revision=POLICY_REVISION,
        )
        secret_store = TransactionalSecretLeaseStore(sessions)
        await secret_store.register_reference(
            SecretReference(
                tenant_id=tenant, reference_id=reference, engagement_id=engagement,
                owner_user_id=actor, kind=SecretReferenceKind.DYNAMIC_DATABASE,
                provider_alias="synthetic-local", role_reference="database-role-r100",
                allowed_capabilities=("synthetic-conformance",), allowed_permissions=("read",),
                created_at=now, expires_at=now + timedelta(hours=1),
                rotation_due_at=now + timedelta(minutes=30), status=SecretReferenceStatus.ACTIVE,
                redaction_label="synthetic-runner-reference",
            ),
            actor_user_id=actor, correlation_id=f"secret-reference-{suffix}",
        )
        await secret_store.register_workload(
            WorkloadClient(
                tenant_id=tenant, client_id=client, job_id=job,
                capability="synthetic-conformance", attestation_fingerprint=attestation,
                expires_at=now + timedelta(minutes=10), revoked_at=None,
            ),
            actor_user_id=actor, correlation_id=f"secret-workload-{suffix}", occurred_at=now,
        )
        mailbox = EphemeralSecretMailbox(client_id=client, attestation_fingerprint=attestation)
        secret_broker = SecretLeaseBroker(secret_store, provider, mailbox, policy)
        evidence_service = EvidenceService(
            sessions, LocalAppendOnlyBackend(evidence_root, profile="synthetic-local"), policy,
        )

        def manifest_factory(*, command, authorization, occurred_at):
            draft = JobManifestDraft(
                schema_version="1.0", manifest_id=f"manifest-{suffix}", job_id=job,
                tenant_id=tenant, engagement_id=engagement, roe_version_id=roe,
                environment="local-conformance", runner_class_id="synthetic-standard",
                network_plane="isolated-none", adapter_id="synthetic-conformance",
                adapter_version="1.0.0", capability_digest=canonical_capability_sha256(capability),
                image_digest=IMAGE, artifact_receipt_id="artifact-r100-cross",
                policy_revision=POLICY_REVISION, policy_decision_id=authorization.decision_id,
                target_ids=(f"target-{suffix}",), target_hashes=("5" * 64,),
                limits=_limits(), egress_profile="none",
                evidence_schema=("synthetic-result-v1",), secret_reference_ids=(reference,),
                issued_at=occurred_at, expires_at=occurred_at + timedelta(minutes=2),
                nonce=f"nonce-{suffix}",
            )
            return sign_job_manifest(draft, key, key_id="r100-cross-key")

        def secret_request_factory(*, prepared, occurred_at):
            deadline = occurred_at + timedelta(minutes=2)
            return LeaseIssueRequest(
                tenant_id=tenant, lease_id=secret_lease_id, reference_id=reference,
                engagement_id=engagement, job_id=job, workload_client_id=client,
                capability="synthetic-conformance", requested_permissions=("read",),
                requested_at=occurred_at, ttl_seconds=120, job_deadline=deadline,
                policy_expires_at=deadline, roe_expires_at=deadline,
                policy_reference="policy:compat_100:dispatch", roe_version_id=roe,
                idempotency_key=f"secret-issue-{suffix}",
            )

        def evidence_request_factory(*, prepared, artifact, authorization, occurred_at):
            return ArtifactWriteRequest(
                tenant_id=tenant, artifact_id=evidence_id, engagement_id=engagement,
                job_id=job, producer_id=actor, content=artifact.content,
                content_type=artifact.content_type, artifact_class=ArtifactClass.REDACTED,
                classification=DataClassification.CONFIDENTIAL, redaction_state="redacted",
                retention_mode=RetentionMode.GOVERNANCE,
                retain_until=occurred_at + timedelta(days=30), legal_hold=False,
                kms_reference="kms:local:compat_100", policy_reference="policy:compat_100:dispatch",
                idempotency_key=f"evidence-{suffix}",
            )

        backend = PersistentSyntheticRunnerBackend(
            sessions,
            PersistentRunnerBinding(
                tenant_id=tenant, actor_user_id=actor,
                runner_registration_id=str(registered["id"]), identity=identity,
                environment="local-conformance", runner_class_id="synthetic-standard",
                policy_revision=POLICY_REVISION, generation=1, capability_revision=1,
                capability=capability, adapter=adapter,
                workspace_root=ROOT / ".tmp" / "r100-runner-work" / suffix,
                sandbox_verified=True,
            ),
            manifest_factory=manifest_factory, secret_broker=secret_broker,
            secret_mailbox=mailbox, secret_request_factory=secret_request_factory,
            evidence_service=evidence_service, evidence_request_factory=evidence_request_factory,
        )
        dispatcher = SyntheticRunnerDispatcher(
            policy, backend, RunnerExecutionCoordinator(),
        )
        temporal = TemporalSettings(
            target=persisted_temporal_target(ROOT), namespace="redagent-local",
            task_queue=f"redagent-r100-cross-{suffix}",
            codec_key_id=f"r100-{suffix}",
            codec_key_path=ROOT / ".local" / "synthetic-r100-key",
            codec_key=b"r" * 32, tls=False, profile="local",
        )
        client_connection = await connect_temporal(temporal)
        gateway = TemporalOrchestrationGateway(client_connection, temporal)
        activities = WorkflowActivities(sessions, runner_dispatcher=dispatcher)
        worker = Worker(
            client_connection, task_queue=temporal.task_queue,
            workflows=[JobLifecycleWorkflow, CampaignLifecycleWorkflow],
            activities=[
                activities.admit_job, activities.apply_command,
                activities.record_system_state, activities.admit_campaign,
                activities.dispatch_synthetic_job,
            ],
            max_concurrent_workflow_tasks=5, max_concurrent_activities=5,
            max_concurrent_workflow_task_polls=2, max_concurrent_activity_task_polls=2,
        )
        worker_task = asyncio.create_task(worker.run())
        workflow_id = deterministic_job_workflow_id(tenant, job)
        await gateway.start_job(JobWorkflowInput(
            CONTRACT_SCHEMA_VERSION, tenant, job, engagement, roe,
            "policy:compat_100:dispatch", 1, 3600, 3, True,
        ))
        await _wait_for_state(gateway, workflow_id, WorkflowState.AWAITING_APPROVAL)
        app = create_app(
            test_issuer_enabled=True, database_settings=settings,
            orchestration_gateway=gateway,
            policy_provider=DeterministicFakePolicyProvider(revision=POLICY_REVISION),
            policy_required_revision=POLICY_REVISION,
        )
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app, raise_app_exceptions=True),
                base_url="http://testserver",
            ) as api:
                approved = await api.post(
                    f"/api/v1/jobs/{job}/commands",
                    headers={
                        "X-RedAgent-Test-Subject": approver,
                        "X-RedAgent-Test-Tenant": tenant,
                        "X-RedAgent-Test-Permissions": "job:approve,job:read",
                        "X-RedAgent-Policy-Reference": "policy:compat_100:dispatch",
                        "X-RedAgent-ROE-Version": roe,
                        "Idempotency-Key": f"approve-{suffix}",
                    },
                    json={
                        "command_id": f"approve-{suffix}", "action": "approve",
                        "expected_revision": 2,
                        "reason": "Distinct approver authorizes compat_100 synthetic dispatch",
                    },
                )
                assert approved.status_code == 200, approved.text
        terminal = await asyncio.wait_for(
            client_connection.get_workflow_handle(
                workflow_id, result_type=JobSnapshot,
            ).result(),
            timeout=30,
        )
        assert terminal.state == WorkflowState.SUCCEEDED.value
        assert terminal.current_gate == "runner_evidence_finalized"
        history = (await client_connection.get_workflow_handle(workflow_id).fetch_history()).to_json()
        for forbidden in ("R098-SYNTHETIC", "private_key", "lease_token"):
            assert forbidden.lower() not in history.lower()
        assert adapter.execution_count == 1 and adapter.secret_observation_sha256
        assert provider.last_material is not None and provider.last_material.cleared

        async with sessions() as session, session.begin():
            await session.execute(select(func.set_config("redagent.tenant_id", tenant, True)))
            boundaries = dict((await session.execute(select(
                metadata.tables["policy_boundary_receipts"].c.boundary,
                func.count().label("count"),
            ).where(
                metadata.tables["policy_boundary_receipts"].c.tenant_id == tenant,
            ).group_by(metadata.tables["policy_boundary_receipts"].c.boundary))).all())
            assert boundaries == {
                "api": 1, "workflow": 1, "evidence": 1,
                "runner": 5, "secret": 2,
            }
            assert await session.scalar(select(func.count()).select_from(
                metadata.tables["runner_execution_receipts"]
            ).where(metadata.tables["runner_execution_receipts"].c.tenant_id == tenant)) == 1
            assert await session.scalar(select(metadata.tables["secret_leases"].c.lease_state).where(
                metadata.tables["secret_leases"].c.tenant_id == tenant,
                metadata.tables["secret_leases"].c.id == secret_lease_id,
            )) == "revoked"
            assert await session.scalar(select(metadata.tables["evidence_artifacts"].c.id).where(
                metadata.tables["evidence_artifacts"].c.tenant_id == tenant,
                metadata.tables["evidence_artifacts"].c.id == evidence_id,
            )) == evidence_id
            rows = []
            for name in (
                "runner_job_manifests", "runner_pull_leases", "runner_execution_receipts",
                "secret_leases", "evidence_artifacts", "policy_boundary_receipts",
                "audit_events", "outbox_events",
            ):
                rows.extend(dict(row) for row in (await session.execute(select(
                    metadata.tables[name]
                ).where(metadata.tables[name].c.tenant_id == tenant))).mappings())
            rendered = json.dumps(rows, default=str, sort_keys=True)
            for forbidden in ("R098-SYNTHETIC", "password", "private_key", '"lease_token":'):
                assert forbidden.lower() not in rendered.lower()
    finally:
        if worker is not None and worker_task is not None:
            await worker.shutdown()
            await asyncio.wait_for(worker_task, timeout=10)
        await engine.dispose()
        shutil.rmtree(evidence_root, ignore_errors=True)
        shutil.rmtree(ROOT / ".tmp" / "r100-runner-work" / suffix, ignore_errors=True)


async def _wait_for_state(
    gateway: TemporalOrchestrationGateway, workflow_id: str, expected: WorkflowState,
) -> None:
    deadline = asyncio.get_running_loop().time() + 20
    while asyncio.get_running_loop().time() < deadline:
        snapshot = await gateway.query_job(workflow_id)
        if snapshot.state == expected.value:
            return
        await asyncio.sleep(0.05)
    raise AssertionError(f"r100_temporal_state_timeout:{expected.value}")


async def _bootstrap_control_plane(
    sessions, tenant, actor, approver, engagement, roe, job, suffix, now,
) -> None:
    async with sessions() as session, session.begin():
        repository = ControlPlaneRepository(
            session, tenant_id=tenant, actor_user_id=actor,
            correlation_id=f"control-bootstrap-{suffix}",
        )
        await repository.bootstrap_tenant(name="compat_100 Cross Boundary", occurred_at=now)
        await repository.bootstrap_user(user_id=actor, subject=actor, occurred_at=now)
        await repository.bootstrap_user(user_id=approver, subject=approver, occurred_at=now)
        await repository.create_engagement(
            engagement_id=engagement, name="compat_100 cross boundary", owner_user_id=actor,
            idempotency_key=f"eng-{suffix}", occurred_at=now,
        )
        created = await repository.create_roe_version(
            roe_version_id=roe, engagement_id=engagement, revision=1,
            document={"active_testing": False}, policy_reference_id=f"policy-{suffix}",
            policy_name="r100-cross", policy_version="1",
            idempotency_key=f"roe-{suffix}", occurred_at=now,
        )
        await repository.approve_roe_version(
            roe_version_id=roe, approval_id=f"approval-{suffix}",
            expected_version=int(created.resource["version"]),
            idempotency_key=f"approval-{suffix}", occurred_at=now,
        )
        identities = IdentityRepository(
            session, tenant_id=tenant, actor_user_id=actor,
            correlation_id=f"identity-{suffix}",
        )
        await identities.provision_membership(
            user_id=actor, roles=("operator",), occurred_at=now,
        )
        await identities.provision_membership(
            user_id=approver, roles=("approver",), occurred_at=now,
        )
        await repository.create_job(
            job_id=job, engagement_id=engagement, roe_version_id=roe,
            request={"capability": "synthetic-conformance", "approval_timeout_seconds": 3600,
                     "max_activity_attempts": 3, "budget_reference": "budget:compat_100:cross"},
            workflow_id=deterministic_job_workflow_id(tenant, job),
            policy_reference="policy:compat_100:dispatch",
            campaign_id=None, idempotency_key=f"job-{suffix}", occurred_at=now,
        )


def _limits() -> ResourceLimits:
    return ResourceLimits(cpu_millis=500, memory_mib=128, pids=32, timeout_seconds=30, evidence_bytes=65_536)


def _sandbox() -> SandboxProfile:
    return SandboxProfile(
        profile_id="synthetic-standard-v1", isolation_tier=IsolationTier.CONTAINER,
        runtime_name="runc", run_as_user=65532, read_only_root=True, privileged=False,
        host_socket=False, host_namespaces=False, capabilities=(), no_new_privileges=True,
        seccomp_profile="runtime-default", network_mode=NetworkMode.NONE,
        writable_mounts=("/work",), limits=_limits(),
    )


def _runner_class() -> RunnerClassDefinition:
    return RunnerClassDefinition(
        schema_version="1.0", class_id="synthetic-standard", revision=1,
        environment="local-conformance", network_plane="isolated-none",
        policy_revision=POLICY_REVISION, sandbox=_sandbox(),
        credential_classes=(CredentialClass.DYNAMIC_DATABASE,),
        evidence_schemas=("synthetic-result-v1",), status="certified",
    )


def _capability() -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(
        schema_version="1.0", capability_id="synthetic-conformance", revision=1,
        adapter_id="synthetic-conformance", adapter_version="1.0.0", image_digest=IMAGE,
        input_schema_id="redagent.synthetic-job.v1", supported_modes=("synthetic",),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="synthetic-standard-v1", network_mode=NetworkMode.NONE,
        credential_class=CredentialClass.DYNAMIC_DATABASE,
        evidence_schema=("synthetic-result-v1",),
        unsupported_features=("arbitrary_command", "native_template", "plugin_loading"),
        limits=_limits(), artifact_receipt_id="artifact-r100-cross",
        reviewed_by="reviewer-r100", status="certified",
    )


def _artifact(now: datetime) -> ArtifactVerificationReceipt:
    return ArtifactVerificationReceipt(
        receipt_id="artifact-r100-cross", image_digest=IMAGE, signature_verified=True,
        signer_identity="redagent-release-r100", provenance_sha256="1" * 64,
        sbom_sha256="2" * 64, vulnerability_review="accepted_no_critical",
        verifier="redagent-offline-v1", verified_at=now,
        expires_at=now + timedelta(days=7),
    )


def _registration(tenant: str, runner: str, now: datetime) -> RunnerRegistration:
    return RunnerRegistration(
        runner_id=runner, tenant_id=tenant, environment="local-conformance",
        runner_class_id="synthetic-standard", network_plane="isolated-none",
        spiffe_id=f"spiffe://redagent.test/runner/{runner}", certificate_fingerprint="4" * 64,
        certificate_serial="1001", adapter_allowlist=("synthetic-conformance:1.0.0",),
        image_allowlist=(IMAGE,), required_policy_revision=POLICY_REVISION, generation=1,
        registered_at=now, expires_at=now + timedelta(minutes=10), revoked_at=None,
    )
