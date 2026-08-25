from __future__ import annotations

import asyncio
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest
from sqlalchemy import func, insert, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.containment_service.contracts import ControlScope, ControlScopeKind, StopRequest
from redagent_platform.containment_service.repository import ContainmentRepository
from redagent_platform.runner_service.contracts import (
    ArtifactVerificationReceipt,
    CredentialClass,
    ExecutionCapabilityManifest,
    IsolationTier,
    JobManifestDraft,
    JobManifestDraftV2,
    NetworkMode,
    ResourceLimits,
    RunnerClassDefinition,
    RunnerRegistration,
    SandboxProfile,
    canonical_capability_sha256,
    sign_job_manifest,
    sign_job_manifest_v2,
)
from redagent_platform.runner_service.identity import PeerCertificateIdentity
from redagent_platform.runner_service.repository import RunnerRepository, RunnerRepositoryConflict


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 15, 30, tzinfo=timezone.utc)
IMAGE = "sha256:" + "a" * 64
TOKEN = bytearray(b"R100-SYNTHETIC-PULL-LEASE")  # pragma: allowlist secret


def test_runner_registry_manifest_claim_replay_audit_and_tenant_isolation() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r100-{suffix}"
    actor = f"operator-r100-{suffix}"
    job_id = f"job-r100-{suffix}"
    registration = _registration(suffix)
    identity = PeerCertificateIdentity(
        runner_id=registration.runner_id,
        spiffe_id=registration.spiffe_id,
        certificate_fingerprint=registration.certificate_fingerprint,
        certificate_serial=registration.certificate_serial,
        not_before=NOW - timedelta(minutes=1),
        not_after=NOW + timedelta(minutes=10),
    )
    capability = _capability()
    artifact = _artifact()
    key = Ed25519PrivateKey.generate()
    try:
        async with sessions() as session, session.begin():
            control = ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"bootstrap-{suffix}",
            )
            await control.bootstrap_tenant(name="compat_100 Runner Tenant", occurred_at=NOW)
            await control.bootstrap_user(user_id=actor, subject=actor, occurred_at=NOW)
            await _bootstrap_job(session, tenant=tenant, actor=actor, job_id=job_id, suffix=suffix)

        async with sessions() as session, session.begin():
            repository = RunnerRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"registry-{suffix}",
                token_factory=lambda: bytearray(TOKEN),
            )
            runner_class = await repository.register_runner_class(
                _runner_class(), author_user_id="author-r100", reviewer_user_id="reviewer-r100", occurred_at=NOW,
            )
            with pytest.raises(RunnerRepositoryConflict, match="runner_class_separation_required"):
                await repository.register_runner_class(
                    _runner_class(class_id="invalid-sod"),
                    author_user_id="same-user", reviewer_user_id="same-user", occurred_at=NOW,
                )
            await repository.register_artifact(artifact, signature_sha256="6" * 64, occurred_at=NOW)
            await repository.register_capability(capability, occurred_at=NOW)
            registered = await repository.register_runner(
                registration, runner_class_record_id=str(runner_class["id"]),
                attestation_sha256="7" * 64, identity=identity, occurred_at=NOW,
            )

            draft = _draft(job_id=job_id, tenant=tenant, suffix=suffix)
            signed = sign_job_manifest(draft, key, key_id="r100-local-signing-v1")
            issued = await repository.issue_manifest(
                signed, runner_registration_id=str(registered["id"]),
                capability_revision=1, idempotency_key=f"issue-{suffix}", occurred_at=NOW,
            )
            replay = await repository.issue_manifest(
                signed, runner_registration_id=str(registered["id"]),
                capability_revision=1, idempotency_key=f"issue-{suffix}", occurred_at=NOW,
            )
            assert replay["id"] == issued["id"]

            v2_draft = JobManifestDraftV2(
                v1=replace(
                    draft,
                    manifest_id=f"manifest-r123-v2-{suffix}",
                    nonce=f"nonce-r123-v2-{suffix}",
                ),
                capability_id=capability.capability_id,
                capability_revision=1,
                execution_manifest_sha256=canonical_capability_sha256(capability),
                profile_id="synthetic-conformance-v1",
                profile_revision=1,
                profile_sha256="d" * 64,
                bundle_id=None,
                bundle_revision=None,
                bundle_sha256=None,
            )
            v2_binding = CapabilityBindingKeyV1(
                schema_version="redagent.r119-capability-binding/v1",
                capability_id=capability.capability_id,
                capability_revision=1,
                execution_manifest_sha256=canonical_capability_sha256(capability),
                adapter_id=capability.adapter_id,
                adapter_version=capability.adapter_version,
                profile_id="synthetic-conformance-v1",
                profile_revision=1,
                profile_sha256="d" * 64,
                bundle_id=None,
                bundle_revision=None,
                bundle_sha256=None,
                semantics_revision=1,
                semantics_sha256="e" * 64,
                normalized_output_sha256="f" * 64,
                projection_revision=1,
                projection_sha256="1" * 64,
            )
            signed_v2 = sign_job_manifest_v2(
                v2_draft, key, key_id="r123-local-signing-v1"
            )
            issued_v2 = await repository.issue_manifest_v2(
                signed_v2,
                runner_registration_id=str(registered["id"]),
                binding=v2_binding,
                idempotency_key=f"issue-r123-v2-{suffix}",
                occurred_at=NOW,
            )
            replayed_v2 = await repository.issue_manifest_v2(
                signed_v2,
                runner_registration_id=str(registered["id"]),
                binding=v2_binding,
                idempotency_key=f"issue-r123-v2-{suffix}",
                occurred_at=NOW,
            )
            assert replayed_v2["id"] == issued_v2["id"]
            assert issued_v2["manifest_document"]["manifest_contract_version"] == (
                "redagent.r123-job-manifest/v2"
            )
            with pytest.raises(
                RunnerRepositoryConflict, match="runner_manifest_v2_binding_mismatch"
            ):
                await repository.issue_manifest_v2(
                    signed_v2,
                    runner_registration_id=str(registered["id"]),
                    binding=replace(v2_binding, profile_sha256="2" * 64),
                    idempotency_key=f"issue-r123-v2-substitution-{suffix}",
                    occurred_at=NOW,
                )
            with pytest.raises(RunnerRepositoryConflict, match="runner_manifest_idempotency_mismatch"):
                mutated = sign_job_manifest(
                    _draft(job_id=job_id, tenant=tenant, suffix=suffix, nonce="different-nonce"),
                    key, key_id="r100-local-signing-v1",
                )
                await repository.issue_manifest(
                    mutated, runner_registration_id=str(registered["id"]),
                    capability_revision=1, idempotency_key=f"issue-{suffix}", occurred_at=NOW,
                )

            first = await repository.claim_manifest(
                manifest_record_id=str(issued["id"]), identity=identity, claim_id=f"claim-{suffix}",
                environment="local-conformance", runner_class_id="synthetic-standard",
                policy_revision="r099-v1", generation=1, occurred_at=NOW + timedelta(seconds=1),
            )
            exact_replay = await repository.claim_manifest(
                manifest_record_id=str(issued["id"]), identity=identity, claim_id=f"claim-{suffix}",
                environment="local-conformance", runner_class_id="synthetic-standard",
                policy_revision="r099-v1", generation=1, occurred_at=NOW + timedelta(seconds=2),
            )
            assert bytes(first.lease_token or b"") == bytes(TOKEN)
            assert exact_replay.lease_id == first.lease_id and exact_replay.lease_token is None
            heartbeat = await repository.heartbeat(
                lease_id=first.lease_id, lease_token=bytearray(TOKEN), generation=1,
                occurred_at=NOW + timedelta(seconds=3),
            )
            assert heartbeat["lease_state"] == "claimed"
            started = await repository.begin_execution(
                lease_id=first.lease_id, lease_token=bytearray(TOKEN), generation=1,
                occurred_at=NOW + timedelta(seconds=3),
            )
            assert started["manifest_state"] == "running"
            event = await repository.record_lifecycle_event(
                lease_id=first.lease_id, lease_token=bytearray(TOKEN), generation=1,
                event_id=f"event-{suffix}", phase="preflight", phase_state="completed",
                reason_code="runner_phase_completed", metadata_values={"duration_ms": 1},
                occurred_at=NOW + timedelta(seconds=4),
            )
            replayed_event = await repository.record_lifecycle_event(
                lease_id=first.lease_id, lease_token=bytearray(TOKEN), generation=1,
                event_id=f"event-{suffix}", phase="preflight", phase_state="completed",
                reason_code="runner_phase_completed", metadata_values={"duration_ms": 1},
                occurred_at=NOW + timedelta(seconds=4),
            )
            assert replayed_event["id"] == event["id"]
            with pytest.raises(RunnerRepositoryConflict, match="runner_lifecycle_event_replay_mismatch"):
                await repository.record_lifecycle_event(
                    lease_id=first.lease_id, lease_token=bytearray(TOKEN), generation=1,
                    event_id=f"event-{suffix}", phase="execute", phase_state="completed",
                    reason_code="runner_phase_completed", metadata_values={"duration_ms": 1},
                    occurred_at=NOW + timedelta(seconds=4),
                )
            with pytest.raises(RunnerRepositoryConflict, match="runner_manifest_already_claimed"):
                await repository.claim_manifest(
                    manifest_record_id=str(issued["id"]), identity=identity, claim_id=f"other-{suffix}",
                    environment="local-conformance", runner_class_id="synthetic-standard",
                    policy_revision="r099-v1", generation=1, occurred_at=NOW + timedelta(seconds=3),
                )

            evidence_id = f"evidence-r100-{suffix}"
            await _bootstrap_evidence(
                session, tenant=tenant, actor=actor, job_id=job_id,
                evidence_id=evidence_id, suffix=suffix,
            )
            finalized = await repository.finalize_execution(
                lease_id=first.lease_id, lease_token=bytearray(TOKEN), generation=1,
                execution_id=f"execution-{suffix}", evidence_artifact_id=evidence_id,
                outcome="succeeded", final_phase="cleanup",
                policy_decision_id=f"decision-r100-{suffix}", evidence_sha256="8" * 64,
                cleanup_completed=True, residual_risk=None,
                occurred_at=NOW + timedelta(seconds=5),
            )
            replayed_final = await repository.finalize_execution(
                lease_id=first.lease_id, lease_token=bytearray(TOKEN), generation=1,
                execution_id=f"execution-{suffix}", evidence_artifact_id=evidence_id,
                outcome="succeeded", final_phase="cleanup",
                policy_decision_id=f"decision-r100-{suffix}", evidence_sha256="8" * 64,
                cleanup_completed=True, residual_risk=None,
                occurred_at=NOW + timedelta(seconds=5),
            )
            assert replayed_final["id"] == finalized["id"]

            failure_suffix = f"failure-{suffix}"
            failed_job_id = f"job-r100-{failure_suffix}"
            await _bootstrap_job(
                session, tenant=tenant, actor=actor,
                job_id=failed_job_id, suffix=failure_suffix,
            )
            failed_signed = sign_job_manifest(
                _draft(job_id=failed_job_id, tenant=tenant, suffix=failure_suffix),
                key, key_id="r100-local-signing-v1",
            )
            failed_manifest = await repository.issue_manifest(
                failed_signed, runner_registration_id=str(registered["id"]),
                capability_revision=1, idempotency_key=f"issue-{failure_suffix}",
                occurred_at=NOW,
            )
            failed_lease = await repository.claim_manifest(
                manifest_record_id=str(failed_manifest["id"]), identity=identity,
                claim_id=f"claim-{failure_suffix}", environment="local-conformance",
                runner_class_id="synthetic-standard", policy_revision="r099-v1",
                generation=1, occurred_at=NOW + timedelta(seconds=1),
            )
            await ContainmentRepository(
                session, tenant_id=tenant, actor_user_id=actor,
                correlation_id=f"containment-{failure_suffix}",
            ).request_stop(StopRequest(
                schema_version="1.0", stop_id=f"stop-{failure_suffix}", tenant_id=tenant,
                scope=ControlScope(ControlScopeKind.JOB, failed_job_id), initiated_by=actor,
                reason="Stop synthetic runner before execution side effect",
                requested_at=NOW + timedelta(seconds=2), expected_version=1,
                idempotency_key=f"stop-{failure_suffix}",
            ))
            with pytest.raises(RunnerRepositoryConflict, match="runner_containment_active"):
                await repository.begin_execution(
                    lease_id=failed_lease.lease_id,
                    lease_token=failed_lease.lease_token or bytearray(), generation=1,
                    occurred_at=NOW + timedelta(seconds=2),
                )
            failure_receipt = await repository.fail_execution(
                lease_id=failed_lease.lease_id,
                lease_token=failed_lease.lease_token or bytearray(), generation=1,
                execution_id=f"execution-{failure_suffix}",
                policy_decision_id=f"decision-{failure_suffix}",
                failure_code="runner_policy_denied", cleanup_completed=True,
                occurred_at=NOW + timedelta(seconds=2),
            )
            assert failure_receipt["outcome"] == "failed"
            assert failure_receipt["evidence_artifact_id"] is None
            assert failure_receipt["evidence_sha256"] is None

        async with sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant})
            snapshot = await RunnerRepository(
                session, tenant_id=tenant, actor_user_id=actor, correlation_id=f"status-{suffix}",
            ).status()
            assert snapshot == {"registrations": 1, "active_leases": 0}
            rows: list[dict[str, object]] = []
            for name in (
                "runner_classes", "runner_registrations", "runner_identities",
                "execution_capability_manifests", "artifact_verification_receipts",
                "runner_job_manifests", "runner_pull_leases",
                "runner_lifecycle_events", "runner_execution_receipts",
            ):
                result = (await session.execute(select(metadata.tables[name]).where(metadata.tables[name].c.tenant_id == tenant))).mappings().all()
                rows.extend(dict(row) for row in result)
            rendered = json.dumps(rows, default=str, sort_keys=True)
            assert TOKEN.decode() not in rendered  # pragma: allowlist secret
            for forbidden in ("private_key", "credential_material", "provider_response", "stdout", "stderr", "argv", "shell"):
                assert forbidden not in rendered.lower()
            assert await session.scalar(select(metadata.tables["audit_events"].c.id).where(
                metadata.tables["audit_events"].c.tenant_id == tenant,
                metadata.tables["audit_events"].c.action == "runner.manifest.claimed",
            ))
            assert await session.scalar(select(metadata.tables["outbox_events"].c.id).where(
                metadata.tables["outbox_events"].c.tenant_id == tenant,
                metadata.tables["outbox_events"].c.event_type == "runner.manifest.claimed",
            ))
            assert await session.scalar(select(func.count()).select_from(
                metadata.tables["runner_execution_receipts"]
            ).where(metadata.tables["runner_execution_receipts"].c.tenant_id == tenant)) == 2

            role_name = f"r100_test_{suffix}"
            # CRITICAL: role identifier is generated exclusively from a hex UUID suffix.
            await session.execute(text(f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS'))
            await session.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"'))
            await session.execute(text(f'GRANT SELECT ON runner_pull_leases TO "{role_name}"'))
            await session.execute(text(f'SET LOCAL ROLE "{role_name}"'))
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": f"other-{suffix}"})
            hidden = await session.scalar(select(metadata.tables["runner_pull_leases"].c.id).where(
                metadata.tables["runner_pull_leases"].c.id == first.lease_id,
            ))
            assert hidden is None
    finally:
        for index in range(len(TOKEN)):
            TOKEN[index] = 0
        await engine.dispose()


async def _bootstrap_job(session, *, tenant: str, actor: str, job_id: str, suffix: str) -> None:
    owned = {"tenant_id": tenant, "version": 1, "created_at": NOW, "updated_at": NOW}
    engagement_id = f"engagement-r100-{suffix}"
    roe_id = f"roe-r100-{suffix}"
    await session.execute(insert(metadata.tables["engagements"]).values(
        id=engagement_id, name="compat_100 synthetic engagement", owner_user_id=actor, **owned,
    ))
    await session.execute(insert(metadata.tables["roe_versions"]).values(
        id=roe_id, engagement_id=engagement_id, revision=1, status="approved", document={"synthetic": True}, **owned,
    ))
    await session.execute(insert(metadata.tables["jobs"]).values(
        id=job_id, engagement_id=engagement_id, roe_version_id=roe_id, created_by_user_id=actor,
        campaign_id=None, status="approved", request={"fixture": "synthetic-r100"},
        policy_reference="policy:r099-v1", workflow_id=f"workflow-r100-{suffix}", workflow_run_id=f"run-r100-{suffix}",
        orchestration_state="ready", orchestration_revision=3, current_gate="runner_dispatch",
        failure_code=None, retry_count=0, dispatch_blocked=False, stop_requested=False, **owned,
    ))


async def _bootstrap_evidence(
    session, *, tenant: str, actor: str, job_id: str, evidence_id: str, suffix: str,
) -> None:
    owned = {"tenant_id": tenant, "version": 1, "created_at": NOW, "updated_at": NOW}
    await session.execute(insert(metadata.tables["evidence_artifacts"]).values(
        id=evidence_id, engagement_id=f"engagement-r100-{suffix}", job_id=job_id,
        producer_id=actor, object_key=f"synthetic/{suffix}", object_version_id="version-1",
        content_sha256="8" * 64, provider_checksum="8" * 64, size_bytes=25,
        content_type="application/json", artifact_class="raw", classification="restricted",
        redaction_state="raw", retention_mode="GOVERNANCE",
        retain_until=NOW + timedelta(days=1), legal_hold=False,
        kms_reference="kms:compat_100:synthetic", attestation_hash="9" * 64,
        policy_reference="policy:r099-v1", quarantine_reason=None, finalized_at=NOW,
        **owned,
    ))


def _limits() -> ResourceLimits:
    return ResourceLimits(cpu_millis=500, memory_mib=128, pids=32, timeout_seconds=30, evidence_bytes=65_536)


def _sandbox() -> SandboxProfile:
    return SandboxProfile(
        profile_id="synthetic-standard-v1", isolation_tier=IsolationTier.CONTAINER, runtime_name="runc",
        run_as_user=65532, read_only_root=True, privileged=False, host_socket=False, host_namespaces=False,
        capabilities=(), no_new_privileges=True, seccomp_profile="runtime-default",
        network_mode=NetworkMode.NONE, writable_mounts=("/work",), limits=_limits(),
    )


def _artifact() -> ArtifactVerificationReceipt:
    return ArtifactVerificationReceipt(
        receipt_id="artifact-receipt-1", image_digest=IMAGE, signature_verified=True,
        signer_identity="redagent-release-r100", provenance_sha256="1" * 64, sbom_sha256="2" * 64,
        vulnerability_review="accepted_no_critical", verifier="redagent-offline-v1",
        verified_at=NOW, expires_at=NOW + timedelta(days=7),
    )


def _runner_class(*, class_id: str = "synthetic-standard") -> RunnerClassDefinition:
    return RunnerClassDefinition(
        schema_version="1.0", class_id=class_id, revision=1, environment="local-conformance",
        network_plane="isolated-none", policy_revision="r099-v1", sandbox=_sandbox(),
        credential_classes=(CredentialClass.DYNAMIC_DATABASE,), evidence_schemas=("synthetic-result-v1",),
        status="certified",
    )


def _capability() -> ExecutionCapabilityManifest:
    return ExecutionCapabilityManifest(
        schema_version="1.0", capability_id="synthetic-conformance", revision=1,
        adapter_id="synthetic-conformance", adapter_version="1.0.0", image_digest=IMAGE,
        input_schema_id="redagent.synthetic-job.v1", supported_modes=("synthetic",),
        phases=("preflight", "prepare", "execute", "monitor", "cancel", "collect", "normalize", "cleanup"),
        sandbox_profile_id="synthetic-standard-v1", network_mode=NetworkMode.NONE,
        credential_class=CredentialClass.DYNAMIC_DATABASE, evidence_schema=("synthetic-result-v1",),
        unsupported_features=("arbitrary_command", "native_template", "plugin_loading"),
        limits=_limits(), artifact_receipt_id="artifact-receipt-1", reviewed_by="reviewer-r100", status="certified",
    )


def _registration(suffix: str) -> RunnerRegistration:
    runner_id = f"runner-r100-{suffix}"
    return RunnerRegistration(
        runner_id=runner_id, tenant_id=f"tenant-r100-{suffix}", environment="local-conformance",
        runner_class_id="synthetic-standard", network_plane="isolated-none",
        spiffe_id=f"spiffe://redagent.test/runner/{runner_id}", certificate_fingerprint="3" * 64,
        certificate_serial="1001", adapter_allowlist=("synthetic-conformance:1.0.0",),
        image_allowlist=(IMAGE,), required_policy_revision="r099-v1", generation=1,
        registered_at=NOW, expires_at=NOW + timedelta(minutes=10), revoked_at=None,
    )


def _draft(*, job_id: str, tenant: str, suffix: str, nonce: str | None = None) -> JobManifestDraft:
    return JobManifestDraft(
        schema_version="1.0", manifest_id=f"manifest-r100-{suffix}", job_id=job_id, tenant_id=tenant,
        engagement_id=f"engagement-r100-{suffix}", roe_version_id=f"roe-r100-{suffix}",
        environment="local-conformance", runner_class_id="synthetic-standard", network_plane="isolated-none",
        adapter_id="synthetic-conformance", adapter_version="1.0.0",
        capability_digest=canonical_capability_sha256(_capability()), image_digest=IMAGE,
        artifact_receipt_id="artifact-receipt-1", policy_revision="r099-v1", policy_decision_id=f"decision-r100-{suffix}",
        target_ids=(f"target-r100-{suffix}",), target_hashes=("5" * 64,), limits=_limits(),
        egress_profile="none", evidence_schema=("synthetic-result-v1",), secret_reference_ids=(),
        issued_at=NOW, expires_at=NOW + timedelta(minutes=2), nonce=nonce or f"nonce-r100-{suffix}",
    )
