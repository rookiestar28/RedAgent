from __future__ import annotations

import asyncio
from dataclasses import asdict, replace
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

from sqlalchemy import func, insert, select, update
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.campaign_service.qualification import QualificationFixtureBinding
from redagent_platform.campaign_service.runtime import (
    PostgresCanonicalAuthorityProvider,
    PostgresEnvelopeAuthorityVerifier,
    PostgresQualificationFixtureOwner,
    PostgresRunnerIdentityOwner,
)
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.campaign_service.service import EffectDispatchCommand
from redagent_platform.campaign_service.resolver import ResolutionRequest
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository
from redagent_platform.runner_service.identity import PeerCertificateIdentity
from redagent_platform.nuclei_service.contracts import CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM
from redagent_platform.zap_service.contracts import CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 8, 24, 4, 0, tzinfo=timezone.utc)


def test_r123_postgres_fixture_owner_resolves_only_current_server_owned_loopback_binding() -> None:
    asyncio.run(_fixture_owner_scenario())


def test_r123_postgres_runner_identity_owner_requires_one_current_exact_observation() -> None:
    asyncio.run(_runner_identity_owner_scenario())


def test_r123_postgres_authority_provider_reads_existing_owners_and_mints_nothing() -> None:
    asyncio.run(_canonical_authority_provider_scenario())


def test_r123_postgres_envelope_verifier_rereads_current_persisted_bindings() -> None:
    asyncio.run(_envelope_verifier_scenario())


async def _fixture_owner_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-runtime-{suffix}"
    actor_id = f"user-r123-runtime-{suffix}"
    engagement_id = f"eng-r123-runtime-{suffix}"
    target_id = f"target-r123-runtime-{suffix}"
    roe_id = f"roe-r123-runtime-{suffix}"
    try:
        await _bootstrap_control_plane(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
        )
        await _bootstrap_owned_loopback_fixture(
            sessions,
            tenant_id=tenant_id,
            target_id=target_id,
            roe_id=roe_id,
            suffix=suffix,
        )

        owner = PostgresQualificationFixtureOwner(sessions)
        binding = await owner.read_owned_loopback_fixture(
            tenant_id=tenant_id,
            principal_id=actor_id,
            fixture_id="owned-loopback-http-first-slice",
            now=NOW + timedelta(seconds=5),
        )
        assert binding == QualificationFixtureBinding(
            fixture_id="owned-loopback-http-first-slice",
            engagement_id=engagement_id,
            target_id=target_id,
            campaign_name="R123 owned-loopback qualification",
        )

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            await session.execute(
                metadata.tables["lab_target_leases"].update()
                .where(metadata.tables["lab_target_leases"].c.tenant_id == tenant_id)
                .values(revoked_at=NOW + timedelta(seconds=6))
            )
        try:
            await owner.read_owned_loopback_fixture(
                tenant_id=tenant_id,
                principal_id=actor_id,
                fixture_id="owned-loopback-http-first-slice",
                now=NOW + timedelta(seconds=7),
            )
        except RuntimeError as exc:
            assert str(exc) == "r123_qualification_fixture_not_current"
        else:
            raise AssertionError("revoked qualification lease was accepted")
    finally:
        await engine.dispose()


async def _runner_identity_owner_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-identity-{suffix}"
    actor_id = f"user-r123-identity-{suffix}"
    runner_id = f"runner-r123-{suffix}"
    spiffe_id = f"spiffe://redagent.test/runner/{runner_id}"
    try:
        async with sessions() as session, session.begin():
            control = ControlPlaneRepository(
                session,
                tenant_id=tenant_id,
                actor_user_id=actor_id,
                correlation_id=f"identity-bootstrap-{suffix}",
            )
            await control.bootstrap_tenant(name="compat_123 runtime tenant", occurred_at=NOW)
            await control.bootstrap_user(user_id=actor_id, subject=actor_id, occurred_at=NOW)
            owned = _owned(tenant_id)
            await session.execute(insert(metadata.tables["runner_classes"]).values(
                id=f"runner-class-{suffix}",
                class_id="r123-closed-runner",
                class_revision=1,
                environment="local-conformance",
                network_plane="owned-loopback",
                isolation_tier="container",
                runtime_name="docker",
                sandbox_profile_id="r123-closed-v1",
                policy_revision="policy-r123-v1",
                resource_limits={"timeout_seconds": 300},
                credential_classes=["none"],
                evidence_schemas=["redagent.r123-terminal/v1"],
                class_status="active",
                author_user_id=actor_id,
                reviewer_user_id=actor_id,
                **owned,
            ))
            registration_id = f"runner-registration-{suffix}"
            await session.execute(insert(metadata.tables["runner_registrations"]).values(
                id=registration_id,
                runner_id=runner_id,
                runner_class_record_id=f"runner-class-{suffix}",
                environment="local-conformance",
                network_plane="owned-loopback",
                spiffe_id=spiffe_id,
                certificate_fingerprint="a" * 64,
                certificate_serial=f"serial-{suffix}",
                adapter_allowlist=["zap-service:2.17.0-r104.2"],
                image_allowlist=["sha256:" + "b" * 64],
                required_policy_revision="policy-r123-v1",
                generation=1,
                attestation_sha256="c" * 64,
                registration_state="active",
                registered_at=NOW,
                expires_at=NOW + timedelta(minutes=10),
                revoked_at=None,
                last_seen_at=NOW,
                **owned,
            ))
            await session.execute(insert(metadata.tables["runner_identities"]).values(
                id=f"runner-identity-{suffix}",
                registration_id=registration_id,
                spiffe_id=spiffe_id,
                certificate_fingerprint="a" * 64,
                certificate_serial=f"serial-{suffix}",
                not_before=NOW - timedelta(minutes=1),
                not_after=NOW + timedelta(minutes=5),
                identity_state="observed",
                observed_at=NOW,
                **owned,
            ))

        owner = PostgresRunnerIdentityOwner(sessions)
        identity = await owner.read_current_identity(
            tenant_id=tenant_id,
            runner_id=runner_id,
            now=NOW + timedelta(seconds=5),
        )
        assert identity == PeerCertificateIdentity(
            runner_id=runner_id,
            spiffe_id=spiffe_id,
            certificate_fingerprint="a" * 64,
            certificate_serial=f"serial-{suffix}",
            not_before=NOW - timedelta(minutes=1),
            not_after=NOW + timedelta(minutes=5),
        )

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            await session.execute(
                metadata.tables["runner_registrations"].update()
                .where(metadata.tables["runner_registrations"].c.tenant_id == tenant_id)
                .values(revoked_at=NOW + timedelta(seconds=6))
            )
        try:
            await owner.read_current_identity(
                tenant_id=tenant_id,
                runner_id=runner_id,
                now=NOW + timedelta(seconds=7),
            )
        except RuntimeError as exc:
            assert str(exc) == "r123_runner_identity_not_current"
        else:
            raise AssertionError("revoked runner identity was accepted")
    finally:
        await engine.dispose()


async def _canonical_authority_provider_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-authority-{suffix}"
    actor_id = f"user-r123-authority-{suffix}"
    engagement_id = f"eng-r123-authority-{suffix}"
    target_id = f"target-r123-authority-{suffix}"
    roe_id = f"roe-r123-authority-{suffix}"
    runner_id = f"runner-r123-{suffix}"
    try:
        await _bootstrap_control_plane(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
        )
        await _bootstrap_owned_loopback_fixture(
            sessions,
            tenant_id=tenant_id,
            target_id=target_id,
            roe_id=roe_id,
            suffix=suffix,
        )
        await _bootstrap_authority_dependencies(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            target_id=target_id,
            runner_id=runner_id,
            suffix=suffix,
        )

        provider = PostgresCanonicalAuthorityProvider(
            sessions,
            clock=lambda: NOW + timedelta(seconds=5),
        )
        request = ResolutionRequest(
            tenant_id=tenant_id,
            principal_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
        )
        snapshot = await provider.read_current_authority(request)
        assert snapshot is not None
        assert snapshot.tenant_id == tenant_id
        assert snapshot.principal_id == actor_id
        assert snapshot.engagement_id == engagement_id
        assert snapshot.target_id == target_id
        assert snapshot.target_value == "http://127.0.0.1:41731"
        assert snapshot.target_resolution_mode == "owned-loopback"
        assert snapshot.credential_class == "none"
        assert snapshot.credential_reference is None
        assert snapshot.policy_decision_id == "policy-r123-owned-loopback"
        assert snapshot.quota_reference == f"quota-policy-{suffix}"
        assert snapshot.reservation_id == f"quota-reservation-{suffix}"
        assert snapshot.runner_id == runner_id
        assert snapshot.runner_workload_identity == f"spiffe://redagent.test/runner/{runner_id}"
        assert snapshot.lease_id == f"lab-lease-{suffix}"
        assert snapshot.stop_requested is False
        assert len(snapshot.roe_sha256) == len(snapshot.policy_sha256) == len(snapshot.target_sha256) == 64

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            before = {
                name: int(await session.scalar(
                    select(func.count()).select_from(metadata.tables[name]).where(
                        metadata.tables[name].c.tenant_id == tenant_id
                    )
                ) or 0)
                for name in (
                    "campaigns", "jobs", "policy_decisions", "quota_reservations",
                    "lab_target_leases", "runner_registrations", "runner_identities",
                )
            }
        assert await provider.read_current_authority(request) == snapshot
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            after = {
                name: int(await session.scalar(
                    select(func.count()).select_from(metadata.tables[name]).where(
                        metadata.tables[name].c.tenant_id == tenant_id
                    )
                ) or 0)
                for name in before
            }
        assert after == before

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            await session.execute(
                metadata.tables["lab_target_leases"].update()
                .where(metadata.tables["lab_target_leases"].c.tenant_id == tenant_id)
                .values(endpoint="http://127.0.0.1:41732")
            )
        assert await provider.read_current_authority(request) is None
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            await session.execute(
                metadata.tables["lab_target_leases"].update()
                .where(metadata.tables["lab_target_leases"].c.tenant_id == tenant_id)
                .values(endpoint="http://127.0.0.1:41731")
            )

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            await session.execute(insert(metadata.tables["containment_controls"]).values(
                id=f"authority-stop-{suffix}",
                stop_id=f"stop-{suffix}",
                scope_kind="tenant",
                scope_id=tenant_id,
                control_mode="kill",
                request_hash="7" * 64,
                idempotency_key=f"authority-stop-{suffix}",
                reason_hash="8" * 64,
                initiated_by_user_id=actor_id,
                approved_by_user_id=None,
                control_state="active",
                requested_at=NOW + timedelta(seconds=6),
                activated_at=NOW + timedelta(seconds=6),
                ack_deadline=NOW + timedelta(minutes=1),
                recovered_at=None,
                **_owned(tenant_id),
            ))
        stopped = await provider.read_current_authority(request)
        assert stopped is not None and stopped.stop_requested is True

        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            await session.execute(
                metadata.tables["policy_decisions"].update()
                .where(metadata.tables["policy_decisions"].c.tenant_id == tenant_id)
                .values(allowed=False)
            )
        assert await provider.read_current_authority(request) is None
    finally:
        await engine.dispose()


async def _envelope_verifier_scenario() -> None:
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant_id = f"tenant-r123-envelope-{suffix}"
    actor_id = f"user-r123-envelope-{suffix}"
    engagement_id = f"eng-r123-envelope-{suffix}"
    target_id = f"target-r123-envelope-{suffix}"
    roe_id = f"roe-r123-envelope-{suffix}"
    campaign_id = f"campaign-r123-envelope-{suffix}"
    strategy_record_id = f"strategy-r123-envelope-{suffix}"
    effect_id = f"effect-r123-envelope-{suffix}"
    invocation_id = f"invocation-r123-envelope-{suffix}"
    envelope_sha256 = "8" * 64
    try:
        await _bootstrap_control_plane(
            sessions,
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
        )
        binding = _runtime_binding()
        snapshot = _runtime_snapshot(
            tenant_id=tenant_id,
            actor_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            roe_id=roe_id,
            suffix=suffix,
        )
        async with sessions() as session, session.begin():
            await _set_tenant(session, tenant_id)
            owned = _owned(tenant_id)
            await session.execute(insert(metadata.tables["campaigns"]).values(
                id=campaign_id,
                engagement_id=engagement_id,
                roe_version_id=roe_id,
                name="compat_123 envelope verification",
                status="running",
                workflow_id=f"workflow-{suffix}",
                workflow_run_id=None,
                orchestration_revision=2,
                intent_sha256="1" * 64,
                current_strategy_revision_id=None,
                aggregate_sequence=2,
                replan_count=0,
                attention_reason=None,
                terminal_receipt_sha256=None,
                **owned,
            ))
            await session.execute(insert(metadata.tables["campaign_strategy_revisions"]).values(
                id=strategy_record_id,
                strategy_revision_id=f"plan-{suffix}",
                campaign_id=campaign_id,
                predecessor_revision_id=None,
                plan_revision=1,
                replan_count=0,
                context_schema="redagent.r119-decision-context/v1",
                context_sha256="2" * 64,
                context_payload={"bindings": [asdict(binding)]},
                decision_schema="redagent.r121-strategy-receipt/v1",
                decision_sha256="3" * 64,
                decision_payload={
                    "policy_revision": snapshot.policy_revision,
                    "policy_sha256": snapshot.policy_sha256,
                    "roe_version_id": snapshot.roe_version_id,
                    "roe_sha256": snapshot.roe_sha256,
                    "objective": {
                        "target": {
                            "reference_id": snapshot.target_id,
                            "sha256": snapshot.target_sha256,
                        }
                    },
                },
                plan_sha256="4" * 64,
                plan_payload={"primary": {"binding_key_sha256": "5" * 64}},
                proposal_ceiling_sha256="6" * 64,
                approval_receipt_id=snapshot.policy_decision_id,
                approval_receipt_revision=1,
                approval_receipt_sha256="7" * 64,
                envelope_core_sha256="9" * 64,
                envelope_sha256=envelope_sha256,
                created_by_user_id=actor_id,
                **owned,
            ))
            await session.execute(
                update(metadata.tables["campaigns"])
                .where(metadata.tables["campaigns"].c.id == campaign_id)
                .values(current_strategy_revision_id=strategy_record_id)
            )
            await session.execute(insert(metadata.tables["campaign_effects"]).values(
                id=f"effect-record-{suffix}",
                effect_id=effect_id,
                campaign_id=campaign_id,
                strategy_revision_id=strategy_record_id,
                node_id=f"node-{suffix}",
                invocation_id=invocation_id,
                effect_intent_sha256="a" * 64,
                effect_intent_payload={"binding": asdict(binding)},
                envelope_sha256=envelope_sha256,
                effect_state="claimed",
                claim_owner="worker-r123",
                claim_expires_at=NOW + timedelta(minutes=2),
                claim_version=1,
                dispatch_attempt=0,
                dispatch_generation=0,
                runner_id=None,
                workload_identity=None,
                request_sha256=None,
                effect_receipt_sha256=None,
                effect_receipt_payload=None,
                external_status=None,
                external_receipt_id=None,
                evidence_ids=[],
                cleanup_receipt_id=None,
                reconciliation_state="none",
                reconciliation_evidence_ids=[],
                redispatch_permitted=False,
                failure_code=None,
                next_retry_at=None,
                outbox_sequence=2,
                started_at=None,
                completed_at=None,
                **owned,
            ))
        command = EffectDispatchCommand(
            tenant_id=tenant_id,
            principal_id=actor_id,
            engagement_id=engagement_id,
            target_id=target_id,
            effect_id=effect_id,
            invocation_id=invocation_id,
            effect_intent_sha256="a" * 64,
            envelope_sha256=envelope_sha256,
            expected_claim_version=1,
            expected_dispatch_attempt=0,
            expected_dispatch_generation=0,
            claim_owner="worker-r123",
            binding=binding,
        )
        verifier = PostgresEnvelopeAuthorityVerifier(sessions)
        assert await verifier.verify_current_envelope(
            command,
            snapshot,
            now=NOW + timedelta(seconds=5),
        ) is None
        assert await verifier.verify_current_envelope(
            command,
            replace(snapshot, policy_sha256="f" * 64),
            now=NOW + timedelta(seconds=5),
        ) == "r123_envelope_policy_drift"
        assert await verifier.verify_current_envelope(
            replace(command, claim_owner="different-worker"),
            snapshot,
            now=NOW + timedelta(seconds=5),
        ) == "r123_envelope_claim_drift"
    finally:
        await engine.dispose()


def _runtime_binding() -> CapabilityBindingKeyV1:
    closed = closed_execution_registry()["zap-controlled-runtime@2"]
    return CapabilityBindingKeyV1(
        schema_version="redagent.r119-capability-binding/v1",
        capability_id=closed.capability_id,
        capability_revision=closed.capability_revision,
        execution_manifest_sha256="a" * 64,
        adapter_id=closed.adapter_id,
        adapter_version=closed.adapter_version,
        profile_id=closed.profile_id,
        profile_revision=closed.profile_revision,
        profile_sha256=closed.profile_sha256,
        bundle_id=closed.bundle_id,
        bundle_revision=closed.bundle_revision,
        bundle_sha256=closed.bundle_sha256,
        semantics_revision=1,
        semantics_sha256="b" * 64,
        normalized_output_sha256="c" * 64,
        projection_revision=1,
        projection_sha256="d" * 64,
    )


def _runtime_snapshot(
    *,
    tenant_id: str,
    actor_id: str,
    engagement_id: str,
    target_id: str,
    roe_id: str,
    suffix: str,
):
    from redagent_platform.campaign_service.resolver import CanonicalAuthoritySnapshot

    return CanonicalAuthoritySnapshot(
        tenant_id=tenant_id,
        principal_id=actor_id,
        engagement_id=engagement_id,
        engagement_version=1,
        roe_version_id=roe_id,
        roe_revision=1,
        roe_sha256="1" * 64,
        roe_status="approved",
        roe_revocation_epoch=0,
        policy_decision_id=f"policy-decision-{suffix}",
        policy_revision="policy-r123-v1",
        policy_sha256="2" * 64,
        policy_status="allowed",
        policy_revocation_epoch=0,
        target_id=target_id,
        target_revision=1,
        target_sha256="3" * 64,
        target_value="http://127.0.0.1:41731",
        target_resolution_mode="owned-loopback",
        credential_class="none",
        credential_reference=None,
        quota_reference=f"quota-{suffix}",
        quota_available=True,
        runner_id=f"runner-{suffix}",
        runner_workload_identity=f"spiffe://redagent.test/runner/{suffix}",
        runner_ready=True,
        reservation_id=f"reservation-{suffix}",
        lease_id=f"lease-{suffix}",
        lease_expires_at=NOW + timedelta(minutes=5),
        stop_requested=False,
        observed_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


async def _bootstrap_control_plane(
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
            correlation_id=f"runtime-bootstrap-{tenant_id}",
        )
        await repo.bootstrap_tenant(name="compat_123 runtime tenant", occurred_at=NOW)
        await repo.bootstrap_user(user_id=actor_id, subject=actor_id, occurred_at=NOW)
        await repo.create_engagement(
            engagement_id=engagement_id,
            name="compat_123 qualification engagement",
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
        await session.execute(insert(metadata.tables["tenant_memberships"]).values(
            id=f"membership-{actor_id}",
            user_id=actor_id,
            status="active",
            generation=1,
            last_validated_at=NOW,
            **_owned(tenant_id),
        ))


async def _bootstrap_owned_loopback_fixture(
    sessions,
    *,
    tenant_id: str,
    target_id: str,
    roe_id: str,
    suffix: str,
) -> None:
    async with sessions() as session, session.begin():
        await _set_tenant(session, tenant_id)
        owned = _owned(tenant_id)
        bundle_id = f"lab-bundle-{suffix}"
        attestation_id = f"lab-attestation-{suffix}"
        await session.execute(insert(metadata.tables["lab_bundles"]).values(
            id=bundle_id,
            bundle_id="r123-owned-loopback-http-first-slice",
            bundle_revision=2,
            fixture_digest="sha256:" + "d" * 64,
            seed_manifest_sha256="e" * 64,
            network_id="redagent-r103-lab",
            manifest={"fixture": "owned-loopback-http"},
            bundle_state="active",
            activated_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            **owned,
        ))
        await session.execute(insert(metadata.tables["lab_target_attestations"]).values(
            id=attestation_id,
            bundle_record_id=bundle_id,
            attestation_id=f"attestation-{suffix}",
            target_id=target_id,
            fixture_kind="web",
            endpoint="http://127.0.0.1:41731",
            network_id="redagent-r103-lab",
            allowed_test_classes=["finding_mapping"],
            expected_finding_manifest_sha256="f" * 64,
            attestation_sha256="1" * 64,
            non_production=True,
            attestation_state="active",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=10),
            **owned,
        ))
        await session.execute(insert(metadata.tables["lab_target_leases"]).values(
            id=f"lab-lease-record-{suffix}",
            attestation_record_id=attestation_id,
            lease_id=f"lab-lease-{suffix}",
            target_id=target_id,
            runner_id=f"runner-r123-{suffix}",
            test_class="finding_mapping",
            endpoint="http://127.0.0.1:41731",
            attestation_sha256="1" * 64,
            policy_reference="policy-r123-owned-loopback",
            roe_version_id=roe_id,
            lease_state="active",
            issued_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            revoked_at=None,
            **owned,
        ))


async def _bootstrap_authority_dependencies(
    sessions,
    *,
    tenant_id: str,
    actor_id: str,
    target_id: str,
    runner_id: str,
    suffix: str,
) -> None:
    async with sessions() as session, session.begin():
        await _set_tenant(session, tenant_id)
        owned = _owned(tenant_id)
        await session.execute(insert(metadata.tables["policy_decisions"]).values(
            id=f"policy-decision-record-{suffix}",
            opa_decision_id="policy-r123-owned-loopback",
            bundle_revision="policy-r123-v1",
            input_hash="2" * 64,
            boundary="workflow",
            action="campaign:execute",
            subject_id=actor_id,
            resource_type="target",
            resource_id=target_id,
            resource_version=1,
            allowed=True,
            reason_code="r123_owned_loopback_allowed",
            obligations=["report_safe_evidence", "cleanup", "reconciliation"],
            issued_at=NOW,
            valid_until=NOW + timedelta(minutes=5),
            correlation_id=f"policy-authority-{suffix}",
            **owned,
        ))
        quota_policy_record = f"quota-policy-record-{suffix}"
        quota_usage_record = f"quota-usage-{suffix}"
        await session.execute(insert(metadata.tables["quota_policies"]).values(
            id=quota_policy_record,
            policy_id=f"quota-policy-{suffix}",
            policy_revision=1,
            dimension="operations",
            extension_name=None,
            scope_kind="tenant",
            scope_id=tenant_id,
            scope_key=f"tenant:{tenant_id}",
            hard_limit=2,
            window_seconds=300,
            active_from=NOW,
            active_until=NOW + timedelta(minutes=5),
            policy_state="active",
            **owned,
        ))
        await session.execute(insert(metadata.tables["quota_usage"]).values(
            id=quota_usage_record,
            policy_record_id=quota_policy_record,
            scope_key=f"tenant:{tenant_id}",
            window_start=NOW,
            window_end=NOW + timedelta(minutes=5),
            reserved_amount=2,
            consumed_amount=0,
            **owned,
        ))
        await session.execute(insert(metadata.tables["quota_reservations"]).values(
            id=f"quota-reservation-record-{suffix}",
            reservation_id=f"quota-reservation-{suffix}",
            policy_record_id=quota_policy_record,
            usage_id=quota_usage_record,
            reserved_amount=2,
            consumed_amount=0,
            released_amount=0,
            reservation_state="reserved",
            expires_at=NOW + timedelta(minutes=5),
            **owned,
        ))
        runner_class_record = f"authority-runner-class-{suffix}"
        runner_registration_record = f"authority-runner-registration-{suffix}"
        spiffe_id = f"spiffe://redagent.test/runner/{runner_id}"
        await session.execute(insert(metadata.tables["runner_classes"]).values(
            id=runner_class_record,
            class_id="r123-closed-runner",
            class_revision=1,
            environment="local-conformance",
            network_plane="owned-loopback",
            isolation_tier="container",
            runtime_name="docker",
            sandbox_profile_id="r123-closed-v1",
            policy_revision="policy-r123-v1",
            resource_limits={"timeout_seconds": 300},
            credential_classes=["none"],
            evidence_schemas=["redagent.r123-terminal/v1"],
            class_status="active",
            author_user_id=actor_id,
            reviewer_user_id=actor_id,
            **owned,
        ))
        await session.execute(insert(metadata.tables["runner_registrations"]).values(
            id=runner_registration_record,
            runner_id=runner_id,
            runner_class_record_id=runner_class_record,
            environment="local-conformance",
            network_plane="owned-loopback",
            spiffe_id=spiffe_id,
            certificate_fingerprint="3" * 64,
            certificate_serial=f"authority-serial-{suffix}",
            adapter_allowlist=[
                "zap-service:2.17.0-r104.2",
                "nuclei-service:3.11.1-r105.2",
            ],
            image_allowlist=[
                CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"],
                CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM["linux/amd64"],
            ],
            required_policy_revision="policy-r123-v1",
            generation=1,
            attestation_sha256="6" * 64,
            registration_state="active",
            registered_at=NOW,
            expires_at=NOW + timedelta(minutes=5),
            revoked_at=None,
            last_seen_at=NOW,
            **owned,
        ))
        await session.execute(insert(metadata.tables["runner_identities"]).values(
            id=f"authority-runner-identity-{suffix}",
            registration_id=runner_registration_record,
            spiffe_id=spiffe_id,
            certificate_fingerprint="3" * 64,
            certificate_serial=f"authority-serial-{suffix}",
            not_before=NOW - timedelta(minutes=1),
            not_after=NOW + timedelta(minutes=5),
            identity_state="observed",
            observed_at=NOW,
            **owned,
        ))


def _database():
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    return engine, async_sessionmaker(engine, expire_on_commit=False)


def _owned(tenant_id: str) -> dict[str, object]:
    return {
        "tenant_id": tenant_id,
        "version": 1,
        "created_at": NOW,
        "updated_at": NOW,
    }


async def _set_tenant(session, tenant_id: str) -> None:
    await session.execute(select(func.set_config("redagent.tenant_id", tenant_id, True)))
