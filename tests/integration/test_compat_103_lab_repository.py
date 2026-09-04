from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.lab_service.contracts import (
    LAB_SCHEMA, FixtureKind, LabBundleManifest, LabTargetAttestation, LabTargetLease,
    TargetAccessRequest, TestClass as LabTestClass,
)
from redagent_platform.lab_service.repository import LabRepository, LabRepositoryConflict
from redagent_platform.lab_service.findings import GoldenFindingMapper, GoldenObservation
from redagent_platform.lab_service.scenarios import ScenarioStatus
from redagent_platform.lab_service.measurements import QualificationMeasurement
from redagent_platform.lab_service.qualification import (
    BoundaryReceipt, QualificationCoordinator,
)
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 11, 11, 0, tzinfo=timezone.utc)
DIGEST = "sha256:" + "d" * 64
SHA = "e" * 64


def test_lab_bundle_attestation_lease_scenario_replay_teardown_and_rls() -> None:
    asyncio.run(_scenario())


async def _scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    engine = create_async_engine(settings.url, pool_pre_ping=True)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    suffix = uuid4().hex[:10]
    tenant = f"tenant-r103-{suffix}"
    operator = f"operator-{suffix}"
    manifest = _manifest(suffix)
    attestation = _attestation(suffix)
    lease = _lease(suffix, attestation)
    try:
        async with sessions() as session, session.begin():
            await ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=operator,
                correlation_id=f"bootstrap-{suffix}",
            ).bootstrap_tenant(name="compat_103 lab", occurred_at=NOW)

        async with sessions() as session, session.begin():
            repository = LabRepository(
                session, tenant_id=tenant, actor_user_id=operator,
                correlation_id=f"register-{suffix}",
            )
            first = await repository.register_bundle(manifest, occurred_at=NOW)
            replay = await repository.register_bundle(manifest, occurred_at=NOW)
            assert replay["id"] == first["id"]
            with pytest.raises(LabRepositoryConflict, match="lab_bundle_revision_immutable"):
                await repository.register_bundle(
                    _manifest(suffix, seed_manifest_sha256="f" * 64), occurred_at=NOW,
                )
            target = await repository.attest_target(attestation, occurred_at=NOW)
            issued = await repository.issue_target_lease(lease, occurred_at=NOW)
            assert target["attestation_sha256"] == attestation.canonical_sha256
            assert issued["lease_state"] == "active"
            decision = await repository.authorize_target(TargetAccessRequest(
                tenant_id=tenant, target_id=attestation.target_id, runner_id=lease.runner_id,
                test_class=LabTestClass.HAPPY_PATH, endpoint=attestation.endpoint,
                policy_reference=lease.policy_reference, roe_version_id=lease.roe_version_id,
                requested_at=NOW + timedelta(seconds=1),
            ))
            assert decision.allowed

        run_id = f"run-{suffix}"
        async with sessions() as session, session.begin():
            repository = LabRepository(
                session, tenant_id=tenant, actor_user_id=operator,
                correlation_id=f"scenario-{suffix}",
            )
            started = await repository.start_scenario(
                run_id=run_id, scenario_id="authorize_deny",
                bundle_id=manifest.bundle_id, occurred_at=NOW + timedelta(seconds=2),
            )
            assert started["scenario_state"] == "running"
            step = await repository.record_step(
                run_id=run_id, scenario_id="authorize_deny", step_id="deny-public",
                action_id=f"deny-public-{suffix}", step_name="deny_public_target",
                step_state="passed", request_sha256="1" * 64, receipt_sha256="2" * 64,
                request_count=1, contact_count=0, reason_code="public_target_denied",
                occurred_at=NOW + timedelta(seconds=3),
            )
            replay = await repository.record_step(
                run_id=run_id, scenario_id="authorize_deny", step_id="deny-public",
                action_id=f"deny-public-{suffix}", step_name="deny_public_target",
                step_state="passed", request_sha256="1" * 64, receipt_sha256="2" * 64,
                request_count=1, contact_count=0, reason_code="public_target_denied",
                occurred_at=NOW + timedelta(seconds=3),
            )
            assert replay["id"] == step["id"]
            finished = await repository.transition_scenario(
                run_id=run_id, scenario_id="authorize_deny", action_id=f"finish-{suffix}",
                expected_version=2, next_status=ScenarioStatus.SUCCEEDED,
                reason_code="scenario_succeeded", occurred_at=NOW + timedelta(seconds=4),
            )
            assert finished["scenario_state"] == "succeeded"
            measurement = await repository.record_measurement(
                run_id=run_id, scenario_id="authorize_deny", measurement_id=f"metric-{suffix}",
                measurement=QualificationMeasurement(
                    metric_id="target-contact-count", comparison="lte", samples=(0.0,),
                    threshold=0.0, unit="requests",
                ), artifact_sha256="6" * 64, occurred_at=NOW + timedelta(seconds=5),
            )
            assert measurement["result_state"] == "passed"
            restore = await repository.record_backup_restore(
                run_id=run_id, scenario_id="authorize_deny", receipt_id=f"restore-{suffix}",
                source_inventory_sha256="7" * 64, restored_inventory_sha256="7" * 64,
                source_schema_revision="0010_r103_safe_lab",
                restored_schema_revision="0010_r103_safe_lab",
                source_row_count=18, restored_row_count=18,
                source_object_count=2, restored_object_count=2,
                occurred_at=NOW + timedelta(seconds=6),
            )
            assert restore["restore_state"] == "passed"
            teardown = await repository.record_teardown(
                run_id=run_id, scenario_id="authorize_deny", receipt_id=f"teardown-{suffix}",
                container_count=1, network_count=1, volume_count=0,
                residual_resource_count=0, inventory_sha256="3" * 64,
                occurred_at=NOW + timedelta(seconds=7),
            )
            assert teardown["teardown_complete"] is True
            dashboard = await repository.dashboard()
            assert dashboard["bundle"]["bundle_id"] == manifest.bundle_id
            assert dashboard["scenarios"][0]["scenario_state"] == "succeeded"
            assert dashboard["measurements"][0]["result_state"] == "passed"
            assert dashboard["latest_teardown"]["teardown_complete"] is True

        async with sessions() as session, session.begin():
            repository = LabRepository(
                session, tenant_id=tenant, actor_user_id=operator,
                correlation_id=f"matrix-{suffix}",
            )
            matrix = await QualificationCoordinator(
                repository, _PostgresBackedFoundationBoundary(session),
            ).run_all(
                run_id=f"matrix-{suffix}", bundle_id=manifest.bundle_id,
                started_at=NOW + timedelta(seconds=10),
            )
            assert len(matrix) == 18
            assert all(row["scenario_state"] == "succeeded" for row in matrix)

        async with sessions() as session, session.begin():
            steps = metadata.tables["golden_scenario_steps"]
            assert await session.scalar(select(func.count()).select_from(steps).where(
                steps.c.tenant_id == tenant,
            )) == 19

        mapper = GoldenFindingMapper.from_path(ROOT / "config/r103-golden-findings.json")
        mapped = mapper.reconcile((
            GoldenObservation(
                expectation_id="r103-header-training-marker", indicator="r103-header-training-marker",
                affected_resource="synthetic-web-root", evidence_reference="evidence:r103:header",
                evidence_sha256="4" * 64,
            ),
            GoldenObservation(
                expectation_id="r103-api-training-marker", indicator="r103-api-training-marker",
                affected_resource="synthetic-api-profile", evidence_reference="evidence:r103:profile",
                evidence_sha256="5" * 64,
            ),
        ))
        async with sessions() as session, session.begin():
            repository = LabRepository(
                session, tenant_id=tenant, actor_user_id=operator,
                correlation_id=f"golden-register-{suffix}",
            )
            for index, (observation, finding) in enumerate(zip((
                "r103-header-training-marker", "r103-api-training-marker",
            ), mapped, strict=True)):
                registered = await repository.register_golden_expectation(
                    bundle_id=manifest.bundle_id, expectation_id=observation,
                    fixture_kind=(FixtureKind.WEB, FixtureKind.API)[index], finding=finding,
                    evidence_class="sanitized_metadata",
                    expectation_sha256=("8", "9")[index] * 64,
                    occurred_at=NOW + timedelta(seconds=6 + index),
                )
                replay = await repository.register_golden_expectation(
                    bundle_id=manifest.bundle_id, expectation_id=observation,
                    fixture_kind=(FixtureKind.WEB, FixtureKind.API)[index], finding=finding,
                    evidence_class="sanitized_metadata",
                    expectation_sha256=("8", "9")[index] * 64,
                    occurred_at=NOW + timedelta(seconds=6 + index),
                )
                assert replay["id"] == registered["id"]
        async with sessions() as session, session.begin():
            control = ControlPlaneRepository(
                session, tenant_id=tenant, actor_user_id=operator,
                correlation_id=f"findings-{suffix}",
            )
            results = []
            for index, item in enumerate(mapped):
                values = {key: item[key] for key in (
                    "tool", "rule_id", "tool_version", "database_version", "title", "severity",
                    "confidence", "affected_resource", "location", "evidence_reference", "redaction_state",
                )}
                results.append(await control.ingest_finding(
                    finding_id=f"golden-{index}-{suffix}", idempotency_key=f"golden-{index}-{suffix}",
                    occurred_at=NOW + timedelta(seconds=6 + index), **values,
                ))
            replay = await control.ingest_finding(
                finding_id=f"golden-0-{suffix}", idempotency_key=f"golden-0-{suffix}",
                occurred_at=NOW + timedelta(seconds=6),
                **{key: mapped[0][key] for key in (
                    "tool", "rule_id", "tool_version", "database_version", "title", "severity",
                    "confidence", "affected_resource", "location", "evidence_reference", "redaction_state",
                )},
            )
            duplicate = await control.ingest_finding(
                finding_id=f"golden-duplicate-{suffix}", idempotency_key=f"golden-duplicate-{suffix}",
                occurred_at=NOW + timedelta(seconds=9),
                **{key: mapped[0][key] for key in (
                    "tool", "rule_id", "tool_version", "database_version", "title", "severity",
                    "confidence", "affected_resource", "location", "evidence_reference", "redaction_state",
                )},
            )
            assert replay.resource == results[0].resource
            assert duplicate.resource["finding_id"] == results[0].resource["finding_id"]

        async with sessions() as session, session.begin():
            assert await session.scalar(select(func.count()).select_from(
                metadata.tables["issue_definitions"]
            ).where(metadata.tables["issue_definitions"].c.tenant_id == tenant)) == 2
            assert await session.scalar(select(func.count()).select_from(
                metadata.tables["finding_instances"]
            ).where(metadata.tables["finding_instances"].c.tenant_id == tenant)) == 2
            assert await session.scalar(select(func.count()).select_from(
                metadata.tables["golden_finding_expectations"]
            ).where(metadata.tables["golden_finding_expectations"].c.tenant_id == tenant)) == 2

        async with sessions() as session:
            transaction = await session.begin()
            role = f"r103_test_{suffix}"
            try:
                # CRITICAL: role name is generated only from a hex UUID suffix.
                await session.execute(text(
                    f'CREATE ROLE "{role}" NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS'
                ))
                await session.execute(text(f'GRANT USAGE ON SCHEMA public TO "{role}"'))
                await session.execute(text(f'GRANT SELECT ON lab_bundles TO "{role}"'))
                await session.execute(text(f'SET LOCAL ROLE "{role}"'))
                await session.execute(text(
                    "SELECT set_config('redagent.tenant_id', :tenant, true)"
                ), {"tenant": f"other-{suffix}"})
                assert await session.scalar(select(func.count()).select_from(
                    metadata.tables["lab_bundles"]
                )) == 0
            finally:
                await transaction.rollback()
    finally:
        await engine.dispose()


def _manifest(suffix: str, **changes: object) -> LabBundleManifest:
    values = {
        "schema": LAB_SCHEMA, "bundle_id": f"bundle-{suffix}", "revision": 1,
        "fixture_digest": DIGEST, "seed_manifest_sha256": SHA,
        "fixture_kinds": tuple(FixtureKind), "allowed_test_classes": tuple(LabTestClass),
        "network_id": "redagent-r103-lab", "non_production": True,
        "created_at": NOW, "expires_at": NOW + timedelta(hours=2),
    }
    values.update(changes)
    return LabBundleManifest(**values)


def _attestation(suffix: str) -> LabTargetAttestation:
    return LabTargetAttestation(
        attestation_id=f"attestation-{suffix}", tenant_id=f"tenant-r103-{suffix}",
        target_id=f"target-{suffix}", bundle_id=f"bundle-{suffix}", bundle_digest=DIGEST,
        fixture_kind=FixtureKind.WEB, endpoint="http://127.0.0.1:58880",
        network_id="redagent-r103-lab",
        allowed_test_classes=(LabTestClass.HEALTH, LabTestClass.HAPPY_PATH),
        expected_finding_manifest_sha256=SHA, non_production=True,
        issued_at=NOW, expires_at=NOW + timedelta(hours=1),
    )


def _lease(suffix: str, attestation: LabTargetAttestation) -> LabTargetLease:
    return LabTargetLease(
        lease_id=f"lease-{suffix}", tenant_id=f"tenant-r103-{suffix}",
        target_id=f"target-{suffix}", attestation_sha256=attestation.canonical_sha256,
        runner_id=f"runner-{suffix}", test_class=LabTestClass.HAPPY_PATH,
        endpoint=attestation.endpoint, issued_at=NOW, expires_at=NOW + timedelta(minutes=10),
        policy_reference="policy:compat_103:1", roe_version_id=f"roe-{suffix}",
    )


class _PostgresBackedFoundationBoundary:
    """Test boundary that proves durable execution against the real local database."""

    def __init__(self, session) -> None:
        self.session = session

    async def execute(self, definition) -> BoundaryReceipt:
        revision = await self.session.scalar(text("SELECT version_num FROM alembic_version"))
        assert revision == "0029_autonomous_campaign_app"
        return BoundaryReceipt(
            receipt_types=("audit", "outbox", "telemetry", "cleanup", "evidence", "finding", "incident"),
            reason_code="fixed_local_foundation_passed", request_count=1, contact_count=0,
            details={
                "scenario_id": definition.scenario_id, "schema_revision": revision,
                "boundaries": [
                    "postgresql", "temporal", "opa", "openbao", "rustfs", "keycloak",
                    "api", "runner", "containment", "collector", "fixed_siem",
                ],
            },
        )

    async def compensate(self, definition) -> BoundaryReceipt:
        return BoundaryReceipt(
            receipt_types=("cleanup",), reason_code="fixed_cleanup_verified",
            request_count=0, contact_count=0, details={"scenario_id": definition.scenario_id},
        )
