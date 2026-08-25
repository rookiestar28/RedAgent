"""PostgreSQL-authoritative compat_103 lab bundles, leases, scenarios, and receipts."""

from __future__ import annotations

from datetime import datetime
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update

from redagent_platform.lab_service.contracts import (
    FixtureKind, LabBundleManifest, LabTargetAttestation, LabTargetLease,
    TargetAccessRequest, TestClass, authorize_target_access,
)
from redagent_platform.lab_service.scenarios import (
    REQUIRED_GOLDEN_SCENARIOS, ScenarioState, ScenarioStatus, advance_scenario,
)
from redagent_platform.lab_service.measurements import QualificationMeasurement
from redagent_platform.persistence.models import metadata


class LabRepositoryConflict(RuntimeError):
    """Stable compat_103 persistence conflict."""


class LabRepository:
    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _identifier("tenant_id", tenant_id, 64)
        self.actor_user_id = _identifier("actor_user_id", actor_user_id, 64)
        self.correlation_id = _identifier("correlation_id", correlation_id, 100)

    async def register_bundle(
        self, manifest: LabBundleManifest, *, occurred_at: datetime,
    ) -> dict[str, object]:
        _aware(occurred_at)
        await self._context(); await self._lock(f"lab-bundle:{manifest.bundle_id}:{manifest.revision}")
        table = metadata.tables["lab_bundles"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.bundle_id == manifest.bundle_id,
            table.c.bundle_revision == manifest.revision,
        ))).mappings().one_or_none()
        manifest_json = _manifest_json(manifest)
        if existing is not None:
            if existing["manifest"] != manifest_json:
                raise LabRepositoryConflict("lab_bundle_revision_immutable")
            return dict(existing)
        row = {
            "id": f"lab-bundle-{uuid4().hex}", "tenant_id": self.tenant_id,
            "bundle_id": manifest.bundle_id, "bundle_revision": manifest.revision,
            "fixture_digest": manifest.fixture_digest,
            "seed_manifest_sha256": manifest.seed_manifest_sha256,
            "network_id": manifest.network_id, "manifest": manifest_json,
            "bundle_state": "active", "activated_at": occurred_at,
            "expires_at": manifest.expires_at, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("lab.bundle.registered", manifest.bundle_id, {
            "revision": manifest.revision, "fixture_digest": manifest.fixture_digest,
        }, occurred_at)
        return row

    async def attest_target(
        self, attestation: LabTargetAttestation, *, occurred_at: datetime,
    ) -> dict[str, object]:
        if attestation.tenant_id != self.tenant_id:
            raise LabRepositoryConflict("lab_target_tenant_mismatch")
        _aware(occurred_at)
        await self._context(); await self._lock(f"lab-attestation:{attestation.attestation_id}")
        bundles = metadata.tables["lab_bundles"]
        bundle = (await self.session.execute(select(bundles).where(
            bundles.c.tenant_id == self.tenant_id,
            bundles.c.bundle_id == attestation.bundle_id,
            bundles.c.fixture_digest == attestation.bundle_digest,
            bundles.c.bundle_state == "active",
        ))).mappings().one_or_none()
        if bundle is None:
            raise LabRepositoryConflict("lab_bundle_active_required")
        table = metadata.tables["lab_target_attestations"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id,
            table.c.attestation_id == attestation.attestation_id,
        ))).mappings().one_or_none()
        if existing is not None:
            if existing["attestation_sha256"] != attestation.canonical_sha256:
                raise LabRepositoryConflict("lab_target_attestation_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"lab-attestation-{uuid4().hex}", "tenant_id": self.tenant_id,
            "bundle_record_id": bundle["id"], "attestation_id": attestation.attestation_id,
            "target_id": attestation.target_id, "fixture_kind": attestation.fixture_kind.value,
            "endpoint": attestation.endpoint, "network_id": attestation.network_id,
            "allowed_test_classes": [item.value for item in attestation.allowed_test_classes],
            "expected_finding_manifest_sha256": attestation.expected_finding_manifest_sha256,
            "attestation_sha256": attestation.canonical_sha256,
            "non_production": True, "attestation_state": "active",
            "issued_at": attestation.issued_at, "expires_at": attestation.expires_at,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("lab.target.attested", attestation.target_id, {
            "attestation_id": attestation.attestation_id,
            "attestation_sha256": attestation.canonical_sha256,
        }, occurred_at)
        return row

    async def issue_target_lease(
        self, lease: LabTargetLease, *, occurred_at: datetime,
    ) -> dict[str, object]:
        if lease.tenant_id != self.tenant_id:
            raise LabRepositoryConflict("lab_target_lease_tenant_mismatch")
        _aware(occurred_at)
        await self._context(); await self._lock(f"lab-lease:{lease.lease_id}")
        attestations = metadata.tables["lab_target_attestations"]
        attestation = (await self.session.execute(select(attestations).where(
            attestations.c.tenant_id == self.tenant_id,
            attestations.c.target_id == lease.target_id,
            attestations.c.attestation_sha256 == lease.attestation_sha256,
            attestations.c.attestation_state == "active",
        ))).mappings().one_or_none()
        if attestation is None:
            raise LabRepositoryConflict("lab_target_attestation_active_required")
        table = metadata.tables["lab_target_leases"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.lease_id == lease.lease_id,
        ))).mappings().one_or_none()
        identity = _lease_identity(lease)
        if existing is not None:
            if tuple(existing[key] for key in identity) != tuple(identity.values()):
                raise LabRepositoryConflict("lab_target_lease_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"lab-lease-{uuid4().hex}", "tenant_id": self.tenant_id,
            "attestation_record_id": attestation["id"], "lease_id": lease.lease_id,
            **identity, "lease_state": "active", "issued_at": lease.issued_at,
            "expires_at": lease.expires_at, "revoked_at": None,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("lab.target.lease_issued", lease.target_id, {
            "lease_id": lease.lease_id, "test_class": lease.test_class.value,
        }, occurred_at)
        return row

    async def register_golden_expectation(
        self, *, bundle_id: str, expectation_id: str, fixture_kind: FixtureKind,
        finding: dict[str, str], evidence_class: str, expectation_sha256: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        bundle_key = _identifier("bundle_id", bundle_id, 100)
        expectation_key = _identifier("expectation_id", expectation_id, 100)
        if not isinstance(fixture_kind, FixtureKind):
            raise LabRepositoryConflict("golden_fixture_kind_invalid")
        if evidence_class not in {"sanitized_metadata", "redacted_evidence"}:
            raise LabRepositoryConflict("golden_evidence_class_invalid")
        _sha(expectation_sha256); _aware(occurred_at)
        required = (
            "tool", "rule_id", "tool_version", "database_version", "title", "severity",
            "confidence", "affected_resource", "fingerprint",
        )
        if any(not isinstance(finding.get(name), str) or not finding[name] for name in required):
            raise LabRepositoryConflict("golden_finding_contract_invalid")
        _sha(finding["fingerprint"])
        await self._context(); await self._lock(f"golden-expectation:{expectation_key}")
        bundles = metadata.tables["lab_bundles"]
        bundle = (await self.session.execute(select(bundles).where(
            bundles.c.tenant_id == self.tenant_id, bundles.c.bundle_id == bundle_key,
            bundles.c.bundle_state == "active",
        ))).mappings().one_or_none()
        if bundle is None:
            raise LabRepositoryConflict("lab_bundle_active_required")
        table = metadata.tables["golden_finding_expectations"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.expectation_id == expectation_key,
        ))).mappings().one_or_none()
        identity = {
            "bundle_record_id": bundle["id"], "expectation_id": expectation_key,
            "fixture_kind": fixture_kind.value, "tool": finding["tool"],
            "rule_id": finding["rule_id"], "tool_version": finding["tool_version"],
            "database_version": finding["database_version"], "title": finding["title"],
            "severity": finding["severity"], "confidence": finding["confidence"],
            "resource_id": finding["affected_resource"], "evidence_class": evidence_class,
            "fingerprint": finding["fingerprint"], "expectation_sha256": expectation_sha256,
        }
        if existing is not None:
            if any(existing[name] != value for name, value in identity.items()):
                raise LabRepositoryConflict("golden_expectation_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"golden-expectation-{uuid4().hex}", "tenant_id": self.tenant_id,
            **identity, "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("lab.golden_expectation.registered", expectation_key, {
            "fixture_kind": fixture_kind.value, "fingerprint": finding["fingerprint"],
        }, occurred_at)
        return row

    async def authorize_target(self, request: TargetAccessRequest):
        await self._context()
        leases = metadata.tables["lab_target_leases"]
        lease_row = (await self.session.execute(select(leases).where(
            leases.c.tenant_id == self.tenant_id, leases.c.target_id == request.target_id,
            leases.c.runner_id == request.runner_id,
            leases.c.test_class == request.test_class.value,
            leases.c.lease_state == "active",
        ).order_by(leases.c.issued_at.desc()).limit(1))).mappings().one_or_none()
        if lease_row is None:
            raise LabRepositoryConflict("lab_target_lease_active_required")
        attestations = metadata.tables["lab_target_attestations"]
        attestation_row = (await self.session.execute(select(attestations).where(
            attestations.c.tenant_id == self.tenant_id,
            attestations.c.id == lease_row["attestation_record_id"],
        ))).mappings().one()
        bundles = metadata.tables["lab_bundles"]
        bundle_row = (await self.session.execute(select(bundles).where(
            bundles.c.tenant_id == self.tenant_id,
            bundles.c.id == attestation_row["bundle_record_id"],
        ))).mappings().one()
        try:
            return authorize_target_access(
                manifest=_manifest(bundle_row), attestation=_attestation(attestation_row, bundle_row),
                lease=_lease(lease_row), request=request,
            )
        except ValueError as exc:
            raise LabRepositoryConflict(str(exc)) from exc

    async def start_scenario(
        self, *, run_id: str, scenario_id: str, bundle_id: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run = _identifier("run_id", run_id, 100); bundle_key = _identifier("bundle_id", bundle_id, 100)
        if scenario_id not in REQUIRED_GOLDEN_SCENARIOS:
            raise LabRepositoryConflict("scenario_id_unknown")
        _aware(occurred_at)
        await self._context(); await self._lock(f"scenario:{run}:{scenario_id}")
        bundles = metadata.tables["lab_bundles"]
        bundle = (await self.session.execute(select(bundles).where(
            bundles.c.tenant_id == self.tenant_id, bundles.c.bundle_id == bundle_key,
            bundles.c.bundle_state == "active",
        ))).mappings().one_or_none()
        if bundle is None:
            raise LabRepositoryConflict("lab_bundle_active_required")
        table = metadata.tables["golden_scenario_runs"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.run_id == run,
            table.c.scenario_id == scenario_id,
        ))).mappings().one_or_none()
        if existing is not None:
            return dict(existing)
        row = {
            "id": f"scenario-run-{uuid4().hex}", "tenant_id": self.tenant_id,
            "bundle_record_id": bundle["id"], "run_id": run, "scenario_id": scenario_id,
            "scenario_state": ScenarioStatus.RUNNING.value, "current_step": 1,
            "last_action_id": f"start:{run}:{scenario_id}"[:100],
            "reason_code": "scenario_started", "started_at": occurred_at,
            "completed_at": None, "version": 2,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("lab.scenario.started", run, {"scenario_id": scenario_id}, occurred_at)
        return row

    async def transition_scenario(
        self, *, run_id: str, scenario_id: str, action_id: str, expected_version: int,
        next_status: ScenarioStatus, reason_code: str, occurred_at: datetime,
    ) -> dict[str, object]:
        run = _identifier("run_id", run_id, 100); action = _identifier("action_id", action_id, 100)
        _aware(occurred_at)
        await self._context(); await self._lock(f"scenario:{run}:{scenario_id}")
        table = metadata.tables["golden_scenario_runs"]
        row = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.run_id == run,
            table.c.scenario_id == scenario_id,
        ).with_for_update())).mappings().one_or_none()
        if row is None:
            raise LabRepositoryConflict("scenario_run_not_found")
        try:
            state = advance_scenario(
                _scenario_state(row), action_id=action, expected_version=expected_version,
                next_status=next_status, reason_code=reason_code,
            )
        except ValueError as exc:
            raise LabRepositoryConflict(str(exc)) from exc
        if state.version == row["version"]:
            return dict(row)
        values = {
            "scenario_state": state.status.value, "current_step": state.current_step,
            "last_action_id": state.last_action_id, "reason_code": state.reason_code,
            "completed_at": occurred_at if state.status in {ScenarioStatus.SUCCEEDED, ScenarioStatus.FAILED, ScenarioStatus.CLEANED} else None,
            "version": state.version, "updated_at": occurred_at,
        }
        await self.session.execute(update(table).where(table.c.id == row["id"]).values(**values))
        await self._audit(f"lab.scenario.{state.status.value}", run, {
            "scenario_id": scenario_id, "version": state.version,
        }, occurred_at)
        return {**dict(row), **values}

    async def record_step(
        self, *, run_id: str, scenario_id: str, step_id: str, action_id: str,
        step_name: str, step_state: str, request_sha256: str, receipt_sha256: str,
        request_count: int, contact_count: int, reason_code: str, occurred_at: datetime,
    ) -> dict[str, object]:
        action = _identifier("action_id", action_id, 100)
        for value in (request_sha256, receipt_sha256): _sha(value)
        if step_state not in {"passed", "failed", "blocked"}:
            raise LabRepositoryConflict("scenario_step_state_invalid")
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in (request_count, contact_count)):
            raise LabRepositoryConflict("scenario_step_counts_invalid")
        _aware(occurred_at); await self._context(); await self._lock(f"scenario-step:{action}")
        runs = metadata.tables["golden_scenario_runs"]
        run = (await self.session.execute(select(runs).where(
            runs.c.tenant_id == self.tenant_id, runs.c.run_id == run_id,
            runs.c.scenario_id == scenario_id,
        ))).mappings().one_or_none()
        if run is None:
            raise LabRepositoryConflict("scenario_run_not_found")
        table = metadata.tables["golden_scenario_steps"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.action_id == action,
        ))).mappings().one_or_none()
        identity = (step_id, step_name, step_state, request_sha256, receipt_sha256, request_count, contact_count, reason_code)
        if existing is not None:
            if tuple(existing[key] for key in (
                "step_id", "step_name", "step_state", "request_sha256", "receipt_sha256",
                "request_count", "contact_count", "reason_code",
            )) != identity:
                raise LabRepositoryConflict("scenario_step_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"scenario-step-{uuid4().hex}", "tenant_id": self.tenant_id,
            "scenario_run_record_id": run["id"], "step_id": step_id, "action_id": action,
            "step_name": step_name, "step_state": step_state,
            "request_sha256": request_sha256, "receipt_sha256": receipt_sha256,
            "request_count": request_count, "contact_count": contact_count,
            "reason_code": reason_code, "occurred_at": occurred_at,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        return row

    async def record_teardown(
        self, *, run_id: str, scenario_id: str, receipt_id: str,
        container_count: int, network_count: int, volume_count: int,
        residual_resource_count: int, inventory_sha256: str, occurred_at: datetime,
    ) -> dict[str, object]:
        receipt = _identifier("receipt_id", receipt_id, 100); _sha(inventory_sha256); _aware(occurred_at)
        counts = (container_count, network_count, volume_count, residual_resource_count)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise LabRepositoryConflict("lab_teardown_counts_invalid")
        await self._context(); await self._lock(f"lab-teardown:{receipt}")
        runs = metadata.tables["golden_scenario_runs"]
        run = (await self.session.execute(select(runs).where(
            runs.c.tenant_id == self.tenant_id, runs.c.run_id == run_id,
            runs.c.scenario_id == scenario_id,
        ))).mappings().one_or_none()
        if run is None:
            raise LabRepositoryConflict("scenario_run_not_found")
        table = metadata.tables["lab_teardown_receipts"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.receipt_id == receipt,
        ))).mappings().one_or_none()
        complete = residual_resource_count == 0
        if existing is not None:
            if existing["inventory_sha256"] != inventory_sha256 or existing["teardown_complete"] != complete:
                raise LabRepositoryConflict("lab_teardown_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"lab-teardown-{uuid4().hex}", "tenant_id": self.tenant_id,
            "scenario_run_record_id": run["id"], "receipt_id": receipt,
            "container_count": container_count, "network_count": network_count,
            "volume_count": volume_count, "residual_resource_count": residual_resource_count,
            "teardown_complete": complete, "inventory_sha256": inventory_sha256,
            "completed_at": occurred_at, "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("lab.teardown.recorded", run_id, {
            "receipt_id": receipt, "teardown_complete": complete,
            "residual_resource_count": residual_resource_count,
        }, occurred_at)
        return row

    async def record_measurement(
        self, *, run_id: str, scenario_id: str, measurement_id: str,
        measurement: QualificationMeasurement, artifact_sha256: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        key = _identifier("measurement_id", measurement_id, 100)
        _sha(artifact_sha256); _aware(occurred_at)
        await self._context(); await self._lock(f"lab-measurement:{key}")
        run = await self._run_record(run_id, scenario_id)
        table = metadata.tables["qualification_measurements"]
        receipt = measurement.receipt()
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.measurement_id == key,
        ))).mappings().one_or_none()
        if existing is not None:
            compared = (*receipt.values(), artifact_sha256)
            keys = (*receipt.keys(), "artifact_sha256")
            if tuple(existing[name] for name in keys) != compared:
                raise LabRepositoryConflict("qualification_measurement_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"lab-measurement-{uuid4().hex}", "tenant_id": self.tenant_id,
            "scenario_run_record_id": run["id"], "measurement_id": key, **receipt,
            "artifact_sha256": artifact_sha256, "measured_at": occurred_at,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("lab.measurement.recorded", key, {
            "metric_id": measurement.metric_id, "result_state": receipt["result_state"],
        }, occurred_at)
        return row

    async def record_backup_restore(
        self, *, run_id: str, scenario_id: str, receipt_id: str,
        source_inventory_sha256: str, restored_inventory_sha256: str,
        source_schema_revision: str, restored_schema_revision: str,
        source_row_count: int, restored_row_count: int,
        source_object_count: int, restored_object_count: int,
        occurred_at: datetime,
    ) -> dict[str, object]:
        key = _identifier("receipt_id", receipt_id, 100)
        for value in (source_inventory_sha256, restored_inventory_sha256): _sha(value)
        for value in (source_schema_revision, restored_schema_revision): _identifier("schema_revision", value, 32)
        counts = (source_row_count, restored_row_count, source_object_count, restored_object_count)
        if any(not isinstance(value, int) or isinstance(value, bool) or value < 0 for value in counts):
            raise LabRepositoryConflict("lab_restore_counts_invalid")
        _aware(occurred_at); await self._context(); await self._lock(f"lab-restore:{key}")
        run = await self._run_record(run_id, scenario_id)
        state = "passed" if (
            source_inventory_sha256 == restored_inventory_sha256
            and source_schema_revision == restored_schema_revision
            and source_row_count == restored_row_count
            and source_object_count == restored_object_count
        ) else "failed"
        table = metadata.tables["lab_backup_restore_receipts"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.receipt_id == key,
        ))).mappings().one_or_none()
        identity = (
            source_inventory_sha256, restored_inventory_sha256,
            source_schema_revision, restored_schema_revision,
            source_row_count, restored_row_count, source_object_count, restored_object_count, state,
        )
        identity_keys = (
            "source_inventory_sha256", "restored_inventory_sha256",
            "source_schema_revision", "restored_schema_revision",
            "source_row_count", "restored_row_count", "source_object_count", "restored_object_count",
            "restore_state",
        )
        if existing is not None:
            if tuple(existing[name] for name in identity_keys) != identity:
                raise LabRepositoryConflict("lab_restore_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"lab-restore-{uuid4().hex}", "tenant_id": self.tenant_id,
            "scenario_run_record_id": run["id"], "receipt_id": key,
            **dict(zip(identity_keys, identity, strict=True)), "completed_at": occurred_at,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._audit("lab.restore.recorded", key, {"restore_state": state}, occurred_at)
        return row

    async def dashboard(self) -> dict[str, object]:
        await self._context()
        bundles = (await self.session.execute(select(metadata.tables["lab_bundles"]).where(
            metadata.tables["lab_bundles"].c.tenant_id == self.tenant_id,
        ).order_by(metadata.tables["lab_bundles"].c.created_at.desc()).limit(1))).mappings().all()
        runs = (await self.session.execute(select(metadata.tables["golden_scenario_runs"]).where(
            metadata.tables["golden_scenario_runs"].c.tenant_id == self.tenant_id,
        ).order_by(metadata.tables["golden_scenario_runs"].c.created_at.desc()).limit(100))).mappings().all()
        measurements = (await self.session.execute(select(metadata.tables["qualification_measurements"]).where(
            metadata.tables["qualification_measurements"].c.tenant_id == self.tenant_id,
        ).order_by(metadata.tables["qualification_measurements"].c.created_at.desc()).limit(100))).mappings().all()
        teardowns = (await self.session.execute(select(metadata.tables["lab_teardown_receipts"]).where(
            metadata.tables["lab_teardown_receipts"].c.tenant_id == self.tenant_id,
        ).order_by(metadata.tables["lab_teardown_receipts"].c.created_at.desc()).limit(1))).mappings().all()
        return {
            "bundle": dict(bundles[0]) if bundles else None,
            "scenarios": [dict(row) for row in runs],
            "measurements": [dict(row) for row in measurements],
            "latest_teardown": dict(teardowns[0]) if teardowns else None,
        }

    async def _run_record(self, run_id: str, scenario_id: str):
        table = metadata.tables["golden_scenario_runs"]
        row = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.run_id == run_id,
            table.c.scenario_id == scenario_id,
        ))).mappings().one_or_none()
        if row is None:
            raise LabRepositoryConflict("scenario_run_not_found")
        return row

    async def _context(self) -> None:
        await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {"scope": f"{self.tenant_id}:{scope}"})

    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, action=event, subject_type="lab",
            subject_id=subject[:64], correlation_id=self.correlation_id, details=details,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", tenant_id=self.tenant_id,
            event_type=event, aggregate_id=subject[:64], payload=details, published=False,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))


def _manifest_json(manifest: LabBundleManifest) -> dict[str, object]:
    return {
        "schema": manifest.schema, "bundle_id": manifest.bundle_id, "revision": manifest.revision,
        "fixture_digest": manifest.fixture_digest,
        "seed_manifest_sha256": manifest.seed_manifest_sha256,
        "fixture_kinds": [item.value for item in manifest.fixture_kinds],
        "allowed_test_classes": [item.value for item in manifest.allowed_test_classes],
        "network_id": manifest.network_id, "non_production": manifest.non_production,
        "created_at": manifest.created_at.isoformat(), "expires_at": manifest.expires_at.isoformat(),
    }


def _manifest(row) -> LabBundleManifest:
    value = row["manifest"]
    return LabBundleManifest(
        schema=value["schema"], bundle_id=value["bundle_id"], revision=value["revision"],
        fixture_digest=value["fixture_digest"], seed_manifest_sha256=value["seed_manifest_sha256"],
        fixture_kinds=tuple(FixtureKind(item) for item in value["fixture_kinds"]),
        allowed_test_classes=tuple(TestClass(item) for item in value["allowed_test_classes"]),
        network_id=value["network_id"], non_production=value["non_production"],
        created_at=datetime.fromisoformat(value["created_at"]),
        expires_at=datetime.fromisoformat(value["expires_at"]),
    )


def _attestation(row, bundle) -> LabTargetAttestation:
    return LabTargetAttestation(
        attestation_id=row["attestation_id"], tenant_id=row["tenant_id"],
        target_id=row["target_id"], bundle_id=bundle["bundle_id"],
        bundle_digest=bundle["fixture_digest"], fixture_kind=FixtureKind(row["fixture_kind"]),
        endpoint=row["endpoint"], network_id=row["network_id"],
        allowed_test_classes=tuple(TestClass(item) for item in row["allowed_test_classes"]),
        expected_finding_manifest_sha256=row["expected_finding_manifest_sha256"],
        non_production=row["non_production"], issued_at=row["issued_at"], expires_at=row["expires_at"],
    )


def _lease(row) -> LabTargetLease:
    return LabTargetLease(
        lease_id=row["lease_id"], tenant_id=row["tenant_id"], target_id=row["target_id"],
        attestation_sha256=row["attestation_sha256"], runner_id=row["runner_id"],
        test_class=TestClass(row["test_class"]), endpoint=row["endpoint"],
        issued_at=row["issued_at"], expires_at=row["expires_at"],
        policy_reference=row["policy_reference"], roe_version_id=row["roe_version_id"],
    )


def _lease_identity(lease: LabTargetLease) -> dict[str, object]:
    return {
        "target_id": lease.target_id, "runner_id": lease.runner_id,
        "test_class": lease.test_class.value, "endpoint": lease.endpoint,
        "attestation_sha256": lease.attestation_sha256,
        "policy_reference": lease.policy_reference, "roe_version_id": lease.roe_version_id,
    }


def _scenario_state(row) -> ScenarioState:
    return ScenarioState(
        run_id=row["run_id"], scenario_id=row["scenario_id"],
        status=ScenarioStatus(row["scenario_state"]), current_step=row["current_step"],
        version=row["version"], last_action_id=row["last_action_id"], reason_code=row["reason_code"],
    )


def _identifier(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not all(
        char.isalnum() or char in "._:-" for char in value
    ):
        raise LabRepositoryConflict(f"lab_{name}_invalid")
    return value


def _sha(value: object) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise LabRepositoryConflict("lab_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise LabRepositoryConflict("lab_time_invalid")
