"""PostgreSQL-authoritative compat_107 scope, plan, run, result, and cleanup truth."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.network_service.compiler import CompiledNetworkPlan
from redagent_platform.network_service.connector import NetworkExecutionResult
from redagent_platform.network_service.contracts import (
    NetworkAuthorization,
    NetworkTargetBinding,
    certified_profiles,
)
from redagent_platform.persistence.models import metadata


class NetworkRepositoryConflict(RuntimeError):
    """Stable compat_107 persistence or revalidation denial."""


class NetworkRepository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        self.session = session
        self.tenant_id = _identifier("tenant_id", tenant_id, 64)
        self.actor_user_id = _identifier("actor_user_id", actor_user_id, 64)
        self.correlation_id = _identifier("correlation_id", correlation_id, 100)

    async def certify_foundation(
        self,
        *,
        artifact_sha256: str,
        sbom_sha256: str,
        license_review_sha256: str,
        vulnerability_review: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        for digest in (artifact_sha256, sbom_sha256, license_review_sha256):
            _sha(digest)
        _aware(occurred_at)
        await self._context()
        await self._lock("network-foundation")
        engine = await self._immutable(
            "network_engine_artifacts",
            {"engine_id": "redagent-stdlib-tcp-connect", "artifact_sha256": artifact_sha256},
            {
                "engine_id": "redagent-stdlib-tcp-connect",
                "engine_version": "1.0.0",
                "artifact_sha256": artifact_sha256,
                "sbom_sha256": sbom_sha256,
                "license_review_sha256": license_review_sha256,
                "vulnerability_review": _identifier("vulnerability_review", vulnerability_review, 64),
                "production_qualified": False,
                "artifact_state": "certified-local-lab",
            },
            occurred_at,
            "engine",
        )
        for adapter_id, version, source, license_id in (
            ("nmap", "7.99", "https://nmap.org/", "NPSL"),
            ("naabu", "2.5.0", "https://github.com/projectdiscovery/naabu", "MIT"),
        ):
            await self._immutable(
                "network_adapter_declarations",
                {"adapter_id": adapter_id, "adapter_version": version},
                {
                    "adapter_id": adapter_id,
                    "adapter_version": version,
                    "source_url": source,
                    "license_id": license_id,
                    "execution_enabled": False,
                    "capabilities": {
                        "execution": "disabled",
                        "native_arguments": False,
                        "scripts": False,
                        "raw_socket": False,
                    },
                    "declaration_state": "reference-only",
                },
                occurred_at,
                "adapter",
            )
        profile = next(iter(certified_profiles().values()))
        profile_material = asdict(profile)
        profile_material["profile_id"] = profile.profile_id.value
        row = await self._immutable(
            "network_profiles",
            {"profile_id": profile.profile_id.value, "profile_revision": 1},
            {
                "profile_id": profile.profile_id.value,
                "profile_revision": 1,
                "engine_record_id": engine["id"],
                "profile_sha256": _canonical_sha(profile_material),
                "category": "low-risk-connect-discovery",
                "limits": {
                    "targets": profile.max_targets,
                    "ports_per_target": profile.max_ports_per_target,
                    "attempts": profile.max_attempts,
                    "rate": profile.rate_per_second,
                    "concurrency": profile.concurrency,
                    "retries": profile.max_retries,
                    "connect_time": profile.connect_timeout_seconds,
                    "run_time": profile.run_timeout_seconds,
                    "banner_bytes": profile.banner_bytes,
                    "output_bytes": profile.output_bytes,
                },
                "enabled": True,
                "profile_state": "certified-local-lab",
            },
            occurred_at,
            "profile",
        )
        await self._audit("network.foundation.certified", str(row["profile_id"]), {
            "artifact_sha256": artifact_sha256,
            "profile_sha256": row["profile_sha256"],
            "production_qualified": False,
            "external_execution_enabled": False,
        }, occurred_at)
        return row

    async def register_target_binding(
        self,
        *,
        topology_id: str,
        target: NetworkTargetBinding,
        occurred_at: datetime,
    ) -> dict[str, object]:
        topology_key = _identifier("topology_id", topology_id, 100)
        _aware(occurred_at)
        await self._context()
        await self._lock(f"network-target:{target.target_set_id}")
        topology = await self._immutable(
            "network_topology_attestations",
            {"topology_id": topology_key, "topology_sha256": target.topology_sha256},
            {
                "topology_id": topology_key,
                "topology_sha256": target.topology_sha256,
                "route_sha256": target.route_sha256,
                "network_id": target.network_id,
                "non_production": target.non_production,
                "no_public_route": True,
                "no_direct_target_route": True,
                "expires_at": target.expires_at,
            },
            occurred_at,
            "topology",
        )
        material = {
            "targets": sorted(target.literal_targets),
            "ports": sorted(target.allowed_ports),
            "protocol": target.protocol.value,
            "topology_sha256": target.topology_sha256,
            "route_sha256": target.route_sha256,
        }
        row = await self._immutable(
            "network_target_sets",
            {"target_set_id": target.target_set_id, "target_set_sha256": _canonical_sha(material)},
            {
                "target_set_id": target.target_set_id,
                "topology_record_id": topology["id"],
                "target_set_sha256": _canonical_sha(material),
                "literal_targets": sorted(target.literal_targets),
                "allowed_ports": sorted(target.allowed_ports),
                "protocol": target.protocol.value,
                "target_set_state": "active-local-lab",
            },
            occurred_at,
            "target-set",
        )
        await self._audit("network.target.attested", target.target_set_id, {
            "topology_sha256": target.topology_sha256,
            "target_set_sha256": row["target_set_sha256"],
        }, occurred_at)
        return row

    async def store_plan(
        self,
        *,
        plan_id: str,
        compiled: CompiledNetworkPlan,
        target: NetworkTargetBinding,
        authorization: NetworkAuthorization,
        occurred_at: datetime,
    ) -> dict[str, object]:
        key = _identifier("plan_id", plan_id, 100)
        _aware(occurred_at)
        await self._context()
        await self._lock(f"network-plan:{key}")
        profile = await self._find("network_profiles", {
            "profile_id": compiled.profile_id.value, "profile_revision": 1,
        })
        targets = metadata.tables["network_target_sets"]
        topologies = metadata.tables["network_topology_attestations"]
        target_row = (await self.session.execute(
            select(targets).join(topologies, targets.c.topology_record_id == topologies.c.id).where(
                targets.c.tenant_id == self.tenant_id,
                targets.c.target_set_id == target.target_set_id,
                targets.c.target_set_state == "active-local-lab",
                topologies.c.tenant_id == self.tenant_id,
                topologies.c.topology_sha256 == target.topology_sha256,
                topologies.c.route_sha256 == target.route_sha256,
                topologies.c.network_id == "redagent-r107-gateway-target",
                topologies.c.non_production.is_(True),
                topologies.c.no_public_route.is_(True),
                topologies.c.no_direct_target_route.is_(True),
                topologies.c.expires_at > occurred_at,
            )
        )).mappings().one_or_none()
        if profile is None or not profile["enabled"] or profile["profile_state"] != "certified-local-lab":
            raise NetworkRepositoryConflict("network_certified_profile_required")
        if target_row is None:
            raise NetworkRepositoryConflict("network_target_revalidation_required")
        if compiled.topology_sha256 != authorization.topology_sha256:
            raise NetworkRepositoryConflict("network_policy_revalidation_required")
        row = await self._immutable(
            "network_plans",
            {"plan_id": key},
            {
                "plan_id": key,
                "profile_record_id": profile["id"],
                "target_set_record_id": target_row["id"],
                "policy_decision_id": authorization.policy_decision_id,
                "policy_revision": authorization.policy_revision,
                "roe_version_id": authorization.roe_version_id,
                "reservation_id": authorization.reservation_id,
                "plan_sha256": compiled.plan_sha256,
                "budgets": {
                    "targets": compiled.target_count,
                    "ports": compiled.port_count,
                    "attempts": compiled.attempt_limit,
                    "rate": compiled.rate_per_second,
                    "concurrency": compiled.concurrency,
                    "retries": compiled.retry_limit,
                    "connect_time": compiled.connect_timeout_seconds,
                    "run_time": compiled.run_timeout_seconds,
                    "banner_bytes": compiled.banner_bytes,
                    "output_bytes": compiled.output_bytes,
                },
                "plan_state": "compiled-local-lab",
                "expires_at": min(authorization.expires_at, target.expires_at),
            },
            occurred_at,
            "plan",
        )
        for item in compiled.tuples:
            await self._immutable(
                "network_plan_tuples",
                {"plan_record_id": row["id"], "tuple_id": item.tuple_id},
                {
                    "plan_record_id": row["id"],
                    "tuple_id": item.tuple_id,
                    "literal_ip": item.ip,
                    "port": item.port,
                    "protocol": item.protocol.value,
                    "tuple_sha256": _canonical_sha(asdict(item)),
                    "tuple_state": "compiled",
                },
                occurred_at,
                "tuple",
            )
        await self._audit("network.plan.compiled", key, {
            "plan_sha256": compiled.plan_sha256,
            "tuple_count": len(compiled.tuples),
        }, occurred_at)
        return row

    async def create_run(
        self,
        *,
        run_id: str,
        plan_id: str,
        job_id: str,
        runner_id: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        run_key = _identifier("run_id", run_id, 100)
        plan_key = _identifier("plan_id", plan_id, 100)
        job_key = _identifier("job_id", job_id, 100)
        runner_key = _identifier("runner_id", runner_id, 100)
        _aware(occurred_at)
        await self._context()
        await self._lock(f"network-run:{run_key}")
        existing = await self._find("network_runs", {"run_id": run_key})
        if existing is not None:
            if existing["job_id"] != job_key or existing["runner_id"] != runner_key:
                raise NetworkRepositoryConflict("network_run_replay_mismatch")
            return existing
        plans = metadata.tables["network_plans"]
        plan = (await self.session.execute(select(plans).where(
            plans.c.tenant_id == self.tenant_id,
            plans.c.plan_id == plan_key,
            plans.c.plan_state == "compiled-local-lab",
            plans.c.expires_at > occurred_at,
        ))).mappings().one_or_none()
        if plan is None:
            raise NetworkRepositoryConflict("network_plan_active_required")
        profiles = metadata.tables["network_profiles"]
        profile = (await self.session.execute(select(profiles).where(
            profiles.c.tenant_id == self.tenant_id,
            profiles.c.id == plan["profile_record_id"],
            profiles.c.enabled.is_(True),
            profiles.c.profile_state == "certified-local-lab",
        ))).mappings().one_or_none()
        targets = metadata.tables["network_target_sets"]
        topologies = metadata.tables["network_topology_attestations"]
        target = (await self.session.execute(select(targets.c.id).join(
            topologies, targets.c.topology_record_id == topologies.c.id,
        ).where(
            targets.c.tenant_id == self.tenant_id,
            targets.c.id == plan["target_set_record_id"],
            targets.c.target_set_state == "active-local-lab",
            topologies.c.tenant_id == self.tenant_id,
            topologies.c.network_id == "redagent-r107-gateway-target",
            topologies.c.non_production.is_(True),
            topologies.c.no_public_route.is_(True),
            topologies.c.no_direct_target_route.is_(True),
            topologies.c.expires_at > occurred_at,
        ))).one_or_none()
        decisions = metadata.tables["policy_decisions"]
        decision = (await self.session.execute(select(decisions.c.id).where(
            decisions.c.tenant_id == self.tenant_id,
            decisions.c.opa_decision_id == plan["policy_decision_id"],
            decisions.c.bundle_revision == plan["policy_revision"],
            decisions.c.action == "network.plan.compile",
            decisions.c.resource_type == "network_profile",
            decisions.c.resource_id == "tcp-connect-discovery-v1",
            decisions.c.allowed.is_(True),
            decisions.c.valid_until > occurred_at,
        ))).one_or_none()
        roes = metadata.tables["roe_versions"]
        roe = (await self.session.execute(select(roes.c.id).where(
            roes.c.tenant_id == self.tenant_id,
            roes.c.id == plan["roe_version_id"],
            roes.c.status == "approved",
        ))).one_or_none()
        reservations = metadata.tables["quota_reservations"]
        reservation = (await self.session.execute(select(reservations.c.id).where(
            reservations.c.tenant_id == self.tenant_id,
            reservations.c.reservation_id == plan["reservation_id"],
            reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
            reservations.c.expires_at > occurred_at,
        ))).one_or_none()
        if profile is None:
            raise NetworkRepositoryConflict("network_profile_revalidation_required")
        if target is None:
            raise NetworkRepositoryConflict("network_target_revalidation_required")
        if decision is None or roe is None:
            raise NetworkRepositoryConflict("network_policy_revalidation_required")
        if reservation is None:
            raise NetworkRepositoryConflict("network_quota_revalidation_required")
        tuples = metadata.tables["network_plan_tuples"]
        tuple_rows = (await self.session.execute(select(tuples.c.id).where(
            tuples.c.tenant_id == self.tenant_id,
            tuples.c.plan_record_id == plan["id"],
            tuples.c.tuple_state == "compiled",
        ))).all()
        tuple_count = len(tuple_rows)
        if tuple_count < 1:
            raise NetworkRepositoryConflict("network_plan_tuple_inventory_required")
        jobs = metadata.tables["jobs"]
        job = (await self.session.execute(select(jobs).where(
            jobs.c.tenant_id == self.tenant_id, jobs.c.id == job_key,
        ))).mappings().one_or_none()
        registrations = metadata.tables["runner_registrations"]
        runner = (await self.session.execute(select(registrations).where(
            registrations.c.tenant_id == self.tenant_id,
            registrations.c.runner_id == runner_key,
            registrations.c.registration_state == "active",
            registrations.c.expires_at > occurred_at,
        ).order_by(registrations.c.generation.desc()).limit(1))).mappings().one_or_none()
        if job is None or not isinstance(job["request"], dict) or job["request"].get("capability") != "network-assessment":
            raise NetworkRepositoryConflict("network_job_capability_required")
        from redagent_platform.network_service.capability import WORKER_IMAGE_DIGEST

        if (
            runner is None
            or runner["required_policy_revision"] != plan["policy_revision"]
            or "redagent-tcp-connect:1.0.0-r107.1" not in runner["adapter_allowlist"]
            or WORKER_IMAGE_DIGEST not in runner["image_allowlist"]
        ):
            raise NetworkRepositoryConflict("network_runner_registration_required")
        row = {
            "id": f"network-run-{uuid4().hex}",
            "tenant_id": self.tenant_id,
            "run_id": run_key,
            "plan_record_id": plan["id"],
            "job_id": job_key,
            "runner_id": runner_key,
            "run_state": "dispatch_pending",
            "completed_tuples": 0,
            "total_tuples": tuple_count,
            "partial": False,
            "reason_code": "network_run_accepted",
            "version": 1,
            "created_at": occurred_at,
            "updated_at": occurred_at,
        }
        await self.session.execute(insert(metadata.tables["network_runs"]).values(**row))
        await self._audit("network.run.accepted", run_key, {
            "plan_id": plan_key, "tuple_count": tuple_count,
        }, occurred_at)
        return row

    async def record_execution(
        self,
        *,
        run_id: str,
        result: NetworkExecutionResult,
        occurred_at: datetime,
        evidence_instance_ids: dict[str, str] | None = None,
    ) -> dict[str, object]:
        run = await self._active_run(run_id)
        if result.run_id != run_id:
            raise NetworkRepositoryConflict("network_execution_run_mismatch")
        plan = metadata.tables["network_plans"]
        plan_sha = (await self.session.execute(select(plan.c.plan_sha256).where(
            plan.c.tenant_id == self.tenant_id, plan.c.id == run["plan_record_id"],
        ))).scalar_one()
        if result.plan_sha256 != plan_sha:
            raise NetworkRepositoryConflict("network_execution_plan_mismatch")
        evidence_by_tuple = evidence_instance_ids or {}
        if any(tuple_id not in {item.tuple_id for item in result.observations} for tuple_id in evidence_by_tuple):
            raise NetworkRepositoryConflict("network_evidence_tuple_unknown")
        for evidence_id in evidence_by_tuple.values():
            _identifier("evidence_instance_id", evidence_id, 100)
        for index, observation in enumerate(result.observations, start=1):
            await self._immutable(
                "network_gateway_decisions",
                {"decision_id": f"{run_id}:gateway:{index}"},
                {
                    "run_record_id": run["id"],
                    "decision_id": f"{run_id}:gateway:{index}",
                    "tuple_id": observation.tuple_id,
                    "allowed": observation.state.value != "denied",
                    "reason_code": observation.reason,
                    "attempt_count": index,
                    "data_bytes": 0,
                    "occurred_at": occurred_at,
                },
                occurred_at,
                "decision",
            )
            await self._immutable(
                "network_observations",
                {"observation_id": f"{run_id}:observation:{index}"},
                {
                    "run_record_id": run["id"],
                    "observation_id": f"{run_id}:observation:{index}",
                    "tuple_id": observation.tuple_id,
                    "connection_state": observation.state.value,
                    "latency_bucket": observation.latency_bucket,
                    "service_class": observation.service_class,
                    "sample_sha256": observation.sample_sha256,
                    "uncertainty": observation.uncertainty,
                    "redaction_state": "redacted-hash-only",
                    "evidence_instance_id": evidence_by_tuple.get(observation.tuple_id),
                },
                occurred_at,
                "observation",
            )
        if result.cancellation is not None:
            await self._immutable(
                "network_cancellation_receipts",
                {"receipt_id": f"{run_id}:cancellation"},
                {
                    "run_record_id": run["id"],
                    "receipt_id": f"{run_id}:cancellation",
                    "gateway_blocked": result.cancellation.gateway_blocked,
                    "worker_stop_attempted": True,
                    "worker_stop_acknowledged": result.cancellation.worker_stop_acknowledged,
                    "forced_termination": result.cancellation.forced_termination,
                    "completed_at": occurred_at,
                },
                occurred_at,
                "cancellation",
            )
        cleanup = await self._immutable(
            "network_cleanup_receipts",
            {"receipt_id": f"{run_id}:cleanup"},
            {
                "run_record_id": run["id"],
                "receipt_id": f"{run_id}:cleanup",
                "container_count": 0,
                "network_count": 0,
                "transient_file_count": 0,
                "residual_resource_count": result.cleanup.residual_resource_count,
                "inventory_sha256": _canonical_sha({"run_id": run_id, "residual": 0}),
                "completed_at": occurred_at,
            },
            occurred_at,
            "cleanup",
        )
        if result.cleanup.residual_resource_count != 0 or not result.cleanup.transient_data_erased:
            state, reason = "cleanup_failed", "network_cleanup_incomplete"
        elif result.cancelled:
            state, reason = "cancelled", "network_cancelled_clean"
        else:
            state, reason = "succeeded", "network_run_complete"
        values = {
            "run_state": state,
            "completed_tuples": result.completed_count,
            "partial": result.partial,
            "reason_code": reason,
            "version": int(run["version"]) + 1,
            "updated_at": occurred_at,
        }
        await self.session.execute(update(metadata.tables["network_runs"]).where(
            metadata.tables["network_runs"].c.id == run["id"],
        ).values(**values))
        await self._audit("network.run.completed", run_id, {
            "state": state, "partial": result.partial,
            "completed": result.completed_count,
            "denied": result.denied_count,
            "residual": cleanup["residual_resource_count"],
        }, occurred_at)
        return {**run, **values}

    async def request_cancel(
        self,
        *,
        run_id: str,
        expected_version: int,
        occurred_at: datetime,
    ) -> dict[str, object]:
        run = await self._active_run(run_id)
        if run["run_state"] in {"cancelled", "succeeded", "failed", "cleanup_failed"}:
            return run
        if run["version"] != expected_version:
            raise NetworkRepositoryConflict("network_run_version_conflict")
        values = {
            "run_state": "cancel_requested",
            "reason_code": "network_gateway_block_required",
            "version": int(run["version"]) + 1,
            "updated_at": occurred_at,
        }
        await self.session.execute(update(metadata.tables["network_runs"]).where(
            metadata.tables["network_runs"].c.id == run["id"],
        ).values(**values))
        await self._audit("network.run.cancel_requested", run_id, {
            "gateway_block_first": True,
        }, occurred_at)
        return {**run, **values}

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context()
        result: dict[str, list[dict[str, object]]] = {}
        for key, table_name in (
            ("profiles", "network_profiles"),
            ("plans", "network_plans"),
            ("runs", "network_runs"),
            ("decisions", "network_gateway_decisions"),
            ("observations", "network_observations"),
            ("cleanups", "network_cleanup_receipts"),
        ):
            table = metadata.tables[table_name]
            rows = (await self.session.execute(select(table).where(
                table.c.tenant_id == self.tenant_id,
            ).order_by(table.c.created_at.desc()).limit(100))).mappings().all()
            result[key] = [dict(row) for row in rows]
        targets = metadata.tables["network_target_sets"]
        topologies = metadata.tables["network_topology_attestations"]
        target_rows = (await self.session.execute(select(
            targets.c.target_set_id, targets.c.target_set_state,
            topologies.c.non_production, topologies.c.no_public_route,
            topologies.c.no_direct_target_route, topologies.c.expires_at,
        ).join(topologies, targets.c.topology_record_id == topologies.c.id).where(
            targets.c.tenant_id == self.tenant_id,
            targets.c.target_set_id == "r107-local-fixture",
            topologies.c.tenant_id == self.tenant_id,
            topologies.c.network_id == "redagent-r107-gateway-target",
        ).order_by(topologies.c.created_at.desc()).limit(100))).mappings().all()
        registrations = metadata.tables["runner_registrations"]
        runner_rows = (await self.session.execute(select(registrations).where(
            registrations.c.tenant_id == self.tenant_id,
        ).order_by(registrations.c.last_seen_at.desc()).limit(100))).mappings().all()
        jobs = metadata.tables["jobs"]
        job_rows = (await self.session.execute(select(jobs).where(
            jobs.c.tenant_id == self.tenant_id,
        ).order_by(jobs.c.created_at.desc()).limit(100))).mappings().all()
        reservations = metadata.tables["quota_reservations"]
        reservation_rows = (await self.session.execute(select(reservations).where(
            reservations.c.tenant_id == self.tenant_id,
            reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
        ).order_by(reservations.c.created_at.desc()).limit(100))).mappings().all()
        from redagent_platform.network_service.capability import WORKER_IMAGE_DIGEST

        # CRITICAL: option visibility is read-only; mutation handlers still revalidate every binding.
        result["target_options"] = [dict(row) for row in target_rows]
        result["runner_options"] = [dict(row) for row in runner_rows if (
            "redagent-tcp-connect:1.0.0-r107.1" in row["adapter_allowlist"]
            and WORKER_IMAGE_DIGEST in row["image_allowlist"]
        )]
        result["job_options"] = [dict(row) for row in job_rows if (
            isinstance(row["request"], dict) and row["request"].get("capability") == "network-assessment"
        )]
        result["reservation_options"] = [dict(row) for row in reservation_rows]
        return result

    async def _active_run(self, run_id: str) -> dict[str, object]:
        key = _identifier("run_id", run_id, 100)
        await self._context()
        await self._lock(f"network-run:{key}")
        row = await self._find("network_runs", {"run_id": key})
        if row is None:
            raise NetworkRepositoryConflict("network_run_not_found")
        return row

    async def _immutable(
        self,
        table_name: str,
        where: dict[str, object],
        values: dict[str, object],
        occurred_at: datetime,
        prefix: str,
    ) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing is not None:
            if any(existing[name] != value for name, value in values.items()):
                raise NetworkRepositoryConflict(f"network_{prefix}_immutable")
            return existing
        row = {
            "id": f"network-{prefix}-{uuid4().hex}",
            "tenant_id": self.tenant_id,
            **values,
            "version": 1,
            "created_at": occurred_at,
            "updated_at": occurred_at,
        }
        await self.session.execute(insert(metadata.tables[table_name]).values(**row))
        return row

    async def _find(self, table_name: str, where: dict[str, object]) -> dict[str, object] | None:
        table = metadata.tables[table_name]
        conditions = [table.c.tenant_id == self.tenant_id]
        conditions.extend(getattr(table.c, name) == value for name, value in where.items())
        row = (await self.session.execute(select(table).where(*conditions))).mappings().one_or_none()
        return None if row is None else dict(row)

    async def _context(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
            {"tenant": self.tenant_id},
        )

    async def _lock(self, scope: str) -> None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": f"{self.tenant_id}:{scope}"},
        )

    async def _audit(
        self,
        event: str,
        subject: str,
        details: dict[str, object],
        occurred_at: datetime,
    ) -> None:
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, action=event, subject_type="network_assessment",
            subject_id=subject[:64], correlation_id=self.correlation_id, details=details,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", tenant_id=self.tenant_id, event_type=event,
            aggregate_id=subject[:64], payload=details, published=False,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))


def _identifier(name: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not all(
        char.isalnum() or char in "._:-" for char in value
    ):
        raise NetworkRepositoryConflict(f"network_{name}_invalid")
    return value


def _sha(value: object) -> None:
    if not isinstance(value, str) or len(value) != 64 or any(char not in "0123456789abcdef" for char in value):
        raise NetworkRepositoryConflict("network_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise NetworkRepositoryConflict("network_time_invalid")


def _canonical_sha(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    ).hexdigest()
