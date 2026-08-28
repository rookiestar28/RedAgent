"""Tenant-scoped, transaction-neutral repositories for the compat_093 control plane."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.campaign_service.registry import closed_execution_binding_for
from redagent_platform.orchestration.contracts import (
    ActivityCommand,
    ActivityResult,
    CampaignActivityResult,
    CampaignWorkflowInput,
    CommandAction,
    CONTRACT_SCHEMA_VERSION,
    JobSnapshot,
    JobWorkflowInput,
    OperatorCommand,
    WorkflowState,
    deterministic_job_workflow_id,
)
from redagent_platform.orchestration.state import CommandRejected, LifecycleReducer
from redagent_platform.persistence.models import JobStatus, assert_job_transition, compute_issue_fingerprint, metadata


class IdempotencyConflict(RuntimeError):
    pass


class ConcurrencyConflict(RuntimeError):
    pass


class RecordConflict(RuntimeError):
    pass


class ActivityAuthorizationError(RuntimeError):
    """A durable Activity failed current actor, policy, ROE, or scope authorization."""


@dataclass(frozen=True)
class MutationResult:
    resource: dict[str, object]
    replayed: bool
    audit_id: str
    outbox_id: str


class ControlPlaneRepository:
    def __init__(
        self,
        session: AsyncSession,
        *,
        tenant_id: str,
        actor_user_id: str,
        correlation_id: str,
    ) -> None:
        self.session = session
        self.tenant_id = _required("tenant_id", tenant_id, 64)
        self.actor_user_id = _required("actor_user_id", actor_user_id, 64)
        self.correlation_id = _required("correlation_id", correlation_id, 100)

    async def bootstrap_tenant(self, *, name: str, occurred_at: datetime) -> None:
        _time(occurred_at)
        table = metadata.tables["tenants"]
        existing = await self.session.scalar(select(table.c.id).where(table.c.id == self.tenant_id))
        if existing is None:
            await self.session.execute(
                insert(table).values(
                    id=self.tenant_id,
                    name=_required("tenant_name", name, 200),
                    version=1,
                    created_at=occurred_at,
                    updated_at=occurred_at,
                )
            )

    async def bootstrap_user(self, *, user_id: str, subject: str, occurred_at: datetime) -> dict[str, object]:
        await self._tenant_context()
        _time(occurred_at)
        table = metadata.tables["users"]
        normalized_id = _required("user_id", user_id, 64)
        normalized_subject = _required("subject", subject, 200)
        row = (
            await self.session.execute(
                select(table).where(table.c.tenant_id == self.tenant_id, table.c.id == normalized_id)
            )
        ).mappings().one_or_none()
        if row is not None:
            if row["subject"] != normalized_subject:
                raise RecordConflict("user_subject_conflict")
            return _public_user(row)
        await self.session.execute(
            insert(table).values(
                id=normalized_id,
                tenant_id=self.tenant_id,
                subject=normalized_subject,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return {
            "user_id": normalized_id,
            "tenant_id": self.tenant_id,
            "subject": normalized_subject,
            "version": 1,
        }

    async def create_engagement(
        self,
        *,
        engagement_id: str,
        name: str,
        owner_user_id: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        request = {
            "engagement_id": _required("engagement_id", engagement_id, 64),
            "name": _required("engagement_name", name, 200),
            "owner_user_id": _required("owner_user_id", owner_user_id, 64),
        }
        operation = "engagement:create"
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay:
            return replay
        engagements = metadata.tables["engagements"]
        existing = await self.session.scalar(
            select(engagements.c.id).where(
                engagements.c.tenant_id == self.tenant_id,
                engagements.c.id == request["engagement_id"],
            )
        )
        if existing:
            raise RecordConflict("engagement_already_exists")
        resource = {**request, "tenant_id": self.tenant_id, "version": 1}
        await self.session.execute(
            insert(engagements).values(
                id=request["engagement_id"],
                tenant_id=self.tenant_id,
                name=request["name"],
                owner_user_id=request["owner_user_id"],
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            subject_type="engagement",
            subject_id=engagement_id,
            event_type="engagement.created",
            occurred_at=occurred_at,
        )

    async def get_engagement(self, engagement_id: str) -> dict[str, object] | None:
        await self._tenant_context()
        table = metadata.tables["engagements"]
        row = (
            await self.session.execute(
                select(table).where(table.c.tenant_id == self.tenant_id, table.c.id == engagement_id)
            )
        ).mappings().one_or_none()
        return _public_engagement(row) if row else None

    async def list_engagements(
        self,
        *,
        limit: int,
        offset: int,
        name_prefix: str | None = None,
    ) -> list[dict[str, object]]:
        await self._tenant_context()
        _pagination(limit, offset)
        table = metadata.tables["engagements"]
        statement = select(table).where(table.c.tenant_id == self.tenant_id)
        if name_prefix is not None:
            statement = statement.where(table.c.name.startswith(_required("name_prefix", name_prefix, 100), autoescape=True))
        rows = (
            await self.session.execute(
                statement.order_by(table.c.created_at, table.c.id).limit(limit).offset(offset)
            )
        ).mappings().all()
        return [_public_engagement(row) for row in rows]

    async def update_engagement(
        self,
        *,
        engagement_id: str,
        expected_version: int,
        name: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        request = {
            "engagement_id": _required("engagement_id", engagement_id, 64),
            "expected_version": _version(expected_version),
            "name": _required("engagement_name", name, 200),
        }
        operation = f"engagement:update:{request['engagement_id']}"
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay:
            return replay
        table = metadata.tables["engagements"]
        statement = (
            update(table)
            .where(
                table.c.tenant_id == self.tenant_id,
                table.c.id == request["engagement_id"],
                table.c.version == request["expected_version"],
            )
            .values(name=request["name"], version=table.c.version + 1, updated_at=occurred_at)
            .returning(table)
        )
        row = (await self.session.execute(statement)).mappings().one_or_none()
        if row is None:
            raise ConcurrencyConflict("engagement_version_conflict")
        resource = _public_engagement(row)
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            subject_type="engagement",
            subject_id=str(request["engagement_id"]),
            event_type="engagement.updated",
            occurred_at=occurred_at,
            response_status=200,
        )

    async def create_target(
        self,
        *,
        target_id: str,
        engagement_id: str,
        target_type: str,
        normalized_value: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        request = {
            "target_id": _required("target_id", target_id, 64),
            "engagement_id": _required("engagement_id", engagement_id, 64),
            "target_type": _required("target_type", target_type, 32),
            "normalized_value": _required("normalized_value", normalized_value, 500),
        }
        operation = f"target:create:{request['engagement_id']}"
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay:
            return replay
        await self._require_engagement(str(request["engagement_id"]))
        table = metadata.tables["targets"]
        resource = {**request, "tenant_id": self.tenant_id, "version": 1}
        await self.session.execute(
            insert(table).values(
                id=request["target_id"],
                tenant_id=self.tenant_id,
                engagement_id=request["engagement_id"],
                target_type=request["target_type"],
                normalized_value=request["normalized_value"],
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            subject_type="target",
            subject_id=str(request["target_id"]),
            event_type="target.created",
            occurred_at=occurred_at,
        )

    async def list_targets(self, engagement_id: str, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._tenant_context()
        _pagination(limit, offset)
        table = metadata.tables["targets"]
        rows = (
            await self.session.execute(
                select(table)
                .where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.engagement_id == _required("engagement_id", engagement_id, 64),
                )
                .order_by(table.c.created_at, table.c.id)
                .limit(limit)
                .offset(offset)
            )
        ).mappings().all()
        return [_public_target(row) for row in rows]

    async def create_roe_version(
        self,
        *,
        roe_version_id: str,
        engagement_id: str,
        revision: int,
        document: dict[str, object],
        policy_reference_id: str,
        policy_name: str,
        policy_version: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        request = {
            "roe_version_id": _required("roe_version_id", roe_version_id, 64),
            "engagement_id": _required("engagement_id", engagement_id, 64),
            "revision": _version(revision),
            "document": _json_object("roe_document", document),
            "policy_reference_id": _required("policy_reference_id", policy_reference_id, 64),
            "policy_name": _required("policy_name", policy_name, 200),
            "policy_version": _required("policy_version", policy_version, 100),
        }
        operation = f"roe:create:{request['engagement_id']}"
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay:
            return replay
        await self._require_engagement(str(request["engagement_id"]))
        roe = metadata.tables["roe_versions"]
        policies = metadata.tables["policy_references"]
        resource = {
            "roe_version_id": request["roe_version_id"],
            "engagement_id": request["engagement_id"],
            "revision": request["revision"],
            "status": "draft",
            "document": request["document"],
            "policy_reference": {
                "policy_reference_id": request["policy_reference_id"],
                "policy_name": request["policy_name"],
                "policy_version": request["policy_version"],
            },
            "tenant_id": self.tenant_id,
            "version": 1,
        }
        await self.session.execute(
            insert(roe).values(
                id=request["roe_version_id"],
                tenant_id=self.tenant_id,
                engagement_id=request["engagement_id"],
                revision=request["revision"],
                status="draft",
                document=request["document"],
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self.session.execute(
            insert(policies).values(
                id=request["policy_reference_id"],
                tenant_id=self.tenant_id,
                roe_version_id=request["roe_version_id"],
                policy_name=request["policy_name"],
                policy_version=request["policy_version"],
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            subject_type="roe_version",
            subject_id=str(request["roe_version_id"]),
            event_type="roe.created",
            occurred_at=occurred_at,
        )

    async def list_roe_versions(self, engagement_id: str, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._tenant_context()
        _pagination(limit, offset)
        table = metadata.tables["roe_versions"]
        rows = (
            await self.session.execute(
                select(table)
                .where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.engagement_id == _required("engagement_id", engagement_id, 64),
                )
                .order_by(table.c.revision, table.c.id)
                .limit(limit)
                .offset(offset)
            )
        ).mappings().all()
        return [_public_roe(row) for row in rows]

    async def approve_roe_version(
        self,
        *,
        roe_version_id: str,
        approval_id: str,
        expected_version: int,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        request = {
            "roe_version_id": _required("roe_version_id", roe_version_id, 64),
            "approval_id": _required("approval_id", approval_id, 64),
            "expected_version": _version(expected_version),
        }
        operation = f"roe:approve:{request['roe_version_id']}"
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay:
            return replay
        table = metadata.tables["roe_versions"]
        current = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == request["roe_version_id"],
                )
            )
        ).mappings().one_or_none()
        if current is None or current["version"] != request["expected_version"]:
            raise ConcurrencyConflict("roe_version_conflict")
        if current["status"] != "draft":
            raise RecordConflict("roe_not_approvable")
        row = (
            await self.session.execute(
                update(table)
                .where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == request["roe_version_id"],
                    table.c.version == request["expected_version"],
                )
                .values(status="approved", version=table.c.version + 1, updated_at=occurred_at)
                .returning(table)
            )
        ).mappings().one_or_none()
        if row is None:
            raise ConcurrencyConflict("roe_version_conflict")
        approvals = metadata.tables["approvals"]
        await self.session.execute(
            insert(approvals).values(
                id=request["approval_id"],
                tenant_id=self.tenant_id,
                roe_version_id=request["roe_version_id"],
                approved_by_user_id=self.actor_user_id,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        resource = _public_roe(row)
        resource["approval_id"] = request["approval_id"]
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            subject_type="roe_version",
            subject_id=str(request["roe_version_id"]),
            event_type="roe.approved",
            occurred_at=occurred_at,
            response_status=200,
        )

    async def create_campaign(
        self,
        *,
        campaign_id: str,
        engagement_id: str,
        roe_version_id: str,
        name: str,
        jobs: list[dict[str, object]],
        workflow_id: str,
        policy_reference: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        if not isinstance(jobs, list) or not 1 <= len(jobs) <= 100:
            raise ValueError("campaign_jobs_invalid")
        normalized_jobs: list[tuple[str, dict[str, object]]] = []
        for item in jobs:
            if not isinstance(item, dict) or set(item) != {"job_id", "request"}:
                raise ValueError("campaign_job_invalid")
            normalized_jobs.append(
                (
                    _required("job_id", str(item["job_id"]), 64),
                    _workflow_request(item["request"]),  # type: ignore[arg-type]
                )
            )
        if len({job_id for job_id, _ in normalized_jobs}) != len(normalized_jobs):
            raise ValueError("campaign_job_ids_must_be_unique")
        request = {
            "campaign_id": _required("campaign_id", campaign_id, 64),
            "engagement_id": _required("engagement_id", engagement_id, 64),
            "roe_version_id": _required("roe_version_id", roe_version_id, 64),
            "name": _required("campaign_name", name, 200),
            "jobs": [{"job_id": job_id, "request": job_request} for job_id, job_request in normalized_jobs],
            "workflow_id": _required("workflow_id", workflow_id, 64),
            "policy_reference": _required("policy_reference", policy_reference, 100),
        }
        operation = "campaign:create"
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay:
            return replay
        await self._require_engagement(str(request["engagement_id"]))
        await self._require_approved_roe(str(request["engagement_id"]), str(request["roe_version_id"]))
        campaigns = metadata.tables["campaigns"]
        await self.session.execute(
            insert(campaigns).values(
                id=request["campaign_id"],
                tenant_id=self.tenant_id,
                engagement_id=request["engagement_id"],
                roe_version_id=request["roe_version_id"],
                name=request["name"],
                status="dispatch_pending",
                workflow_id=request["workflow_id"],
                workflow_run_id=None,
                orchestration_revision=1,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        job_table = metadata.tables["jobs"]
        for job_id, job_request in normalized_jobs:
            await self.session.execute(
                insert(job_table).values(
                    id=job_id,
                    tenant_id=self.tenant_id,
                    engagement_id=request["engagement_id"],
                    roe_version_id=request["roe_version_id"],
                    created_by_user_id=self.actor_user_id,
                    campaign_id=request["campaign_id"],
                    status=JobStatus.PENDING.value,
                    request=job_request,
                    policy_reference=request["policy_reference"],
                    workflow_id=deterministic_job_workflow_id(self.tenant_id, job_id),
                    workflow_run_id=None,
                    orchestration_state=WorkflowState.DISPATCH_PENDING.value,
                    orchestration_revision=1,
                    current_gate="campaign_child_dispatch_pending",
                    failure_code=None,
                    retry_count=0,
                    dispatch_blocked=True,
                    stop_requested=False,
                    version=1,
                    created_at=occurred_at,
                    updated_at=occurred_at,
                )
            )
        resource = {
            "campaign_id": request["campaign_id"],
            "tenant_id": self.tenant_id,
            "engagement_id": request["engagement_id"],
            "roe_version_id": request["roe_version_id"],
            "name": request["name"],
            "status": "dispatch_pending",
            "workflow_id": request["workflow_id"],
            "workflow_run_id": None,
            "orchestration_revision": 1,
            "version": 1,
        }
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            subject_type="campaign",
            subject_id=str(request["campaign_id"]),
            event_type="campaign.created",
            occurred_at=occurred_at,
        )

    async def get_campaign(self, campaign_id: str) -> dict[str, object] | None:
        await self._tenant_context()
        table = metadata.tables["campaigns"]
        row = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == _required("campaign_id", campaign_id, 64),
                )
            )
        ).mappings().one_or_none()
        return _public_campaign(row) if row else None

    async def list_campaigns(self, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._tenant_context()
        _pagination(limit, offset)
        table = metadata.tables["campaigns"]
        rows = (
            await self.session.execute(
                select(table)
                .where(table.c.tenant_id == self.tenant_id)
                .order_by(table.c.created_at, table.c.id)
                .limit(limit)
                .offset(offset)
            )
        ).mappings().all()
        return [_public_campaign(row) for row in rows]

    async def record_campaign_workflow_run(
        self,
        *,
        campaign_id: str,
        workflow_id: str,
        workflow_run_id: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        await self._tenant_context()
        _time(occurred_at)
        table = metadata.tables["campaigns"]
        row = (
            await self.session.execute(
                update(table)
                .where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == _required("campaign_id", campaign_id, 64),
                    table.c.workflow_id == _required("workflow_id", workflow_id, 64),
                )
                .values(
                    workflow_run_id=_required("workflow_run_id", workflow_run_id, 64),
                    status="children_started",
                    orchestration_revision=table.c.orchestration_revision + 1,
                    version=table.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(table)
            )
        ).mappings().one_or_none()
        if row is None:
            raise ConcurrencyConflict("campaign_workflow_conflict")
        return _public_campaign(row)

    async def create_job(
        self,
        *,
        job_id: str,
        engagement_id: str,
        roe_version_id: str,
        request: dict[str, object],
        workflow_id: str,
        policy_reference: str,
        campaign_id: str | None,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        normalized = {
            "job_id": _required("job_id", job_id, 64),
            "engagement_id": _required("engagement_id", engagement_id, 64),
            "roe_version_id": _required("roe_version_id", roe_version_id, 64),
            "request": _workflow_request(request),
            "workflow_id": _required("workflow_id", workflow_id, 64),
            "policy_reference": _required("policy_reference", policy_reference, 100),
            "campaign_id": _required("campaign_id", campaign_id, 64) if campaign_id else None,
        }
        operation = "job:create"
        replay = await self._idempotency_replay(operation, idempotency_key, normalized)
        if replay:
            return replay
        await self._require_engagement(str(normalized["engagement_id"]))
        await self._require_approved_roe(str(normalized["engagement_id"]), str(normalized["roe_version_id"]))
        if normalized["campaign_id"] is not None:
            campaigns = metadata.tables["campaigns"]
            if await self.session.scalar(
                select(campaigns.c.id).where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == normalized["campaign_id"],
                    campaigns.c.engagement_id == normalized["engagement_id"],
                )
            ) is None:
                raise RecordConflict("campaign_not_found")
        table = metadata.tables["jobs"]
        resource = {
            **normalized,
            "created_by_user_id": self.actor_user_id,
            "status": JobStatus.PENDING.value,
            "tenant_id": self.tenant_id,
            "workflow_run_id": None,
            "orchestration_state": WorkflowState.DISPATCH_PENDING.value,
            "orchestration_revision": 1,
            "current_gate": "temporal_dispatch_pending",
            "failure_code": None,
            "retry_count": 0,
            "dispatch_blocked": True,
            "stop_requested": False,
            "version": 1,
        }
        await self.session.execute(
            insert(table).values(
                id=normalized["job_id"],
                tenant_id=self.tenant_id,
                engagement_id=normalized["engagement_id"],
                roe_version_id=normalized["roe_version_id"],
                created_by_user_id=self.actor_user_id,
                campaign_id=normalized["campaign_id"],
                status=JobStatus.PENDING.value,
                request=normalized["request"],
                policy_reference=normalized["policy_reference"],
                workflow_id=normalized["workflow_id"],
                workflow_run_id=None,
                orchestration_state=WorkflowState.DISPATCH_PENDING.value,
                orchestration_revision=1,
                current_gate="temporal_dispatch_pending",
                failure_code=None,
                retry_count=0,
                dispatch_blocked=True,
                stop_requested=False,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=normalized,
            resource=resource,
            subject_type="job",
            subject_id=str(normalized["job_id"]),
            event_type="job.created",
            occurred_at=occurred_at,
        )

    async def create_runner_job(
        self,
        *,
        campaign_id: str,
        strategy_revision_id: str,
        effect_id: str,
        claim_owner: str,
        capability_id: str,
        envelope_sha256: str,
        occurred_at: datetime,
    ) -> MutationResult:
        """Create the exact claimed-effect job without widening the legacy public schema."""
        await self._tenant_context()
        _time(occurred_at)
        normalized_campaign = _required("campaign_id", campaign_id, 64)
        normalized_strategy = _required(
            "strategy_revision_id", strategy_revision_id, 100
        )
        normalized_effect = _required("effect_id", effect_id, 100)
        normalized_owner = _required("claim_owner", claim_owner, 100)
        if capability_id not in {
            "zap-controlled-runtime", "nuclei-trusted-runtime",
        }:
            raise ValueError("r123_runner_job_capability_denied")
        if (
            not isinstance(envelope_sha256, str)
            or len(envelope_sha256) != 64
            or any(character not in "0123456789abcdef" for character in envelope_sha256)
        ):
            raise ValueError("r123_runner_job_envelope_invalid")
        campaigns = metadata.tables["campaigns"]
        strategies = metadata.tables["campaign_strategy_revisions"]
        effects = metadata.tables["campaign_effects"]
        authority = (
            await self.session.execute(
                select(
                    campaigns.c.engagement_id,
                    campaigns.c.roe_version_id,
                    strategies.c.id.label("strategy_record_id"),
                )
                .select_from(
                    campaigns.join(
                        strategies,
                        strategies.c.id == campaigns.c.current_strategy_revision_id,
                    ).join(
                        effects,
                        effects.c.strategy_revision_id == strategies.c.id,
                    )
                )
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == normalized_campaign,
                    campaigns.c.status != "completed",
                    strategies.c.strategy_revision_id == normalized_strategy,
                    effects.c.effect_id == normalized_effect,
                    effects.c.campaign_id == normalized_campaign,
                    effects.c.effect_state == "claimed",
                    effects.c.claim_owner == normalized_owner,
                    effects.c.claim_expires_at > occurred_at,
                    effects.c.envelope_sha256 == envelope_sha256,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if authority is None:
            raise RecordConflict("r123_runner_job_effect_claim_mismatch")
        effect_payload = await self.session.scalar(
            select(effects.c.effect_intent_payload).where(
                effects.c.tenant_id == self.tenant_id,
                effects.c.effect_id == normalized_effect,
            )
        )
        try:
            expected_capability = closed_execution_binding_for(capability_id).capability_key
        except ValueError as exc:
            raise RecordConflict("r123_runner_job_capability_mismatch") from exc
        if not isinstance(effect_payload, dict) or effect_payload.get(
            "capability_id"
        ) != expected_capability:
            raise RecordConflict("r123_runner_job_capability_mismatch")
        stable = hashlib.sha256(
            f"{self.tenant_id}\0{normalized_campaign}\0{normalized_effect}".encode("utf-8")
        ).hexdigest()[:32]
        job_id = f"job-r123-{stable}"
        workflow_id = f"redagent-r123-effect-{stable}"
        idempotency_key = f"r123-runner-job-{stable}"
        request = {
            "schema_version": "redagent.r123-runner-job/v1",
            "capability_id": capability_id,
            "strategy_revision_id": normalized_strategy,
            "effect_id": normalized_effect,
            "envelope_sha256": envelope_sha256,
        }
        operation = "job:r123:create"
        normalized = {
            "job_id": job_id,
            "campaign_id": normalized_campaign,
            "engagement_id": str(authority["engagement_id"]),
            "roe_version_id": str(authority["roe_version_id"]),
            "request": request,
            "workflow_id": workflow_id,
            "policy_reference": "policy:r123-current-authority",
        }
        replay = await self._idempotency_replay(
            operation, idempotency_key, normalized
        )
        if replay is not None:
            return replay
        resource = {
            **normalized,
            "created_by_user_id": self.actor_user_id,
            "status": "approved",
            "workflow_run_id": None,
            "orchestration_state": WorkflowState.READY.value,
            "orchestration_revision": 1,
            "current_gate": "runner_dispatch",
            "failure_code": None,
            "retry_count": 0,
            "dispatch_blocked": False,
            "stop_requested": False,
            "tenant_id": self.tenant_id,
            "version": 1,
        }
        jobs = metadata.tables["jobs"]
        await self.session.execute(
            insert(jobs).values(
                id=job_id,
                tenant_id=self.tenant_id,
                engagement_id=authority["engagement_id"],
                roe_version_id=authority["roe_version_id"],
                created_by_user_id=self.actor_user_id,
                campaign_id=normalized_campaign,
                status="approved",
                request=request,
                policy_reference="policy:r123-current-authority",
                workflow_id=workflow_id,
                workflow_run_id=None,
                orchestration_state=WorkflowState.READY.value,
                orchestration_revision=1,
                current_gate="runner_dispatch",
                failure_code=None,
                retry_count=0,
                dispatch_blocked=False,
                stop_requested=False,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=normalized,
            resource=resource,
            subject_type="job",
            subject_id=job_id,
            event_type="r123.runner.job.created",
            occurred_at=occurred_at,
        )

    async def get_job(self, job_id: str) -> dict[str, object] | None:
        await self._tenant_context()
        table = metadata.tables["jobs"]
        row = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == _required("job_id", job_id, 64),
                )
            )
        ).mappings().one_or_none()
        return _public_job(row) if row else None

    async def list_jobs(self, *, limit: int, offset: int) -> list[dict[str, object]]:
        await self._tenant_context()
        _pagination(limit, offset)
        table = metadata.tables["jobs"]
        rows = (
            await self.session.execute(
                select(table)
                .where(table.c.tenant_id == self.tenant_id)
                .order_by(table.c.created_at, table.c.id)
                .limit(limit)
                .offset(offset)
            )
        ).mappings().all()
        return [_public_job(row) for row in rows]

    async def admit_workflow_job(
        self,
        request: JobWorkflowInput,
        *,
        workflow_run_id: str,
        occurred_at: datetime,
    ) -> ActivityResult:
        await self._tenant_context()
        _time(occurred_at)
        if request.tenant_id != self.tenant_id:
            raise ActivityAuthorizationError("workflow_tenant_mismatch")
        jobs = metadata.tables["jobs"]
        row = (
            await self.session.execute(
                select(jobs).where(jobs.c.tenant_id == self.tenant_id, jobs.c.id == request.job_id)
            )
        ).mappings().one_or_none()
        if row is None:
            raise RecordConflict("job_not_found")
        expected_workflow_id = deterministic_job_workflow_id(self.tenant_id, request.job_id)
        if (
            row["workflow_id"] != expected_workflow_id
            or row["engagement_id"] != request.engagement_id
            or row["roe_version_id"] != request.roe_version_id
            or row["policy_reference"] != request.policy_reference
            or row["version"] != request.expected_job_version
            or row["orchestration_state"] != WorkflowState.DISPATCH_PENDING.value
        ):
            raise ActivityAuthorizationError("workflow_admission_context_mismatch")
        await self._require_approved_roe(request.engagement_id, request.roe_version_id)
        updated = (
            await self.session.execute(
                update(jobs)
                .where(
                    jobs.c.tenant_id == self.tenant_id,
                    jobs.c.id == request.job_id,
                    jobs.c.version == request.expected_job_version,
                    jobs.c.orchestration_revision == 1,
                )
                .values(
                    workflow_run_id=_required("workflow_run_id", workflow_run_id, 64),
                    orchestration_state=WorkflowState.AWAITING_APPROVAL.value,
                    orchestration_revision=2,
                    current_gate="operator_approval_required",
                    version=jobs.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(jobs)
            )
        ).mappings().one_or_none()
        if updated is None:
            raise ConcurrencyConflict("workflow_admission_conflict")
        await self._record_workflow_event(
            action="workflow.job.admitted",
            subject_id=request.job_id,
            event_type="workflow.job.admitted",
            state=WorkflowState.AWAITING_APPROVAL.value,
            revision=2,
            occurred_at=occurred_at,
        )
        return ActivityResult(CONTRACT_SCHEMA_VERSION, request.job_id, "admission", WorkflowState.AWAITING_APPROVAL.value, 2, False)

    async def apply_workflow_command(
        self,
        command: ActivityCommand,
        *,
        occurred_at: datetime,
    ) -> ActivityResult:
        await self._tenant_context()
        _time(occurred_at)
        if command.tenant_id != self.tenant_id or command.actor_user_id != self.actor_user_id:
            raise ActivityAuthorizationError("workflow_actor_context_mismatch")
        commands = metadata.tables["workflow_commands"]
        existing_command = (
            await self.session.execute(
                select(commands).where(
                    commands.c.tenant_id == self.tenant_id,
                    commands.c.job_id == command.job_id,
                    commands.c.command_id == command.command_id,
                )
            )
        ).mappings().one_or_none()
        if existing_command is not None:
            if existing_command["request_hash"] != command.request_hash:
                raise IdempotencyConflict("workflow_command_id_mismatch")
            return ActivityResult(
                CONTRACT_SCHEMA_VERSION,
                command.job_id,
                command.command_id,
                str(existing_command["state"]),
                int(existing_command["result_revision"]),
                True,
            )
        jobs = metadata.tables["jobs"]
        row = (
            await self.session.execute(
                select(jobs).where(jobs.c.tenant_id == self.tenant_id, jobs.c.id == command.job_id)
            )
        ).mappings().one_or_none()
        if row is None:
            raise RecordConflict("job_not_found")
        if row["policy_reference"] != command.policy_reference:
            raise ActivityAuthorizationError("workflow_policy_reference_mismatch")
        await self._require_approved_roe(str(row["engagement_id"]), str(row["roe_version_id"]))
        await self._authorize_workflow_actor(command, row)
        snapshot = _job_snapshot(row)
        if command.expected_revision != snapshot.revision:
            raise ConcurrencyConflict("workflow_revision_conflict")
        reducer = LifecycleReducer.from_snapshot(snapshot)
        if command.action == "emergency_stop":
            next_snapshot = reducer.request_stop(command.command_id)
        elif command.action == "dispatch_started":
            if command.actor_user_id != "redagent-workflow":
                raise ActivityAuthorizationError("workflow_system_actor_required")
            next_snapshot = reducer.begin_dispatch()
        elif command.action in {
            "containment_completed", "containment_completed_with_residual_risk", "containment_failed",
        }:
            if command.actor_user_id != "redagent-workflow":
                raise ActivityAuthorizationError("workflow_system_actor_required")
            outcomes = {
                "containment_completed": "contained",
                "containment_completed_with_residual_risk": "contained_with_residual_risk",
                "containment_failed": "containment_failed",
            }
            next_snapshot = reducer.complete_stop(
                outcome=outcomes[command.action],
                failure_code=None if command.action == "containment_completed" else command.action,
            )
        elif command.action == "approval_timeout":
            if command.actor_user_id != "redagent-workflow":
                raise ActivityAuthorizationError("workflow_system_actor_required")
            next_snapshot = reducer.fail("approval_timeout")
        else:
            try:
                action = CommandAction(command.action)
            except ValueError as exc:
                raise ValueError("workflow_command_action_invalid") from exc
            try:
                next_snapshot = reducer.apply(
                    OperatorCommand(
                        CONTRACT_SCHEMA_VERSION,
                        command.command_id,
                        action,
                        command.actor_user_id,
                        command.expected_revision,
                        command.policy_reference,
                        "Persisted bounded workflow lifecycle command",
                    )
                ).snapshot
            except CommandRejected as exc:
                raise ConcurrencyConflict(str(exc)) from exc
        status = _business_status(next_snapshot.state)
        updated = (
            await self.session.execute(
                update(jobs)
                .where(
                    jobs.c.tenant_id == self.tenant_id,
                    jobs.c.id == command.job_id,
                    jobs.c.orchestration_revision == command.expected_revision,
                )
                .values(
                    status=status,
                    orchestration_state=next_snapshot.state,
                    orchestration_revision=next_snapshot.revision,
                    current_gate=next_snapshot.current_gate,
                    failure_code=next_snapshot.failure_code,
                    retry_count=next_snapshot.retry_count,
                    dispatch_blocked=next_snapshot.dispatch_blocked,
                    stop_requested=next_snapshot.stop_requested,
                    version=jobs.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(jobs)
            )
        ).mappings().one_or_none()
        if updated is None:
            raise ConcurrencyConflict("workflow_revision_conflict")
        audit_id, outbox_id = await self._record_workflow_event(
            action=f"workflow.job.{command.action}",
            subject_id=command.job_id,
            event_type=f"workflow.job.{command.action}",
            state=next_snapshot.state,
            revision=next_snapshot.revision,
            occurred_at=occurred_at,
        )
        await self.session.execute(
            insert(commands).values(
                id=str(uuid4()),
                tenant_id=self.tenant_id,
                job_id=command.job_id,
                command_id=command.command_id,
                action=command.action,
                request_hash=command.request_hash,
                state=next_snapshot.state,
                result_revision=next_snapshot.revision,
                actor_user_id=command.actor_user_id,
                expected_revision=command.expected_revision,
                policy_reference=command.policy_reference,
                audit_id=audit_id,
                outbox_id=outbox_id,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return ActivityResult(
            CONTRACT_SCHEMA_VERSION,
            command.job_id,
            command.command_id,
            next_snapshot.state,
            next_snapshot.revision,
            False,
        )

    async def admit_campaign_workflow(
        self,
        request: CampaignWorkflowInput,
        *,
        workflow_run_id: str,
        occurred_at: datetime,
    ) -> CampaignActivityResult:
        await self._tenant_context()
        _time(occurred_at)
        if request.tenant_id != self.tenant_id:
            raise ActivityAuthorizationError("workflow_tenant_mismatch")
        table = metadata.tables["campaigns"]
        row = (
            await self.session.execute(
                update(table)
                .where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == request.campaign_id,
                    table.c.orchestration_revision == 1,
                )
                .values(
                    workflow_run_id=_required("workflow_run_id", workflow_run_id, 64),
                    status="children_started",
                    orchestration_revision=2,
                    version=table.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(table)
            )
        ).mappings().one_or_none()
        if row is None:
            existing = await self.get_campaign(request.campaign_id)
            if existing and existing["workflow_run_id"] == workflow_run_id:
                return CampaignActivityResult(CONTRACT_SCHEMA_VERSION, request.campaign_id, "children_started", int(existing["orchestration_revision"]))
            raise ConcurrencyConflict("campaign_workflow_conflict")
        await self._record_workflow_event(
            action="workflow.campaign.children_started",
            subject_id=request.campaign_id,
            event_type="workflow.campaign.children_started",
            state="children_started",
            revision=2,
            occurred_at=occurred_at,
            subject_type="campaign",
        )
        return CampaignActivityResult(CONTRACT_SCHEMA_VERSION, request.campaign_id, "children_started", 2)

    async def _authorize_workflow_actor(self, command: ActivityCommand, job_row) -> None:
        if command.action in {
            "approval_timeout", "dispatch_started", "containment_completed",
            "containment_completed_with_residual_risk", "containment_failed",
        } and command.actor_user_id == "redagent-workflow":
            return
        memberships = metadata.tables["tenant_memberships"]
        assignments = metadata.tables["role_assignments"]
        active = await self.session.scalar(
            select(memberships.c.id).where(
                memberships.c.tenant_id == self.tenant_id,
                memberships.c.user_id == command.actor_user_id,
                memberships.c.status == "active",
            )
        )
        roles = frozenset(
            await self.session.scalars(
                select(assignments.c.role).where(
                    assignments.c.tenant_id == self.tenant_id,
                    assignments.c.user_id == command.actor_user_id,
                    assignments.c.active.is_(True),
                )
            )
        )
        if active is None:
            raise ActivityAuthorizationError("workflow_membership_inactive")
        if command.action == "approve":
            if "approver" not in roles:
                raise ActivityAuthorizationError("workflow_approver_role_required")
            if command.actor_user_id == job_row["created_by_user_id"]:
                raise ActivityAuthorizationError("workflow_separation_of_duties_required")
        elif command.action == "emergency_stop":
            if not roles & {"operator", "tenant_admin"}:
                raise ActivityAuthorizationError("workflow_stop_role_required")
        elif command.action not in {"approval_timeout"} and not roles & {"operator", "tenant_admin"}:
            raise ActivityAuthorizationError("workflow_operator_role_required")

    async def _record_workflow_event(
        self,
        *,
        action: str,
        subject_id: str,
        event_type: str,
        state: str,
        revision: int,
        occurred_at: datetime,
        subject_type: str = "job",
    ) -> tuple[str, str]:
        audit_id = str(uuid4())
        outbox_id = str(uuid4())
        await self.session.execute(
            insert(metadata.tables["audit_events"]).values(
                id=audit_id,
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action=action,
                subject_type=subject_type,
                subject_id=subject_id,
                correlation_id=self.correlation_id,
                details={"state": state, "orchestration_revision": revision},
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self.session.execute(
            insert(metadata.tables["outbox_events"]).values(
                id=outbox_id,
                tenant_id=self.tenant_id,
                event_type=event_type,
                aggregate_id=subject_id,
                payload={"subject_type": subject_type, "subject_id": subject_id, "state": state, "orchestration_revision": revision},
                published=False,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return audit_id, outbox_id

    async def transition_job(
        self,
        *,
        job_id: str,
        expected_version: int,
        next_status: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        try:
            parsed_status = JobStatus(next_status)
        except ValueError as exc:
            raise ValueError(f"job_status_invalid:{next_status}") from exc
        request = {
            "job_id": _required("job_id", job_id, 64),
            "expected_version": _version(expected_version),
            "next_status": parsed_status.value,
        }
        operation = f"job:transition:{request['job_id']}:{parsed_status.value}"
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay:
            return replay
        table = metadata.tables["jobs"]
        current = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == request["job_id"],
                )
            )
        ).mappings().one_or_none()
        if current is None or current["version"] != request["expected_version"]:
            raise ConcurrencyConflict("job_version_conflict")
        # CRITICAL: workflow-managed jobs may only advance through durable orchestration commands and Activities.
        if current["workflow_id"] is not None:
            raise RecordConflict("workflow_managed_job_requires_command")
        assert_job_transition(JobStatus(current["status"]), parsed_status)
        row = (
            await self.session.execute(
                update(table)
                .where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.id == request["job_id"],
                    table.c.version == request["expected_version"],
                )
                .values(status=parsed_status.value, version=table.c.version + 1, updated_at=occurred_at)
                .returning(table)
            )
        ).mappings().one_or_none()
        if row is None:
            raise ConcurrencyConflict("job_version_conflict")
        resource = _public_job(row)
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            subject_type="job",
            subject_id=str(request["job_id"]),
            event_type=f"job.{parsed_status.value}",
            occurred_at=occurred_at,
            response_status=200,
        )

    async def _require_engagement(self, engagement_id: str) -> None:
        table = metadata.tables["engagements"]
        existing = await self.session.scalar(
            select(table.c.id).where(table.c.tenant_id == self.tenant_id, table.c.id == engagement_id)
        )
        if existing is None:
            raise RecordConflict("engagement_not_found")

    async def _require_approved_roe(self, engagement_id: str, roe_version_id: str) -> None:
        roe = metadata.tables["roe_versions"]
        approved = await self.session.scalar(
            select(roe.c.id).where(
                roe.c.tenant_id == self.tenant_id,
                roe.c.id == roe_version_id,
                roe.c.engagement_id == engagement_id,
                roe.c.status == "approved",
            )
        )
        if approved is None:
            raise ActivityAuthorizationError("approved_roe_required")

    async def ingest_finding(
        self,
        *,
        finding_id: str,
        tool: str,
        rule_id: str,
        tool_version: str,
        database_version: str,
        title: str,
        severity: str,
        confidence: str,
        affected_resource: str,
        location: str,
        evidence_reference: str,
        redaction_state: str,
        idempotency_key: str,
        occurred_at: datetime,
    ) -> MutationResult:
        await self._tenant_context()
        _time(occurred_at)
        request = {
            "finding_id": _required("finding_id", finding_id, 64),
            "tool": _required("tool", tool, 100).lower(),
            "rule_id": _required("rule_id", rule_id, 200),
            "tool_version": _required("tool_version", tool_version, 100),
            "database_version": _required("database_version", database_version, 100),
            "title": " ".join(_required("title", title, 500).split()),
            "severity": _required("severity", severity, 32),
            "confidence": _required("confidence", confidence, 32),
            "affected_resource": _required("affected_resource", affected_resource, 500),
            "location": _required("location", location, 1000),
            "evidence_reference": _required("evidence_reference", evidence_reference, 500),
            "redaction_state": _required("redaction_state", redaction_state, 32),
        }
        operation = "finding:ingest"
        replay = await self._idempotency_replay(operation, idempotency_key, request)
        if replay:
            return replay
        fingerprint = compute_issue_fingerprint(
            tool=request["tool"],
            rule_id=request["rule_id"],
            database_version=request["database_version"],
            title=request["title"],
        )
        definitions = metadata.tables["issue_definitions"]
        definition_id = await self.session.scalar(
            select(definitions.c.id).where(
                definitions.c.tenant_id == self.tenant_id,
                definitions.c.fingerprint == fingerprint,
            )
        )
        if definition_id is None:
            definition_id = str(uuid4())
            await self.session.execute(
                insert(definitions).values(
                    id=definition_id,
                    tenant_id=self.tenant_id,
                    fingerprint=fingerprint,
                    title=request["title"],
                    tool=request["tool"],
                    rule_id=request["rule_id"],
                    tool_version=request["tool_version"],
                    database_version=request["database_version"],
                    severity=request["severity"],
                    confidence=request["confidence"],
                    version=1,
                    created_at=occurred_at,
                    updated_at=occurred_at,
                )
            )
        instances = metadata.tables["finding_instances"]
        instance_id = await self.session.scalar(
            select(instances.c.id).where(
                instances.c.tenant_id == self.tenant_id,
                instances.c.issue_definition_id == definition_id,
                instances.c.affected_resource == request["affected_resource"],
                instances.c.location == request["location"],
            )
        )
        if instance_id is None:
            instance_id = request["finding_id"]
            await self.session.execute(
                insert(instances).values(
                    id=instance_id,
                    tenant_id=self.tenant_id,
                    issue_definition_id=definition_id,
                    affected_resource=request["affected_resource"],
                    location=request["location"],
                    evidence_reference=request["evidence_reference"],
                    redaction_state=request["redaction_state"],
                    version=1,
                    created_at=occurred_at,
                    updated_at=occurred_at,
                )
            )
        resource = {
            "finding_id": instance_id,
            "issue_definition_id": definition_id,
            "fingerprint": fingerprint,
            "tenant_id": self.tenant_id,
            "version": 1,
        }
        return await self._record_mutation(
            operation=operation,
            idempotency_key=idempotency_key,
            request=request,
            resource=resource,
            subject_type="finding_instance",
            subject_id=instance_id,
            event_type="finding.ingested",
            occurred_at=occurred_at,
        )

    async def claim_outbox(self, *, limit: int) -> list[dict[str, object]]:
        await self._tenant_context()
        if not 1 <= limit <= 100:
            raise ValueError("outbox_claim_limit_invalid")
        table = metadata.tables["outbox_events"]
        rows = (
            await self.session.execute(
                select(table)
                .where(table.c.tenant_id == self.tenant_id, table.c.published.is_(False))
                .order_by(table.c.created_at, table.c.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        ).mappings().all()
        return [dict(row) for row in rows]

    async def complete_outbox(self, event_id: str, *, occurred_at: datetime) -> None:
        await self._tenant_context()
        _time(occurred_at)
        table = metadata.tables["outbox_events"]
        await self.session.execute(
            update(table)
            .where(table.c.tenant_id == self.tenant_id, table.c.id == event_id, table.c.published.is_(False))
            .values(published=True, version=table.c.version + 1, updated_at=occurred_at)
        )

    async def _tenant_context(self) -> None:
        # CRITICAL: tenant input is a bound value; never interpolate it into SQL or SET statements.
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )

    async def _idempotency_replay(
        self,
        operation: str,
        idempotency_key: str,
        request: dict[str, object],
    ) -> MutationResult | None:
        key = _required("idempotency_key", idempotency_key, 200)
        request_hash = _hash(request)
        # CRITICAL: serialize the key before read/write so concurrent retries cannot both mutate state.
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(:lock_key)"),
            {"lock_key": _advisory_lock_key(self.tenant_id, operation, key)},
        )
        table = metadata.tables["idempotency_records"]
        row = (
            await self.session.execute(
                select(table).where(
                    table.c.tenant_id == self.tenant_id,
                    table.c.operation == operation,
                    table.c.idempotency_key == key,
                )
            )
        ).mappings().one_or_none()
        if row is None:
            return None
        if row["request_hash"] != request_hash:
            raise IdempotencyConflict("idempotency_key_request_mismatch")
        response = row["response_body"]
        return MutationResult(
            resource=dict(response["resource"]),
            replayed=True,
            audit_id=str(response["audit_id"]),
            outbox_id=str(response["outbox_id"]),
        )

    async def _record_mutation(
        self,
        *,
        operation: str,
        idempotency_key: str,
        request: dict[str, object],
        resource: dict[str, object],
        subject_type: str,
        subject_id: str,
        event_type: str,
        occurred_at: datetime,
        response_status: int = 201,
    ) -> MutationResult:
        audit_id = str(uuid4())
        outbox_id = str(uuid4())
        audits = metadata.tables["audit_events"]
        outbox = metadata.tables["outbox_events"]
        idempotency = metadata.tables["idempotency_records"]
        await self.session.execute(
            insert(audits).values(
                id=audit_id,
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action=operation,
                subject_type=subject_type,
                subject_id=subject_id,
                correlation_id=self.correlation_id,
                details={"resource_version": resource["version"]},
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self.session.execute(
            insert(outbox).values(
                id=outbox_id,
                tenant_id=self.tenant_id,
                event_type=event_type,
                aggregate_id=subject_id,
                payload={"subject_type": subject_type, "subject_id": subject_id, "version": resource["version"]},
                published=False,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        response = {"resource": resource, "audit_id": audit_id, "outbox_id": outbox_id}
        await self.session.execute(
            insert(idempotency).values(
                id=str(uuid4()),
                tenant_id=self.tenant_id,
                operation=operation,
                idempotency_key=_required("idempotency_key", idempotency_key, 200),
                request_hash=_hash(request),
                response_status=response_status,
                response_body=response,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return MutationResult(resource=resource, replayed=False, audit_id=audit_id, outbox_id=outbox_id)


def _hash(value: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def _advisory_lock_key(tenant_id: str, operation: str, idempotency_key: str) -> int:
    digest = hashlib.sha256(f"{tenant_id}\x1f{operation}\x1f{idempotency_key}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _required(name: str, value: str, maximum: int) -> str:
    normalized = value.strip()
    if not normalized or len(normalized) > maximum:
        raise ValueError(f"{name}_invalid")
    return normalized


def _time(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _version(value: int) -> int:
    if isinstance(value, bool) or value < 1:
        raise ValueError("version_invalid")
    return value


def _pagination(limit: int, offset: int) -> None:
    # IMPORTANT: 501 is reserved for the API's bounded one-row continuation probe.
    if isinstance(limit, bool) or isinstance(offset, bool) or not 1 <= limit <= 501 or not 0 <= offset <= 100000:
        raise ValueError("pagination_invalid")


def _json_object(name: str, value: dict[str, object]) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name}_must_be_object")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 64 * 1024:
        raise ValueError(f"{name}_too_large")
    return json.loads(encoded)


def _workflow_request(value: dict[str, object]) -> dict[str, object]:
    normalized = _json_object("job_request", value)
    if set(normalized) != {
        "capability",
        "approval_timeout_seconds",
        "max_activity_attempts",
        "budget_reference",
    }:
        raise ValueError("job_request_fields_invalid")
    if normalized["capability"] not in {"synthetic-noop", "synthetic-conformance", "zap-controlled-runtime"}:
        raise ValueError("job_capability_invalid")
    approval_timeout = normalized["approval_timeout_seconds"]
    attempts = normalized["max_activity_attempts"]
    if isinstance(approval_timeout, bool) or not isinstance(approval_timeout, int) or not 1 <= approval_timeout <= 604_800:
        raise ValueError("approval_timeout_invalid")
    if isinstance(attempts, bool) or not isinstance(attempts, int) or not 1 <= attempts <= 5:
        raise ValueError("activity_attempts_invalid")
    _required("budget_reference", str(normalized["budget_reference"]), 100)
    return normalized


def _public_user(row) -> dict[str, object]:
    return {"user_id": row["id"], "tenant_id": row["tenant_id"], "subject": row["subject"], "version": row["version"]}


def _public_engagement(row) -> dict[str, object]:
    return {
        "engagement_id": row["id"],
        "tenant_id": row["tenant_id"],
        "name": row["name"],
        "owner_user_id": row["owner_user_id"],
        "version": row["version"],
    }


def _public_target(row) -> dict[str, object]:
    return {
        "target_id": row["id"],
        "tenant_id": row["tenant_id"],
        "engagement_id": row["engagement_id"],
        "target_type": row["target_type"],
        "normalized_value": row["normalized_value"],
        "version": row["version"],
    }


def _public_roe(row) -> dict[str, object]:
    return {
        "roe_version_id": row["id"],
        "tenant_id": row["tenant_id"],
        "engagement_id": row["engagement_id"],
        "revision": row["revision"],
        "status": row["status"],
        "document": row["document"],
        "version": row["version"],
    }


def _public_job(row) -> dict[str, object]:
    return {
        "job_id": row["id"],
        "tenant_id": row["tenant_id"],
        "engagement_id": row["engagement_id"],
        "roe_version_id": row["roe_version_id"],
        "created_by_user_id": row["created_by_user_id"],
        "campaign_id": row["campaign_id"],
        "status": row["status"],
        "request": row["request"],
        "policy_reference": row["policy_reference"],
        "workflow_id": row["workflow_id"],
        "workflow_run_id": row["workflow_run_id"],
        "orchestration_state": row["orchestration_state"],
        "orchestration_revision": row["orchestration_revision"],
        "current_gate": row["current_gate"],
        "failure_code": row["failure_code"],
        "retry_count": row["retry_count"],
        "dispatch_blocked": row["dispatch_blocked"],
        "stop_requested": row["stop_requested"],
        "version": row["version"],
    }


def _public_campaign(row) -> dict[str, object]:
    return {
        "campaign_id": row["id"],
        "tenant_id": row["tenant_id"],
        "engagement_id": row["engagement_id"],
        "roe_version_id": row["roe_version_id"],
        "name": row["name"],
        "status": row["status"],
        "workflow_id": row["workflow_id"],
        "workflow_run_id": row["workflow_run_id"],
        "orchestration_revision": row["orchestration_revision"],
        "version": row["version"],
    }


def _job_snapshot(row) -> JobSnapshot:
    return JobSnapshot(
        schema_version=CONTRACT_SCHEMA_VERSION,
        job_id=str(row["id"]),
        state=str(row["orchestration_state"]),
        revision=int(row["orchestration_revision"]),
        current_gate=str(row["current_gate"]),
        failure_code=str(row["failure_code"]) if row["failure_code"] is not None else None,
        retry_count=int(row["retry_count"]),
        dispatch_blocked=bool(row["dispatch_blocked"]),
        stop_requested=bool(row["stop_requested"]),
        last_command_id=None,
    )


def _business_status(state: str) -> str:
    parsed = WorkflowState(state)
    if parsed is WorkflowState.FAILED:
        return JobStatus.FAILED.value
    if parsed is WorkflowState.CANCELLED:
        return JobStatus.CANCELLED.value
    if parsed is WorkflowState.STOP_REQUESTED:
        return "stop_requested"
    return JobStatus.PENDING.value
