"""Tenant-scoped PostgreSQL ownership for compat_123 campaign transitions."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timedelta
from uuid import uuid4

from sqlalchemy import and_, insert, or_, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.campaign_service.lineage import (
    CampaignTerminalLineageV1,
    verify_success_lineage,
)
from redagent_platform.campaign_service.execution import (
    EffectReceiptV1,
    ReconciliationState,
)
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.persistence.models import metadata


class CampaignRecordConflict(RuntimeError):
    pass


class CampaignClaimConflict(RuntimeError):
    pass


@dataclass(frozen=True)
class StartCampaignCommand:
    campaign_id: str
    engagement_id: str
    target_id: str
    roe_id: str
    strategy_record_id: str
    strategy_revision_id: str
    workflow_id: str
    name: str
    intent_sha256: str
    context_schema: str
    context_sha256: str
    context_payload: dict[str, object]
    decision_schema: str
    decision_sha256: str
    decision_payload: dict[str, object]
    plan_revision: int
    replan_count: int
    plan_sha256: str
    plan_payload: dict[str, object]
    proposal_ceiling_sha256: str
    approval_receipt_id: str
    approval_receipt_revision: int
    approval_receipt_sha256: str
    envelope_core_sha256: str
    envelope_sha256: str
    workflow_request_sha256: str

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("campaign_id", self.campaign_id, 64),
            ("engagement_id", self.engagement_id, 64),
            ("target_id", self.target_id, 64),
            ("roe_id", self.roe_id, 64),
            ("strategy_record_id", self.strategy_record_id, 64),
            ("strategy_revision_id", self.strategy_revision_id, 100),
            ("workflow_id", self.workflow_id, 64),
            ("name", self.name, 200),
            ("context_schema", self.context_schema, 100),
            ("decision_schema", self.decision_schema, 100),
            ("approval_receipt_id", self.approval_receipt_id, 100),
        ):
            _required(name, value, maximum)
        for name, value in (
            ("intent_sha256", self.intent_sha256),
            ("context_sha256", self.context_sha256),
            ("decision_sha256", self.decision_sha256),
            ("plan_sha256", self.plan_sha256),
            ("proposal_ceiling_sha256", self.proposal_ceiling_sha256),
            ("approval_receipt_sha256", self.approval_receipt_sha256),
            ("envelope_core_sha256", self.envelope_core_sha256),
            ("envelope_sha256", self.envelope_sha256),
            ("workflow_request_sha256", self.workflow_request_sha256),
        ):
            _sha256(name, value)
        for name, value in (
            ("context_payload", self.context_payload),
            ("decision_payload", self.decision_payload),
            ("plan_payload", self.plan_payload),
        ):
            _json_object(name, value)
        if isinstance(self.plan_revision, bool) or not 1 <= self.plan_revision <= 2:
            raise ValueError("plan_revision_invalid")
        if isinstance(self.replan_count, bool) or not 0 <= self.replan_count <= 1:
            raise ValueError("replan_count_invalid")
        if (
            isinstance(self.approval_receipt_revision, bool)
            or self.approval_receipt_revision < 1
        ):
            raise ValueError("approval_receipt_revision_invalid")


@dataclass(frozen=True)
class EffectReservationCommand:
    effect_record_id: str
    effect_id: str
    campaign_id: str
    strategy_record_id: str
    node_id: str
    invocation_id: str
    effect_intent_sha256: str
    effect_intent_payload: dict[str, object]
    envelope_sha256: str

    def __post_init__(self) -> None:
        for name, value, maximum in (
            ("effect_record_id", self.effect_record_id, 64),
            ("effect_id", self.effect_id, 100),
            ("campaign_id", self.campaign_id, 64),
            ("strategy_record_id", self.strategy_record_id, 64),
            ("node_id", self.node_id, 100),
            ("invocation_id", self.invocation_id, 100),
        ):
            _required(name, value, maximum)
        _sha256("effect_intent_sha256", self.effect_intent_sha256)
        _sha256("envelope_sha256", self.envelope_sha256)
        _json_object("effect_intent_payload", self.effect_intent_payload)


@dataclass(frozen=True)
class CampaignTransitionResult:
    campaign_id: str
    workflow_id: str
    aggregate_sequence: int
    audit_id: str
    outbox_id: str
    replayed: bool = False


class PostgresCampaignCoreAuthorizedOptionOwner:
    """Project bounded operator options from canonical tenant-owned control-plane rows."""

    def __init__(self, sessions: object) -> None:
        self._sessions = sessions

    async def list_engagements(
        self, *, tenant_id: str, principal_id: str, now: datetime
    ) -> tuple[object, ...]:
        _required("r124_option_tenant", tenant_id, 64)
        _required("r124_option_principal", principal_id, 64)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("r124_option_now_invalid")
        engagements = metadata.tables["engagements"]
        targets = metadata.tables["targets"]
        roe_versions = metadata.tables["roe_versions"]
        artifact_bindings = metadata.tables["artifact_bindings"]
        async with self._sessions() as session, session.begin():
            await session.execute(
                select(text("set_config('redagent.tenant_id', :tenant_id, true)"))
                .params(tenant_id=tenant_id)
            )
            if not await campaign_core_principal_is_active(
                session,
                tenant_id=tenant_id,
                principal_id=principal_id,
                now=now,
            ):
                return ()
            rows = (
                await session.execute(
                    select(
                        engagements.c.id,
                        engagements.c.name,
                        engagements.c.version,
                        engagements.c.updated_at,
                        select(targets.c.id)
                        .where(
                            targets.c.tenant_id == tenant_id,
                            targets.c.engagement_id == engagements.c.id,
                        )
                        .limit(1)
                        .scalar_subquery()
                        .label("target_id"),
                        select(artifact_bindings.c.binding_id)
                        .where(
                            artifact_bindings.c.tenant_id == tenant_id,
                            artifact_bindings.c.artifact_kind == "repository_snapshot",
                            artifact_bindings.c.binding_state == "active-canonical-fixture",
                            artifact_bindings.c.expires_at > now,
                        )
                        .limit(1)
                        .scalar_subquery()
                        .label("artifact_binding_id"),
                        select(roe_versions.c.revision)
                        .where(
                            roe_versions.c.tenant_id == tenant_id,
                            roe_versions.c.engagement_id == engagements.c.id,
                            roe_versions.c.status == "approved",
                        )
                        .order_by(roe_versions.c.revision.desc())
                        .limit(1)
                        .scalar_subquery()
                        .label("roe_revision"),
                    )
                    .where(engagements.c.tenant_id == tenant_id)
                    .order_by(engagements.c.name, engagements.c.id)
                    .limit(501)
                )
            ).mappings().all()
        if len(rows) > 500:
            raise ValueError("r124_engagement_inventory_unbounded")
        from redagent_platform.campaign_service.service import CampaignCoreAuthorizedResource

        return tuple(
            CampaignCoreAuthorizedResource(
                resource_id=str(row["id"]),
                label=str(row["name"]),
                revision=str(row["version"]),
                freshness="current" if row["roe_revision"] is not None else "stale",
                eligible=(
                    row["target_id"] is not None or row["artifact_binding_id"] is not None
                ) and row["roe_revision"] is not None,
                unavailable_reason=(
                    None
                    if (
                        row["target_id"] is not None
                        or row["artifact_binding_id"] is not None
                    ) and row["roe_revision"] is not None
                    else (
                        "no_authorized_target"
                        if row["target_id"] is None and row["artifact_binding_id"] is None
                        else "no_approved_roe"
                    )
                ),
            )
            for row in rows
        )

    async def list_targets(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        engagement_id: str,
        now: datetime,
    ) -> tuple[object, ...]:
        _required("r124_option_tenant", tenant_id, 64)
        _required("r124_option_principal", principal_id, 64)
        _required("r124_option_engagement", engagement_id, 64)
        if now.tzinfo is None or now.utcoffset() is None:
            raise ValueError("r124_option_now_invalid")
        targets = metadata.tables["targets"]
        roe_versions = metadata.tables["roe_versions"]
        artifact_bindings = metadata.tables["artifact_bindings"]
        async with self._sessions() as session, session.begin():
            await session.execute(
                select(text("set_config('redagent.tenant_id', :tenant_id, true)"))
                .params(tenant_id=tenant_id)
            )
            if not await campaign_core_principal_is_active(
                session,
                tenant_id=tenant_id,
                principal_id=principal_id,
                now=now,
            ):
                return ()
            approved_revision = (
                await session.scalar(
                    select(roe_versions.c.revision)
                    .where(
                        roe_versions.c.tenant_id == tenant_id,
                        roe_versions.c.engagement_id == engagement_id,
                        roe_versions.c.status == "approved",
                    )
                    .order_by(roe_versions.c.revision.desc())
                    .limit(1)
                )
            )
            rows = (
                await session.execute(
                    select(
                        targets.c.id,
                        targets.c.target_type,
                        targets.c.normalized_value,
                        targets.c.version,
                    )
                    .where(
                        targets.c.tenant_id == tenant_id,
                        targets.c.engagement_id == engagement_id,
                    )
                    .order_by(targets.c.target_type, targets.c.normalized_value)
                    .limit(501)
                )
            ).mappings().all()
            artifact_rows = (
                await session.execute(
                    select(
                        artifact_bindings.c.binding_id,
                        artifact_bindings.c.version,
                        artifact_bindings.c.expires_at,
                    )
                    .where(
                        artifact_bindings.c.tenant_id == tenant_id,
                        artifact_bindings.c.artifact_kind == "repository_snapshot",
                        artifact_bindings.c.binding_state == "active-canonical-fixture",
                        artifact_bindings.c.expires_at > now,
                    )
                    .order_by(artifact_bindings.c.binding_id)
                    .limit(501)
                )
            ).mappings().all()
        if len(rows) + len(artifact_rows) > 500:
            raise ValueError("r124_target_inventory_unbounded")
        from redagent_platform.campaign_service.service import CampaignCoreAuthorizedResource

        regular = tuple(
            CampaignCoreAuthorizedResource(
                resource_id=str(row["id"]),
                parent_id=engagement_id,
                label=f'{row["target_type"]}: {row["normalized_value"]}',
                revision=f'{row["version"]}:{approved_revision or 0}',
                freshness="current" if approved_revision is not None else "stale",
                eligible=approved_revision is not None,
                unavailable_reason=None if approved_revision is not None else "no_approved_roe",
            )
            for row in rows
        )
        artifacts = tuple(
            CampaignCoreAuthorizedResource(
                resource_id=str(row["binding_id"]),
                parent_id=engagement_id,
                label="Repository snapshot: canonical data-only binding",
                revision=f'{row["version"]}:{approved_revision or 0}',
                freshness="current" if approved_revision is not None else "stale",
                eligible=approved_revision is not None,
                unavailable_reason=None if approved_revision is not None else "no_approved_roe",
                target_class="repository-snapshot",
            )
            for row in artifact_rows
        )
        return (*regular, *artifacts)


async def campaign_core_principal_is_active(
    session: AsyncSession,
    *,
    tenant_id: str,
    principal_id: str,
    now: datetime,
) -> bool:
    if principal_id.startswith("service:"):
        service_identity_id = principal_id.removeprefix("service:")
        if not service_identity_id:
            return False
        services = metadata.tables["service_identities"]
        # CRITICAL: service-backed CLI access must remain bound to a current,
        # unrevoked tenant identity; the API guard separately enforces its roles.
        row = await session.scalar(
            select(services.c.id).where(
                services.c.tenant_id == tenant_id,
                services.c.id == service_identity_id,
                services.c.revoked_at.is_(None),
                services.c.expires_at > now,
            ).limit(1)
        )
        return row is not None
    users = metadata.tables["users"]
    memberships = metadata.tables["tenant_memberships"]
    row = await session.scalar(
        select(users.c.id)
        .join(
            memberships,
            and_(
                memberships.c.tenant_id == users.c.tenant_id,
                memberships.c.user_id == users.c.id,
            ),
        )
        .where(
            users.c.tenant_id == tenant_id,
            users.c.id == principal_id,
            memberships.c.status == "active",
            memberships.c.last_validated_at >= now - timedelta(minutes=5),
            memberships.c.last_validated_at <= now,
        )
        .limit(1)
    )
    return row is not None


@dataclass(frozen=True)
class ClaimedWorkflowStart:
    event_id: str
    campaign_id: str
    aggregate_sequence: int
    attempt_count: int
    claim_owner: str
    claim_expires_at: datetime
    payload: dict[str, object]


@dataclass(frozen=True)
class EffectTransitionResult:
    effect_id: str
    campaign_id: str
    effect_state: str
    claim_version: int
    dispatch_attempt: int
    aggregate_sequence: int
    redispatch_permitted: bool


@dataclass(frozen=True)
class CampaignTerminalResult:
    campaign_id: str
    aggregate_sequence: int
    terminal_receipt_sha256: str
    replayed: bool


@dataclass(frozen=True)
class EffectManifestContext:
    campaign_id: str
    engagement_id: str
    roe_id: str
    strategy_record_id: str
    strategy_revision_id: str
    plan_sha256: str
    invocation_id: str
    envelope_sha256: str
    claim_version: int


@dataclass(frozen=True)
class TrustedEffectOwners:
    effect_id: str
    execution_receipt_id: str
    evidence_ids: tuple[str, ...]
    finding_import_id: str
    finding_issue_ids: tuple[str, ...]
    retest_receipt_ids: tuple[str, ...]
    no_finding_coverage: bool
    coverage_state: str


class CampaignRepository:
    """Transaction-neutral repository; the caller owns commit and rollback."""

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

    async def start_campaign(
        self, command: StartCampaignCommand, *, occurred_at: datetime
    ) -> CampaignTransitionResult:
        await self._tenant_context()
        _aware("occurred_at", occurred_at)
        engagements = metadata.tables["engagements"]
        roe_versions = metadata.tables["roe_versions"]
        policy_references = metadata.tables["policy_references"]
        targets = metadata.tables["targets"]
        campaigns = metadata.tables["campaigns"]
        strategies = metadata.tables["campaign_strategy_revisions"]
        authority = (
            await self.session.execute(
                select(
                    engagements.c.id.label("engagement_id"),
                    roe_versions.c.id.label("roe_id"),
                    targets.c.id.label("target_id"),
                    policy_references.c.id.label("policy_reference_id"),
                )
                .select_from(
                    engagements.join(
                        roe_versions,
                        and_(
                            roe_versions.c.tenant_id == engagements.c.tenant_id,
                            roe_versions.c.engagement_id == engagements.c.id,
                        ),
                    )
                    .join(
                        targets,
                        and_(
                            targets.c.tenant_id == engagements.c.tenant_id,
                            targets.c.engagement_id == engagements.c.id,
                        ),
                    )
                    .join(
                        policy_references,
                        and_(
                            policy_references.c.tenant_id == engagements.c.tenant_id,
                            policy_references.c.roe_version_id == roe_versions.c.id,
                        ),
                    )
                )
                .where(
                    engagements.c.tenant_id == self.tenant_id,
                    engagements.c.id == command.engagement_id,
                    roe_versions.c.id == command.roe_id,
                    roe_versions.c.status == "approved",
                    targets.c.id == command.target_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if authority is None:
            raise CampaignRecordConflict("current_campaign_scope_not_found")
        existing = await self.session.scalar(
            select(campaigns.c.id).where(
                campaigns.c.tenant_id == self.tenant_id,
                campaigns.c.id == command.campaign_id,
            )
        )
        if existing is not None:
            raise CampaignRecordConflict("campaign_already_exists")
        await self.session.execute(
            insert(campaigns).values(
                id=command.campaign_id,
                tenant_id=self.tenant_id,
                engagement_id=command.engagement_id,
                roe_version_id=command.roe_id,
                name=command.name,
                status="dispatch_pending",
                workflow_id=command.workflow_id,
                workflow_run_id=None,
                orchestration_revision=1,
                intent_sha256=command.intent_sha256,
                current_strategy_revision_id=None,
                aggregate_sequence=1,
                replan_count=command.replan_count,
                attention_reason=None,
                terminal_receipt_sha256=None,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self.session.execute(
            insert(strategies).values(
                id=command.strategy_record_id,
                tenant_id=self.tenant_id,
                strategy_revision_id=command.strategy_revision_id,
                campaign_id=command.campaign_id,
                predecessor_revision_id=None,
                plan_revision=command.plan_revision,
                replan_count=command.replan_count,
                context_schema=command.context_schema,
                context_sha256=command.context_sha256,
                context_payload=command.context_payload,
                decision_schema=command.decision_schema,
                decision_sha256=command.decision_sha256,
                decision_payload=command.decision_payload,
                plan_sha256=command.plan_sha256,
                plan_payload=command.plan_payload,
                proposal_ceiling_sha256=command.proposal_ceiling_sha256,
                approval_receipt_id=command.approval_receipt_id,
                approval_receipt_revision=command.approval_receipt_revision,
                approval_receipt_sha256=command.approval_receipt_sha256,
                envelope_core_sha256=command.envelope_core_sha256,
                envelope_sha256=command.envelope_sha256,
                created_by_user_id=self.actor_user_id,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        await self.session.execute(
            update(campaigns)
            .where(
                campaigns.c.tenant_id == self.tenant_id,
                campaigns.c.id == command.campaign_id,
            )
            .values(current_strategy_revision_id=command.strategy_record_id)
        )
        payload = {
            "schema_version": "redagent.r123-workflow-start/v1",
            "tenant_id": self.tenant_id,
            "principal_id": self.actor_user_id,
            "engagement_id": command.engagement_id,
            "campaign_id": command.campaign_id,
            "strategy_revision_id": command.strategy_revision_id,
            "workflow_id": command.workflow_id,
            "workflow_request_sha256": command.workflow_request_sha256,
            "envelope_sha256": command.envelope_sha256,
            "target_id": command.target_id,
        }
        audit_id, outbox_id = await self._record_transition(
            campaign_id=command.campaign_id,
            aggregate_sequence=1,
            action="campaign.r123.start_requested",
            event_type="workflow.start.requested.v1",
            payload=payload,
            occurred_at=occurred_at,
            relay_pending=True,
        )
        return CampaignTransitionResult(
            campaign_id=command.campaign_id,
            workflow_id=command.workflow_id,
            aggregate_sequence=1,
            audit_id=audit_id,
            outbox_id=outbox_id,
        )

    async def read_effect_manifest_context(
        self,
        *,
        effect_id: str,
        claim_owner: str,
        now: datetime,
    ) -> EffectManifestContext:
        """Read the live claimed-effect bindings required by canonical runner issuance."""
        await self._tenant_context()
        normalized_effect = _required("effect_id", effect_id, 100)
        normalized_owner = _required("claim_owner", claim_owner, 100)
        _aware("now", now)
        effects = metadata.tables["campaign_effects"]
        campaigns = metadata.tables["campaigns"]
        strategies = metadata.tables["campaign_strategy_revisions"]
        row = (
            await self.session.execute(
                select(
                    effects,
                    campaigns.c.engagement_id,
                    campaigns.c.roe_version_id,
                    effects.c.strategy_revision_id.label("strategy_record_key"),
                    strategies.c.strategy_revision_id.label("strategy_revision_key"),
                    strategies.c.plan_sha256,
                )
                .join(campaigns, campaigns.c.id == effects.c.campaign_id)
                .join(strategies, strategies.c.id == effects.c.strategy_revision_id)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect,
                    effects.c.effect_state == "claimed",
                    effects.c.claim_owner == normalized_owner,
                    effects.c.claim_expires_at > now,
                    campaigns.c.current_strategy_revision_id == strategies.c.id,
                    campaigns.c.status != "completed",
                )
            )
        ).mappings().one_or_none()
        if row is None:
            raise CampaignClaimConflict("effect_manifest_context_claim_mismatch")
        return EffectManifestContext(
            campaign_id=str(row["campaign_id"]),
            engagement_id=str(row["engagement_id"]),
            roe_id=str(row["roe_version_id"]),
            strategy_record_id=str(row["strategy_record_key"]),
            strategy_revision_id=str(row["strategy_revision_key"]),
            plan_sha256=str(row["plan_sha256"]),
            invocation_id=str(row["invocation_id"]),
            envelope_sha256=str(row["envelope_sha256"]),
            claim_version=int(row["claim_version"]),
        )

    async def claim_workflow_starts(
        self,
        *,
        claim_owner: str,
        now: datetime,
        lease_seconds: int,
        limit: int,
    ) -> list[ClaimedWorkflowStart]:
        await self._tenant_context()
        owner = _required("claim_owner", claim_owner, 100)
        _aware("now", now)
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 300:
            raise ValueError("outbox_lease_seconds_invalid")
        if isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("outbox_claim_limit_invalid")
        outbox = metadata.tables["outbox_events"]
        rows = (
            await self.session.execute(
                select(outbox)
                .where(
                    outbox.c.tenant_id == self.tenant_id,
                    outbox.c.event_type == "workflow.start.requested.v1",
                    outbox.c.schema_revision == 2,
                    outbox.c.published.is_(False),
                    outbox.c.available_at <= now,
                    or_(
                        outbox.c.delivery_state == "pending",
                        and_(
                            outbox.c.delivery_state == "claimed",
                            outbox.c.claim_expires_at <= now,
                        ),
                    ),
                )
                .order_by(outbox.c.aggregate_sequence, outbox.c.created_at, outbox.c.id)
                .limit(limit)
                .with_for_update(skip_locked=True)
            )
        ).mappings().all()
        expires_at = now + timedelta(seconds=lease_seconds)
        claimed: list[ClaimedWorkflowStart] = []
        for row in rows:
            attempt_count = int(row["attempt_count"]) + 1
            if attempt_count > 10:
                continue
            updated = (
                await self.session.execute(
                    update(outbox)
                    .where(
                        outbox.c.tenant_id == self.tenant_id,
                        outbox.c.id == row["id"],
                        outbox.c.version == row["version"],
                    )
                    .values(
                        delivery_state="claimed",
                        claim_owner=owner,
                        claim_expires_at=expires_at,
                        attempt_count=attempt_count,
                        version=outbox.c.version + 1,
                        updated_at=now,
                    )
                    .returning(outbox)
                )
            ).mappings().one_or_none()
            if updated is None:
                continue
            claimed.append(
                ClaimedWorkflowStart(
                    event_id=str(updated["id"]),
                    campaign_id=str(updated["aggregate_id"]),
                    aggregate_sequence=int(updated["aggregate_sequence"]),
                    attempt_count=int(updated["attempt_count"]),
                    claim_owner=str(updated["claim_owner"]),
                    claim_expires_at=updated["claim_expires_at"],
                    payload=dict(updated["payload"]),
                )
            )
        return claimed

    async def reserve_effect(
        self, command: EffectReservationCommand, *, occurred_at: datetime
    ) -> EffectTransitionResult:
        await self._tenant_context()
        _aware("occurred_at", occurred_at)
        campaigns = metadata.tables["campaigns"]
        strategies = metadata.tables["campaign_strategy_revisions"]
        effects = metadata.tables["campaign_effects"]
        outbox = metadata.tables["outbox_events"]
        campaign = (
            await self.session.execute(
                select(campaigns)
                .join(
                    strategies,
                    and_(
                        strategies.c.tenant_id == campaigns.c.tenant_id,
                        strategies.c.campaign_id == campaigns.c.id,
                    ),
                )
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == command.campaign_id,
                    campaigns.c.current_strategy_revision_id == command.strategy_record_id,
                    strategies.c.id == command.strategy_record_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if campaign is None:
            raise CampaignRecordConflict("current_strategy_not_found")
        existing = await self.session.scalar(
            select(effects.c.id).where(
                effects.c.tenant_id == self.tenant_id,
                or_(
                    effects.c.effect_id == command.effect_id,
                    and_(
                        effects.c.campaign_id == command.campaign_id,
                        effects.c.strategy_revision_id == command.strategy_record_id,
                        effects.c.node_id == command.node_id,
                    ),
                ),
            )
        )
        if existing is not None:
            raise CampaignRecordConflict("effect_reservation_conflict")
        aggregate_sequence = int(campaign["aggregate_sequence"]) + 1
        await self.session.execute(
            insert(effects).values(
                id=command.effect_record_id,
                tenant_id=self.tenant_id,
                effect_id=command.effect_id,
                campaign_id=command.campaign_id,
                strategy_revision_id=command.strategy_record_id,
                node_id=command.node_id,
                invocation_id=command.invocation_id,
                effect_intent_sha256=command.effect_intent_sha256,
                effect_intent_payload=command.effect_intent_payload,
                envelope_sha256=command.envelope_sha256,
                effect_state="reserved",
                claim_owner=None,
                claim_expires_at=None,
                claim_version=0,
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
                outbox_sequence=aggregate_sequence,
                started_at=None,
                completed_at=None,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        updated_campaign = (
            await self.session.execute(
                update(campaigns)
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == command.campaign_id,
                    campaigns.c.aggregate_sequence == campaign["aggregate_sequence"],
                )
                .values(
                    aggregate_sequence=aggregate_sequence,
                    version=campaigns.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(campaigns.c.id)
            )
        ).scalar_one_or_none()
        if updated_campaign is None:
            raise CampaignRecordConflict("campaign_effect_sequence_conflict")
        await self._record_transition(
            campaign_id=command.campaign_id,
            aggregate_sequence=aggregate_sequence,
            action="campaign.r123.effect_reserved",
            event_type="effect.dispatch.requested.v1",
            payload={
                "schema_version": "redagent.r123-effect-intent/v1",
                "campaign_id": command.campaign_id,
                "strategy_record_id": command.strategy_record_id,
                "node_id": command.node_id,
                "effect_id": command.effect_id,
                "effect_intent_sha256": command.effect_intent_sha256,
                "envelope_sha256": command.envelope_sha256,
            },
            occurred_at=occurred_at,
            relay_pending=False,
        )
        return EffectTransitionResult(
            effect_id=command.effect_id,
            campaign_id=command.campaign_id,
            effect_state="reserved",
            claim_version=0,
            dispatch_attempt=0,
            aggregate_sequence=aggregate_sequence,
            redispatch_permitted=False,
        )

    async def claim_effect(
        self,
        *,
        effect_id: str,
        claim_owner: str,
        expected_claim_version: int,
        now: datetime,
        lease_seconds: int,
    ) -> EffectTransitionResult:
        await self._tenant_context()
        normalized_effect_id = _required("effect_id", effect_id, 100)
        normalized_owner = _required("claim_owner", claim_owner, 100)
        _claim_version(expected_claim_version)
        _aware("now", now)
        if isinstance(lease_seconds, bool) or not 1 <= lease_seconds <= 300:
            raise ValueError("effect_lease_seconds_invalid")
        effects = metadata.tables["campaign_effects"]
        row = (
            await self.session.execute(
                update(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect_id,
                    effects.c.claim_version == expected_claim_version,
                    effects.c.dispatch_attempt < 2,
                    or_(
                        effects.c.effect_state == "reserved",
                        and_(
                            effects.c.effect_state == "not_applied",
                            effects.c.redispatch_permitted.is_(True),
                            effects.c.next_retry_at.is_not(None),
                            effects.c.next_retry_at <= now,
                        ),
                        and_(
                            effects.c.effect_state == "claimed",
                            effects.c.claim_expires_at <= now,
                        ),
                    ),
                )
                .values(
                    effect_state="claimed",
                    claim_owner=normalized_owner,
                    claim_expires_at=now + timedelta(seconds=lease_seconds),
                    claim_version=effects.c.claim_version + 1,
                    redispatch_permitted=False,
                    version=effects.c.version + 1,
                    updated_at=now,
                )
                .returning(effects)
            )
        ).mappings().one_or_none()
        if row is None:
            raise CampaignClaimConflict("effect_claim_conflict")
        await self._record_effect_audit(row, action="campaign.r123.effect_claimed", occurred_at=now)
        return _effect_result(row)

    async def mark_effect_dispatching(
        self,
        *,
        effect_id: str,
        claim_owner: str,
        expected_claim_version: int,
        request_sha256: str,
        runner_id: str,
        workload_identity: str,
        occurred_at: datetime,
    ) -> EffectTransitionResult:
        await self._tenant_context()
        normalized_effect_id = _required("effect_id", effect_id, 100)
        normalized_owner = _required("claim_owner", claim_owner, 100)
        normalized_runner = _required("runner_id", runner_id, 100)
        normalized_workload = _required("workload_identity", workload_identity, 300)
        _claim_version(expected_claim_version)
        _sha256("request_sha256", request_sha256)
        _aware("occurred_at", occurred_at)
        effects = metadata.tables["campaign_effects"]
        row = (
            await self.session.execute(
                update(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect_id,
                    effects.c.effect_state == "claimed",
                    effects.c.claim_owner == normalized_owner,
                    effects.c.claim_expires_at > occurred_at,
                    effects.c.claim_version == expected_claim_version,
                    effects.c.dispatch_attempt < 2,
                )
                .values(
                    effect_state="dispatching",
                    claim_version=effects.c.claim_version + 1,
                    dispatch_attempt=effects.c.dispatch_attempt + 1,
                    dispatch_generation=effects.c.dispatch_generation + 1,
                    runner_id=normalized_runner,
                    workload_identity=normalized_workload,
                    request_sha256=request_sha256,
                    started_at=occurred_at,
                    effect_receipt_sha256=None,
                    effect_receipt_payload=None,
                    external_status=None,
                    external_receipt_id=None,
                    evidence_ids=[],
                    cleanup_receipt_id=None,
                    reconciliation_state="none",
                    reconciliation_evidence_ids=[],
                    failure_code=None,
                    next_retry_at=None,
                    completed_at=None,
                    version=effects.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(effects)
            )
        ).mappings().one_or_none()
        if row is None:
            raise CampaignClaimConflict("effect_dispatch_claim_conflict")
        await self._record_effect_audit(
            row, action="campaign.r123.effect_dispatching", occurred_at=occurred_at
        )
        return _effect_result(row)

    async def record_effect_ambiguity(
        self,
        *,
        effect_id: str,
        claim_owner: str,
        expected_claim_version: int,
        failure_code: str,
        occurred_at: datetime,
    ) -> EffectTransitionResult:
        await self._tenant_context()
        normalized_effect_id = _required("effect_id", effect_id, 100)
        normalized_owner = _required("claim_owner", claim_owner, 100)
        normalized_failure = _required("failure_code", failure_code, 100)
        _claim_version(expected_claim_version)
        _aware("occurred_at", occurred_at)
        effects = metadata.tables["campaign_effects"]
        row = (
            await self.session.execute(
                update(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect_id,
                    effects.c.effect_state == "dispatching",
                    effects.c.claim_owner == normalized_owner,
                    effects.c.claim_version == expected_claim_version,
                )
                .values(
                    effect_state="reconciliation_required",
                    reconciliation_state="reconciliation_required",
                    redispatch_permitted=False,
                    failure_code=normalized_failure,
                    claim_owner=None,
                    claim_expires_at=None,
                    claim_version=effects.c.claim_version + 1,
                    version=effects.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(effects)
            )
        ).mappings().one_or_none()
        if row is None:
            replay = (
                await self.session.execute(
                    select(effects).where(
                        effects.c.tenant_id == self.tenant_id,
                        effects.c.effect_id == normalized_effect_id,
                    )
                )
            ).mappings().one_or_none()
            if (
                replay is not None
                and replay["effect_state"] == "reconciliation_required"
                and replay["reconciliation_state"] == "reconciliation_required"
                and replay["claim_owner"] is None
                and replay["claim_version"] == expected_claim_version + 1
                and replay["failure_code"] == normalized_failure
                and replay["redispatch_permitted"] is False
            ):
                # IMPORTANT: exact replay resolves ambiguity-transition response loss.
                return _effect_result(replay)
            raise CampaignClaimConflict("effect_ambiguity_claim_conflict")
        await self._record_effect_audit(
            row, action="campaign.r123.effect_reconciliation_required", occurred_at=occurred_at
        )
        return _effect_result(row)

    async def record_effect_not_applied(
        self,
        *,
        effect_id: str,
        expected_claim_version: int,
        receipt_sha256: str,
        receipt_payload: dict[str, object],
        occurred_at: datetime,
    ) -> EffectTransitionResult:
        await self._tenant_context()
        normalized_effect_id = _required("effect_id", effect_id, 100)
        _claim_version(expected_claim_version)
        _sha256("receipt_sha256", receipt_sha256)
        _json_object("receipt_payload", receipt_payload)
        _aware("occurred_at", occurred_at)
        receipt = _effect_receipt_contract(receipt_payload)
        if (
            receipt.effect_id != normalized_effect_id
            or receipt.reconciliation_state is not ReconciliationState.NOT_APPLIED
            or receipt.completed_at != occurred_at
            or receipt_sha256 != receipt.receipt_sha256
            or receipt_payload != receipt.canonical_payload
        ):
            raise ValueError("effect_not_applied_receipt_invalid")
        effects = metadata.tables["campaign_effects"]
        current = (
            await self.session.execute(
                select(effects).where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if current is None:
            raise CampaignClaimConflict("effect_reconciliation_conflict")
        if current["effect_state"] == "not_applied":
            if (
                current["claim_version"] == expected_claim_version + 1
                and current["effect_receipt_sha256"] == receipt_sha256
                and current["effect_receipt_payload"] == receipt_payload
            ):
                return _effect_result(current)
            raise CampaignClaimConflict("effect_reconciliation_replay_conflict")
        if (
            current["effect_state"] != "reconciliation_required"
            or current["reconciliation_state"] != "reconciliation_required"
            or current["claim_version"] != expected_claim_version
            or current["effect_intent_sha256"] != receipt.effect_intent_sha256
            or current["envelope_sha256"] != receipt.envelope_sha256
            or current["dispatch_attempt"] != receipt.dispatch_attempt
            or current["dispatch_generation"] != receipt.dispatch_generation
            or current["runner_id"] != receipt.runner_id
            or current["workload_identity"] != receipt.workload_identity
            or current["request_sha256"] != receipt.request_sha256
            or current["started_at"] != receipt.started_at
        ):
            raise CampaignClaimConflict("effect_reconciliation_conflict")
        row = (
            await self.session.execute(
                update(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect_id,
                    effects.c.effect_state == "reconciliation_required",
                    effects.c.claim_version == expected_claim_version,
                )
                .values(
                    effect_state="not_applied",
                    reconciliation_state="not_applied",
                    effect_receipt_sha256=receipt_sha256,
                    effect_receipt_payload=receipt_payload,
                    external_status=receipt.external_status,
                    external_receipt_id=receipt.external_receipt_id,
                    evidence_ids=list(receipt.evidence_ids),
                    cleanup_receipt_id=receipt.cleanup_receipt_id,
                    reconciliation_evidence_ids=list(
                        receipt.reconciliation_evidence_ids
                    ),
                    redispatch_permitted=True,
                    failure_code=None,
                    next_retry_at=occurred_at + timedelta(seconds=1),
                    completed_at=occurred_at,
                    claim_version=effects.c.claim_version + 1,
                    version=effects.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(effects)
            )
        ).mappings().one_or_none()
        if row is None:
            raise CampaignClaimConflict("effect_reconciliation_conflict")
        await self._record_effect_audit(
            row, action="campaign.r123.effect_not_applied", occurred_at=occurred_at
        )
        return _effect_result(row)

    async def record_effect_lookup_unavailable(
        self,
        *,
        effect_id: str,
        expected_claim_version: int,
        failure_code: str,
        occurred_at: datetime,
    ) -> EffectTransitionResult:
        await self._tenant_context()
        normalized_effect_id = _required("effect_id", effect_id, 100)
        normalized_failure = _required("failure_code", failure_code, 100)
        _claim_version(expected_claim_version)
        _aware("occurred_at", occurred_at)
        effects = metadata.tables["campaign_effects"]
        current = (
            await self.session.execute(
                select(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if (
            current is None
            or current["effect_state"] != "reconciliation_required"
            or current["reconciliation_state"] != "reconciliation_required"
            or current["claim_version"] != expected_claim_version
        ):
            raise CampaignClaimConflict("effect_reconciliation_conflict")
        next_retry = current["next_retry_at"]
        if next_retry is not None and occurred_at < next_retry:
            # IMPORTANT: Activity response-loss replay preserves the existing retry boundary.
            return _effect_result(current)
        terminal = next_retry is not None and occurred_at >= next_retry
        audit_id = str(uuid4())
        values: dict[str, object] = {
            "failure_code": normalized_failure,
            "claim_version": effects.c.claim_version + 1,
            "version": effects.c.version + 1,
            "updated_at": occurred_at,
        }
        if terminal:
            values.update(
                effect_state="manual_review_required",
                reconciliation_state="manual_review_required",
                reconciliation_evidence_ids=[audit_id],
                redispatch_permitted=False,
                next_retry_at=None,
                completed_at=occurred_at,
            )
            action = "campaign.r123.effect_manual_review_required"
        else:
            values["next_retry_at"] = occurred_at + timedelta(seconds=1)
            action = "campaign.r123.effect_status_lookup_retry_scheduled"
        row = (
            await self.session.execute(
                update(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect_id,
                    effects.c.claim_version == expected_claim_version,
                )
                .values(**values)
                .returning(effects)
            )
        ).mappings().one_or_none()
        if row is None:
            raise CampaignClaimConflict("effect_reconciliation_conflict")
        await self._record_effect_audit(
            row,
            action=action,
            occurred_at=occurred_at,
            audit_id=audit_id,
        )
        return _effect_result(row)

    async def record_effect_receipt(
        self,
        *,
        effect_id: str,
        claim_owner: str,
        expected_claim_version: int,
        receipt_sha256: str,
        receipt_payload: dict[str, object],
        occurred_at: datetime,
    ) -> EffectTransitionResult:
        await self._tenant_context()
        normalized_effect_id = _required("effect_id", effect_id, 100)
        normalized_owner = _required("claim_owner", claim_owner, 100)
        _claim_version(expected_claim_version)
        _sha256("receipt_sha256", receipt_sha256)
        _aware("occurred_at", occurred_at)
        _json_object("receipt_payload", receipt_payload)
        receipt = _effect_receipt_contract(receipt_payload)
        payload_effect_id = receipt.effect_id
        payload_runner_id = receipt.runner_id
        payload_workload = receipt.workload_identity
        dispatch_attempt = receipt.dispatch_attempt
        dispatch_generation = receipt.dispatch_generation
        started_at = receipt.started_at
        completed_at = receipt.completed_at
        if completed_at is None:  # guarded by the confirmed contract
            raise ValueError("effect_receipt_payload_invalid")
        if (
            receipt.reconciliation_state is not ReconciliationState.CONFIRMED
            or receipt.external_status != "confirmed"
            or completed_at != occurred_at
            or receipt_sha256 != receipt.receipt_sha256
            or receipt_payload != receipt.canonical_payload
        ):
            raise ValueError("effect_receipt_payload_invalid")
        external_receipt_id = receipt.external_receipt_id or ""
        cleanup_receipt_id = receipt.cleanup_receipt_id or ""
        evidence_ids = list(receipt.evidence_ids)
        reconciliation_evidence_ids = list(receipt.reconciliation_evidence_ids)

        effects = metadata.tables["campaign_effects"]
        current = (
            await self.session.execute(
                select(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if current is None:
            raise CampaignClaimConflict("effect_receipt_claim_conflict")

        # IMPORTANT: an exact terminal receipt replay is read-only; never create a second effect.
        if current["effect_state"] == "confirmed":
            if (
                current["claim_version"] == expected_claim_version + 1
                and current["effect_receipt_sha256"] == receipt_sha256
                and current["effect_receipt_payload"] == receipt_payload
            ):
                return _effect_result(current)
            raise CampaignClaimConflict("effect_receipt_replay_conflict")

        direct_confirmation = (
            current["effect_state"] == "dispatching"
            and current["claim_owner"] == normalized_owner
        )
        reconciliation_confirmation = (
            current["effect_state"] == "reconciliation_required"
            and current["reconciliation_state"] == "reconciliation_required"
            and current["claim_owner"] is None
        )
        if (
            not (direct_confirmation or reconciliation_confirmation)
            or current["claim_version"] != expected_claim_version
            or payload_effect_id != normalized_effect_id
            or receipt_payload["effect_intent_sha256"]
            != current["effect_intent_sha256"]
            or receipt_payload["envelope_sha256"] != current["envelope_sha256"]
            or dispatch_attempt != current["dispatch_attempt"]
            or dispatch_generation != current["dispatch_generation"]
            or payload_runner_id != current["runner_id"]
            or payload_workload != current["workload_identity"]
            or receipt_payload["request_sha256"] != current["request_sha256"]
            or started_at != current["started_at"]
        ):
            raise CampaignClaimConflict("effect_receipt_claim_conflict")

        row = (
            await self.session.execute(
                update(effects)
                .where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect_id,
                    effects.c.claim_version == expected_claim_version,
                    or_(
                        and_(
                            effects.c.effect_state == "dispatching",
                            effects.c.claim_owner == normalized_owner,
                        ),
                        and_(
                            effects.c.effect_state == "reconciliation_required",
                            effects.c.reconciliation_state
                            == "reconciliation_required",
                            effects.c.claim_owner.is_(None),
                        ),
                    ),
                )
                .values(
                    effect_state="confirmed",
                    claim_owner=None,
                    claim_expires_at=None,
                    claim_version=effects.c.claim_version + 1,
                    effect_receipt_sha256=receipt_sha256,
                    effect_receipt_payload=receipt_payload,
                    external_status=receipt_payload["external_status"],
                    external_receipt_id=external_receipt_id,
                    evidence_ids=evidence_ids,
                    cleanup_receipt_id=cleanup_receipt_id,
                    reconciliation_state=receipt.reconciliation_state.value,
                    reconciliation_evidence_ids=reconciliation_evidence_ids,
                    redispatch_permitted=False,
                    failure_code=None,
                    next_retry_at=None,
                    completed_at=completed_at,
                    version=effects.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(effects)
            )
        ).mappings().one_or_none()
        if row is None:
            raise CampaignClaimConflict("effect_receipt_claim_conflict")
        await self._record_effect_audit(
            row,
            action=(
                "campaign.r123.effect_confirmed"
                if direct_confirmation
                else "campaign.r123.effect_reconciled_confirmed"
            ),
            occurred_at=occurred_at,
        )
        return _effect_result(row)

    async def record_activity_checkpoint(
        self,
        *,
        campaign_id: str,
        strategy_revision_id: str,
        expected_aggregate_sequence: int,
        checkpoint_kind: str,
        outcome: str,
        reason: str,
        effect_id: str | None,
        occurred_at: datetime,
    ) -> int:
        """Advance one Activity-owned campaign revision with exact retry reconciliation."""
        await self._tenant_context()
        normalized_campaign = _required("campaign_id", campaign_id, 64)
        normalized_strategy = _required(
            "strategy_revision_id", strategy_revision_id, 100
        )
        if checkpoint_kind not in {"reconcile", "dispatch", "contain"}:
            raise ValueError("campaign_checkpoint_kind_invalid")
        normalized_outcome = _required("checkpoint_outcome", outcome, 100)
        normalized_reason = _required("checkpoint_reason", reason, 100)
        normalized_effect = (
            None if effect_id is None else _required("effect_id", effect_id, 100)
        )
        if (
            isinstance(expected_aggregate_sequence, bool)
            or not 1 <= expected_aggregate_sequence <= 2_147_483_646
        ):
            raise ValueError("campaign_checkpoint_sequence_invalid")
        _aware("occurred_at", occurred_at)
        next_sequence = expected_aggregate_sequence + 1
        payload: dict[str, object] = {
            "schema_version": "redagent.r123-activity-checkpoint/v1",
            "campaign_id": normalized_campaign,
            "strategy_revision_id": normalized_strategy,
            "source_revision": expected_aggregate_sequence,
            "checkpoint_kind": checkpoint_kind,
            "outcome": normalized_outcome,
            "reason": normalized_reason,
            "effect_id": normalized_effect,
        }
        outbox = metadata.tables["outbox_events"]
        replay = (
            await self.session.execute(
                select(outbox.c.payload).where(
                    outbox.c.tenant_id == self.tenant_id,
                    outbox.c.aggregate_id == normalized_campaign,
                    outbox.c.aggregate_sequence == next_sequence,
                    outbox.c.event_type == "campaign.activity.checkpoint.v1",
                )
            )
        ).scalar_one_or_none()
        if replay is not None:
            if replay != payload:
                raise CampaignRecordConflict("campaign_checkpoint_replay_conflict")
            return next_sequence

        campaigns = metadata.tables["campaigns"]
        strategies = metadata.tables["campaign_strategy_revisions"]
        current = (
            await self.session.execute(
                select(campaigns.c.status)
                .join(
                    strategies,
                    and_(
                        strategies.c.tenant_id == campaigns.c.tenant_id,
                        strategies.c.campaign_id == campaigns.c.id,
                        strategies.c.id == campaigns.c.current_strategy_revision_id,
                    ),
                )
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == normalized_campaign,
                    strategies.c.strategy_revision_id == normalized_strategy,
                    campaigns.c.aggregate_sequence == expected_aggregate_sequence,
                    campaigns.c.status != "completed",
                )
                .with_for_update()
            )
        ).scalar_one_or_none()
        if current is None:
            raise CampaignRecordConflict("campaign_checkpoint_binding_conflict")
        status = "contained" if checkpoint_kind == "contain" else str(current)
        attention_reason = (
            normalized_reason
            if normalized_outcome
            in {"blocked", "terminal_failure", "reconciliation_required", "containment_failed"}
            else None
        )
        updated = (
            await self.session.execute(
                update(campaigns)
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == normalized_campaign,
                    campaigns.c.aggregate_sequence == expected_aggregate_sequence,
                )
                .values(
                    status=status,
                    aggregate_sequence=next_sequence,
                    attention_reason=attention_reason,
                    version=campaigns.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(campaigns.c.id)
            )
        ).scalar_one_or_none()
        if updated is None:
            raise CampaignRecordConflict("campaign_checkpoint_sequence_conflict")
        await self._record_transition(
            campaign_id=normalized_campaign,
            aggregate_sequence=next_sequence,
            action=f"campaign.r123.{checkpoint_kind}_{normalized_outcome}",
            event_type="campaign.activity.checkpoint.v1",
            payload=payload,
            occurred_at=occurred_at,
            relay_pending=False,
        )
        return next_sequence

    async def validate_trusted_effect_owners(
        self,
        *,
        effect_id: str,
        external_receipt_id: str,
        evidence_ids: tuple[str, ...],
        cleanup_receipt_id: str,
        require_complete_coverage: bool = True,
        require_retest: bool = True,
        allow_reconciliation_required: bool = False,
    ) -> TrustedEffectOwners:
        """Require canonical result owners, plus terminal retest truth when requested."""
        await self._tenant_context()
        if (
            not isinstance(require_complete_coverage, bool)
            or not isinstance(require_retest, bool)
            or not isinstance(allow_reconciliation_required, bool)
        ):
            raise ValueError("effect_trusted_retest_requirement_invalid")
        normalized_effect = _required("effect_id", effect_id, 100)
        normalized_execution = _required(
            "external_receipt_id", external_receipt_id, 100
        )
        normalized_cleanup = _required(
            "cleanup_receipt_id", cleanup_receipt_id, 100
        )
        normalized_evidence = tuple(
            _identifier_list("evidence_ids", list(evidence_ids), maximum_items=32)
        )
        if not normalized_evidence:
            raise CampaignRecordConflict("effect_trusted_evidence_required")
        effects = metadata.tables["campaign_effects"]
        jobs = metadata.tables["jobs"]
        manifests = metadata.tables["runner_job_manifests"]
        leases = metadata.tables["runner_pull_leases"]
        receipts = metadata.tables["runner_execution_receipts"]
        artifacts = metadata.tables["evidence_artifacts"]
        imports = metadata.tables["finding_import_sessions"]
        records = metadata.tables["finding_import_records"]
        occurrences = metadata.tables["finding_occurrences"]
        issues = metadata.tables["managed_issues"]
        links = metadata.tables["finding_evidence_links"]
        retests = metadata.tables["finding_retests"]
        effect = (
            await self.session.execute(
                select(effects).where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.effect_id == normalized_effect,
                )
            )
        ).mappings().one_or_none()
        trusted_states = {"dispatching", "confirmed"}
        if allow_reconciliation_required:
            # CRITICAL: only the explicit read-only reconciliation owner may admit ambiguity.
            trusted_states.add("reconciliation_required")
        if effect is None or effect["effect_state"] not in trusted_states:
            raise CampaignRecordConflict("effect_trusted_owner_state_invalid")
        if effect["cleanup_receipt_id"] is not None and effect["cleanup_receipt_id"] != normalized_cleanup:
            raise CampaignRecordConflict("effect_trusted_cleanup_mismatch")
        capability = effect["effect_intent_payload"].get("capability_id")
        if not isinstance(capability, str):
            raise CampaignRecordConflict("effect_trusted_capability_invalid")
        closed_binding = closed_execution_registry().get(capability)
        if closed_binding is None:
            raise CampaignRecordConflict("effect_trusted_capability_invalid")
        capability_id = closed_binding.capability_id
        execution = (
            await self.session.execute(
                select(
                    receipts,
                    manifests.c.capability_id,
                    manifests.c.capability_revision,
                    manifests.c.manifest_state,
                    jobs.c.campaign_id,
                    jobs.c.id.label("runner_job_id"),
                )
                .join(leases, leases.c.id == receipts.c.lease_id)
                .join(manifests, manifests.c.id == leases.c.manifest_id)
                .join(jobs, jobs.c.id == manifests.c.job_id)
                .where(
                    receipts.c.tenant_id == self.tenant_id,
                    receipts.c.execution_id == normalized_execution,
                )
            )
        ).mappings().one_or_none()
        if execution is None or (
            execution["campaign_id"] != effect["campaign_id"]
            or execution["capability_id"] != capability_id
            or execution["capability_revision"] != closed_binding.capability_revision
            or execution["outcome"] != "succeeded"
            or execution["final_phase"] != "cleanup"
            or execution["cleanup_completed"] is not True
            or execution["residual_risk"] is not None
            or execution["manifest_state"] != "completed"
            or execution["evidence_artifact_id"] not in normalized_evidence
        ):
            raise CampaignRecordConflict("effect_trusted_execution_owner_mismatch")
        evidence_rows = (
            await self.session.execute(
                select(artifacts).where(
                    artifacts.c.tenant_id == self.tenant_id,
                    artifacts.c.id.in_(normalized_evidence),
                )
            )
        ).mappings().all()
        if len(evidence_rows) != len(normalized_evidence) or any(
            row["job_id"] != execution["runner_job_id"]
            or row["artifact_class"] not in {"report_safe", "export_safe"}
            or row["redaction_state"] != row["artifact_class"]
            or row["quarantine_reason"] is not None
            or row["finalized_at"] is None
            for row in evidence_rows
        ):
            raise CampaignRecordConflict("effect_trusted_evidence_owner_mismatch")
        primary = next(
            row
            for row in evidence_rows
            if row["id"] == execution["evidence_artifact_id"]
        )
        if primary["content_sha256"] != execution["evidence_sha256"]:
            raise CampaignRecordConflict("effect_trusted_evidence_digest_mismatch")
        import_row = (
            await self.session.execute(
                select(imports).where(
                    imports.c.tenant_id == self.tenant_id,
                    imports.c.run_id == normalized_execution,
                )
            )
        ).mappings().one_or_none()
        if import_row is None:
            raise CampaignRecordConflict("effect_trusted_finding_import_mismatch")
        coverage_state = str(import_row["coverage_state"])
        if (
            coverage_state not in {"complete", "partial", "unknown"}
            or import_row["import_state"] != "accepted"
            or import_row["adapter_id"] != closed_binding.adapter_id
            or (
                (require_complete_coverage or require_retest)
                and coverage_state != "complete"
            )
        ):
            raise CampaignRecordConflict("effect_trusted_finding_import_mismatch")
        record_ids = tuple(
            (
                await self.session.scalars(
                    select(records.c.id).where(
                        records.c.tenant_id == self.tenant_id,
                        records.c.import_record_ref == import_row["id"],
                    )
                )
            ).all()
        )
        if len(record_ids) != import_row["record_count"]:
            raise CampaignRecordConflict("effect_trusted_finding_import_mismatch")
        if not record_ids:
            return TrustedEffectOwners(
                effect_id=normalized_effect,
                execution_receipt_id=normalized_execution,
                evidence_ids=normalized_evidence,
                finding_import_id=str(import_row["import_id"]),
                finding_issue_ids=(),
                retest_receipt_ids=(),
                no_finding_coverage=coverage_state == "complete",
                coverage_state=coverage_state,
            )
        issue_rows = (
            await self.session.execute(
                select(
                    issues.c.issue_id,
                    links.c.evidence_id,
                    links.c.redaction_state,
                    links.c.purpose,
                    links.c.link_state,
                )
                .join(occurrences, occurrences.c.issue_record_id == issues.c.id)
                .join(records, records.c.id == occurrences.c.import_record_ref)
                .join(links, links.c.occurrence_record_id == occurrences.c.id)
                .where(
                    issues.c.tenant_id == self.tenant_id,
                    records.c.import_record_ref == import_row["id"],
                )
                .order_by(issues.c.issue_id)
            )
        ).mappings().all()
        issue_ids = tuple(dict.fromkeys(str(row["issue_id"]) for row in issue_rows))
        if not issue_ids or any(
            row["evidence_id"] not in normalized_evidence
            or row["redaction_state"] not in {"report_safe", "export_safe"}
            or row["purpose"] != "report"
            or row["link_state"] != "approved"
            for row in issue_rows
        ):
            raise CampaignRecordConflict("effect_trusted_finding_owner_mismatch")
        if not require_retest:
            return TrustedEffectOwners(
                effect_id=normalized_effect,
                execution_receipt_id=normalized_execution,
                evidence_ids=normalized_evidence,
                finding_import_id=str(import_row["import_id"]),
                finding_issue_ids=issue_ids,
                retest_receipt_ids=(),
                no_finding_coverage=False,
                coverage_state=coverage_state,
            )
        retest_rows = (
            await self.session.execute(
                select(retests.c.retest_id, issues.c.issue_id)
                .join(issues, issues.c.id == retests.c.issue_record_id)
                .where(
                    retests.c.tenant_id == self.tenant_id,
                    issues.c.issue_id.in_(issue_ids),
                    retests.c.coverage_state == "complete",
                    retests.c.result_state == "passed",
                    retests.c.completed_at.is_not(None),
                )
                .order_by(issues.c.issue_id, retests.c.retest_id)
            )
        ).mappings().all()
        by_issue: dict[str, list[str]] = {}
        for row in retest_rows:
            by_issue.setdefault(str(row["issue_id"]), []).append(str(row["retest_id"]))
        if set(by_issue) != set(issue_ids) or any(len(values) != 1 for values in by_issue.values()):
            raise CampaignRecordConflict("effect_trusted_retest_owner_mismatch")
        return TrustedEffectOwners(
            effect_id=normalized_effect,
            execution_receipt_id=normalized_execution,
            evidence_ids=normalized_evidence,
            finding_import_id=str(import_row["import_id"]),
            finding_issue_ids=issue_ids,
            retest_receipt_ids=tuple(by_issue[issue][0] for issue in issue_ids),
            no_finding_coverage=False,
            coverage_state=coverage_state,
        )

    async def finalize_campaign(
        self,
        lineage: CampaignTerminalLineageV1,
        *,
        expected_aggregate_sequence: int,
        occurred_at: datetime,
    ) -> CampaignTerminalResult:
        await self._tenant_context()
        _aware("occurred_at", occurred_at)
        if (
            isinstance(expected_aggregate_sequence, bool)
            or not 1 <= expected_aggregate_sequence <= 2_147_483_647
        ):
            raise ValueError("campaign_terminal_sequence_invalid")
        receipt_sha256 = verify_success_lineage(lineage)
        if lineage.tenant_id != self.tenant_id:
            raise CampaignRecordConflict("campaign_terminal_tenant_mismatch")
        campaigns = metadata.tables["campaigns"]
        strategies = metadata.tables["campaign_strategy_revisions"]
        effects = metadata.tables["campaign_effects"]
        outbox = metadata.tables["outbox_events"]
        campaign = (
            await self.session.execute(
                select(campaigns, strategies)
                .join(
                    strategies,
                    and_(
                        strategies.c.tenant_id == campaigns.c.tenant_id,
                        strategies.c.campaign_id == campaigns.c.id,
                        strategies.c.id == campaigns.c.current_strategy_revision_id,
                    ),
                )
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == lineage.campaign_id,
                    strategies.c.strategy_revision_id == lineage.strategy_revision_id,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if campaign is None:
            raise CampaignRecordConflict("campaign_terminal_strategy_not_current")
        if campaign["status"] == "completed":
            if campaign["terminal_receipt_sha256"] != receipt_sha256:
                raise CampaignRecordConflict("campaign_terminal_replay_conflict")
            return CampaignTerminalResult(
                campaign_id=lineage.campaign_id,
                aggregate_sequence=int(campaign["aggregate_sequence"]),
                terminal_receipt_sha256=receipt_sha256,
                replayed=True,
            )
        if (
            campaign["aggregate_sequence"] != expected_aggregate_sequence
            or campaign["workflow_id"] != lineage.workflow_id
            or campaign["workflow_run_id"] != lineage.workflow_run_id
            or campaign["intent_sha256"] != lineage.objective_sha256
            or campaign["context_sha256"] != lineage.context_snapshot_sha256
            or campaign["decision_sha256"] != lineage.decision_sha256
            or campaign["plan_sha256"] != lineage.plan_sha256
            or campaign["approval_receipt_id"] != lineage.approval_receipt_id
            or campaign["approval_receipt_sha256"] != lineage.approval_receipt_sha256
            or campaign["envelope_sha256"] != lineage.resolved_envelope_sha256
        ):
            raise CampaignRecordConflict("campaign_terminal_lineage_binding_mismatch")
        start_event = await self.session.scalar(
            select(outbox.c.id).where(
                outbox.c.tenant_id == self.tenant_id,
                outbox.c.id == lineage.outbox_event_id,
                outbox.c.aggregate_id == lineage.campaign_id,
                outbox.c.event_type == "workflow.start.requested.v1",
                outbox.c.delivery_state == "delivered",
                outbox.c.published.is_(True),
            )
        )
        if start_event is None:
            raise CampaignRecordConflict("campaign_terminal_outbox_binding_mismatch")
        effect_rows = (
            await self.session.execute(
                select(effects).where(
                    effects.c.tenant_id == self.tenant_id,
                    effects.c.campaign_id == lineage.campaign_id,
                )
            )
        ).mappings().all()
        by_effect = {str(row["effect_id"]): row for row in effect_rows}
        if set(by_effect) != {item.effect_id for item in lineage.nodes}:
            raise CampaignRecordConflict("campaign_terminal_effect_inventory_mismatch")
        for item in lineage.nodes:
            row = by_effect[item.effect_id]
            if (
                row["node_id"] != item.node_id
                or row["effect_intent_payload"].get("capability_id")
                != f"{item.capability_id}@{item.capability_revision}"
                or row["effect_receipt_sha256"] != item.effect_receipt_sha256
                or row["external_receipt_id"] != item.execution_receipt_id
                or tuple(row["evidence_ids"]) != item.evidence_ids
                or row["cleanup_receipt_id"] != item.cleanup_receipt_id
                or row["reconciliation_state"] != item.reconciliation_state
                or row["effect_state"] not in {"confirmed", "compensated"}
            ):
                raise CampaignRecordConflict("campaign_terminal_effect_binding_mismatch")
        await self._validate_terminal_owner_lineage(lineage)
        aggregate_sequence = expected_aggregate_sequence + 1
        updated = (
            await self.session.execute(
                update(campaigns)
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == lineage.campaign_id,
                    campaigns.c.aggregate_sequence == expected_aggregate_sequence,
                    campaigns.c.status != "completed",
                )
                .values(
                    status="completed",
                    aggregate_sequence=aggregate_sequence,
                    terminal_receipt_sha256=receipt_sha256,
                    attention_reason=None,
                    version=campaigns.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(campaigns.c.id)
            )
        ).scalar_one_or_none()
        if updated is None:
            raise CampaignRecordConflict("campaign_terminal_sequence_conflict")
        await self._record_transition(
            campaign_id=lineage.campaign_id,
            aggregate_sequence=aggregate_sequence,
            action="campaign.r123.completed",
            event_type="campaign.completed.v1",
            payload={
                "schema_version": "redagent.r123-campaign-terminal/v1",
                "campaign_id": lineage.campaign_id,
                "strategy_revision_id": lineage.strategy_revision_id,
                "terminal_receipt_sha256": receipt_sha256,
                "node_effect_ids": [item.effect_id for item in lineage.nodes],
                "terminal_reason": lineage.terminal_reason,
                "campaign_cleanup_receipt_id": lineage.campaign_cleanup_receipt_id,
                "residual_risk_receipt_id": lineage.residual_risk_receipt_id,
            },
            occurred_at=occurred_at,
            relay_pending=False,
        )
        return CampaignTerminalResult(
            campaign_id=lineage.campaign_id,
            aggregate_sequence=aggregate_sequence,
            terminal_receipt_sha256=receipt_sha256,
            replayed=False,
        )

    async def _validate_terminal_owner_lineage(
        self, lineage: CampaignTerminalLineageV1
    ) -> None:
        artifacts = metadata.tables["evidence_artifacts"]
        requested_evidence = {
            evidence_id for node in lineage.nodes for evidence_id in node.evidence_ids
        }
        evidence_rows = (
            await self.session.execute(
                select(artifacts).where(
                    artifacts.c.tenant_id == self.tenant_id,
                    artifacts.c.id.in_(requested_evidence),
                )
            )
        ).mappings().all()
        evidence_by_id = {str(row["id"]): row for row in evidence_rows}
        if set(evidence_by_id) != requested_evidence:
            raise CampaignRecordConflict("campaign_terminal_evidence_owner_mismatch")
        for row in evidence_rows:
            if (
                row["artifact_class"] not in {"report_safe", "export_safe"}
                or row["redaction_state"] != row["artifact_class"]
                or row["quarantine_reason"] is not None
                or row["finalized_at"] is None
            ):
                raise CampaignRecordConflict("campaign_terminal_evidence_not_report_safe")

        receipts = metadata.tables["runner_execution_receipts"]
        leases = metadata.tables["runner_pull_leases"]
        manifests = metadata.tables["runner_job_manifests"]
        jobs = metadata.tables["jobs"]
        imports = metadata.tables["finding_import_sessions"]
        import_records = metadata.tables["finding_import_records"]
        occurrences = metadata.tables["finding_occurrences"]
        issues = metadata.tables["managed_issues"]
        evidence_links = metadata.tables["finding_evidence_links"]
        retests = metadata.tables["finding_retests"]
        for node in lineage.nodes:
            execution = (
                await self.session.execute(
                    select(
                        receipts,
                        manifests,
                        jobs.c.id.label("runner_job_id"),
                        jobs.c.campaign_id,
                    )
                    .join(leases, leases.c.id == receipts.c.lease_id)
                    .join(manifests, manifests.c.id == leases.c.manifest_id)
                    .join(jobs, jobs.c.id == manifests.c.job_id)
                    .where(
                        receipts.c.tenant_id == self.tenant_id,
                        receipts.c.execution_id == node.execution_receipt_id,
                    )
                )
            ).mappings().one_or_none()
            if execution is None or (
                execution["campaign_id"] != lineage.campaign_id
                or execution["capability_id"] != node.capability_id
                or execution["capability_revision"] != node.capability_revision
                or execution["outcome"] != "succeeded"
                or execution["final_phase"] != "cleanup"
                or execution["cleanup_completed"] is not True
                or execution["residual_risk"] is not None
                or execution["evidence_artifact_id"] not in node.evidence_ids
                or evidence_by_id[str(execution["evidence_artifact_id"])]["job_id"]
                != execution["runner_job_id"]
                or evidence_by_id[str(execution["evidence_artifact_id"])][
                    "content_sha256"
                ]
                != execution["evidence_sha256"]
                or execution["manifest_state"] != "completed"
            ):
                raise CampaignRecordConflict("campaign_terminal_execution_owner_mismatch")

            import_row = (
                await self.session.execute(
                    select(imports).where(
                        imports.c.tenant_id == self.tenant_id,
                        imports.c.import_id == node.finding_import_id,
                    )
                )
            ).mappings().one_or_none()
            if import_row is None or (
                import_row["coverage_state"] != "complete"
                or import_row["import_state"] != "accepted"
            ):
                raise CampaignRecordConflict("campaign_terminal_finding_import_mismatch")
            imported_record_ids = tuple(
                (
                    await self.session.scalars(
                        select(import_records.c.id).where(
                            import_records.c.tenant_id == self.tenant_id,
                            import_records.c.import_record_ref == import_row["id"],
                        )
                    )
                ).all()
            )
            if len(imported_record_ids) != import_row["record_count"]:
                raise CampaignRecordConflict("campaign_terminal_finding_import_mismatch")
            if node.no_finding_coverage:
                if imported_record_ids:
                    raise CampaignRecordConflict("campaign_terminal_no_finding_coverage_mismatch")
                continue

            linked_rows = (
                await self.session.execute(
                    select(
                        issues.c.issue_id,
                        evidence_links.c.evidence_id,
                        evidence_links.c.redaction_state,
                        evidence_links.c.purpose,
                        evidence_links.c.link_state,
                    )
                    .join(occurrences, occurrences.c.issue_record_id == issues.c.id)
                    .join(
                        import_records,
                        import_records.c.id == occurrences.c.import_record_ref,
                    )
                    .join(
                        evidence_links,
                        evidence_links.c.occurrence_record_id == occurrences.c.id,
                    )
                    .where(
                        issues.c.tenant_id == self.tenant_id,
                        import_records.c.import_record_ref == import_row["id"],
                    )
                )
            ).mappings().all()
            if {str(row["issue_id"]) for row in linked_rows} != set(
                node.finding_issue_ids
            ) or any(
                row["evidence_id"] not in node.evidence_ids
                or row["redaction_state"] not in {"report_safe", "export_safe"}
                or row["purpose"] != "report"
                or row["link_state"] != "approved"
                for row in linked_rows
            ):
                raise CampaignRecordConflict("campaign_terminal_finding_owner_mismatch")

            retest_rows = (
                await self.session.execute(
                    select(retests.c.retest_id, issues.c.issue_id)
                    .join(issues, issues.c.id == retests.c.issue_record_id)
                    .where(
                        retests.c.tenant_id == self.tenant_id,
                        retests.c.retest_id.in_(node.retest_receipt_ids),
                        retests.c.coverage_state == "complete",
                        retests.c.result_state == "passed",
                        retests.c.completed_at.is_not(None),
                    )
                )
            ).mappings().all()
            actual_retests = {
                str(row["retest_id"]): str(row["issue_id"]) for row in retest_rows
            }
            expected_retests = dict(
                zip(node.retest_receipt_ids, node.finding_issue_ids, strict=True)
            )
            if actual_retests != expected_retests:
                raise CampaignRecordConflict("campaign_terminal_retest_owner_mismatch")

    async def acknowledge_workflow_start(
        self,
        *,
        event_id: str,
        claim_owner: str,
        workflow_run_id: str,
        occurred_at: datetime,
        duplicate_confirmed: bool = False,
    ) -> CampaignTransitionResult:
        await self._tenant_context()
        normalized_event_id = _required("event_id", event_id, 64)
        normalized_owner = _required("claim_owner", claim_owner, 100)
        normalized_run_id = _required("workflow_run_id", workflow_run_id, 100)
        _aware("occurred_at", occurred_at)
        if not isinstance(duplicate_confirmed, bool):
            raise ValueError("duplicate_confirmed_invalid")
        outbox = metadata.tables["outbox_events"]
        row = (
            await self.session.execute(
                select(outbox)
                .where(
                    outbox.c.tenant_id == self.tenant_id,
                    outbox.c.id == normalized_event_id,
                    outbox.c.event_type == "workflow.start.requested.v1",
                    outbox.c.delivery_state == "claimed",
                    outbox.c.claim_owner == normalized_owner,
                    outbox.c.claim_expires_at > occurred_at,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if row is None:
            raise CampaignClaimConflict("outbox_claim_conflict")
        await self.session.execute(
            update(outbox)
            .where(
                outbox.c.tenant_id == self.tenant_id,
                outbox.c.id == normalized_event_id,
                outbox.c.version == row["version"],
            )
            .values(
                published=True,
                delivery_state="delivered",
                delivered_at=occurred_at,
                reconciliation_state=(
                    "duplicate_confirmed" if duplicate_confirmed else "none"
                ),
                claim_owner=None,
                claim_expires_at=None,
                version=outbox.c.version + 1,
                updated_at=occurred_at,
            )
        )
        campaigns = metadata.tables["campaigns"]
        campaign = (
            await self.session.execute(
                update(campaigns)
                .where(
                    campaigns.c.tenant_id == self.tenant_id,
                    campaigns.c.id == row["aggregate_id"],
                    campaigns.c.workflow_id == row["payload"]["workflow_id"],
                    campaigns.c.aggregate_sequence == row["aggregate_sequence"],
                )
                .values(
                    workflow_run_id=normalized_run_id,
                    status="workflow_started",
                    aggregate_sequence=campaigns.c.aggregate_sequence + 1,
                    orchestration_revision=campaigns.c.orchestration_revision + 1,
                    version=campaigns.c.version + 1,
                    updated_at=occurred_at,
                )
                .returning(campaigns)
            )
        ).mappings().one_or_none()
        if campaign is None:
            raise CampaignClaimConflict("campaign_workflow_ack_conflict")
        aggregate_sequence = int(campaign["aggregate_sequence"])
        audit_id, acknowledgement_outbox_id = await self._record_transition(
            campaign_id=str(campaign["id"]),
            aggregate_sequence=aggregate_sequence,
            action=(
                "campaign.r123.workflow_duplicate_confirmed"
                if duplicate_confirmed
                else "campaign.r123.workflow_started"
            ),
            event_type="workflow.started.v1",
            payload={
                "schema_version": "redagent.r123-workflow-started/v1",
                "campaign_id": str(campaign["id"]),
                "workflow_id": str(campaign["workflow_id"]),
                "workflow_run_id": normalized_run_id,
                "start_event_id": normalized_event_id,
                "duplicate_confirmed": duplicate_confirmed,
            },
            occurred_at=occurred_at,
            relay_pending=False,
        )
        return CampaignTransitionResult(
            campaign_id=str(campaign["id"]),
            workflow_id=str(campaign["workflow_id"]),
            aggregate_sequence=aggregate_sequence,
            audit_id=audit_id,
            outbox_id=acknowledgement_outbox_id,
        )

    async def record_workflow_start_failure(
        self,
        *,
        event_id: str,
        claim_owner: str,
        failure: object,
        last_error: str,
        occurred_at: datetime,
        max_attempts: int,
    ) -> None:
        # Local import avoids making the persistence owner a module-load dependency of the relay.
        from redagent_platform.campaign_service.relay import RelayFailure, apply_relay_failure

        await self._tenant_context()
        normalized_event_id = _required("event_id", event_id, 64)
        normalized_owner = _required("claim_owner", claim_owner, 100)
        normalized_error = _required("last_error", last_error, 500)
        _aware("occurred_at", occurred_at)
        if not isinstance(failure, RelayFailure):
            raise ValueError("relay_failure_invalid")
        outbox = metadata.tables["outbox_events"]
        row = (
            await self.session.execute(
                select(outbox)
                .where(
                    outbox.c.tenant_id == self.tenant_id,
                    outbox.c.id == normalized_event_id,
                    outbox.c.event_type == "workflow.start.requested.v1",
                    outbox.c.delivery_state == "claimed",
                    outbox.c.claim_owner == normalized_owner,
                )
                .with_for_update()
            )
        ).mappings().one_or_none()
        if row is None:
            raise CampaignClaimConflict("outbox_claim_conflict")
        decision = apply_relay_failure(
            attempt_count=int(row["attempt_count"]),
            failure=failure,
            now=occurred_at,
            max_attempts=max_attempts,
        )
        await self.session.execute(
            update(outbox)
            .where(
                outbox.c.tenant_id == self.tenant_id,
                outbox.c.id == normalized_event_id,
                outbox.c.version == row["version"],
            )
            .values(
                delivery_state=decision.delivery_state.value,
                reconciliation_state=decision.reconciliation_state,
                available_at=decision.available_at or row["available_at"],
                claim_owner=None,
                claim_expires_at=None,
                last_error=normalized_error,
                dead_lettered_at=decision.dead_lettered_at,
                version=outbox.c.version + 1,
                updated_at=occurred_at,
            )
        )
        audit = metadata.tables["audit_events"]
        await self.session.execute(
            insert(audit).values(
                id=str(uuid4()),
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action="campaign.r123.workflow_start_delivery_failed",
                subject_type="campaign",
                subject_id=str(row["aggregate_id"]),
                correlation_id=self.correlation_id,
                details={
                    "event_id": normalized_event_id,
                    "delivery_state": decision.delivery_state.value,
                    "reconciliation_state": decision.reconciliation_state,
                    "attempt_count": decision.attempt_count,
                    "error_code": normalized_error,
                },
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )

    async def _record_transition(
        self,
        *,
        campaign_id: str,
        aggregate_sequence: int,
        action: str,
        event_type: str,
        payload: dict[str, object],
        occurred_at: datetime,
        relay_pending: bool,
    ) -> tuple[str, str]:
        audit = metadata.tables["audit_events"]
        outbox = metadata.tables["outbox_events"]
        audit_id = str(uuid4())
        outbox_id = str(uuid4())
        await self.session.execute(
            insert(audit).values(
                id=audit_id,
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action=action,
                subject_type="campaign",
                subject_id=campaign_id,
                correlation_id=self.correlation_id,
                details={"aggregate_sequence": aggregate_sequence},
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
                aggregate_id=campaign_id,
                payload=payload,
                published=not relay_pending,
                schema_revision=2,
                aggregate_type="campaign",
                aggregate_sequence=aggregate_sequence,
                available_at=occurred_at,
                claim_owner=None,
                claim_expires_at=None,
                attempt_count=0,
                last_error=None,
                delivered_at=occurred_at if not relay_pending else None,
                delivery_state="pending" if relay_pending else "delivered",
                reconciliation_state="none",
                dead_lettered_at=None,
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return audit_id, outbox_id

    async def _record_effect_audit(
        self,
        row,
        *,
        action: str,
        occurred_at: datetime,
        audit_id: str | None = None,
    ) -> str:
        audit = metadata.tables["audit_events"]
        record_id = audit_id or str(uuid4())
        await self.session.execute(
            insert(audit).values(
                id=record_id,
                tenant_id=self.tenant_id,
                actor_user_id=self.actor_user_id,
                action=action,
                subject_type="campaign_effect",
                subject_id=str(row["id"]),
                correlation_id=self.correlation_id,
                details={
                    "effect_id": str(row["effect_id"]),
                    "effect_state": str(row["effect_state"]),
                    "claim_version": int(row["claim_version"]),
                    "dispatch_attempt": int(row["dispatch_attempt"]),
                },
                version=1,
                created_at=occurred_at,
                updated_at=occurred_at,
            )
        )
        return record_id

    async def _tenant_context(self) -> None:
        # CRITICAL: relay and aggregate mutations must remain under the exact record tenant RLS context.
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": self.tenant_id},
        )


def _required(name: str, value: str, maximum: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{name}_invalid")
    normalized = value.strip()
    if not normalized or normalized != value or len(value) > maximum:
        raise ValueError(f"{name}_invalid")
    return value


def _sha256(name: str, value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{name}_invalid")


def _json_object(name: str, value: dict[str, object]) -> None:
    if not isinstance(value, dict):
        raise ValueError(f"{name}_must_be_object")
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 64 * 1024:
        raise ValueError(f"{name}_too_large")


def _aware(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")


def _claim_version(value: int) -> None:
    if isinstance(value, bool) or not 0 <= value <= 2_147_483_647:
        raise ValueError("effect_claim_version_invalid")


def _canonical_sha256(value: dict[str, object]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identifier_list(name: str, value: list[str], *, maximum_items: int) -> list[str]:
    if not isinstance(value, list) or len(value) > maximum_items:
        raise ValueError(f"{name}_invalid")
    normalized = [_required(name, item, 100) for item in value]
    if len(set(normalized)) != len(normalized):
        raise ValueError(f"{name}_invalid")
    return normalized


def _effect_receipt_contract(payload: dict[str, object]) -> EffectReceiptV1:
    expected_keys = {
        "schema_version",
        "effect_id",
        "effect_intent_sha256",
        "envelope_sha256",
        "dispatch_attempt",
        "dispatch_generation",
        "runner_id",
        "workload_identity",
        "request_sha256",
        "started_at",
        "completed_at",
        "adapter_accepted",
        "external_status",
        "external_receipt_id",
        "evidence_ids",
        "cleanup_receipt_id",
        "output_complete",
        "external_contact_count",
        "reconciliation_state",
        "reconciliation_evidence_ids",
        "redispatch_permitted",
        "failure_code",
    }
    if set(payload) != expected_keys:
        raise ValueError("effect_receipt_payload_invalid")
    evidence = payload["evidence_ids"]
    reconciliation_evidence = payload["reconciliation_evidence_ids"]
    if not isinstance(evidence, list) or not isinstance(reconciliation_evidence, list):
        raise ValueError("effect_receipt_payload_invalid")
    try:
        started_at = datetime.fromisoformat(payload["started_at"])
        completed_value = payload["completed_at"]
        completed_at = (
            None
            if completed_value is None
            else datetime.fromisoformat(completed_value)
        )
        receipt = EffectReceiptV1(
            schema_version=payload["schema_version"],
            effect_id=payload["effect_id"],
            effect_intent_sha256=payload["effect_intent_sha256"],
            envelope_sha256=payload["envelope_sha256"],
            dispatch_attempt=payload["dispatch_attempt"],
            dispatch_generation=payload["dispatch_generation"],
            runner_id=payload["runner_id"],
            workload_identity=payload["workload_identity"],
            request_sha256=payload["request_sha256"],
            started_at=started_at,
            completed_at=completed_at,
            adapter_accepted=payload["adapter_accepted"],
            external_status=payload["external_status"],
            external_receipt_id=payload["external_receipt_id"],
            evidence_ids=tuple(evidence),
            cleanup_receipt_id=payload["cleanup_receipt_id"],
            output_complete=payload["output_complete"],
            external_contact_count=payload["external_contact_count"],
            reconciliation_state=ReconciliationState(payload["reconciliation_state"]),
            reconciliation_evidence_ids=tuple(reconciliation_evidence),
            redispatch_permitted=payload["redispatch_permitted"],
            failure_code=payload["failure_code"],
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("effect_receipt_payload_invalid") from exc
    return receipt


def _effect_result(row) -> EffectTransitionResult:
    return EffectTransitionResult(
        effect_id=str(row["effect_id"]),
        campaign_id=str(row["campaign_id"]),
        effect_state=str(row["effect_state"]),
        claim_version=int(row["claim_version"]),
        dispatch_attempt=int(row["dispatch_attempt"]),
        aggregate_sequence=int(row["outbox_sequence"]),
        redispatch_permitted=bool(row["redispatch_permitted"]),
    )
