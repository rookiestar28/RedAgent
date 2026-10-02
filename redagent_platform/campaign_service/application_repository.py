"""PostgreSQL ownership for the canonical autonomous campaign application lifecycle."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import hashlib
import json
from typing import Mapping
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.application_contracts import (
    ApplicationBindingConflict,
    ApplicationIdempotencyConflict,
    ApplicationNotFound,
    ApplicationRevisionConflict,
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignLifecycle,
    AutonomousCampaignMode,
    AutonomousCampaignMutationResultV1,
    CreateAutonomousCampaignIntentV1,
    RevokeAutonomousCampaignIntentV1,
    assert_lifecycle_transition,
)
from redagent_platform.campaign_service.admission_contracts import CampaignBudgetVectorV1
from redagent_platform.campaign_service.admission_start_contracts import (
    AutonomousCampaignApprovalBundleV1,
)
from redagent_platform.campaign_service.approval_contracts import (
    ApproveAutonomousCampaignPlanV1,
    AutonomousCampaignApprovalDecision,
    AutonomousCampaignApprovalDecisionResultV1,
    AutonomousCampaignApprovalReceiptV1,
    AutonomousCampaignPlanActionV1,
    AutonomousCampaignPlanApproverV1,
    AutonomousCampaignPlanPreviewResultV1,
    AutonomousCampaignPlanPreviewV1,
    DenyAutonomousCampaignPlanV1,
    StageAutonomousCampaignPlanV1,
    canonical_approval_decision_request_sha256,
)
from redagent_platform.campaign_service.planning.contracts import (
    CleanupMode,
    ValidationResult,
    canonical_planning_bytes,
    canonical_planning_sha256,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1


_CREATE_OPERATION = "autonomous_campaign.application.create.v1"
_REVOKE_OPERATION = "autonomous_campaign.application.revoke.v1"
_STAGE_PLAN_OPERATION = "autonomous_campaign.plan.stage.v1"
_APPROVE_PLAN_OPERATION = "autonomous_campaign.plan.approve.v1"
_DENY_PLAN_OPERATION = "autonomous_campaign.plan.deny.v1"


class PostgresAutonomousCampaignApplicationRepository:
    """Commit current state, append-only history, audit, and replay in one tenant transaction."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def create_intent(self, command: CreateAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1:
        if not isinstance(command, CreateAutonomousCampaignIntentV1):
            raise ValueError("create_intent_command_invalid")
        request_sha256 = _semantic_request_sha256(command)
        try:
            async with self._sessions() as session, session.begin():
                await _tenant_context(session, command.tenant_id)
                await _lock_idempotency(
                    session,
                    tenant_id=command.tenant_id,
                    operation=_CREATE_OPERATION,
                    idempotency_key=command.idempotency_key,
                )
                replay = await _read_replay(
                    session,
                    tenant_id=command.tenant_id,
                    operation=_CREATE_OPERATION,
                    idempotency_key=command.idempotency_key,
                    request_sha256=request_sha256,
                )
                if replay is not None:
                    return replay
                await _assert_canonical_bindings(
                    session,
                    tenant_id=command.tenant_id,
                    actor_user_id=command.actor_user_id,
                    engagement_id=command.engagement_id,
                    target_id=command.target_id,
                )
                state = AutonomousCampaignApplicationStateV1(
                    schema_version=command.schema_version,
                    tenant_id=command.tenant_id,
                    campaign_id=command.campaign_id,
                    engagement_id=command.engagement_id,
                    target_id=command.target_id,
                    created_by_user_id=command.actor_user_id,
                    intent_sha256=command.intent_sha256,
                    source_binding_sha256=command.source_binding_sha256,
                    mode=command.mode,
                    lifecycle_state=AutonomousCampaignLifecycle.INTENT_CREATED,
                    aggregate_revision=1,
                    attention_reason=None,
                    created_at=command.occurred_at,
                    updated_at=command.occurred_at,
                )
                applications = metadata.tables["autonomous_campaign_applications"]
                await session.execute(
                    insert(applications).values(
                        id=state.campaign_id,
                        contract_version=state.schema_version,
                        engagement_id=state.engagement_id,
                        target_id=state.target_id,
                        created_by_user_id=state.created_by_user_id,
                        intent_sha256=state.intent_sha256,
                        source_binding_sha256=state.source_binding_sha256,
                        mode=state.mode.value,
                        lifecycle_state=state.lifecycle_state.value,
                        aggregate_revision=state.aggregate_revision,
                        attention_reason=None,
                        tenant_id=state.tenant_id,
                        version=1,
                        created_at=state.created_at,
                        updated_at=state.updated_at,
                    )
                )
                result = await _record_mutation(
                    session,
                    state=state,
                    operation=_CREATE_OPERATION,
                    idempotency_key=command.idempotency_key,
                    correlation_id=command.correlation_id,
                    actor_user_id=command.actor_user_id,
                    request_sha256=request_sha256,
                    event_type="autonomous_campaign.intent.created.v1",
                    previous_state=None,
                    event_payload={
                        "intent_sha256": command.intent_sha256,
                        "source_binding_sha256": command.source_binding_sha256,
                        "mode": command.mode.value,
                    },
                    occurred_at=command.occurred_at,
                    response_status=201,
                )
            return result
        except IntegrityError as exc:
            raise ApplicationBindingConflict("autonomous_campaign_persistence_conflict") from exc

    async def read(self, *, tenant_id: str, campaign_id: str) -> AutonomousCampaignApplicationStateV1 | None:
        _identifier("tenant_id", tenant_id, 64)
        _identifier("campaign_id", campaign_id, 64)
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, tenant_id)
            row = await _read_row(session, tenant_id=tenant_id, campaign_id=campaign_id)
        return None if row is None else _state_from_row(row)

    async def revoke_intent(self, command: RevokeAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1:
        if not isinstance(command, RevokeAutonomousCampaignIntentV1):
            raise ValueError("revoke_intent_command_invalid")
        request_sha256 = _semantic_request_sha256(command)
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, command.tenant_id)
            await _lock_idempotency(
                session,
                tenant_id=command.tenant_id,
                operation=_REVOKE_OPERATION,
                idempotency_key=command.idempotency_key,
            )
            replay = await _read_replay(
                session,
                tenant_id=command.tenant_id,
                operation=_REVOKE_OPERATION,
                idempotency_key=command.idempotency_key,
                request_sha256=request_sha256,
            )
            if replay is not None:
                return replay
            await _assert_actor_binding(
                session,
                tenant_id=command.tenant_id,
                actor_user_id=command.actor_user_id,
            )
            applications = metadata.tables["autonomous_campaign_applications"]
            row = (
                (
                    await session.execute(
                        select(applications)
                        .where(
                            applications.c.tenant_id == command.tenant_id,
                            applications.c.id == command.campaign_id,
                        )
                        .with_for_update()
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                raise ApplicationNotFound("autonomous_campaign_not_found")
            current = _state_from_row(row)
            if current.aggregate_revision != command.expected_revision:
                raise ApplicationRevisionConflict("application_revision_conflict")
            assert_lifecycle_transition(
                current.lifecycle_state,
                AutonomousCampaignLifecycle.REVOKED,
            )
            successor = AutonomousCampaignApplicationStateV1(
                schema_version=current.schema_version,
                tenant_id=current.tenant_id,
                campaign_id=current.campaign_id,
                engagement_id=current.engagement_id,
                target_id=current.target_id,
                created_by_user_id=current.created_by_user_id,
                intent_sha256=current.intent_sha256,
                source_binding_sha256=current.source_binding_sha256,
                mode=current.mode,
                lifecycle_state=AutonomousCampaignLifecycle.REVOKED,
                aggregate_revision=current.aggregate_revision + 1,
                attention_reason=None,
                created_at=current.created_at,
                updated_at=command.occurred_at,
            )
            updated = await session.execute(
                update(applications)
                .where(
                    applications.c.tenant_id == command.tenant_id,
                    applications.c.id == command.campaign_id,
                    applications.c.aggregate_revision == command.expected_revision,
                )
                .values(
                    lifecycle_state=successor.lifecycle_state.value,
                    aggregate_revision=successor.aggregate_revision,
                    version=applications.c.version + 1,
                    updated_at=successor.updated_at,
                )
            )
            if getattr(updated, "rowcount", None) != 1:
                raise ApplicationRevisionConflict("application_revision_conflict")
            return await _record_mutation(
                session,
                state=successor,
                operation=_REVOKE_OPERATION,
                idempotency_key=command.idempotency_key,
                correlation_id=command.correlation_id,
                actor_user_id=command.actor_user_id,
                request_sha256=request_sha256,
                event_type="autonomous_campaign.intent.revoked.v1",
                previous_state=current.lifecycle_state,
                event_payload={"reason_sha256": command.reason_sha256},
                occurred_at=command.occurred_at,
                response_status=202,
            )

    async def stage_plan(
        self,
        command: StageAutonomousCampaignPlanV1,
        preview: AutonomousCampaignPlanPreviewV1,
    ) -> AutonomousCampaignPlanPreviewResultV1:
        if not isinstance(command, StageAutonomousCampaignPlanV1) or not isinstance(
            preview, AutonomousCampaignPlanPreviewV1
        ):
            raise ValueError("stage_plan_input_invalid")
        request_sha256 = _approval_request_sha256(command)
        try:
            async with self._sessions() as session, session.begin():
                await _tenant_context(session, command.tenant_id)
                await _lock_idempotency(
                    session,
                    tenant_id=command.tenant_id,
                    operation=_STAGE_PLAN_OPERATION,
                    idempotency_key=command.idempotency_key,
                )
                replay = await _read_plan_preview_replay(
                    session,
                    command=command,
                    operation=_STAGE_PLAN_OPERATION,
                    request_sha256=request_sha256,
                )
                if replay is not None:
                    return replay
                await _assert_actor_binding(
                    session,
                    tenant_id=command.tenant_id,
                    actor_user_id=command.actor_user_id,
                )
                applications = metadata.tables["autonomous_campaign_applications"]
                row = (
                    (
                        await session.execute(
                            select(applications)
                            .where(
                                applications.c.tenant_id == command.tenant_id,
                                applications.c.id == command.campaign_id,
                            )
                            .with_for_update()
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise ApplicationNotFound("autonomous_campaign_not_found")
                current = _state_from_row(row)
                if current.aggregate_revision != command.expected_revision:
                    raise ApplicationRevisionConflict("application_revision_conflict")
                if (
                    preview.tenant_id != current.tenant_id
                    or preview.campaign_id != current.campaign_id
                    or preview.engagement_id != current.engagement_id
                    or preview.application_revision != current.aggregate_revision + 2
                    or preview.execution_mode is not current.mode
                ):
                    raise ApplicationBindingConflict("plan_preview_application_binding_mismatch")
                assert_lifecycle_transition(current.lifecycle_state, AutonomousCampaignLifecycle.PLAN_VALIDATED)
                assert_lifecycle_transition(
                    AutonomousCampaignLifecycle.PLAN_VALIDATED,
                    AutonomousCampaignLifecycle.AWAITING_APPROVAL,
                )
                validated = _successor_state(
                    current,
                    lifecycle_state=AutonomousCampaignLifecycle.PLAN_VALIDATED,
                    aggregate_revision=current.aggregate_revision + 1,
                    occurred_at=command.occurred_at,
                )
                awaiting = _successor_state(
                    current,
                    lifecycle_state=AutonomousCampaignLifecycle.AWAITING_APPROVAL,
                    aggregate_revision=current.aggregate_revision + 2,
                    occurred_at=command.occurred_at,
                )
                await session.execute(
                    insert(metadata.tables["autonomous_campaign_plan_previews"]).values(
                        id=preview.preview_id,
                        application_id=preview.campaign_id,
                        application_revision=preview.application_revision,
                        contract_version=preview.schema_version,
                        preview_sha256=preview.preview_sha256,
                        preview_payload=_json_payload(preview),
                        created_by_user_id=command.actor_user_id,
                        expires_at=preview.expires_at,
                        tenant_id=preview.tenant_id,
                        version=1,
                        created_at=command.occurred_at,
                        updated_at=command.occurred_at,
                    )
                )
                updated = await session.execute(
                    update(applications)
                    .where(
                        applications.c.tenant_id == command.tenant_id,
                        applications.c.id == command.campaign_id,
                        applications.c.aggregate_revision == command.expected_revision,
                    )
                    .values(
                        lifecycle_state=awaiting.lifecycle_state.value,
                        aggregate_revision=awaiting.aggregate_revision,
                        version=applications.c.version + 2,
                        updated_at=awaiting.updated_at,
                    )
                )
                if getattr(updated, "rowcount", None) != 1:
                    raise ApplicationRevisionConflict("application_revision_conflict")
                first_audit, first_event = await _record_lifecycle_event(
                    session,
                    state=validated,
                    operation=_STAGE_PLAN_OPERATION,
                    correlation_id=command.correlation_id,
                    actor_user_id=command.actor_user_id,
                    request_sha256=request_sha256,
                    event_type="autonomous_campaign.plan.validated.v1",
                    previous_state=current.lifecycle_state,
                    event_payload={
                        "preview_id": preview.preview_id,
                        "preview_sha256": preview.preview_sha256,
                        "certificate_sha256": preview.certificate_sha256,
                    },
                    occurred_at=command.occurred_at,
                )
                second_audit, second_event = await _record_lifecycle_event(
                    session,
                    state=awaiting,
                    operation=_STAGE_PLAN_OPERATION,
                    correlation_id=command.correlation_id,
                    actor_user_id=command.actor_user_id,
                    request_sha256=request_sha256,
                    event_type="autonomous_campaign.plan.awaiting_approval.v1",
                    previous_state=validated.lifecycle_state,
                    event_payload={
                        "preview_id": preview.preview_id,
                        "preview_sha256": preview.preview_sha256,
                        "expires_at": preview.expires_at.isoformat(),
                    },
                    occurred_at=command.occurred_at,
                )
                result = AutonomousCampaignPlanPreviewResultV1(
                    application=awaiting,
                    preview=preview,
                    audit_ids=(first_audit, second_audit),
                    event_ids=(first_event, second_event),
                    replayed=False,
                )
                await _record_idempotency(
                    session,
                    tenant_id=command.tenant_id,
                    operation=_STAGE_PLAN_OPERATION,
                    idempotency_key=command.idempotency_key,
                    request_sha256=request_sha256,
                    response_status=201,
                    response_body=_plan_preview_result_payload(result),
                    occurred_at=command.occurred_at,
                )
            return result
        except IntegrityError as exc:
            raise ApplicationBindingConflict("autonomous_campaign_plan_persistence_conflict") from exc

    async def read_plan_preview(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
    ) -> AutonomousCampaignPlanPreviewV1 | None:
        _identifier("tenant_id", tenant_id, 64)
        _identifier("campaign_id", campaign_id, 64)
        previews = metadata.tables["autonomous_campaign_plan_previews"]
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, tenant_id)
            row = (
                (
                    await session.execute(
                        select(previews.c.preview_payload, previews.c.preview_sha256)
                        .where(
                            previews.c.tenant_id == tenant_id,
                            previews.c.application_id == campaign_id,
                        )
                        .order_by(previews.c.application_revision.desc())
                        .limit(1)
                    )
                )
                .mappings()
                .one_or_none()
            )
        return (
            None
            if row is None
            else _verified_preview_from_payload(row["preview_payload"], str(row["preview_sha256"]))
        )

    async def read_current_approval_bundle(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        approval_receipt_id: str,
    ) -> AutonomousCampaignApprovalBundleV1 | None:
        """Reload the exact current R172 approval lineage from immutable rows."""
        _identifier("tenant_id", tenant_id, 64)
        _identifier("campaign_id", campaign_id, 64)
        _identifier("approval_receipt_id", approval_receipt_id, 64)
        applications = metadata.tables["autonomous_campaign_applications"]
        previews = metadata.tables["autonomous_campaign_plan_previews"]
        receipts = metadata.tables["autonomous_campaign_plan_approval_receipts"]
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, tenant_id)
            application_row = (
                (
                    await session.execute(
                        select(applications).where(
                            applications.c.tenant_id == tenant_id,
                            applications.c.id == campaign_id,
                        )
                    )
                )
                .mappings()
                .one_or_none()
            )
            if application_row is None:
                return None
            receipt_row = (
                (
                    await session.execute(
                        select(receipts).where(
                            receipts.c.tenant_id == tenant_id,
                            receipts.c.application_id == campaign_id,
                            receipts.c.id == approval_receipt_id,
                        )
                    )
                )
                .mappings()
                .one_or_none()
            )
            if receipt_row is None:
                return None
            preview_row = (
                (
                    await session.execute(
                        select(previews).where(
                            previews.c.tenant_id == tenant_id,
                            previews.c.application_id == campaign_id,
                            previews.c.id == receipt_row["preview_id"],
                        )
                    )
                )
                .mappings()
                .one_or_none()
            )
            if preview_row is None:
                return None

        application = _state_from_row(application_row)
        preview = _verified_preview_from_payload(
            preview_row["preview_payload"], str(preview_row["preview_sha256"])
        )
        receipt = _verified_receipt_from_payload(
            receipt_row["receipt_payload"], str(receipt_row["receipt_sha256"])
        )
        if (
            application.lifecycle_state
            not in {
                AutonomousCampaignLifecycle.APPROVED,
                AutonomousCampaignLifecycle.ADMITTED,
                AutonomousCampaignLifecycle.EXECUTION_QUEUED,
                AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
                AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
                AutonomousCampaignLifecycle.FAILED_CONTAINED,
                AutonomousCampaignLifecycle.DENIED,
                AutonomousCampaignLifecycle.EXPIRED,
                AutonomousCampaignLifecycle.REVOKED,
            }
            or receipt.decision is not AutonomousCampaignApprovalDecision.APPROVED
            or receipt.application_revision > application.aggregate_revision
            or int(receipt_row["application_revision"]) != receipt.application_revision
            or preview.application_revision + 1 != receipt.application_revision
            or int(preview_row["application_revision"]) != preview.application_revision
            or str(receipt_row["preview_id"]) != preview.preview_id
            or receipt.preview_id != preview.preview_id
            or receipt.receipt_id != approval_receipt_id
        ):
            return None
        return AutonomousCampaignApprovalBundleV1(
            application=application,
            preview=preview,
            approval_receipt=receipt,
        )

    async def decide_plan(
        self,
        command: ApproveAutonomousCampaignPlanV1 | DenyAutonomousCampaignPlanV1,
        receipt: AutonomousCampaignApprovalReceiptV1,
    ) -> AutonomousCampaignApprovalDecisionResultV1:
        if not isinstance(command, (ApproveAutonomousCampaignPlanV1, DenyAutonomousCampaignPlanV1)) or not isinstance(
            receipt, AutonomousCampaignApprovalReceiptV1
        ):
            raise ValueError("decide_plan_input_invalid")
        operation = (
            _APPROVE_PLAN_OPERATION
            if receipt.decision is AutonomousCampaignApprovalDecision.APPROVED
            else _DENY_PLAN_OPERATION
        )
        request_sha256 = _approval_request_sha256(command)
        try:
            async with self._sessions() as session, session.begin():
                await _tenant_context(session, command.tenant_id)
                await _lock_idempotency(
                    session,
                    tenant_id=command.tenant_id,
                    operation=operation,
                    idempotency_key=command.idempotency_key,
                )
                replay = await _read_approval_decision_replay(
                    session,
                    command=command,
                    operation=operation,
                    request_sha256=request_sha256,
                )
                if replay is not None:
                    return replay
                await _assert_actor_binding(
                    session,
                    tenant_id=command.tenant_id,
                    actor_user_id=command.actor_user_id,
                )
                applications = metadata.tables["autonomous_campaign_applications"]
                row = (
                    (
                        await session.execute(
                            select(applications)
                            .where(
                                applications.c.tenant_id == command.tenant_id,
                                applications.c.id == command.campaign_id,
                            )
                            .with_for_update()
                        )
                    )
                    .mappings()
                    .one_or_none()
                )
                if row is None:
                    raise ApplicationNotFound("autonomous_campaign_not_found")
                current = _state_from_row(row)
                if current.aggregate_revision != command.expected_revision:
                    raise ApplicationRevisionConflict("application_revision_conflict")
                target_state = (
                    AutonomousCampaignLifecycle.APPROVED
                    if receipt.decision is AutonomousCampaignApprovalDecision.APPROVED
                    else AutonomousCampaignLifecycle.DENIED
                )
                assert_lifecycle_transition(current.lifecycle_state, target_state)
                previews = metadata.tables["autonomous_campaign_plan_previews"]
                preview_exists = await session.scalar(
                    select(previews.c.id).where(
                        previews.c.tenant_id == command.tenant_id,
                        previews.c.application_id == command.campaign_id,
                        previews.c.id == command.preview_id,
                        previews.c.preview_sha256 == command.preview_sha256,
                        previews.c.application_revision == command.expected_revision,
                    )
                )
                if preview_exists is None or receipt.application_revision != command.expected_revision + 1:
                    raise ApplicationBindingConflict("approval_preview_application_binding_mismatch")
                successor = _successor_state(
                    current,
                    lifecycle_state=target_state,
                    aggregate_revision=current.aggregate_revision + 1,
                    occurred_at=command.occurred_at,
                )
                await session.execute(
                    insert(metadata.tables["autonomous_campaign_plan_approval_receipts"]).values(
                        id=receipt.receipt_id,
                        application_id=receipt.campaign_id,
                        preview_id=receipt.preview_id,
                        application_revision=receipt.application_revision,
                        contract_version=receipt.schema_version,
                        decision=receipt.decision.value,
                        reason_code=receipt.reason_code,
                        receipt_sha256=receipt.receipt_sha256,
                        receipt_payload=_json_payload(receipt),
                        decided_by_user_id=receipt.approver_user_id,
                        tenant_id=receipt.tenant_id,
                        version=1,
                        created_at=command.occurred_at,
                        updated_at=command.occurred_at,
                    )
                )
                updated = await session.execute(
                    update(applications)
                    .where(
                        applications.c.tenant_id == command.tenant_id,
                        applications.c.id == command.campaign_id,
                        applications.c.aggregate_revision == command.expected_revision,
                    )
                    .values(
                        lifecycle_state=successor.lifecycle_state.value,
                        aggregate_revision=successor.aggregate_revision,
                        version=applications.c.version + 1,
                        updated_at=successor.updated_at,
                    )
                )
                if getattr(updated, "rowcount", None) != 1:
                    raise ApplicationRevisionConflict("application_revision_conflict")
                event_type = (
                    "autonomous_campaign.plan.approved.v1"
                    if target_state is AutonomousCampaignLifecycle.APPROVED
                    else "autonomous_campaign.plan.denied.v1"
                )
                audit_id, event_id = await _record_lifecycle_event(
                    session,
                    state=successor,
                    operation=operation,
                    correlation_id=command.correlation_id,
                    actor_user_id=command.actor_user_id,
                    request_sha256=request_sha256,
                    event_type=event_type,
                    previous_state=current.lifecycle_state,
                    event_payload={
                        "preview_id": receipt.preview_id,
                        "preview_sha256": receipt.preview_sha256,
                        "receipt_id": receipt.receipt_id,
                        "receipt_sha256": receipt.receipt_sha256,
                        "reason_code": receipt.reason_code,
                        "policy_reference": receipt.policy_reference,
                    },
                    policy_reference=receipt.policy_reference,
                    occurred_at=command.occurred_at,
                )
                result = AutonomousCampaignApprovalDecisionResultV1(
                    application=successor,
                    receipt=receipt,
                    audit_id=audit_id,
                    event_id=event_id,
                    replayed=False,
                )
                await _record_idempotency(
                    session,
                    tenant_id=command.tenant_id,
                    operation=operation,
                    idempotency_key=command.idempotency_key,
                    request_sha256=request_sha256,
                    response_status=200,
                    response_body=_approval_decision_result_payload(result),
                    occurred_at=command.occurred_at,
                )
            return result
        except IntegrityError as exc:
            raise ApplicationBindingConflict("autonomous_campaign_approval_persistence_conflict") from exc


async def _assert_canonical_bindings(
    session: AsyncSession,
    *,
    tenant_id: str,
    actor_user_id: str,
    engagement_id: str,
    target_id: str,
) -> None:
    await _assert_actor_binding(session, tenant_id=tenant_id, actor_user_id=actor_user_id)
    engagements = metadata.tables["engagements"]
    targets = metadata.tables["targets"]
    engagement = await session.scalar(
        select(engagements.c.id).where(
            engagements.c.tenant_id == tenant_id,
            engagements.c.id == engagement_id,
        )
    )
    target = await session.scalar(
        select(targets.c.id).where(
            targets.c.tenant_id == tenant_id,
            targets.c.id == target_id,
            targets.c.engagement_id == engagement_id,
        )
    )
    if engagement is None or target is None:
        raise ApplicationBindingConflict("application_binding_not_found")


async def _assert_actor_binding(session: AsyncSession, *, tenant_id: str, actor_user_id: str) -> None:
    users = metadata.tables["users"]
    actor = await session.scalar(
        select(users.c.id).where(
            users.c.tenant_id == tenant_id,
            users.c.id == actor_user_id,
        )
    )
    if actor is None:
        raise ApplicationBindingConflict("application_actor_not_found")


async def _record_mutation(
    session: AsyncSession,
    *,
    state: AutonomousCampaignApplicationStateV1,
    operation: str,
    idempotency_key: str,
    correlation_id: str,
    actor_user_id: str,
    request_sha256: str,
    event_type: str,
    previous_state: AutonomousCampaignLifecycle | None,
    event_payload: dict[str, object],
    occurred_at: datetime,
    response_status: int,
) -> AutonomousCampaignMutationResultV1:
    audit_id, event_id = await _record_lifecycle_event(
        session,
        state=state,
        operation=operation,
        correlation_id=correlation_id,
        actor_user_id=actor_user_id,
        request_sha256=request_sha256,
        event_type=event_type,
        previous_state=previous_state,
        event_payload=event_payload,
        occurred_at=occurred_at,
    )
    result = AutonomousCampaignMutationResultV1(
        application=state,
        audit_id=audit_id,
        event_id=event_id,
        replayed=False,
    )
    await _record_idempotency(
        session,
        tenant_id=state.tenant_id,
        operation=operation,
        idempotency_key=idempotency_key,
        request_sha256=request_sha256,
        response_status=response_status,
        response_body=_result_payload(result),
        occurred_at=occurred_at,
    )
    return result


async def _record_lifecycle_event(
    session: AsyncSession,
    *,
    state: AutonomousCampaignApplicationStateV1,
    operation: str,
    correlation_id: str,
    actor_user_id: str,
    request_sha256: str,
    event_type: str,
    previous_state: AutonomousCampaignLifecycle | None,
    event_payload: dict[str, object],
    occurred_at: datetime,
    policy_reference: str | None = None,
) -> tuple[str, str]:
    audit_id = f"audit-{uuid4().hex}"
    event_id = f"event-{uuid4().hex}"
    lifecycle_sha256 = _lifecycle_sha256(state)
    audit_details: dict[str, object] = {
        "aggregate_revision": state.aggregate_revision,
        "lifecycle_sha256": lifecycle_sha256,
    }
    if policy_reference is not None:
        audit_details["policy_reference"] = policy_reference
    await session.execute(
        insert(metadata.tables["audit_events"]).values(
            id=audit_id,
            tenant_id=state.tenant_id,
            actor_user_id=actor_user_id,
            action=operation,
            subject_type="autonomous_campaign_application",
            subject_id=state.campaign_id,
            correlation_id=correlation_id,
            details=audit_details,
            version=1,
            created_at=occurred_at,
            updated_at=occurred_at,
        )
    )
    await session.execute(
        insert(metadata.tables["autonomous_campaign_application_events"]).values(
            id=event_id,
            application_id=state.campaign_id,
            audit_event_id=audit_id,
            event_sequence=state.aggregate_revision,
            event_type=event_type,
            previous_state=None if previous_state is None else previous_state.value,
            next_state=state.lifecycle_state.value,
            actor_user_id=actor_user_id,
            request_sha256=request_sha256,
            lifecycle_sha256=lifecycle_sha256,
            event_payload=event_payload,
            occurred_at=occurred_at,
            tenant_id=state.tenant_id,
            version=1,
            created_at=occurred_at,
            updated_at=occurred_at,
        )
    )
    return audit_id, event_id


async def _record_idempotency(
    session: AsyncSession,
    *,
    tenant_id: str,
    operation: str,
    idempotency_key: str,
    request_sha256: str,
    response_status: int,
    response_body: dict[str, object],
    occurred_at: datetime,
) -> None:
    await session.execute(
        insert(metadata.tables["idempotency_records"]).values(
            id=f"idem-{uuid4().hex}",
            tenant_id=tenant_id,
            operation=operation,
            idempotency_key=idempotency_key,
            request_hash=request_sha256,
            response_status=response_status,
            response_body=response_body,
            version=1,
            created_at=occurred_at,
            updated_at=occurred_at,
        )
    )


async def _read_replay(
    session: AsyncSession,
    *,
    tenant_id: str,
    operation: str,
    idempotency_key: str,
    request_sha256: str,
) -> AutonomousCampaignMutationResultV1 | None:
    records = metadata.tables["idempotency_records"]
    row = (
        (
            await session.execute(
                select(records.c.request_hash, records.c.response_body).where(
                    records.c.tenant_id == tenant_id,
                    records.c.operation == operation,
                    records.c.idempotency_key == idempotency_key,
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    if row["request_hash"] != request_sha256:
        raise ApplicationIdempotencyConflict("application_idempotency_mismatch")
    return _result_from_payload(row["response_body"], replayed=True)


async def _read_plan_preview_replay(
    session: AsyncSession,
    *,
    command: StageAutonomousCampaignPlanV1,
    operation: str,
    request_sha256: str,
) -> AutonomousCampaignPlanPreviewResultV1 | None:
    payload = await _read_idempotency_payload(
        session,
        tenant_id=command.tenant_id,
        operation=operation,
        idempotency_key=command.idempotency_key,
        request_sha256=request_sha256,
    )
    if payload is None:
        return None
    try:
        result = _plan_preview_result_from_payload(payload, replayed=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ApplicationBindingConflict("plan_preview_replay_copy_invalid") from exc
    await _verify_plan_preview_replay(
        session,
        command=command,
        operation=operation,
        request_sha256=request_sha256,
        result=result,
    )
    return result


async def _read_approval_decision_replay(
    session: AsyncSession,
    *,
    command: ApproveAutonomousCampaignPlanV1 | DenyAutonomousCampaignPlanV1,
    operation: str,
    request_sha256: str,
) -> AutonomousCampaignApprovalDecisionResultV1 | None:
    payload = await _read_idempotency_payload(
        session,
        tenant_id=command.tenant_id,
        operation=operation,
        idempotency_key=command.idempotency_key,
        request_sha256=request_sha256,
    )
    if payload is None:
        return None
    try:
        result = _approval_decision_result_from_payload(payload, replayed=True)
    except (KeyError, TypeError, ValueError) as exc:
        raise ApplicationBindingConflict("approval_replay_copy_invalid") from exc
    await _verify_approval_decision_replay(
        session,
        command=command,
        operation=operation,
        request_sha256=request_sha256,
        result=result,
    )
    return result


async def _read_idempotency_payload(
    session: AsyncSession,
    *,
    tenant_id: str,
    operation: str,
    idempotency_key: str,
    request_sha256: str,
) -> object | None:
    records = metadata.tables["idempotency_records"]
    row = (
        (
            await session.execute(
                select(records.c.request_hash, records.c.response_body).where(
                    records.c.tenant_id == tenant_id,
                    records.c.operation == operation,
                    records.c.idempotency_key == idempotency_key,
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        return None
    if row["request_hash"] != request_sha256:
        raise ApplicationIdempotencyConflict("application_idempotency_mismatch")
    return row["response_body"]


async def _verify_plan_preview_replay(
    session: AsyncSession,
    *,
    command: StageAutonomousCampaignPlanV1,
    operation: str,
    request_sha256: str,
    result: AutonomousCampaignPlanPreviewResultV1,
) -> None:
    preview = await _read_immutable_preview(
        session,
        tenant_id=command.tenant_id,
        campaign_id=command.campaign_id,
        preview_id=result.preview.preview_id,
    )
    if (
        preview != result.preview
        or result.application.tenant_id != command.tenant_id
        or result.application.campaign_id != command.campaign_id
        or result.application.engagement_id != preview.engagement_id
        or result.application.aggregate_revision != preview.application_revision
        or result.application.lifecycle_state is not AutonomousCampaignLifecycle.AWAITING_APPROVAL
        or preview.signed_authority_sha256 != command.signed_authority.signed_authority_sha256
        or preview.authority_sha256 != command.signed_authority.authority.authority_sha256
        or preview.domain_sha256 != command.domain.domain_sha256
        or preview.plan_revision_sha256 != command.revision.revision_sha256
        or preview.certificate_sha256 != command.certificate.certificate_sha256
    ):
        raise ApplicationBindingConflict("plan_preview_replay_immutable_binding_mismatch")
    validated = replace(
        result.application,
        lifecycle_state=AutonomousCampaignLifecycle.PLAN_VALIDATED,
        aggregate_revision=result.application.aggregate_revision - 1,
    )
    await _verify_replay_lineage(
        session,
        state=validated,
        operation=operation,
        request_sha256=request_sha256,
        actor_user_id=command.actor_user_id,
        audit_id=result.audit_ids[0],
        event_id=result.event_ids[0],
        event_type="autonomous_campaign.plan.validated.v1",
        previous_states=(
            AutonomousCampaignLifecycle.INTENT_CREATED,
            AutonomousCampaignLifecycle.AWAITING_APPROVAL,
            AutonomousCampaignLifecycle.APPROVED,
        ),
        event_payload={
            "preview_id": preview.preview_id,
            "preview_sha256": preview.preview_sha256,
            "certificate_sha256": preview.certificate_sha256,
        },
        policy_reference=None,
    )
    await _verify_replay_lineage(
        session,
        state=result.application,
        operation=operation,
        request_sha256=request_sha256,
        actor_user_id=command.actor_user_id,
        audit_id=result.audit_ids[1],
        event_id=result.event_ids[1],
        event_type="autonomous_campaign.plan.awaiting_approval.v1",
        previous_states=(AutonomousCampaignLifecycle.PLAN_VALIDATED,),
        event_payload={
            "preview_id": preview.preview_id,
            "preview_sha256": preview.preview_sha256,
            "expires_at": preview.expires_at.isoformat(),
        },
        policy_reference=None,
    )


async def _verify_approval_decision_replay(
    session: AsyncSession,
    *,
    command: ApproveAutonomousCampaignPlanV1 | DenyAutonomousCampaignPlanV1,
    operation: str,
    request_sha256: str,
    result: AutonomousCampaignApprovalDecisionResultV1,
) -> None:
    receipts = metadata.tables["autonomous_campaign_plan_approval_receipts"]
    row = (
        (
            await session.execute(
                select(receipts).where(
                    receipts.c.tenant_id == command.tenant_id,
                    receipts.c.application_id == command.campaign_id,
                    receipts.c.id == result.receipt.receipt_id,
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ApplicationBindingConflict("approval_replay_immutable_binding_mismatch")
    try:
        immutable_receipt = _verified_receipt_from_payload(
            row["receipt_payload"],
            str(row["receipt_sha256"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ApplicationBindingConflict("approval_replay_immutable_binding_mismatch") from exc
    preview = await _read_immutable_preview(
        session,
        tenant_id=command.tenant_id,
        campaign_id=command.campaign_id,
        preview_id=immutable_receipt.preview_id,
    )
    expected_decision = (
        AutonomousCampaignApprovalDecision.APPROVED
        if isinstance(command, ApproveAutonomousCampaignPlanV1)
        else AutonomousCampaignApprovalDecision.DENIED
    )
    expected_state = (
        AutonomousCampaignLifecycle.APPROVED
        if expected_decision is AutonomousCampaignApprovalDecision.APPROVED
        else AutonomousCampaignLifecycle.DENIED
    )
    if (
        immutable_receipt != result.receipt
        or str(row["contract_version"]) != immutable_receipt.schema_version
        or str(row["decision"]) != immutable_receipt.decision.value
        or str(row["reason_code"]) != immutable_receipt.reason_code
        or str(row["preview_id"]) != immutable_receipt.preview_id
        or int(row["application_revision"]) != immutable_receipt.application_revision
        or str(row["decided_by_user_id"]) != immutable_receipt.approver_user_id
        or immutable_receipt.decision is not expected_decision
        or immutable_receipt.tenant_id != command.tenant_id
        or immutable_receipt.campaign_id != command.campaign_id
        or immutable_receipt.preview_id != command.preview_id
        or immutable_receipt.preview_sha256 != command.preview_sha256
        or immutable_receipt.application_revision != command.expected_revision + 1
        or immutable_receipt.approver_user_id != command.actor_user_id
        or immutable_receipt.permission_set_sha256 != canonical_planning_sha256(command.actor_permissions)
        or immutable_receipt.policy_reference != command.policy_reference
        or immutable_receipt.idempotency_key != command.idempotency_key
        or immutable_receipt.request_sha256 != request_sha256
        or not _receipt_matches_preview(immutable_receipt, preview)
        or result.application.tenant_id != command.tenant_id
        or result.application.campaign_id != command.campaign_id
        or result.application.engagement_id != immutable_receipt.engagement_id
        or result.application.aggregate_revision != immutable_receipt.application_revision
        or result.application.lifecycle_state is not expected_state
    ):
        raise ApplicationBindingConflict("approval_replay_immutable_binding_mismatch")
    await _verify_replay_lineage(
        session,
        state=result.application,
        operation=operation,
        request_sha256=request_sha256,
        actor_user_id=command.actor_user_id,
        audit_id=result.audit_id,
        event_id=result.event_id,
        event_type=(
            "autonomous_campaign.plan.approved.v1"
            if expected_decision is AutonomousCampaignApprovalDecision.APPROVED
            else "autonomous_campaign.plan.denied.v1"
        ),
        previous_states=(AutonomousCampaignLifecycle.AWAITING_APPROVAL,),
        event_payload={
            "preview_id": immutable_receipt.preview_id,
            "preview_sha256": immutable_receipt.preview_sha256,
            "receipt_id": immutable_receipt.receipt_id,
            "receipt_sha256": immutable_receipt.receipt_sha256,
            "reason_code": immutable_receipt.reason_code,
            "policy_reference": immutable_receipt.policy_reference,
        },
        policy_reference=immutable_receipt.policy_reference,
    )


async def _read_immutable_preview(
    session: AsyncSession,
    *,
    tenant_id: str,
    campaign_id: str,
    preview_id: str,
) -> AutonomousCampaignPlanPreviewV1:
    previews = metadata.tables["autonomous_campaign_plan_previews"]
    row = (
        (
            await session.execute(
                select(previews).where(
                    previews.c.tenant_id == tenant_id,
                    previews.c.application_id == campaign_id,
                    previews.c.id == preview_id,
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    if row is None:
        raise ApplicationBindingConflict("plan_preview_replay_immutable_binding_mismatch")
    try:
        preview = _verified_preview_from_payload(row["preview_payload"], str(row["preview_sha256"]))
    except (KeyError, TypeError, ValueError) as exc:
        raise ApplicationBindingConflict("plan_preview_replay_immutable_binding_mismatch") from exc
    if (
        str(row["contract_version"]) != preview.schema_version
        or int(row["application_revision"]) != preview.application_revision
        or str(row["created_by_user_id"]) == ""
        or row["expires_at"] != preview.expires_at
    ):
        raise ApplicationBindingConflict("plan_preview_replay_immutable_binding_mismatch")
    return preview


def _receipt_matches_preview(
    receipt: AutonomousCampaignApprovalReceiptV1,
    preview: AutonomousCampaignPlanPreviewV1,
) -> bool:
    return (
        receipt.tenant_id == preview.tenant_id
        and receipt.campaign_id == preview.campaign_id
        and receipt.engagement_id == preview.engagement_id
        and receipt.application_revision == preview.application_revision + 1
        and receipt.preview_id == preview.preview_id
        and receipt.preview_sha256 == preview.preview_sha256
        and receipt.signed_authority_sha256 == preview.signed_authority_sha256
        and receipt.authority_sha256 == preview.authority_sha256
        and receipt.domain_sha256 == preview.domain_sha256
        and receipt.plan_revision_id == preview.plan_revision_id
        and receipt.plan_revision_sha256 == preview.plan_revision_sha256
        and receipt.plan_sha256 == preview.plan_sha256
        and receipt.certificate_sha256 == preview.certificate_sha256
        and receipt.validator_version == preview.validator_version
        and receipt.validator_sha256 == preview.validator_sha256
        and receipt.target_id == preview.target_id
        and receipt.capability_set_sha256 == preview.capability_set_sha256
        and receipt.authorized_budget_sha256 == preview.authorized_budget.budget_sha256
        and receipt.plan_budget_sha256 == preview.plan_budget.budget_sha256
        and receipt.policy_revision == preview.policy_revision
        and receipt.policy_bundle_sha256 == preview.policy_bundle_sha256
        and receipt.lifecycle_epoch == preview.lifecycle_epoch
        and receipt.policy_revocation_epoch == preview.policy_revocation_epoch
        and receipt.roe_revocation_epoch == preview.roe_revocation_epoch
        and receipt.kill_switch_epoch == preview.kill_switch_epoch
        and receipt.expires_at == preview.expires_at
    )


async def _verify_replay_lineage(
    session: AsyncSession,
    *,
    state: AutonomousCampaignApplicationStateV1,
    operation: str,
    request_sha256: str,
    actor_user_id: str,
    audit_id: str,
    event_id: str,
    event_type: str,
    previous_states: tuple[AutonomousCampaignLifecycle, ...],
    event_payload: dict[str, object],
    policy_reference: str | None,
) -> None:
    events = metadata.tables["autonomous_campaign_application_events"]
    audits = metadata.tables["audit_events"]
    row = (
        (
            await session.execute(
                select(
                    events.c.application_id.label("event_application_id"),
                    events.c.audit_event_id.label("event_audit_id"),
                    events.c.event_sequence,
                    events.c.event_type,
                    events.c.previous_state,
                    events.c.next_state,
                    events.c.actor_user_id.label("event_actor_user_id"),
                    events.c.request_sha256,
                    events.c.lifecycle_sha256,
                    events.c.event_payload,
                    audits.c.actor_user_id.label("audit_actor_user_id"),
                    audits.c.action.label("audit_action"),
                    audits.c.subject_type.label("audit_subject_type"),
                    audits.c.subject_id.label("audit_subject_id"),
                    audits.c.details.label("audit_details"),
                )
                .join(audits, audits.c.id == events.c.audit_event_id)
                .where(
                    events.c.tenant_id == state.tenant_id,
                    audits.c.tenant_id == state.tenant_id,
                    events.c.id == event_id,
                    audits.c.id == audit_id,
                )
            )
        )
        .mappings()
        .one_or_none()
    )
    lifecycle_sha256 = _lifecycle_sha256(state)
    audit_details: dict[str, object] = {
        "aggregate_revision": state.aggregate_revision,
        "lifecycle_sha256": lifecycle_sha256,
    }
    if policy_reference is not None:
        audit_details["policy_reference"] = policy_reference
    if (
        row is None
        or str(row["event_application_id"]) != state.campaign_id
        or str(row["event_audit_id"]) != audit_id
        or int(row["event_sequence"]) != state.aggregate_revision
        or str(row["event_type"]) != event_type
        or str(row["previous_state"]) not in {item.value for item in previous_states}
        or str(row["next_state"]) != state.lifecycle_state.value
        or str(row["event_actor_user_id"]) != actor_user_id
        or str(row["request_sha256"]) != request_sha256
        or str(row["lifecycle_sha256"]) != lifecycle_sha256
        or row["event_payload"] != event_payload
        or str(row["audit_actor_user_id"]) != actor_user_id
        or str(row["audit_action"]) != operation
        or str(row["audit_subject_type"]) != "autonomous_campaign_application"
        or str(row["audit_subject_id"]) != state.campaign_id
        or row["audit_details"] != audit_details
    ):
        # CRITICAL: replay copies are hints; immutable lifecycle and audit lineage remain authoritative.
        raise ApplicationBindingConflict("approval_replay_immutable_binding_mismatch")


async def _read_row(session: AsyncSession, *, tenant_id: str, campaign_id: str) -> RowMapping | None:
    applications = metadata.tables["autonomous_campaign_applications"]
    return (
        (
            await session.execute(
                select(applications).where(
                    applications.c.tenant_id == tenant_id,
                    applications.c.id == campaign_id,
                )
            )
        )
        .mappings()
        .one_or_none()
    )


async def _tenant_context(session: AsyncSession, tenant_id: str) -> None:
    _identifier("tenant_id", tenant_id, 64)
    # CRITICAL: tenant input remains a bound value; interpolation would bypass the RLS boundary.
    await session.execute(
        text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )


async def _lock_idempotency(
    session: AsyncSession,
    *,
    tenant_id: str,
    operation: str,
    idempotency_key: str,
) -> None:
    # CRITICAL: serialize before replay lookup so concurrent retries cannot both mutate lifecycle.
    await session.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": _advisory_lock_key(tenant_id, operation, idempotency_key)},
    )


def _semantic_request_sha256(
    command: CreateAutonomousCampaignIntentV1 | RevokeAutonomousCampaignIntentV1,
) -> str:
    if isinstance(command, CreateAutonomousCampaignIntentV1):
        payload = {
            "schema_version": command.schema_version,
            "tenant_id": command.tenant_id,
            "campaign_id": command.campaign_id,
            "engagement_id": command.engagement_id,
            "target_id": command.target_id,
            "actor_user_id": command.actor_user_id,
            "intent_sha256": command.intent_sha256,
            "source_binding_sha256": command.source_binding_sha256,
            "expected_revision": command.expected_revision,
        }
        if command.mode is not AutonomousCampaignMode.PLAN_ONLY:
            payload["mode"] = command.mode.value
    else:
        payload = {
            "schema_version": command.schema_version,
            "tenant_id": command.tenant_id,
            "campaign_id": command.campaign_id,
            "actor_user_id": command.actor_user_id,
            "reason_sha256": command.reason_sha256,
            "expected_revision": command.expected_revision,
        }
    return _canonical_sha256(payload)


def _approval_request_sha256(
    command: StageAutonomousCampaignPlanV1 | ApproveAutonomousCampaignPlanV1 | DenyAutonomousCampaignPlanV1,
) -> str:
    if isinstance(command, StageAutonomousCampaignPlanV1):
        payload: object = {
            "schema_version": command.schema_version,
            "tenant_id": command.tenant_id,
            "campaign_id": command.campaign_id,
            "actor_user_id": command.actor_user_id,
            "expected_revision": command.expected_revision,
            "signed_authority_sha256": command.signed_authority.signed_authority_sha256,
            "authority_lifecycle": command.authority_lifecycle,
            "domain_sha256": command.domain.domain_sha256,
            "plan_revision_sha256": command.revision.revision_sha256,
            "certificate_sha256": command.certificate.certificate_sha256,
        }
    else:
        return canonical_approval_decision_request_sha256(command)
    return canonical_planning_sha256(payload)


def _lifecycle_sha256(state: AutonomousCampaignApplicationStateV1) -> str:
    return _canonical_sha256(
        {
            "schema_version": state.schema_version,
            "tenant_id": state.tenant_id,
            "campaign_id": state.campaign_id,
            "engagement_id": state.engagement_id,
            "target_id": state.target_id,
            "created_by_user_id": state.created_by_user_id,
            "intent_sha256": state.intent_sha256,
            "source_binding_sha256": state.source_binding_sha256,
            "mode": state.mode.value,
            "lifecycle_state": state.lifecycle_state.value,
            "aggregate_revision": state.aggregate_revision,
            "attention_reason": state.attention_reason,
            "updated_at": state.updated_at.isoformat(),
        }
    )


def _result_payload(result: AutonomousCampaignMutationResultV1) -> dict[str, object]:
    return {
        "application": _state_payload(result.application),
        "audit_id": result.audit_id,
        "event_id": result.event_id,
    }


def _result_from_payload(payload: object, *, replayed: bool) -> AutonomousCampaignMutationResultV1:
    if not isinstance(payload, dict) or not isinstance(payload.get("application"), dict):
        raise ValueError("application_replay_payload_invalid")
    return AutonomousCampaignMutationResultV1(
        application=_state_from_payload(payload["application"]),
        audit_id=str(payload["audit_id"]),
        event_id=str(payload["event_id"]),
        replayed=replayed,
    )


def _plan_preview_result_payload(result: AutonomousCampaignPlanPreviewResultV1) -> dict[str, object]:
    return {
        "application": _state_payload(result.application),
        "preview": _json_payload(result.preview),
        "audit_ids": list(result.audit_ids),
        "event_ids": list(result.event_ids),
    }


def _plan_preview_result_from_payload(
    payload: object,
    *,
    replayed: bool,
) -> AutonomousCampaignPlanPreviewResultV1:
    if not isinstance(payload, dict):
        raise ValueError("plan_preview_replay_payload_invalid")
    audit_ids = _stored_pair("audit_ids", payload.get("audit_ids"))
    event_ids = _stored_pair("event_ids", payload.get("event_ids"))
    return AutonomousCampaignPlanPreviewResultV1(
        application=_state_from_payload(payload.get("application")),
        preview=_preview_from_payload(payload.get("preview")),
        audit_ids=audit_ids,
        event_ids=event_ids,
        replayed=replayed,
    )


def _approval_decision_result_payload(result: AutonomousCampaignApprovalDecisionResultV1) -> dict[str, object]:
    return {
        "application": _state_payload(result.application),
        "receipt": _json_payload(result.receipt),
        "audit_id": result.audit_id,
        "event_id": result.event_id,
    }


def _approval_decision_result_from_payload(
    payload: object,
    *,
    replayed: bool,
) -> AutonomousCampaignApprovalDecisionResultV1:
    if not isinstance(payload, dict):
        raise ValueError("approval_replay_payload_invalid")
    return AutonomousCampaignApprovalDecisionResultV1(
        application=_state_from_payload(payload.get("application")),
        receipt=_receipt_from_payload(payload.get("receipt")),
        audit_id=str(payload["audit_id"]),
        event_id=str(payload["event_id"]),
        replayed=replayed,
    )


def _state_payload(state: AutonomousCampaignApplicationStateV1) -> dict[str, object]:
    return {
        "schema_version": state.schema_version,
        "tenant_id": state.tenant_id,
        "campaign_id": state.campaign_id,
        "engagement_id": state.engagement_id,
        "target_id": state.target_id,
        "created_by_user_id": state.created_by_user_id,
        "intent_sha256": state.intent_sha256,
        "source_binding_sha256": state.source_binding_sha256,
        "mode": state.mode.value,
        "lifecycle_state": state.lifecycle_state.value,
        "aggregate_revision": state.aggregate_revision,
        "attention_reason": state.attention_reason,
        "created_at": state.created_at.isoformat(),
        "updated_at": state.updated_at.isoformat(),
    }


def _state_from_payload(payload: object) -> AutonomousCampaignApplicationStateV1:
    if not isinstance(payload, dict):
        raise ValueError("application_replay_payload_invalid")
    return AutonomousCampaignApplicationStateV1(
        schema_version=str(payload["schema_version"]),
        tenant_id=str(payload["tenant_id"]),
        campaign_id=str(payload["campaign_id"]),
        engagement_id=str(payload["engagement_id"]),
        target_id=str(payload["target_id"]),
        created_by_user_id=str(payload["created_by_user_id"]),
        intent_sha256=str(payload["intent_sha256"]),
        source_binding_sha256=str(payload["source_binding_sha256"]),
        mode=AutonomousCampaignMode(str(payload["mode"])),
        lifecycle_state=AutonomousCampaignLifecycle(str(payload["lifecycle_state"])),
        aggregate_revision=int(payload["aggregate_revision"]),
        attention_reason=None if payload["attention_reason"] is None else str(payload["attention_reason"]),
        created_at=datetime.fromisoformat(str(payload["created_at"])),
        updated_at=datetime.fromisoformat(str(payload["updated_at"])),
    )


def _preview_from_payload(payload: object) -> AutonomousCampaignPlanPreviewV1:
    if not isinstance(payload, dict):
        raise ValueError("plan_preview_payload_invalid")
    actions = _stored_list("actions", payload.get("actions"))
    approvers = _stored_list("required_approvers", payload.get("required_approvers"))
    return AutonomousCampaignPlanPreviewV1(
        child_lineage_sha256=payload.get("child_lineage_sha256"),
        execution_mode=AutonomousCampaignMode(str(payload.get("execution_mode", "plan_only"))),
        execution_bindings=tuple(CapabilityBindingKeyV1(**item) for item in payload.get("execution_bindings", [])),
        schema_version=str(payload["schema_version"]),
        preview_id=str(payload["preview_id"]),
        tenant_id=str(payload["tenant_id"]),
        campaign_id=str(payload["campaign_id"]),
        engagement_id=str(payload["engagement_id"]),
        application_revision=int(payload["application_revision"]),
        application_intent_sha256=str(payload["application_intent_sha256"]),
        source_binding_sha256=str(payload["source_binding_sha256"]),
        signed_authority_sha256=str(payload["signed_authority_sha256"]),
        authority_sha256=str(payload["authority_sha256"]),
        domain_sha256=str(payload["domain_sha256"]),
        plan_revision_id=str(payload["plan_revision_id"]),
        plan_revision_sha256=str(payload["plan_revision_sha256"]),
        plan_sha256=str(payload["plan_sha256"]),
        objective_id=str(payload["objective_id"]),
        objective_sha256=str(payload["objective_sha256"]),
        target_id=str(payload["target_id"]),
        capability_ids=tuple(str(item) for item in _stored_list("capability_ids", payload.get("capability_ids"))),
        capability_set_sha256=str(payload["capability_set_sha256"]),
        effect_classes=tuple(str(item) for item in _stored_list("effect_classes", payload.get("effect_classes"))),
        actions=tuple(_action_from_payload(item) for item in actions),
        authorized_budget=_budget_from_payload("authorized_budget", payload.get("authorized_budget")),
        plan_budget=_budget_from_payload("plan_budget", payload.get("plan_budget")),
        certificate_sha256=str(payload["certificate_sha256"]),
        validator_version=str(payload["validator_version"]),
        validator_sha256=str(payload["validator_sha256"]),
        validation_result=ValidationResult(str(payload["validation_result"])),
        policy_revision=str(payload["policy_revision"]),
        policy_bundle_sha256=str(payload["policy_bundle_sha256"]),
        lifecycle_epoch=int(payload["lifecycle_epoch"]),
        policy_revocation_epoch=int(payload["policy_revocation_epoch"]),
        roe_revocation_epoch=int(payload["roe_revocation_epoch"]),
        kill_switch_epoch=int(payload["kill_switch_epoch"]),
        required_approvers=tuple(_approver_from_payload(item) for item in approvers),
        issued_at=datetime.fromisoformat(str(payload["issued_at"])),
        expires_at=datetime.fromisoformat(str(payload["expires_at"])),
    )


def _verified_preview_from_payload(payload: object, expected_sha256: str) -> AutonomousCampaignPlanPreviewV1:
    preview = _preview_from_payload(payload)
    # CRITICAL: never trust a JSON preview whose immutable row digest no longer matches its content.
    if preview.preview_sha256 != expected_sha256:
        raise ApplicationBindingConflict("plan_preview_persistence_digest_mismatch")
    return preview


def _receipt_from_payload(payload: object) -> AutonomousCampaignApprovalReceiptV1:
    if not isinstance(payload, dict):
        raise ValueError("approval_receipt_payload_invalid")
    values = dict(payload)
    values["decision"] = AutonomousCampaignApprovalDecision(str(values["decision"]))
    values["decided_at"] = datetime.fromisoformat(str(values["decided_at"]))
    values["expires_at"] = datetime.fromisoformat(str(values["expires_at"]))
    return AutonomousCampaignApprovalReceiptV1(**values)


def _verified_receipt_from_payload(payload: object, expected_sha256: str) -> AutonomousCampaignApprovalReceiptV1:
    receipt = _receipt_from_payload(payload)
    # CRITICAL: the immutable relational digest, not a replay copy, authenticates receipt content.
    if receipt.receipt_sha256 != expected_sha256:
        raise ApplicationBindingConflict("approval_receipt_persistence_digest_mismatch")
    return receipt


def _action_from_payload(payload: object) -> AutonomousCampaignPlanActionV1:
    value = _stored_dict("action", payload)
    return AutonomousCampaignPlanActionV1(
        node_id=str(value["node_id"]),
        order=_stored_integer("action_order", value["order"]),
        operator_id=str(value["operator_id"]),
        target_id=str(value["target_id"]),
        capability_id=str(value["capability_id"]),
        capability_revision=_stored_integer("action_capability_revision", value["capability_revision"]),
        effect_class=str(value["effect_class"]),
        executable=_stored_boolean("action_executable", value["executable"]),
        max_duration_seconds=_stored_integer("action_max_duration_seconds", value["max_duration_seconds"]),
        max_requests=_stored_integer("action_max_requests", value["max_requests"]),
        max_rate_per_minute=_stored_integer("action_max_rate_per_minute", value["max_rate_per_minute"]),
        concurrency_weight=_stored_integer("action_concurrency_weight", value["concurrency_weight"]),
        max_retries=_stored_integer("action_max_retries", value["max_retries"]),
        max_risk_micropoints=_stored_integer("action_max_risk_micropoints", value["max_risk_micropoints"]),
        max_cost_microunits=_stored_integer("action_max_cost_microunits", value["max_cost_microunits"]),
        max_evidence_bytes=_stored_integer("action_max_evidence_bytes", value["max_evidence_bytes"]),
        max_data_bytes=_stored_integer("action_max_data_bytes", value["max_data_bytes"]),
        cleanup_mode=CleanupMode(str(value["cleanup_mode"])),
    )


def _budget_from_payload(name: str, payload: object) -> CampaignBudgetVectorV1:
    value = _stored_dict(name, payload)
    return CampaignBudgetVectorV1(
        schema_version=str(value["schema_version"]),
        duration_seconds=_stored_integer(f"{name}_duration_seconds", value["duration_seconds"]),
        requests=_stored_integer(f"{name}_requests", value["requests"]),
        rate_per_minute=_stored_integer(f"{name}_rate_per_minute", value["rate_per_minute"]),
        concurrency=_stored_integer(f"{name}_concurrency", value["concurrency"]),
        risk_micropoints=_stored_integer(f"{name}_risk_micropoints", value["risk_micropoints"]),
        cost_microunits=_stored_integer(f"{name}_cost_microunits", value["cost_microunits"]),
        evidence_bytes=_stored_integer(f"{name}_evidence_bytes", value["evidence_bytes"]),
        data_bytes=_stored_integer(f"{name}_data_bytes", value["data_bytes"]),
    )


def _approver_from_payload(payload: object) -> AutonomousCampaignPlanApproverV1:
    value = _stored_dict("required_approver", payload)
    return AutonomousCampaignPlanApproverV1(
        principal_id=str(value["principal_id"]),
        role_id=str(value["role_id"]),
    )


def _json_payload(value: object) -> dict[str, object]:
    normalized = json.loads(canonical_planning_bytes(value).decode("utf-8"))
    if not isinstance(normalized, dict):
        raise ValueError("approval_persistence_payload_invalid")
    if isinstance(value, AutonomousCampaignPlanPreviewV1) and value.child_lineage_sha256 is None:
        normalized.pop("child_lineage_sha256", None)
    return normalized


def _stored_dict(name: str, value: object) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"application_{name}_invalid")
    return dict(value)


def _stored_list(name: str, value: object) -> list[object]:
    if not isinstance(value, list):
        raise ValueError(f"application_{name}_invalid")
    return value


def _stored_pair(name: str, value: object) -> tuple[str, str]:
    items = _stored_list(name, value)
    if len(items) != 2:
        raise ValueError(f"application_{name}_invalid")
    return str(items[0]), str(items[1])


def _state_from_row(row: RowMapping) -> AutonomousCampaignApplicationStateV1:
    return AutonomousCampaignApplicationStateV1(
        schema_version=str(row["contract_version"]),
        tenant_id=str(row["tenant_id"]),
        campaign_id=str(row["id"]),
        engagement_id=str(row["engagement_id"]),
        target_id=str(row["target_id"]),
        created_by_user_id=str(row["created_by_user_id"]),
        intent_sha256=str(row["intent_sha256"]),
        source_binding_sha256=str(row["source_binding_sha256"]),
        mode=AutonomousCampaignMode(str(row["mode"])),
        lifecycle_state=AutonomousCampaignLifecycle(str(row["lifecycle_state"])),
        aggregate_revision=_stored_integer("aggregate_revision", row["aggregate_revision"]),
        attention_reason=None if row["attention_reason"] is None else str(row["attention_reason"]),
        created_at=_stored_datetime("created_at", row["created_at"]),
        updated_at=_stored_datetime("updated_at", row["updated_at"]),
    )


def _successor_state(
    current: AutonomousCampaignApplicationStateV1,
    *,
    lifecycle_state: AutonomousCampaignLifecycle,
    aggregate_revision: int,
    occurred_at: datetime,
) -> AutonomousCampaignApplicationStateV1:
    return AutonomousCampaignApplicationStateV1(
        schema_version=current.schema_version,
        tenant_id=current.tenant_id,
        campaign_id=current.campaign_id,
        engagement_id=current.engagement_id,
        target_id=current.target_id,
        created_by_user_id=current.created_by_user_id,
        intent_sha256=current.intent_sha256,
        source_binding_sha256=current.source_binding_sha256,
        mode=current.mode,
        lifecycle_state=lifecycle_state,
        aggregate_revision=aggregate_revision,
        attention_reason=None,
        created_at=current.created_at,
        updated_at=occurred_at,
    )


def _canonical_sha256(value: Mapping[str, object]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _advisory_lock_key(tenant_id: str, operation: str, idempotency_key: str) -> int:
    digest = hashlib.sha256(f"{tenant_id}\x1f{operation}\x1f{idempotency_key}".encode("utf-8")).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _identifier(name: str, value: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name}_invalid")


def _stored_integer(name: str, value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValueError(f"application_{name}_invalid")
    return value


def _stored_boolean(name: str, value: object) -> bool:
    if type(value) is not bool:
        raise ValueError(f"application_{name}_invalid")
    return value


def _stored_datetime(name: str, value: object) -> datetime:
    if not isinstance(value, datetime):
        raise ValueError(f"application_{name}_invalid")
    return value
