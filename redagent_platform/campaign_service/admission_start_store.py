"""Atomic PostgreSQL owner for R173 admission, execution material, and start intent."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import hashlib
import json
import re
from sqlalchemy import insert, or_, select, text, update
from sqlalchemy.engine import RowMapping
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.admission_contracts import (
    AdmissionOutcome,
    CampaignBudgetVectorV1,
    PlanAdmissionReceiptV1,
)
from redagent_platform.campaign_service.admission_repository import (
    AdmissionReservationCommandV1,
    CampaignAdmissionRepository,
    _receipt_from_payload,
)
from redagent_platform.campaign_service.admission_start_contracts import (
    ADMISSION_START_BRIDGE_EVENT_TYPE,
    ADMISSION_START_BRIDGE_SCHEMA_VERSION,
    AutonomousCampaignAdmissionContextV1,
    AutonomousCampaignAdmissionStartCommandV1,
    AutonomousCampaignAdmissionStartResultV1,
    AutonomousCampaignAdmissionStartState,
    AutonomousCampaignApprovalBundleV1,
    AutonomousCampaignStartBridgeWorkflowInputV1,
    admission_start_bridge_request_sha256,
    canonical_admission_start_request_sha256,
    deterministic_admission_start_bridge_workflow_id,
)
from redagent_platform.campaign_service.application_contracts import (
    ApplicationBindingConflict,
    ApplicationIdempotencyConflict,
    ApplicationPlanInvalid,
    ApplicationRevisionConflict,
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignLifecycle,
    assert_lifecycle_transition,
)
from redagent_platform.campaign_service.application_repository import (
    _record_lifecycle_event,
    _state_from_row,
    _verified_preview_from_payload,
    _verified_receipt_from_payload,
)
from redagent_platform.campaign_service.dag_execution_service import (
    DagExecutionStartRequestV1,
    prepare_dag_execution_start,
)
from redagent_platform.campaign_service.dag_execution_store import (
    CampaignDagExecutionRepository,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes
from redagent_platform.persistence.models import metadata


_ADMISSION_START_OPERATION = "autonomous_campaign.admission_start.v1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,199}$")


class PostgresAutonomousCampaignAdmissionStartStore:
    """Adapt R158 to one R173 caller-owned transaction and exact replay boundary."""

    def __init__(
        self,
        sessions: async_sessionmaker[AsyncSession],
        *,
        command: AutonomousCampaignAdmissionStartCommandV1,
        bundle: AutonomousCampaignApprovalBundleV1,
        context: AutonomousCampaignAdmissionContextV1,
    ) -> None:
        if not callable(sessions) or not isinstance(
            command, AutonomousCampaignAdmissionStartCommandV1
        ):
            raise ValueError("admission_start_store_dependency_invalid")
        if not isinstance(bundle, AutonomousCampaignApprovalBundleV1) or not isinstance(
            context, AutonomousCampaignAdmissionContextV1
        ):
            raise ValueError("admission_start_store_material_invalid")
        if (
            command.tenant_id != bundle.application.tenant_id
            or command.campaign_id != bundle.application.campaign_id
            or context.tenant_id != command.tenant_id
            or context.campaign_id != command.campaign_id
        ):
            raise ValueError("admission_start_store_binding_mismatch")
        self._sessions = sessions
        self._command = command
        self._bundle = bundle
        self._context = context
        self._request_sha256 = canonical_admission_start_request_sha256(command)

    async def replay(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        idempotency_key: str,
        request_sha256: str,
    ) -> AutonomousCampaignAdmissionStartResultV1 | None:
        self._assert_lookup(tenant_id, campaign_id, idempotency_key)
        async with self._sessions() as session, session.begin():
            await _tenant_context(session, tenant_id)
            receipt_row = await _read_admission_receipt_row(
                session,
                tenant_id=tenant_id,
                campaign_id=campaign_id,
                idempotency_key=idempotency_key,
            )
            if receipt_row is None:
                return None
            if str(receipt_row["request_sha256"]) != request_sha256:
                raise ApplicationIdempotencyConflict("plan_admission_idempotency_mismatch")
            receipt = _receipt_from_payload(receipt_row["receipt_payload"])
            return await self._result_for_receipt(session, receipt, replayed=True)

    async def preview_residual(
        self,
        *,
        tenant_id: str,
        campaign_id: str,
        envelope_sha256: str,
        authorized_budget: CampaignBudgetVectorV1,
    ) -> CampaignBudgetVectorV1:
        self._assert_lookup(
            tenant_id,
            campaign_id,
            self._command.idempotency_key,
        )
        async with self._sessions() as session, session.begin():
            return await self._admission_repository(session).preview_residual(
                campaign_id=campaign_id,
                envelope_sha256=envelope_sha256,
                authorized=authorized_budget,
            )

    async def admit(
        self,
        command: AdmissionReservationCommandV1,
    ) -> AutonomousCampaignAdmissionStartResultV1:
        self._assert_admission_command(command)
        try:
            async with self._sessions() as session, session.begin():
                await _tenant_context(session, self._command.tenant_id)
                await self._lock_application_scope(session)
                replay = await self._locked_replay(
                    session,
                    request_sha256=command.request_sha256,
                )
                if replay is not None:
                    return replay
                current = await self._lock_current_bundle(session)
                admission_receipt = await self._admission_repository(session).admit(command)
                if admission_receipt.outcome is not AdmissionOutcome.ADMITTED:
                    raise ApplicationPlanInvalid("admission_start_receipt_not_admitted")

                execution_id = deterministic_autonomous_execution_id(
                    self._command.tenant_id,
                    self._command.campaign_id,
                    self._command.approval_receipt_id,
                )
                node_count = len(self._context.revision.candidate_plan.nodes)
                material = await prepare_dag_execution_start(
                    DagExecutionStartRequestV1(
                        tenant_id=self._command.tenant_id,
                        principal_id=self._command.actor_user_id,
                        campaign_id=self._command.campaign_id,
                        engagement_id=current.engagement_id,
                        execution_id=execution_id,
                        idempotency_key=self._command.idempotency_key,
                        revision=self._context.revision,
                        domain=self._context.domain,
                        certificate=self._context.certificate,
                        admission_receipt=admission_receipt,
                        max_activity_attempts=2,
                        max_transitions=min(10_000, max(16, node_count * 8)),
                    ),
                    now=self._command.occurred_at,
                )
                await CampaignDagExecutionRepository(
                    session,
                    tenant_id=self._command.tenant_id,
                    actor_user_id=self._command.actor_user_id,
                    correlation_id=self._command.correlation_id,
                ).insert_prepared_material(material, now=self._command.occurred_at)

                bridge_input = AutonomousCampaignStartBridgeWorkflowInputV1(
                    schema_version=ADMISSION_START_BRIDGE_SCHEMA_VERSION,
                    tenant_id=self._command.tenant_id,
                    campaign_id=self._command.campaign_id,
                    execution_run_id=material.execution_run_id,
                    input_sha256=material.input_sha256,
                    approval_receipt_sha256=self._command.approval_receipt_sha256,
                    admission_receipt_sha256=admission_receipt.receipt_sha256,
                )
                workflow_id = deterministic_admission_start_bridge_workflow_id(
                    self._command.tenant_id,
                    material.execution_run_id,
                )
                workflow_request_sha256 = admission_start_bridge_request_sha256(bridge_input)
                stable = hashlib.sha256(
                    (
                        f"r173-start\0{self._command.tenant_id}\0"
                        f"{self._command.campaign_id}\0{self._command.approval_receipt_id}"
                    ).encode("utf-8")
                ).hexdigest()[:40]
                start_id = f"autostart-{stable}"
                outbox_id = f"outbox-autostart-{stable[:32]}"

                successor = await _transition_application(
                    session,
                    current=current,
                    target=AutonomousCampaignLifecycle.ADMITTED,
                    operation=_ADMISSION_START_OPERATION,
                    event_type="autonomous_campaign.admitted.v1",
                    actor_user_id=self._command.actor_user_id,
                    correlation_id=self._command.correlation_id,
                    request_sha256=self._request_sha256,
                    policy_reference=self._command.policy_reference,
                    event_payload={
                        "approval_receipt_id": self._command.approval_receipt_id,
                        "approval_receipt_sha256": self._command.approval_receipt_sha256,
                        "admission_receipt_id": admission_receipt.receipt_id,
                        "admission_receipt_sha256": admission_receipt.receipt_sha256,
                        "reservation_id": admission_receipt.reservation_id,
                        "execution_run_id": material.execution_run_id,
                        "workflow_id": workflow_id,
                        "workflow_request_sha256": workflow_request_sha256,
                    },
                    occurred_at=self._command.occurred_at,
                )
                state, application_audit_id, application_event_id = successor
                workflow_payload = _json_payload(bridge_input)
                await session.execute(
                    insert(metadata.tables["autonomous_campaign_execution_starts"]).values(
                        id=start_id,
                        application_id=self._command.campaign_id,
                        approved_revision=current.aggregate_revision,
                        admitted_revision=state.aggregate_revision,
                        preview_id=self._bundle.preview.preview_id,
                        approval_receipt_id=self._command.approval_receipt_id,
                        approval_receipt_sha256=self._command.approval_receipt_sha256,
                        admission_receipt_id=admission_receipt.receipt_id,
                        admission_receipt_sha256=admission_receipt.receipt_sha256,
                        reservation_id=admission_receipt.reservation_id,
                        execution_run_id=material.execution_run_id,
                        workflow_id=workflow_id,
                        workflow_run_id=None,
                        idempotency_key=self._command.idempotency_key,
                        request_sha256=self._request_sha256,
                        workflow_request_sha256=workflow_request_sha256,
                        workflow_input_payload=workflow_payload,
                        input_sha256=material.input_sha256,
                        signed_authority_sha256=material.signed_authority_sha256,
                        authority_sha256=material.authority_sha256,
                        domain_sha256=material.domain_sha256,
                        plan_sha256=material.plan_sha256,
                        certificate_sha256=material.certificate_sha256,
                        reserved_budget_sha256=material.reserved_budget_sha256,
                        policy_revision=self._context.signed_authority.authority.policy_revision,
                        policy_bundle_sha256=admission_receipt.policy_bundle_sha256,
                        lifecycle_epoch=material.lifecycle_epoch,
                        policy_revocation_epoch=material.policy_revocation_epoch,
                        roe_revocation_epoch=material.roe_revocation_epoch,
                        kill_switch_epoch=material.kill_switch_epoch,
                        outbox_event_id=outbox_id,
                        outbox_event_type=ADMISSION_START_BRIDGE_EVENT_TYPE,
                        application_audit_id=application_audit_id,
                        application_event_id=application_event_id,
                        start_state=AutonomousCampaignAdmissionStartState.START_PENDING.value,
                        reason_code=None,
                        issued_at=self._command.occurred_at,
                        expires_at=admission_receipt.expires_at,
                        tenant_id=self._command.tenant_id,
                        version=1,
                        created_at=self._command.occurred_at,
                        updated_at=self._command.occurred_at,
                    )
                )
                await session.execute(
                    insert(metadata.tables["outbox_events"]).values(
                        id=outbox_id,
                        event_type=ADMISSION_START_BRIDGE_EVENT_TYPE,
                        aggregate_id=start_id,
                        payload=workflow_payload,
                        published=False,
                        schema_revision=2,
                        aggregate_type="autonomous_campaign_start",
                        aggregate_sequence=1,
                        available_at=self._command.occurred_at,
                        claim_owner=None,
                        claim_expires_at=None,
                        attempt_count=0,
                        last_error=None,
                        delivered_at=None,
                        delivery_state="pending",
                        reconciliation_state="none",
                        dead_lettered_at=None,
                        tenant_id=self._command.tenant_id,
                        version=1,
                        created_at=self._command.occurred_at,
                        updated_at=self._command.occurred_at,
                    )
                )
                link_row = await _read_start_row(
                    session,
                    tenant_id=self._command.tenant_id,
                    application_id=self._command.campaign_id,
                    admission_receipt_id=admission_receipt.receipt_id,
                )
                if link_row is None:
                    raise RuntimeError("admission_start_link_insert_missing")
                return _admitted_result(
                    application=state,
                    approval_receipt_id=self._command.approval_receipt_id,
                    approval_receipt_sha256=self._command.approval_receipt_sha256,
                    admission_receipt=admission_receipt,
                    link=link_row,
                    replayed=False,
                )
        except IntegrityError as exc:
            raise ApplicationBindingConflict("admission_start_persistence_conflict") from exc

    async def deny(self, **values: object) -> AutonomousCampaignAdmissionStartResultV1:
        context = values.get("context")
        if not isinstance(context, dict) or context.get("tenant_id") != self._command.tenant_id:
            raise ValueError("admission_start_denial_context_invalid")
        request_sha256 = str(values["request_sha256"])
        try:
            async with self._sessions() as session, session.begin():
                await _tenant_context(session, self._command.tenant_id)
                await self._lock_application_scope(session)
                replay = await self._locked_replay(
                    session,
                    request_sha256=request_sha256,
                )
                if replay is not None:
                    return replay
                current = await self._lock_current_bundle(session)
                receipt = await self._admission_repository(session).deny(**values)
                if receipt.outcome is not AdmissionOutcome.DENIED:
                    raise ApplicationPlanInvalid("admission_start_denial_receipt_invalid")
                target = _denial_application_state(receipt.reason_code)
                state, application_audit_id, application_event_id = await _transition_application(
                    session,
                    current=current,
                    target=target,
                    operation=_ADMISSION_START_OPERATION,
                    event_type=f"autonomous_campaign.admission_{target.value.lower()}.v1",
                    actor_user_id=self._command.actor_user_id,
                    correlation_id=self._command.correlation_id,
                    request_sha256=self._request_sha256,
                    policy_reference=self._command.policy_reference,
                    event_payload={
                        "approval_receipt_id": self._command.approval_receipt_id,
                        "approval_receipt_sha256": self._command.approval_receipt_sha256,
                        "admission_receipt_id": receipt.receipt_id,
                        "admission_receipt_sha256": receipt.receipt_sha256,
                        "denial_stage": receipt.denial_stage,
                        "reason_code": receipt.reason_code,
                    },
                    occurred_at=self._command.occurred_at,
                )
                return _denied_result(
                    application=state,
                    approval_receipt_id=self._command.approval_receipt_id,
                    approval_receipt_sha256=self._command.approval_receipt_sha256,
                    admission_receipt=receipt,
                    application_audit_id=application_audit_id,
                    application_event_id=application_event_id,
                    replayed=False,
                )
        except IntegrityError as exc:
            raise ApplicationBindingConflict("admission_start_denial_persistence_conflict") from exc

    async def _locked_replay(
        self,
        session: AsyncSession,
        *,
        request_sha256: str,
    ) -> AutonomousCampaignAdmissionStartResultV1 | None:
        row = await _read_admission_receipt_row(
            session,
            tenant_id=self._command.tenant_id,
            campaign_id=self._command.campaign_id,
            idempotency_key=self._command.idempotency_key,
        )
        if row is None:
            collision = await _read_start_collision(
                session,
                tenant_id=self._command.tenant_id,
                application_id=self._command.campaign_id,
                approval_receipt_id=self._command.approval_receipt_id,
                idempotency_key=self._command.idempotency_key,
            )
            if collision is not None:
                raise ApplicationIdempotencyConflict("admission_start_identity_collision")
            return None
        if str(row["request_sha256"]) != request_sha256:
            raise ApplicationIdempotencyConflict("plan_admission_idempotency_mismatch")
        receipt = _receipt_from_payload(row["receipt_payload"])
        return await self._result_for_receipt(session, receipt, replayed=True)

    async def _result_for_receipt(
        self,
        session: AsyncSession,
        receipt: PlanAdmissionReceiptV1,
        *,
        replayed: bool,
    ) -> AutonomousCampaignAdmissionStartResultV1:
        application = await _read_application_state(
            session,
            tenant_id=self._command.tenant_id,
            campaign_id=self._command.campaign_id,
        )
        if receipt.outcome is AdmissionOutcome.ADMITTED:
            link = await _read_start_row(
                session,
                tenant_id=self._command.tenant_id,
                application_id=self._command.campaign_id,
                admission_receipt_id=receipt.receipt_id,
            )
            if link is None:
                raise ApplicationBindingConflict("admission_start_link_missing")
            self._verify_link(link, receipt)
            return _admitted_result(
                application=application,
                approval_receipt_id=self._command.approval_receipt_id,
                approval_receipt_sha256=self._command.approval_receipt_sha256,
                admission_receipt=receipt,
                link=link,
                replayed=replayed,
            )
        event = await _read_application_event(
            session,
            tenant_id=self._command.tenant_id,
            campaign_id=self._command.campaign_id,
            event_sequence=application.aggregate_revision,
        )
        if event is None:
            raise ApplicationBindingConflict("admission_start_denial_event_missing")
        return _denied_result(
            application=application,
            approval_receipt_id=self._command.approval_receipt_id,
            approval_receipt_sha256=self._command.approval_receipt_sha256,
            admission_receipt=receipt,
            application_audit_id=str(event["audit_event_id"]),
            application_event_id=str(event["id"]),
            replayed=replayed,
        )

    async def _lock_application_scope(self, session: AsyncSession) -> None:
        await session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {
                "scope": (
                    f"autonomous-admission-start:{self._command.tenant_id}:"
                    f"{self._command.campaign_id}"
                )
            },
        )

    async def _lock_current_bundle(
        self,
        session: AsyncSession,
    ) -> AutonomousCampaignApplicationStateV1:
        applications = metadata.tables["autonomous_campaign_applications"]
        approvals = metadata.tables["autonomous_campaign_plan_approval_receipts"]
        previews = metadata.tables["autonomous_campaign_plan_previews"]
        application_row = (
            (
                await session.execute(
                    select(applications)
                    .where(
                        applications.c.tenant_id == self._command.tenant_id,
                        applications.c.id == self._command.campaign_id,
                    )
                    .with_for_update()
                )
            )
            .mappings()
            .one_or_none()
        )
        approval_row = (
            (
                await session.execute(
                    select(approvals)
                    .where(
                        approvals.c.tenant_id == self._command.tenant_id,
                        approvals.c.application_id == self._command.campaign_id,
                        approvals.c.id == self._command.approval_receipt_id,
                    )
                    .with_for_update()
                )
            )
            .mappings()
            .one_or_none()
        )
        preview_row = (
            (
                await session.execute(
                    select(previews)
                    .where(
                        previews.c.tenant_id == self._command.tenant_id,
                        previews.c.application_id == self._command.campaign_id,
                        previews.c.id == self._bundle.preview.preview_id,
                    )
                    .with_for_update()
                )
            )
            .mappings()
            .one_or_none()
        )
        if application_row is None or approval_row is None or preview_row is None:
            raise ApplicationPlanInvalid("admission_start_approval_rows_missing")
        current = _state_from_row(application_row)
        approval = _verified_receipt_from_payload(
            approval_row["receipt_payload"], str(approval_row["receipt_sha256"])
        )
        preview = _verified_preview_from_payload(
            preview_row["preview_payload"], str(preview_row["preview_sha256"])
        )
        if (
            current != self._bundle.application
            or approval != self._bundle.approval_receipt
            or preview != self._bundle.preview
            or current.lifecycle_state is not AutonomousCampaignLifecycle.APPROVED
            or current.aggregate_revision != self._command.expected_revision
        ):
            raise ApplicationRevisionConflict("admission_start_approval_changed")
        return current

    def _verify_link(
        self,
        link: RowMapping,
        receipt: PlanAdmissionReceiptV1,
    ) -> None:
        if (
            link["application_id"] != self._command.campaign_id
            or link["approval_receipt_id"] != self._command.approval_receipt_id
            or link["approval_receipt_sha256"] != self._command.approval_receipt_sha256
            or link["admission_receipt_id"] != receipt.receipt_id
            or link["admission_receipt_sha256"] != receipt.receipt_sha256
            or link["idempotency_key"] != self._command.idempotency_key
            or link["request_sha256"] != self._request_sha256
            or link["outbox_event_type"] != ADMISSION_START_BRIDGE_EVENT_TYPE
        ):
            raise ApplicationIdempotencyConflict("admission_start_replay_mismatch")

    def _assert_lookup(
        self,
        tenant_id: str,
        campaign_id: str,
        idempotency_key: str,
    ) -> None:
        if (
            tenant_id != self._command.tenant_id
            or campaign_id != self._command.campaign_id
            or idempotency_key != self._command.idempotency_key
        ):
            raise ValueError("admission_start_lookup_binding_mismatch")

    def _assert_admission_command(self, command: AdmissionReservationCommandV1) -> None:
        if not isinstance(command, AdmissionReservationCommandV1):
            raise ValueError("admission_start_admission_command_invalid")
        if (
            command.policy_request.tenant_id != self._command.tenant_id
            or command.campaign_id != self._command.campaign_id
            or command.engagement_id != self._bundle.application.engagement_id
            or command.idempotency_key != self._command.idempotency_key
            or command.issued_at != self._command.occurred_at
            or command.signed_authority_sha256
            != self._context.signed_authority.signed_authority_sha256
        ):
            raise ValueError("admission_start_admission_binding_mismatch")

    def _admission_repository(self, session: AsyncSession) -> CampaignAdmissionRepository:
        return CampaignAdmissionRepository(
            session,
            tenant_id=self._command.tenant_id,
            actor_user_id=self._command.actor_user_id,
            correlation_id=self._command.correlation_id,
        )


def deterministic_autonomous_execution_id(
    tenant_id: str,
    campaign_id: str,
    approval_receipt_id: str,
) -> str:
    for value in (tenant_id, campaign_id, approval_receipt_id):
        if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
            raise ValueError("autonomous_execution_identity_invalid")
    stable = hashlib.sha256(
        f"autonomous-execution-v1\0{tenant_id}\0{campaign_id}\0{approval_receipt_id}".encode(
            "utf-8"
        )
    ).hexdigest()[:40]
    return f"autonomous-execution-{stable}"


async def _tenant_context(session: AsyncSession, tenant_id: str) -> None:
    await session.execute(
        text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
        {"tenant_id": tenant_id},
    )


async def _read_admission_receipt_row(
    session: AsyncSession,
    *,
    tenant_id: str,
    campaign_id: str,
    idempotency_key: str,
) -> RowMapping | None:
    receipts = metadata.tables["plan_admission_receipts"]
    return (
        (
            await session.execute(
                select(receipts).where(
                    receipts.c.tenant_id == tenant_id,
                    receipts.c.campaign_id == campaign_id,
                    receipts.c.idempotency_key == idempotency_key,
                )
            )
        )
        .mappings()
        .one_or_none()
    )


async def _read_start_collision(
    session: AsyncSession,
    *,
    tenant_id: str,
    application_id: str,
    approval_receipt_id: str,
    idempotency_key: str,
) -> RowMapping | None:
    starts = metadata.tables["autonomous_campaign_execution_starts"]
    return (
        (
            await session.execute(
                select(starts).where(
                    starts.c.tenant_id == tenant_id,
                    or_(
                        (
                            (starts.c.application_id == application_id)
                            & (starts.c.approval_receipt_id == approval_receipt_id)
                        ),
                        (
                            (starts.c.application_id == application_id)
                            & (starts.c.idempotency_key == idempotency_key)
                        ),
                    ),
                )
            )
        )
        .mappings()
        .one_or_none()
    )


async def _read_start_row(
    session: AsyncSession,
    *,
    tenant_id: str,
    application_id: str,
    admission_receipt_id: str,
) -> RowMapping | None:
    starts = metadata.tables["autonomous_campaign_execution_starts"]
    return (
        (
            await session.execute(
                select(starts).where(
                    starts.c.tenant_id == tenant_id,
                    starts.c.application_id == application_id,
                    starts.c.admission_receipt_id == admission_receipt_id,
                )
            )
        )
        .mappings()
        .one_or_none()
    )


async def _read_application_state(
    session: AsyncSession,
    *,
    tenant_id: str,
    campaign_id: str,
) -> AutonomousCampaignApplicationStateV1:
    applications = metadata.tables["autonomous_campaign_applications"]
    row = (
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
    if row is None:
        raise ApplicationBindingConflict("admission_start_application_missing")
    return _state_from_row(row)


async def _read_application_event(
    session: AsyncSession,
    *,
    tenant_id: str,
    campaign_id: str,
    event_sequence: int,
) -> RowMapping | None:
    events = metadata.tables["autonomous_campaign_application_events"]
    return (
        (
            await session.execute(
                select(events).where(
                    events.c.tenant_id == tenant_id,
                    events.c.application_id == campaign_id,
                    events.c.event_sequence == event_sequence,
                )
            )
        )
        .mappings()
        .one_or_none()
    )


async def _transition_application(
    session: AsyncSession,
    *,
    current: AutonomousCampaignApplicationStateV1,
    target: AutonomousCampaignLifecycle,
    operation: str,
    event_type: str,
    actor_user_id: str,
    correlation_id: str,
    request_sha256: str,
    policy_reference: str,
    event_payload: dict[str, object],
    occurred_at: datetime,
    attention_reason: str | None = None,
) -> tuple[AutonomousCampaignApplicationStateV1, str, str]:
    assert_lifecycle_transition(current.lifecycle_state, target)
    successor = replace(
        current,
        lifecycle_state=target,
        aggregate_revision=current.aggregate_revision + 1,
        attention_reason=attention_reason,
        updated_at=occurred_at,
    )
    applications = metadata.tables["autonomous_campaign_applications"]
    changed = await session.execute(
        update(applications)
        .where(
            applications.c.tenant_id == current.tenant_id,
            applications.c.id == current.campaign_id,
            applications.c.aggregate_revision == current.aggregate_revision,
            applications.c.lifecycle_state == current.lifecycle_state.value,
        )
        .values(
            lifecycle_state=successor.lifecycle_state.value,
            aggregate_revision=successor.aggregate_revision,
            attention_reason=successor.attention_reason,
            version=applications.c.version + 1,
            updated_at=occurred_at,
        )
    )
    if getattr(changed, "rowcount", None) != 1:
        raise ApplicationRevisionConflict("application_revision_conflict")
    audit_id, event_id = await _record_lifecycle_event(
        session,
        state=successor,
        operation=operation,
        correlation_id=correlation_id,
        actor_user_id=actor_user_id,
        request_sha256=request_sha256,
        event_type=event_type,
        previous_state=current.lifecycle_state,
        event_payload=event_payload,
        policy_reference=policy_reference,
        occurred_at=occurred_at,
    )
    return successor, audit_id, event_id


def _admitted_result(
    *,
    application: AutonomousCampaignApplicationStateV1,
    approval_receipt_id: str,
    approval_receipt_sha256: str,
    admission_receipt: PlanAdmissionReceiptV1,
    link: RowMapping,
    replayed: bool,
) -> AutonomousCampaignAdmissionStartResultV1:
    return AutonomousCampaignAdmissionStartResultV1(
        application=application,
        approval_receipt_id=approval_receipt_id,
        approval_receipt_sha256=approval_receipt_sha256,
        admission_receipt=admission_receipt,
        execution_run_id=str(link["execution_run_id"]),
        workflow_id=str(link["workflow_id"]),
        workflow_run_id=(
            None if link["workflow_run_id"] is None else str(link["workflow_run_id"])
        ),
        workflow_request_sha256=str(link["workflow_request_sha256"]),
        input_sha256=str(link["input_sha256"]),
        start_state=AutonomousCampaignAdmissionStartState(str(link["start_state"])),
        start_reason_code=(
            None if link["reason_code"] is None else str(link["reason_code"])
        ),
        audit_ids=tuple(
            sorted(
                {
                    admission_receipt.audit_id,
                    str(link["application_audit_id"]),
                }
            )
        ),
        event_ids=(str(link["application_event_id"]),),
        outbox_event_id=str(link["outbox_event_id"]),
        replayed=replayed,
    )


def _denied_result(
    *,
    application: AutonomousCampaignApplicationStateV1,
    approval_receipt_id: str,
    approval_receipt_sha256: str,
    admission_receipt: PlanAdmissionReceiptV1,
    application_audit_id: str,
    application_event_id: str,
    replayed: bool,
) -> AutonomousCampaignAdmissionStartResultV1:
    return AutonomousCampaignAdmissionStartResultV1(
        application=application,
        approval_receipt_id=approval_receipt_id,
        approval_receipt_sha256=approval_receipt_sha256,
        admission_receipt=admission_receipt,
        execution_run_id=None,
        workflow_id=None,
        workflow_run_id=None,
        workflow_request_sha256=None,
        input_sha256=None,
        start_state=None,
        start_reason_code=None,
        audit_ids=tuple(sorted({admission_receipt.audit_id, application_audit_id})),
        event_ids=(application_event_id,),
        outbox_event_id=None,
        replayed=replayed,
    )


def _denial_application_state(reason_code: str) -> AutonomousCampaignLifecycle:
    normalized = reason_code.lower()
    if "expired" in normalized:
        return AutonomousCampaignLifecycle.EXPIRED
    if "revoked" in normalized or "kill_switch" in normalized:
        return AutonomousCampaignLifecycle.REVOKED
    return AutonomousCampaignLifecycle.DENIED


def _json_payload(value: object) -> dict[str, object]:
    payload = json.loads(canonical_planning_bytes(value))
    if not isinstance(payload, dict):
        raise ValueError("admission_start_payload_invalid")
    return payload
