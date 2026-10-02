"""Pure bounded delivery for campaign DAG workflow-start outbox claims."""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from redagent_platform.campaign_service.dag_execution_contracts import (
    dag_workflow_request_sha256,
    deterministic_dag_workflow_id,
)
from redagent_platform.campaign_service.relay import (
    RelayDeliveryResult,
    RelayFailure,
    WorkflowAlreadyStarted,
    WorkflowStartGateway,
    WorkflowStartUnavailable,
    WorkflowStartUnknown,
)
from redagent_platform.campaign_service.repository import ClaimedWorkflowStart
from redagent_platform.orchestration.dag_execution_gateway import (
    workflow_input_from_dag_start_payload,
)


class DagWorkflowRelayRepository(Protocol):
    async def acknowledge_dag_workflow_start(
        self,
        *,
        event_id: str,
        claim_owner: str,
        workflow_run_id: str,
        occurred_at: datetime,
        duplicate_confirmed: bool = False,
    ) -> object: ...

    async def record_dag_workflow_start_failure(
        self,
        *,
        event_id: str,
        claim_owner: str,
        failure: RelayFailure,
        last_error: str,
        occurred_at: datetime,
        max_attempts: int,
    ) -> object: ...


class DagWorkflowRelay:
    def __init__(
        self,
        *,
        repository: DagWorkflowRelayRepository,
        gateway: WorkflowStartGateway,
        max_attempts: int = 5,
    ) -> None:
        if type(max_attempts) is not int or not 1 <= max_attempts <= 10:
            raise ValueError("dag_relay_max_attempts_invalid")
        self._repository = repository
        self._gateway = gateway
        self._max_attempts = max_attempts

    async def deliver(
        self, claim: ClaimedWorkflowStart, *, now: datetime
    ) -> RelayDeliveryResult:
        _aware(now)
        request = workflow_input_from_dag_start_payload(claim.payload)
        if claim.campaign_id != request.execution_run_id:
            raise ValueError("dag_relay_claim_aggregate_mismatch")
        workflow_id = deterministic_dag_workflow_id(
            request.tenant_id, request.execution_run_id
        )
        request_sha256 = dag_workflow_request_sha256(request)
        if claim.reconciliation_only:
            return await self._reconcile_duplicate(
                claim, workflow_id=workflow_id, request_sha256=request_sha256, now=now
            )
        try:
            receipt = await self._gateway.start(
                workflow_id=workflow_id,
                request_sha256=request_sha256,
                payload=claim.payload,
            )
        except (WorkflowAlreadyStarted, WorkflowStartUnknown):
            return await self._reconcile_duplicate(
                claim,
                workflow_id=workflow_id,
                request_sha256=request_sha256,
                now=now,
            )
        except WorkflowStartUnavailable as exc:
            await self._failure(claim, RelayFailure.TRANSIENT, str(exc), now)
            return RelayDeliveryResult.RETRY_SCHEDULED
        await self._repository.acknowledge_dag_workflow_start(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            workflow_run_id=receipt.workflow_run_id,
            occurred_at=now,
            duplicate_confirmed=False,
        )
        return RelayDeliveryResult.DELIVERED

    async def _reconcile_duplicate(
        self,
        claim: ClaimedWorkflowStart,
        *,
        workflow_id: str,
        request_sha256: str,
        now: datetime,
    ) -> RelayDeliveryResult:
        try:
            existing = await self._gateway.query(workflow_id)
        except Exception:  # noqa: BLE001
            # CRITICAL: an unqueryable duplicate may already exist; never retry start blindly.
            await self._failure(
                claim,
                RelayFailure.AMBIGUOUS_START,
                "duplicate_query_unavailable",
                now,
            )
            return RelayDeliveryResult.RECONCILIATION_REQUIRED
        if (
            existing.workflow_id != workflow_id
            or existing.request_sha256 != request_sha256
        ):
            await self._failure(
                claim,
                RelayFailure.AMBIGUOUS_START,
                "duplicate_binding_mismatch",
                now,
            )
            return RelayDeliveryResult.RECONCILIATION_REQUIRED
        await self._repository.acknowledge_dag_workflow_start(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            workflow_run_id=existing.workflow_run_id,
            occurred_at=now,
            duplicate_confirmed=True,
        )
        return RelayDeliveryResult.DUPLICATE_CONFIRMED

    async def _failure(
        self,
        claim: ClaimedWorkflowStart,
        failure: RelayFailure,
        last_error: str,
        now: datetime,
    ) -> None:
        await self._repository.record_dag_workflow_start_failure(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            failure=failure,
            last_error=_bounded_error(last_error),
            occurred_at=now,
            max_attempts=self._max_attempts,
        )


def _bounded_error(value: str) -> str:
    normalized = value.strip() if isinstance(value, str) else "relay_error"
    return (normalized or "relay_error")[:500]


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("dag_relay_now_timezone_required")
