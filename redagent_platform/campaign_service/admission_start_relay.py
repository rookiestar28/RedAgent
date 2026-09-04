"""Pure bounded delivery for committed R173 start-bridge outbox claims."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Protocol

from redagent_platform.campaign_service.admission_start_contracts import (
    ClaimedAutonomousCampaignStartBridgeV1,
    admission_start_bridge_request_sha256,
    deterministic_admission_start_bridge_workflow_id,
)
from redagent_platform.campaign_service.relay import (
    RelayDeliveryResult,
    WorkflowAlreadyStarted,
    WorkflowNotFound,
    WorkflowStartGateway,
    WorkflowStartUnknown,
    WorkflowStartUnavailable,
)
from redagent_platform.orchestration.admission_start_gateway import (
    workflow_input_from_admission_start_payload,
)


class AutonomousCampaignStartBridgeFailure(str, Enum):
    TRANSIENT_BEFORE_IO = "transient_before_io"
    UNKNOWN_START = "unknown_start"
    BINDING_MISMATCH = "binding_mismatch"
    ABSENT_CONFIRMED = "absent_confirmed"


class AutonomousCampaignStartBridgeRelayRepository(Protocol):
    async def confirm_admission_start_bridge_ready(
        self,
        *,
        event_id: str,
        claim_owner: str,
        payload: dict[str, object],
        occurred_at: datetime,
    ) -> bool: ...

    async def acknowledge_admission_start_bridge(
        self,
        *,
        event_id: str,
        claim_owner: str,
        workflow_run_id: str,
        occurred_at: datetime,
        duplicate_confirmed: bool = False,
    ) -> object: ...

    async def record_admission_start_bridge_failure(
        self,
        *,
        event_id: str,
        claim_owner: str,
        failure: AutonomousCampaignStartBridgeFailure,
        last_error: str,
        occurred_at: datetime,
        max_attempts: int,
    ) -> object: ...


class AutonomousCampaignStartBridgeRelay:
    def __init__(
        self,
        *,
        repository: AutonomousCampaignStartBridgeRelayRepository,
        gateway: WorkflowStartGateway,
        max_attempts: int = 5,
    ) -> None:
        if type(max_attempts) is not int or not 1 <= max_attempts <= 10:
            raise ValueError("start_bridge_relay_max_attempts_invalid")
        self._repository = repository
        self._gateway = gateway
        self._max_attempts = max_attempts

    async def deliver(
        self,
        claim: ClaimedAutonomousCampaignStartBridgeV1,
        *,
        now: datetime,
    ) -> RelayDeliveryResult:
        _aware(now)
        if claim.reconciliation_only:
            return await self._reconcile_unknown(claim, now=now)
        ready = await self._repository.confirm_admission_start_bridge_ready(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            payload=claim.payload,
            occurred_at=now,
        )
        if ready is not True:
            return RelayDeliveryResult.AUTHORITY_DENIED
        request = workflow_input_from_admission_start_payload(claim.payload)
        workflow_id = deterministic_admission_start_bridge_workflow_id(
            request.tenant_id,
            request.execution_run_id,
        )
        request_sha256 = admission_start_bridge_request_sha256(request)
        try:
            receipt = await self._gateway.start(
                workflow_id=workflow_id,
                request_sha256=request_sha256,
                payload=claim.payload,
            )
        except WorkflowAlreadyStarted:
            return await self._reconcile_duplicate(
                claim,
                workflow_id=workflow_id,
                request_sha256=request_sha256,
                now=now,
            )
        except WorkflowStartUnknown as exc:
            await self._failure(
                claim,
                AutonomousCampaignStartBridgeFailure.UNKNOWN_START,
                str(exc),
                now,
            )
            return RelayDeliveryResult.RECONCILIATION_REQUIRED
        except WorkflowStartUnavailable as exc:
            await self._failure(
                claim,
                AutonomousCampaignStartBridgeFailure.TRANSIENT_BEFORE_IO,
                str(exc),
                now,
            )
            return RelayDeliveryResult.RETRY_SCHEDULED
        await self._repository.acknowledge_admission_start_bridge(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            workflow_run_id=receipt.workflow_run_id,
            occurred_at=now,
            duplicate_confirmed=False,
        )
        return RelayDeliveryResult.DELIVERED

    async def _reconcile_duplicate(
        self,
        claim: ClaimedAutonomousCampaignStartBridgeV1,
        *,
        workflow_id: str,
        request_sha256: str,
        now: datetime,
    ) -> RelayDeliveryResult:
        try:
            existing = await self._gateway.query(workflow_id)
        except Exception:  # noqa: BLE001
            # CRITICAL: an unqueryable duplicate may already exist; never issue a second start.
            await self._failure(
                claim,
                AutonomousCampaignStartBridgeFailure.UNKNOWN_START,
                "duplicate_query_unavailable",
                now,
            )
            return RelayDeliveryResult.RECONCILIATION_REQUIRED
        if existing.workflow_id != workflow_id or existing.request_sha256 != request_sha256:
            await self._failure(
                claim,
                AutonomousCampaignStartBridgeFailure.BINDING_MISMATCH,
                "duplicate_binding_mismatch",
                now,
            )
            return RelayDeliveryResult.MANUAL_REVIEW_REQUIRED
        await self._repository.acknowledge_admission_start_bridge(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            workflow_run_id=existing.workflow_run_id,
            occurred_at=now,
            duplicate_confirmed=True,
        )
        return RelayDeliveryResult.DUPLICATE_CONFIRMED

    async def _reconcile_unknown(
        self,
        claim: ClaimedAutonomousCampaignStartBridgeV1,
        *,
        now: datetime,
    ) -> RelayDeliveryResult:
        request = workflow_input_from_admission_start_payload(claim.payload)
        workflow_id = deterministic_admission_start_bridge_workflow_id(
            request.tenant_id,
            request.execution_run_id,
        )
        request_sha256 = admission_start_bridge_request_sha256(request)
        try:
            existing = await self._gateway.query(workflow_id)
        except WorkflowNotFound as exc:
            await self._failure(
                claim,
                AutonomousCampaignStartBridgeFailure.ABSENT_CONFIRMED,
                str(exc),
                now,
            )
            return RelayDeliveryResult.ABSENCE_CONFIRMED
        except Exception:  # noqa: BLE001
            # CRITICAL: query-only recovery must never fall back to start; an unavailable
            # lookup leaves the possibly-started identity charged and durably retryable.
            await self._failure(
                claim,
                AutonomousCampaignStartBridgeFailure.UNKNOWN_START,
                "reconciliation_query_unavailable",
                now,
            )
            return RelayDeliveryResult.RECONCILIATION_REQUIRED
        if existing.workflow_id != workflow_id or existing.request_sha256 != request_sha256:
            await self._failure(
                claim,
                AutonomousCampaignStartBridgeFailure.BINDING_MISMATCH,
                "reconciliation_binding_mismatch",
                now,
            )
            return RelayDeliveryResult.MANUAL_REVIEW_REQUIRED
        await self._repository.acknowledge_admission_start_bridge(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            workflow_run_id=existing.workflow_run_id,
            occurred_at=now,
            duplicate_confirmed=True,
        )
        return RelayDeliveryResult.DUPLICATE_CONFIRMED

    async def _failure(
        self,
        claim: ClaimedAutonomousCampaignStartBridgeV1,
        failure: AutonomousCampaignStartBridgeFailure,
        last_error: str,
        now: datetime,
    ) -> None:
        await self._repository.record_admission_start_bridge_failure(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            failure=failure,
            last_error=(last_error.strip() or "start_bridge_relay_error")[:500],
            occurred_at=now,
            max_attempts=self._max_attempts,
        )


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("start_bridge_relay_now_timezone_required")
