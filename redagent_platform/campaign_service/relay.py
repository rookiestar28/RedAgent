"""Pure bounded delivery decisions for the compat_123 tenant relay."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Protocol

from redagent_platform.campaign_service.repository import ClaimedWorkflowStart
from redagent_platform.campaign_service.resolver import CampaignContextResolver, ResolutionRequest


class OutboxDeliveryState(str, Enum):
    PENDING = "pending"
    CLAIMED = "claimed"
    DELIVERED = "delivered"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    DEAD_LETTER = "dead_letter"


class RelayFailure(str, Enum):
    TRANSIENT = "transient"
    AMBIGUOUS_START = "ambiguous_start"
    PERMANENT = "permanent"


class RelayDeliveryResult(str, Enum):
    DELIVERED = "delivered"
    DUPLICATE_CONFIRMED = "duplicate_confirmed"
    RETRY_SCHEDULED = "retry_scheduled"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    AUTHORITY_DENIED = "authority_denied"


class WorkflowAlreadyStarted(RuntimeError):
    pass


class WorkflowStartUnavailable(RuntimeError):
    pass


@dataclass(frozen=True)
class WorkflowStartReceipt:
    workflow_run_id: str

    def __post_init__(self) -> None:
        _required("workflow_run_id", self.workflow_run_id, 100)


@dataclass(frozen=True)
class WorkflowQueryReceipt:
    workflow_id: str
    request_sha256: str
    workflow_run_id: str

    def __post_init__(self) -> None:
        _required("workflow_id", self.workflow_id, 64)
        _sha256("request_sha256", self.request_sha256)
        _required("workflow_run_id", self.workflow_run_id, 100)


class WorkflowStartGateway(Protocol):
    async def start(
        self, *, workflow_id: str, request_sha256: str, payload: dict[str, object]
    ) -> WorkflowStartReceipt: ...

    async def query(self, workflow_id: str) -> WorkflowQueryReceipt: ...


class WorkflowRelayRepository(Protocol):
    async def acknowledge_workflow_start(
        self,
        *,
        event_id: str,
        claim_owner: str,
        workflow_run_id: str,
        occurred_at: datetime,
        duplicate_confirmed: bool = False,
    ) -> object: ...

    async def record_workflow_start_failure(
        self,
        *,
        event_id: str,
        claim_owner: str,
        failure: RelayFailure,
        last_error: str,
        occurred_at: datetime,
        max_attempts: int,
    ) -> object: ...


@dataclass(frozen=True)
class RelayFailureDecision:
    delivery_state: OutboxDeliveryState
    reconciliation_state: str
    attempt_count: int
    available_at: datetime | None
    dead_lettered_at: datetime | None


class R123WorkflowRelay:
    def __init__(
        self,
        *,
        resolver: CampaignContextResolver,
        repository: WorkflowRelayRepository,
        gateway: WorkflowStartGateway,
        max_attempts: int = 5,
    ) -> None:
        if isinstance(max_attempts, bool) or not 1 <= max_attempts <= 10:
            raise ValueError("relay_max_attempts_invalid")
        self._resolver = resolver
        self._repository = repository
        self._gateway = gateway
        self._max_attempts = max_attempts

    async def deliver(
        self, claim: ClaimedWorkflowStart, *, now: datetime
    ) -> RelayDeliveryResult:
        _aware("relay_now", now)
        payload = _workflow_payload(claim.payload)
        resolution = await self._resolver.resolve(
            ResolutionRequest(
                tenant_id=str(payload["tenant_id"]),
                principal_id=str(payload["principal_id"]),
                engagement_id=str(payload["engagement_id"]),
                target_id=str(payload["target_id"]),
            ),
            now=now,
        )
        if not resolution.allowed:
            await self._failure(
                claim,
                RelayFailure.PERMANENT,
                resolution.reason,
                now,
            )
            return RelayDeliveryResult.AUTHORITY_DENIED
        workflow_id = str(payload["workflow_id"])
        request_sha256 = str(payload["workflow_request_sha256"])
        try:
            receipt = await self._gateway.start(
                workflow_id=workflow_id,
                request_sha256=request_sha256,
                payload=payload,
            )
        except WorkflowAlreadyStarted:
            return await self._reconcile_duplicate(
                claim,
                workflow_id=workflow_id,
                request_sha256=request_sha256,
                now=now,
            )
        except WorkflowStartUnavailable as exc:
            await self._failure(claim, RelayFailure.TRANSIENT, str(exc), now)
            return RelayDeliveryResult.RETRY_SCHEDULED
        await self._repository.acknowledge_workflow_start(
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
        except Exception:
            # CRITICAL: an unqueryable duplicate may already have started; never retry it blindly.
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
        await self._repository.acknowledge_workflow_start(
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
        await self._repository.record_workflow_start_failure(
            event_id=claim.event_id,
            claim_owner=claim.claim_owner,
            failure=failure,
            last_error=_bounded_error(last_error),
            occurred_at=now,
            max_attempts=self._max_attempts,
        )


def apply_relay_failure(
    *,
    attempt_count: int,
    failure: RelayFailure,
    now: datetime,
    max_attempts: int,
) -> RelayFailureDecision:
    if isinstance(attempt_count, bool) or not 1 <= attempt_count <= 10:
        raise ValueError("relay_attempt_count_invalid")
    if isinstance(max_attempts, bool) or not 1 <= max_attempts <= 10:
        raise ValueError("relay_max_attempts_invalid")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("relay_now_timezone_required")
    if not isinstance(failure, RelayFailure):
        raise ValueError("relay_failure_invalid")
    if failure is RelayFailure.AMBIGUOUS_START:
        return RelayFailureDecision(
            delivery_state=OutboxDeliveryState.RECONCILIATION_REQUIRED,
            reconciliation_state="manual_review_required",
            attempt_count=attempt_count,
            available_at=None,
            dead_lettered_at=None,
        )
    if failure is RelayFailure.PERMANENT or attempt_count >= max_attempts:
        return RelayFailureDecision(
            delivery_state=OutboxDeliveryState.DEAD_LETTER,
            reconciliation_state="manual_review_required",
            attempt_count=attempt_count,
            available_at=None,
            dead_lettered_at=now,
        )
    delay_seconds = min(300, 2**attempt_count)
    return RelayFailureDecision(
        delivery_state=OutboxDeliveryState.PENDING,
        reconciliation_state="none",
        attempt_count=attempt_count,
        available_at=now + timedelta(seconds=delay_seconds),
        dead_lettered_at=None,
    )


def _workflow_payload(value: dict[str, object]) -> dict[str, object]:
    expected = {
        "schema_version",
        "tenant_id",
        "principal_id",
        "engagement_id",
        "target_id",
        "campaign_id",
        "strategy_revision_id",
        "workflow_id",
        "workflow_request_sha256",
        "envelope_sha256",
    }
    if not isinstance(value, dict) or set(value) != expected:
        raise ValueError("workflow_start_payload_fields_invalid")
    if value["schema_version"] != "redagent.r123-workflow-start/v1":
        raise ValueError("workflow_start_payload_schema_invalid")
    for name in (
        "tenant_id",
        "principal_id",
        "engagement_id",
        "target_id",
        "campaign_id",
        "strategy_revision_id",
        "workflow_id",
    ):
        _required(name, str(value[name]), 100)
    _sha256("workflow_request_sha256", str(value["workflow_request_sha256"]))
    _sha256("envelope_sha256", str(value["envelope_sha256"]))
    return dict(value)


def _required(name: str, value: str, maximum: int) -> None:
    if not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")


def _bounded_error(value: str) -> str:
    normalized = " ".join(value.split())[:500]
    return normalized or "relay_failure"
