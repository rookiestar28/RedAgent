"""Versioned, zero-I/O contracts for the canonical autonomous campaign application."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping, Protocol


APPLICATION_CONTRACT_VERSION = "redagent.autonomous-campaign-application/v1"


class AutonomousCampaignMode(str, Enum):
    DISABLED = "disabled"
    PLAN_ONLY = "plan_only"


class AutonomousCampaignLifecycle(str, Enum):
    INTENT_CREATED = "INTENT_CREATED"
    PLAN_VALIDATED = "PLAN_VALIDATED"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    APPROVED = "APPROVED"
    ADMITTED = "ADMITTED"
    EXECUTION_QUEUED = "EXECUTION_QUEUED"
    RUNNING = "RUNNING"
    EVIDENCE_PENDING = "EVIDENCE_PENDING"
    VERIFIED = "VERIFIED"
    DENIED = "DENIED"
    EXPIRED = "EXPIRED"
    REVOKED = "REVOKED"
    MANUAL_REVIEW_REQUIRED = "MANUAL_REVIEW_REQUIRED"
    RECONCILIATION_REQUIRED = "RECONCILIATION_REQUIRED"
    FAILED_CONTAINED = "FAILED_CONTAINED"
    CLEANUP_INCOMPLETE = "CLEANUP_INCOMPLETE"
    EVIDENCE_INCOMPLETE = "EVIDENCE_INCOMPLETE"


class ApplicationOutcomeError(RuntimeError):
    """Closed application-service outcome that callers may safely classify."""


class ApplicationNotFound(ApplicationOutcomeError):
    """No tenant-visible autonomous campaign exists for the requested identity."""


class ApplicationBindingConflict(ApplicationOutcomeError):
    """A canonical tenant, engagement, target, or actor binding is not valid."""


class ApplicationTransitionConflict(ApplicationOutcomeError):
    """The requested lifecycle edge is outside the closed transition graph."""


class ApplicationRevisionConflict(ApplicationOutcomeError):
    """The expected predecessor revision is not current."""


class ApplicationIdempotencyConflict(ApplicationOutcomeError):
    """An idempotency identity was reused for different semantic input."""


class ApplicationModeDisabled(ApplicationOutcomeError):
    """The autonomous campaign application service is disabled."""


class ApplicationDependencyUnavailable(ApplicationOutcomeError):
    """A required application repository dependency failed closed."""


class ApplicationPlanInvalid(ApplicationOutcomeError):
    """Server-owned plan material is absent, stale, unsupported, or not independently valid."""


class ApplicationPlanUnavailable(ApplicationOutcomeError):
    """No current tenant-visible immutable plan preview is available."""


class ApplicationApprovalForbidden(ApplicationOutcomeError):
    """The current human actor is not permitted to decide the exact preview."""


class ApplicationApprovalExpired(ApplicationOutcomeError):
    """The exact preview is no longer inside its server-owned validity window."""


_ATTENTION_STATES = frozenset(
    {
        AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
        AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
        AutonomousCampaignLifecycle.CLEANUP_INCOMPLETE,
        AutonomousCampaignLifecycle.EVIDENCE_INCOMPLETE,
    }
)
_TERMINAL_STATES = frozenset(
    {
        AutonomousCampaignLifecycle.VERIFIED,
        AutonomousCampaignLifecycle.DENIED,
        AutonomousCampaignLifecycle.EXPIRED,
        AutonomousCampaignLifecycle.REVOKED,
        AutonomousCampaignLifecycle.FAILED_CONTAINED,
    }
)
_FAIL_CLOSED_EDGES = frozenset(
    {
        AutonomousCampaignLifecycle.DENIED,
        AutonomousCampaignLifecycle.EXPIRED,
        AutonomousCampaignLifecycle.REVOKED,
        AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
    }
)
_LIFECYCLE_EDGES: Mapping[AutonomousCampaignLifecycle, frozenset[AutonomousCampaignLifecycle]] = {
    AutonomousCampaignLifecycle.INTENT_CREATED: frozenset(
        {AutonomousCampaignLifecycle.PLAN_VALIDATED, *_FAIL_CLOSED_EDGES}
    ),
    AutonomousCampaignLifecycle.PLAN_VALIDATED: frozenset(
        {AutonomousCampaignLifecycle.AWAITING_APPROVAL, *_FAIL_CLOSED_EDGES}
    ),
    AutonomousCampaignLifecycle.AWAITING_APPROVAL: frozenset(
        {
            AutonomousCampaignLifecycle.APPROVED,
            AutonomousCampaignLifecycle.PLAN_VALIDATED,
            *_FAIL_CLOSED_EDGES,
        }
    ),
    AutonomousCampaignLifecycle.APPROVED: frozenset(
        {
            AutonomousCampaignLifecycle.ADMITTED,
            AutonomousCampaignLifecycle.PLAN_VALIDATED,
            *_FAIL_CLOSED_EDGES,
        }
    ),
    AutonomousCampaignLifecycle.ADMITTED: frozenset(
        {AutonomousCampaignLifecycle.EXECUTION_QUEUED, *_FAIL_CLOSED_EDGES}
    ),
    AutonomousCampaignLifecycle.EXECUTION_QUEUED: frozenset(
        {
            AutonomousCampaignLifecycle.RUNNING,
            AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
            AutonomousCampaignLifecycle.REVOKED,
            AutonomousCampaignLifecycle.FAILED_CONTAINED,
            AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
        }
    ),
    AutonomousCampaignLifecycle.RUNNING: frozenset(
        {
            AutonomousCampaignLifecycle.EVIDENCE_PENDING,
            AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
            AutonomousCampaignLifecycle.REVOKED,
            AutonomousCampaignLifecycle.FAILED_CONTAINED,
            AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
        }
    ),
    AutonomousCampaignLifecycle.EVIDENCE_PENDING: frozenset(
        {
            AutonomousCampaignLifecycle.VERIFIED,
            AutonomousCampaignLifecycle.EVIDENCE_INCOMPLETE,
            AutonomousCampaignLifecycle.CLEANUP_INCOMPLETE,
            AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
        }
    ),
    AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED: frozenset(
        {
            AutonomousCampaignLifecycle.RUNNING,
            AutonomousCampaignLifecycle.FAILED_CONTAINED,
            AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
        }
    ),
    AutonomousCampaignLifecycle.CLEANUP_INCOMPLETE: frozenset(
        {
            AutonomousCampaignLifecycle.EVIDENCE_PENDING,
            AutonomousCampaignLifecycle.FAILED_CONTAINED,
            AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
        }
    ),
    AutonomousCampaignLifecycle.EVIDENCE_INCOMPLETE: frozenset(
        {
            AutonomousCampaignLifecycle.EVIDENCE_PENDING,
            AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
        }
    ),
    **{state: frozenset() for state in _TERMINAL_STATES},
    AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED: frozenset(
        {AutonomousCampaignLifecycle.REVOKED, AutonomousCampaignLifecycle.FAILED_CONTAINED}
    ),
}


def load_autonomous_campaign_mode(env: Mapping[str, str]) -> AutonomousCampaignMode:
    value = env.get("REDAGENT_AUTONOMOUS_CAMPAIGN_MODE", "plan_only").strip().lower()
    try:
        return AutonomousCampaignMode(value)
    except ValueError as exc:
        raise ValueError("autonomous_campaign_mode_invalid") from exc


def assert_lifecycle_transition(
    previous: AutonomousCampaignLifecycle,
    successor: AutonomousCampaignLifecycle,
) -> None:
    if not isinstance(previous, AutonomousCampaignLifecycle) or not isinstance(successor, AutonomousCampaignLifecycle):
        raise ApplicationTransitionConflict("lifecycle_state_unknown")
    if successor not in _LIFECYCLE_EDGES[previous]:
        raise ApplicationTransitionConflict("lifecycle_transition_denied")


@dataclass(frozen=True, slots=True)
class CreateAutonomousCampaignIntentV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    engagement_id: str
    target_id: str
    actor_user_id: str
    intent_sha256: str
    source_binding_sha256: str
    expected_revision: int
    idempotency_key: str
    correlation_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name, value, maximum in (
            ("tenant_id", self.tenant_id, 64),
            ("campaign_id", self.campaign_id, 64),
            ("engagement_id", self.engagement_id, 64),
            ("target_id", self.target_id, 64),
            ("actor_user_id", self.actor_user_id, 64),
            ("idempotency_key", self.idempotency_key, 200),
            ("correlation_id", self.correlation_id, 100),
        ):
            _identifier(name, value, maximum)
        _sha256("intent_sha256", self.intent_sha256)
        _sha256("source_binding_sha256", self.source_binding_sha256)
        if (
            not isinstance(self.expected_revision, int)
            or isinstance(self.expected_revision, bool)
            or self.expected_revision != 0
        ):
            raise ValueError("create_expected_revision_invalid")
        _aware("occurred_at", self.occurred_at)


@dataclass(frozen=True, slots=True)
class RevokeAutonomousCampaignIntentV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    actor_user_id: str
    reason_sha256: str
    expected_revision: int
    idempotency_key: str
    correlation_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name, value, maximum in (
            ("tenant_id", self.tenant_id, 64),
            ("campaign_id", self.campaign_id, 64),
            ("actor_user_id", self.actor_user_id, 64),
            ("idempotency_key", self.idempotency_key, 200),
            ("correlation_id", self.correlation_id, 100),
        ):
            _identifier(name, value, maximum)
        _sha256("reason_sha256", self.reason_sha256)
        if (
            not isinstance(self.expected_revision, int)
            or isinstance(self.expected_revision, bool)
            or self.expected_revision < 1
        ):
            raise ValueError("expected_revision_invalid")
        _aware("occurred_at", self.occurred_at)


@dataclass(frozen=True, slots=True)
class AutonomousCampaignApplicationStateV1:
    schema_version: str
    tenant_id: str
    campaign_id: str
    engagement_id: str
    target_id: str
    created_by_user_id: str
    intent_sha256: str
    source_binding_sha256: str
    mode: AutonomousCampaignMode
    lifecycle_state: AutonomousCampaignLifecycle
    aggregate_revision: int
    attention_reason: str | None
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name, value, maximum in (
            ("tenant_id", self.tenant_id, 64),
            ("campaign_id", self.campaign_id, 64),
            ("engagement_id", self.engagement_id, 64),
            ("target_id", self.target_id, 64),
            ("created_by_user_id", self.created_by_user_id, 64),
        ):
            _identifier(name, value, maximum)
        _sha256("intent_sha256", self.intent_sha256)
        _sha256("source_binding_sha256", self.source_binding_sha256)
        if self.mode is not AutonomousCampaignMode.PLAN_ONLY:
            raise ValueError("application_mode_not_plan_only")
        if not isinstance(self.lifecycle_state, AutonomousCampaignLifecycle):
            raise ValueError("lifecycle_state_unknown")
        if (
            not isinstance(self.aggregate_revision, int)
            or isinstance(self.aggregate_revision, bool)
            or self.aggregate_revision < 1
        ):
            raise ValueError("aggregate_revision_invalid")
        if self.attention_reason is not None:
            _identifier("attention_reason", self.attention_reason, 100)
            if self.lifecycle_state not in _ATTENTION_STATES:
                raise ValueError("attention_reason_state_mismatch")
        _aware("created_at", self.created_at)
        _aware("updated_at", self.updated_at)
        if self.updated_at < self.created_at:
            raise ValueError("application_timestamp_order_invalid")


@dataclass(frozen=True, slots=True)
class AutonomousCampaignMutationResultV1:
    application: AutonomousCampaignApplicationStateV1
    audit_id: str
    event_id: str
    replayed: bool

    def __post_init__(self) -> None:
        _identifier("audit_id", self.audit_id, 64)
        _identifier("event_id", self.event_id, 64)
        if not isinstance(self.replayed, bool):
            raise ValueError("replayed_invalid")


@dataclass(frozen=True, slots=True)
class AutonomousCampaignReadinessV1:
    application: AutonomousCampaignApplicationStateV1
    mode: AutonomousCampaignMode
    plan_ready: bool
    approval_ready: bool
    admission_ready: bool
    start_ready: bool
    unavailable_reason: str


class AutonomousCampaignApplicationRepository(Protocol):
    async def create_intent(self, command: CreateAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1: ...

    async def read(self, *, tenant_id: str, campaign_id: str) -> AutonomousCampaignApplicationStateV1 | None: ...

    async def revoke_intent(self, command: RevokeAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1: ...


def _schema(value: str) -> None:
    if value != APPLICATION_CONTRACT_VERSION:
        raise ValueError("schema_version_unsupported")


def _identifier(name: str, value: str, maximum: int) -> None:
    if not isinstance(value, str) or not value or value != value.strip() or len(value) > maximum:
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")
