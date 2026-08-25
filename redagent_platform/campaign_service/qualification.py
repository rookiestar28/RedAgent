"""Bounded compat_123 owned-loopback qualification and readiness application boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Protocol

from redagent_platform.campaign_service.registry import (
    ExecutionReadinessFacts,
    StrategyLoopMode,
    StrategyLoopReadiness,
    evaluate_strategy_loop_readiness,
)
from redagent_platform.campaign_service.repository import CampaignTransitionResult
from redagent_platform.campaign_service.service import (
    CampaignStartRequest,
    R123CampaignStartService,
)


_FIXTURE_ID = "owned-loopback-http-first-slice"
_OBJECTIVES = frozenset({"http_posture", "security_header_assertion"})


@dataclass(frozen=True, slots=True, kw_only=True)
class OwnedLoopbackQualificationIntentV1:
    """The complete caller-visible compat_123 qualification intent.

    Authentication supplies tenant/principal identity. The fixed fixture owner supplies every
    engagement, target, runner, lease, workflow, and campaign identity server-side.
    """

    fixture_id: str
    objective_kind: str
    header_code: str | None
    require_corroboration: bool
    risk_profile: str
    schema_version: str = "redagent.r123-owned-loopback-qualification-intent/v1"

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r123-owned-loopback-qualification-intent/v1":
            raise ValueError("r123_qualification_schema_invalid")
        if self.fixture_id != _FIXTURE_ID:
            raise ValueError("r123_qualification_fixture_invalid")
        if self.objective_kind not in _OBJECTIVES:
            raise ValueError("r123_qualification_objective_invalid")
        if self.objective_kind == "security_header_assertion":
            if self.header_code != "x-content-type-options":
                raise ValueError("r123_qualification_header_invalid")
        elif self.header_code is not None:
            raise ValueError("r123_qualification_header_forbidden")
        if not isinstance(self.require_corroboration, bool):
            raise ValueError("r123_qualification_corroboration_invalid")
        if self.risk_profile != "tier1_passive":
            raise ValueError("r123_qualification_risk_profile_denied")

    def to_public_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True, kw_only=True)
class QualificationFixtureBinding:
    """Server-owned stable business selection for the sole compat_123 qualification fixture."""

    fixture_id: str
    engagement_id: str
    target_id: str
    campaign_name: str

    def __post_init__(self) -> None:
        if self.fixture_id != _FIXTURE_ID:
            raise ValueError("r123_qualification_fixture_invalid")
        for name, value, maximum in (
            ("engagement", self.engagement_id, 64),
            ("target", self.target_id, 64),
            ("campaign_name", self.campaign_name, 200),
        ):
            _text(f"r123_qualification_{name}", value, maximum)


class QualificationFixtureOwner(Protocol):
    async def read_owned_loopback_fixture(
        self,
        *,
        tenant_id: str,
        principal_id: str,
        fixture_id: str,
        now: datetime,
    ) -> QualificationFixtureBinding: ...


class CampaignStarter(Protocol):
    async def start(
        self, request: CampaignStartRequest, *, now: datetime
    ) -> CampaignTransitionResult: ...


@dataclass(frozen=True, slots=True)
class QualificationStartReceiptV1:
    schema_version: str
    campaign_id: str
    aggregate_sequence: int
    status: str

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.r123-qualification-start-receipt/v1":
            raise ValueError("r123_qualification_receipt_schema_invalid")
        _text("r123_qualification_campaign", self.campaign_id, 64)
        if self.aggregate_sequence != 1 or self.status != "dispatch_pending":
            raise ValueError("r123_qualification_receipt_state_invalid")


class R123QualificationService:
    """Resolve the fixed fixture then delegate to the canonical compat_123 start service."""

    def __init__(
        self,
        fixtures: QualificationFixtureOwner,
        starter: CampaignStarter | R123CampaignStartService,
    ) -> None:
        self._fixtures = fixtures
        self._starter = starter

    async def start(
        self,
        intent: OwnedLoopbackQualificationIntentV1,
        *,
        tenant_id: str,
        principal_id: str,
        now: datetime,
    ) -> QualificationStartReceiptV1:
        if not isinstance(intent, OwnedLoopbackQualificationIntentV1):
            raise ValueError("r123_qualification_intent_invalid")
        _aware(now)
        _text("r123_qualification_tenant", tenant_id, 64)
        _text("r123_qualification_principal", principal_id, 64)
        binding = await self._fixtures.read_owned_loopback_fixture(
            tenant_id=tenant_id,
            principal_id=principal_id,
            fixture_id=intent.fixture_id,
            now=now,
        )
        if not isinstance(binding, QualificationFixtureBinding):
            raise ValueError("r123_qualification_fixture_binding_invalid")
        # CRITICAL: do not add caller-supplied runtime IDs here; the canonical start service owns them.
        result = await self._starter.start(
            CampaignStartRequest(
                tenant_id=tenant_id,
                principal_id=principal_id,
                engagement_id=binding.engagement_id,
                target_id=binding.target_id,
                name=binding.campaign_name,
                objective_kind=intent.objective_kind,
                header_code=intent.header_code,
                require_corroboration=intent.require_corroboration,
                risk_profile=intent.risk_profile,
            ),
            now=now,
        )
        if not isinstance(result, CampaignTransitionResult):
            raise ValueError("r123_qualification_start_receipt_invalid")
        return QualificationStartReceiptV1(
            schema_version="redagent.r123-qualification-start-receipt/v1",
            campaign_id=result.campaign_id,
            aggregate_sequence=result.aggregate_sequence,
            status="dispatch_pending",
        )


class StrategyLoopFactsOwner(Protocol):
    async def read(self, *, now: datetime) -> ExecutionReadinessFacts: ...


class R123StatusService:
    """Project closed readiness without allowing a disabled path to touch dependencies."""

    def __init__(
        self,
        mode: StrategyLoopMode,
        facts_owner: StrategyLoopFactsOwner | None,
    ) -> None:
        if not isinstance(mode, StrategyLoopMode):
            raise ValueError("r123_status_mode_invalid")
        if mode is StrategyLoopMode.TWO_CAPABILITY and facts_owner is None:
            raise ValueError("r123_status_facts_owner_required")
        self._mode = mode
        self._facts_owner = facts_owner

    @property
    def mode(self) -> StrategyLoopMode:
        """Expose the immutable activation mode for composition validation."""
        return self._mode

    async def read(self, *, now: datetime) -> StrategyLoopReadiness:
        _aware(now)
        if self._mode is StrategyLoopMode.DISABLED:
            return evaluate_strategy_loop_readiness(
                self._mode,
                ExecutionReadinessFacts(**{
                    name: False
                    for name in ExecutionReadinessFacts.__dataclass_fields__
                }),
            )
        assert self._facts_owner is not None
        facts = await self._facts_owner.read(now=now)
        if not isinstance(facts, ExecutionReadinessFacts):
            raise ValueError("r123_status_readiness_facts_invalid")
        return evaluate_strategy_loop_readiness(self._mode, facts)


def _text(name: str, value: object, maximum: int) -> None:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError(f"{name}_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("r123_qualification_time_timezone_required")
