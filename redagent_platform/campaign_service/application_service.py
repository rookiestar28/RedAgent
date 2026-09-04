"""Canonical Phase 26 application-service boundary for autonomous campaign lifecycle state."""

from __future__ import annotations

from collections.abc import Awaitable
from typing import TypeVar

from redagent_platform.campaign_service.application_contracts import (
    ApplicationDependencyUnavailable,
    ApplicationModeDisabled,
    ApplicationNotFound,
    ApplicationOutcomeError,
    AutonomousCampaignApplicationRepository,
    AutonomousCampaignApplicationStateV1,
    AutonomousCampaignMode,
    AutonomousCampaignMutationResultV1,
    AutonomousCampaignReadinessV1,
    CreateAutonomousCampaignIntentV1,
    RevokeAutonomousCampaignIntentV1,
)


_T = TypeVar("_T")


class AutonomousCampaignApplicationService:
    """Own Phase 26 commands while keeping planning and all execution paths unavailable."""

    def __init__(
        self,
        repository: AutonomousCampaignApplicationRepository,
        *,
        mode: AutonomousCampaignMode = AutonomousCampaignMode.PLAN_ONLY,
    ) -> None:
        if not isinstance(mode, AutonomousCampaignMode):
            raise ValueError("autonomous_campaign_mode_invalid")
        self._repository = repository
        self._mode = mode

    @property
    def mode(self) -> AutonomousCampaignMode:
        return self._mode

    async def create_intent(self, command: CreateAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1:
        self._require_enabled()
        if not isinstance(command, CreateAutonomousCampaignIntentV1):
            raise ValueError("create_intent_command_invalid")
        return await _await_repository(self._repository.create_intent(command))

    async def read(self, *, tenant_id: str, campaign_id: str) -> AutonomousCampaignReadinessV1:
        self._require_enabled()
        state = await _await_repository(self._repository.read(tenant_id=tenant_id, campaign_id=campaign_id))
        if state is None:
            raise ApplicationNotFound("autonomous_campaign_not_found")
        return self.project(state)

    async def revoke_intent(self, command: RevokeAutonomousCampaignIntentV1) -> AutonomousCampaignMutationResultV1:
        self._require_enabled()
        if not isinstance(command, RevokeAutonomousCampaignIntentV1):
            raise ValueError("revoke_intent_command_invalid")
        return await _await_repository(self._repository.revoke_intent(command))

    @staticmethod
    def project(state: AutonomousCampaignApplicationStateV1) -> AutonomousCampaignReadinessV1:
        if not isinstance(state, AutonomousCampaignApplicationStateV1):
            raise ValueError("autonomous_campaign_state_invalid")
        return AutonomousCampaignReadinessV1(
            application=state,
            mode=state.mode,
            plan_ready=False,
            approval_ready=False,
            admission_ready=False,
            start_ready=False,
            unavailable_reason="r172_not_accepted",
        )

    def _require_enabled(self) -> None:
        # CRITICAL: every entry point rejects DISABLED before repository access or tenant state leaks.
        if self._mode is AutonomousCampaignMode.DISABLED:
            raise ApplicationModeDisabled("autonomous_campaign_disabled")


async def _await_repository(operation: Awaitable[_T]) -> _T:
    try:
        return await operation
    except ApplicationOutcomeError:
        raise
    except Exception as exc:
        # CRITICAL: never expose driver-specific failures; callers require one closed dependency outcome.
        raise ApplicationDependencyUnavailable("application_dependency_unavailable") from exc
