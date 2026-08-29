"""Fresh current-revision policy adapter for one DAG pre-I/O decision."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from redagent_platform.policy_service.contracts import (
    PolicyDecision,
    PolicyDecisionInput,
)


class DagPolicyDecisionAdapter:
    def __init__(self, provider: Any) -> None:
        if not callable(getattr(provider, "assess_readiness", None)) or not callable(
            getattr(provider, "decide", None)
        ):
            raise ValueError("dag_policy_provider_invalid")
        self._provider = provider

    async def decide(
        self, request: PolicyDecisionInput, *, now: datetime
    ) -> PolicyDecision:
        if not isinstance(request, PolicyDecisionInput):
            raise ValueError("dag_policy_request_invalid")
        _aware(now)
        required_revision = request.policy_reference
        readiness = await self._provider.assess_readiness(
            required_revision=required_revision
        )
        if (
            getattr(readiness, "ready", None) is not True
            or getattr(readiness, "active_revision", None) != required_revision
            or getattr(readiness, "bundle_plugin_state", None) != "OK"
        ):
            raise ValueError("dag_policy_not_ready")
        decision = await self._provider.decide(
            request,
            required_revision=required_revision,
            now=now,
        )
        if not isinstance(decision, PolicyDecision):
            raise ValueError("dag_policy_decision_invalid")
        decision.assert_current(request, required_revision=required_revision, now=now)
        return decision


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("dag_policy_time_invalid")
