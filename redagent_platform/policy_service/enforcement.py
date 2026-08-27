"""Reusable fail-closed enforcement point for every compat_099 trust boundary."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import re
from typing import Protocol

from redagent_platform.policy_service.contracts import PolicyDecision, PolicyDecisionInput
from redagent_platform.policy_service.providers import PolicyProviderReadiness


_OPERATION = re.compile(r"^[a-z][a-z0-9_.:-]{0,99}$")


class PolicyEnforcementError(RuntimeError):
    pass


class PolicyDecisionProvider(Protocol):
    async def assess_readiness(self, *, required_revision: str) -> PolicyProviderReadiness: ...

    async def decide(
        self,
        request: PolicyDecisionInput,
        *,
        required_revision: str,
        now: datetime,
    ) -> PolicyDecision: ...


class PolicyDecisionRecorder(Protocol):
    async def persist_decision_and_receipt(
        self,
        request: PolicyDecisionInput,
        decision: PolicyDecision,
        *,
        operation: str,
    ) -> str: ...


@dataclass(frozen=True, slots=True)
class PolicyEnforcementResult:
    decision_id: str
    receipt_id: str
    bundle_revision: str
    input_hash: str
    obligations: tuple[str, ...]


class PolicyBoundaryEnforcer:
    """Evaluate current facts and atomically require an audit receipt.

    Provider decisions are short-lived results, never reusable capabilities.
    The recorder owns the database transaction that writes decision, boundary
    receipt, immutable audit event, and outbox event.
    """

    def __init__(self, provider: PolicyDecisionProvider, recorder: PolicyDecisionRecorder) -> None:
        if provider is None or recorder is None:
            raise ValueError("policy_enforcer_dependency_required")
        self._provider = provider
        self._recorder = recorder

    async def assess_readiness(self, *, required_revision: str) -> PolicyProviderReadiness:
        try:
            return await self._provider.assess_readiness(required_revision=required_revision)
        except Exception as exc:
            raise PolicyEnforcementError("policy_provider_not_ready") from exc

    async def enforce(
        self,
        request: PolicyDecisionInput,
        *,
        required_revision: str,
        operation: str,
        now: datetime,
    ) -> PolicyEnforcementResult:
        if not isinstance(request, PolicyDecisionInput) or not isinstance(operation, str) or not _OPERATION.fullmatch(operation):
            raise PolicyEnforcementError("policy_enforcement_request_invalid")
        try:
            decision = await self._provider.decide(
                request, required_revision=required_revision, now=now,
            )
            # CRITICAL: every PEP revalidates revision, hash, and lifetime even if the provider adapter already did.
            decision.assert_current(request, required_revision=required_revision, now=now)
        except Exception as exc:
            raise PolicyEnforcementError("policy_decision_invalid") from exc
        try:
            receipt_id = await self._recorder.persist_decision_and_receipt(
                request, decision, operation=operation,
            )
        except Exception as exc:
            raise PolicyEnforcementError("policy_decision_persistence_failed") from exc
        if not isinstance(receipt_id, str) or not receipt_id or len(receipt_id) > 100:
            raise PolicyEnforcementError("policy_decision_persistence_failed")
        if not decision.allowed:
            raise PolicyEnforcementError(f"policy_boundary_denied:{decision.reason_code}")
        return PolicyEnforcementResult(
            decision_id=decision.decision_id,
            receipt_id=receipt_id,
            bundle_revision=decision.bundle_revision,
            input_hash=decision.input_hash,
            obligations=tuple(item.value for item in decision.obligations),
        )
