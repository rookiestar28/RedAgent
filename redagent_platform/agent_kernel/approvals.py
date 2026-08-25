"""Exact one-time compat_113 proposal approval binding."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
import hashlib
import json
from typing import Mapping

from redagent_platform.agent_kernel.contracts import ModelBudget


@dataclass(frozen=True, kw_only=True)
class ProposalContext:
    proposal_id: str
    tenant_id: str
    operator_id: str
    campaign_id: str
    tool_fqn: str
    tool_schema_sha256: str
    arguments: Mapping[str, object]
    target_ids: tuple[str, ...]
    roe_version_id: str
    policy_revision: str
    policy_decision_id: str
    credential_class: str
    egress_class: str
    side_effects: tuple[str, ...]
    budget: ModelBudget
    registry_sha256: str
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _aware(self.issued_at)
        _aware(self.expires_at)
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=5):
            raise ValueError("proposal_expiry_invalid")
        if not self.target_ids or not self.side_effects or not isinstance(self.arguments, Mapping):
            raise ValueError("proposal_context_invalid")


@dataclass(frozen=True, kw_only=True)
class ApprovalGrant:
    approval_id: str
    proposal_sha256: str
    approved_by: str
    issued_at: datetime
    expires_at: datetime
    nonce: str

    def __post_init__(self) -> None:
        _aware(self.issued_at)
        _aware(self.expires_at)
        if not self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=5):
            raise ValueError("approval_expiry_invalid")
        if len(self.proposal_sha256) != 64:
            raise ValueError("approval_proposal_sha256_invalid")

    @classmethod
    def for_proposal(cls, proposal: ProposalContext, **values: object) -> "ApprovalGrant":
        if values.get("approved_by") == proposal.operator_id:
            raise ValueError("approval_separation_required")
        return cls(proposal_sha256=proposal_sha256(proposal), **values)  # type: ignore[arg-type]


@dataclass(frozen=True, kw_only=True)
class ApprovalConsumptionReceipt:
    approval_id: str
    proposal_sha256: str
    consumed: bool
    consumed_at: datetime


class ApprovalLedger:
    def __init__(self) -> None:
        self._consumed: set[tuple[str, str]] = set()

    def consume(self, grant: ApprovalGrant, proposal: ProposalContext, *, tenant_id: str, now: datetime) -> ApprovalConsumptionReceipt:
        # CRITICAL: approval consumption must rebind every mutable fact and remain one-time.
        _aware(now)
        if proposal.tenant_id != tenant_id:
            raise ValueError("approval_tenant_mismatch")
        if grant.approved_by == proposal.operator_id:
            raise ValueError("approval_separation_required")
        if not grant.issued_at <= now < grant.expires_at or now >= proposal.expires_at:
            raise ValueError("approval_expired")
        if grant.proposal_sha256 != proposal_sha256(proposal):
            raise ValueError("approval_binding_mismatch")
        key = (tenant_id, grant.nonce)
        if key in self._consumed:
            raise ValueError("approval_replayed")
        self._consumed.add(key)
        return ApprovalConsumptionReceipt(
            approval_id=grant.approval_id,
            proposal_sha256=grant.proposal_sha256,
            consumed=True,
            consumed_at=now,
        )


def proposal_sha256(proposal: ProposalContext) -> str:
    return hashlib.sha256(json.dumps(_normalize(asdict(proposal)), sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()).hexdigest()


def _normalize(value: object) -> object:
    if isinstance(value, datetime):
        _aware(value)
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, Mapping):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")
