"""In-process compat_112 sink with no SMTP, DNS, relay, forward, or external webhook capability."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib

from redagent_platform.human_simulation.compiler import CompiledCampaignPlan, verify_plan_integrity


@dataclass(frozen=True, kw_only=True)
class DeliveryReceipt:
    run_id: str; message_id: str; message_sha256: str; captured: bool; human_delivered: bool
    external_contact_count: int; relay_count: int; forward_count: int; occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class DeletionReceipt:
    run_id: str; deleted_message_count: int; residual_message_count: int; zero_residual: bool; occurred_at: datetime


class OwnedMessageSink:
    def __init__(self) -> None:
        self._messages: dict[str, tuple[str, str, str, str]] = {}

    @property
    def count(self) -> int:
        return len(self._messages)

    def deliver(self, *, plan: CompiledCampaignPlan, run_id: str, occurred_at: datetime) -> DeliveryReceipt:
        verify_plan_integrity(plan)
        if self._messages:
            raise ValueError("human_delivery_quota_exceeded")
        message_id = f"message-{run_id}"; material = (plan.sender, plan.recipient, plan.subject, plan.body)
        self._messages[message_id] = material
        digest = hashlib.sha256("\n".join(material).encode()).hexdigest()
        return DeliveryReceipt(run_id=run_id, message_id=message_id, message_sha256=digest, captured=True,
            human_delivered=False, external_contact_count=0, relay_count=0, forward_count=0, occurred_at=occurred_at)

    def delete(self, *, plan: CompiledCampaignPlan, run_id: str, occurred_at: datetime) -> DeletionReceipt:
        verify_plan_integrity(plan); count = len(self._messages); self._messages.clear()
        return DeletionReceipt(run_id=run_id, deleted_message_count=count, residual_message_count=0,
            zero_residual=True, occurred_at=occurred_at)
