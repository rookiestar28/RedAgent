"""Immutable successor-on-edit lifecycle for compat_114 proposals."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Mapping

from redagent_platform.workbench.contracts import WorkbenchProposal


@dataclass(frozen=True, kw_only=True)
class SuccessorResult:
    predecessor: WorkbenchProposal
    successor: WorkbenchProposal
    invalidated_approval_id: str | None


def create_successor(predecessor: WorkbenchProposal, *, proposal_id: str,
                     sanitized_arguments: Mapping[str, object], now: datetime) -> SuccessorResult:
    successor = replace(predecessor, proposal_id=proposal_id, revision=predecessor.revision + 1,
                        predecessor_proposal_id=predecessor.proposal_id, sanitized_arguments=dict(sanitized_arguments),
                        approval_id=None, issued_at=now, expires_at=now + timedelta(minutes=2))
    return SuccessorResult(predecessor=predecessor, successor=successor,
                           invalidated_approval_id=predecessor.approval_id)
