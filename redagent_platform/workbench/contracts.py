"""Closed compat_114 trust-lane, proposal, and disclosure contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
from enum import Enum
import hashlib
import json
import re
from typing import Mapping


_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN = frozenset({"credential", "secret", "token", "raw_evidence", "reasoning", "prompt", "message",
                        "command", "shell", "url", "headers", "environment", "runner", "dispatch"})


class TrustLane(str, Enum):
    TRUSTED_OPERATOR = "trusted_operator"
    IMMUTABLE_AUTHORITY = "immutable_authority"
    UNTRUSTED_EXTERNAL = "untrusted_external"
    AI_SUGGESTION = "ai_suggestion"
    APPROVAL = "approval"
    EXECUTION_RESULT = "execution_result"
    REVIEWER_CONCLUSION = "reviewer_conclusion"


@dataclass(frozen=True, kw_only=True)
class WorkbenchItem:
    item_id: str
    lane: TrustLane
    summary: str
    provenance_sha256: str

    def __post_init__(self) -> None:
        _identifier(self.item_id)
        if not isinstance(self.lane, TrustLane):
            raise ValueError("workbench_lane_invalid")
        if not isinstance(self.summary, str) or not 1 <= len(self.summary.encode()) <= 4096:
            raise ValueError("workbench_summary_invalid")
        _sha256(self.provenance_sha256)


@dataclass(frozen=True, kw_only=True)
class WorkbenchProposal:
    proposal_id: str
    campaign_id: str
    revision: int
    predecessor_proposal_id: str | None
    server_id: str
    server_inventory_sha256: str
    tool_fqn: str
    tool_schema_sha256: str
    sanitized_arguments: Mapping[str, object]
    target_ids: tuple[str, ...]
    roe_version_id: str
    policy_revision: str
    policy_decision_id: str
    credential_class: str
    egress_class: str
    side_effects: tuple[str, ...]
    disclosure_fields: tuple[str, ...]
    budget_sha256: str
    approval_id: str | None
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.proposal_id, self.campaign_id, self.server_id, self.tool_fqn, self.roe_version_id,
                      self.policy_revision, self.policy_decision_id):
            _identifier(value)
        if self.predecessor_proposal_id is not None:
            _identifier(self.predecessor_proposal_id)
        if self.approval_id is not None:
            _identifier(self.approval_id)
        for value in (self.server_inventory_sha256, self.tool_schema_sha256, self.budget_sha256):
            _sha256(value)
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or self.revision < 1:
            raise ValueError("workbench_revision_invalid")
        if not self.target_ids or not self.side_effects or not self.disclosure_fields:
            raise ValueError("workbench_proposal_context_incomplete")
        for values in (self.target_ids, self.side_effects, self.disclosure_fields):
            for value in values:
                _identifier(value)
        _reject_forbidden(self.sanitized_arguments)
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None or not (
            self.issued_at < self.expires_at <= self.issued_at + timedelta(minutes=5)
        ):
            raise ValueError("workbench_expiry_invalid")


def proposal_sha256(proposal: WorkbenchProposal) -> str:
    values = asdict(proposal)
    values.pop("approval_id")
    values["issued_at"] = proposal.issued_at.isoformat()
    values["expires_at"] = proposal.expires_at.isoformat()
    return hashlib.sha256(json.dumps(values, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _reject_forbidden(value: object) -> None:
    if isinstance(value, Mapping):
        for key, nested in value.items():
            if str(key).lower() in _FORBIDDEN:
                raise ValueError("workbench_argument_forbidden")
            _reject_forbidden(nested)
    elif isinstance(value, (tuple, list)):
        for nested in value:
            _reject_forbidden(nested)


def _identifier(value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError("workbench_identifier_invalid")


def _sha256(value: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError("workbench_sha256_invalid")
