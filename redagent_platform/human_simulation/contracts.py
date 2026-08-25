"""Immutable compat_112 campaign, approval, and authorization contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
import json
import re


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, kw_only=True)
class CampaignManifest:
    campaign_id: str; revision: int; purpose: str; jurisdiction_review_id: str; privacy_review_id: str
    roster_sha256: str; suppression_sha256: str; template_sha256: str; sender: str; recipient: str
    subject: str; body: str; canary_id: str; sink_id: str; scheduled_at: datetime
    max_deliveries: int; rate_per_minute: int; retention_seconds: int; post_notice_id: str
    human_delivery: bool = False; external_delivery: bool = False; relay_allowed: bool = False
    forwarding_allowed: bool = False; tracking_allowed: bool = False; attachments_allowed: bool = False

    def __post_init__(self) -> None:
        for value in (self.campaign_id, self.jurisdiction_review_id, self.privacy_review_id, self.canary_id, self.sink_id, self.post_notice_id):
            _identifier(value)
        for value in (self.roster_sha256, self.suppression_sha256, self.template_sha256):
            _sha(value)
        _aware(self.scheduled_at)
        if self.revision != 1 or self.purpose != "synthetic-security-awareness-sink-qualification":
            raise ValueError("human_campaign_purpose_invalid")
        if self.sender != "awareness@redagent.invalid" or self.recipient != "simulation-recipient@redagent.invalid":
            raise ValueError("human_recipient_boundary_invalid")
        if not self.subject or not self.body or "https://" in self.body or "http://" in self.body:
            raise ValueError("human_template_boundary_invalid")
        if (self.max_deliveries, self.rate_per_minute, self.retention_seconds) != (1, 1, 300):
            raise ValueError("human_campaign_limits_invalid")
        if any((self.human_delivery, self.external_delivery, self.relay_allowed, self.forwarding_allowed,
                self.tracking_allowed, self.attachments_allowed)):
            raise ValueError("human_delivery_boundary_invalid")


@dataclass(frozen=True, kw_only=True)
class CampaignApproval:
    approval_id: str; campaign_id: str; campaign_sha256: str; rendered_sha256: str; test_delivery_sha256: str
    requester_id: str; preview_reviewer_id: str; send_approver_id: str; approved_at: datetime; expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.approval_id, self.campaign_id, self.requester_id, self.preview_reviewer_id, self.send_approver_id):
            _identifier(value)
        for value in (self.campaign_sha256, self.rendered_sha256, self.test_delivery_sha256):
            _sha(value)
        _window(self.approved_at, self.expires_at)
        if len({self.requester_id, self.preview_reviewer_id, self.send_approver_id}) != 3:
            raise ValueError("human_approval_separation_invalid")


@dataclass(frozen=True, kw_only=True)
class CampaignAuthorization:
    authorization_id: str; policy_decision_id: str; policy_revision: str; roe_revision: str
    reservation_id: str; delivery_lease_id: str; stop_switch_id: str; quota_id: str
    campaign_sha256: str; approved_at: datetime; expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.authorization_id, self.policy_decision_id, self.policy_revision, self.roe_revision,
                      self.reservation_id, self.delivery_lease_id, self.stop_switch_id, self.quota_id):
            _identifier(value)
        _sha(self.campaign_sha256); _window(self.approved_at, self.expires_at)


def campaign_sha256(campaign: CampaignManifest) -> str:
    return hashlib.sha256(json.dumps(asdict(campaign), sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("human_identifier_invalid")


def _sha(value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError("human_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("human_time_invalid")


def _window(start: datetime, end: datetime) -> None:
    _aware(start); _aware(end)
    if not start < end:
        raise ValueError("human_time_window_invalid")
