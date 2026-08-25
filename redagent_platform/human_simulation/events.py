"""Signed, minimized, replay-resistant compat_112 event envelopes."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta
import hashlib
import hmac
import json


_CATEGORIES = {"synthetic_accepted", "empty", "rejected_real_or_unknown", "canary_triggered", "reported"}


@dataclass(frozen=True, kw_only=True)
class MinimizedEvent:
    event_id: str; campaign_id: str; message_id: str; category: str; occurred_at: datetime
    def __post_init__(self) -> None:
        if self.category not in _CATEGORIES:
            raise ValueError("human_event_category_invalid")
        if self.occurred_at.tzinfo is None or self.occurred_at.utcoffset() is None:
            raise ValueError("human_event_time_invalid")


@dataclass(frozen=True, kw_only=True)
class SignedEventEnvelope:
    body: str; body_sha256: str; signature_sha256: str


def sign_event(*, event: MinimizedEvent, key: bytes) -> SignedEventEnvelope:
    body = json.dumps(asdict(event), sort_keys=True, separators=(",", ":"), default=str)
    body_sha = hashlib.sha256(body.encode()).hexdigest(); signature = hmac.new(key, body.encode(), hashlib.sha256).hexdigest()
    return SignedEventEnvelope(body=body, body_sha256=body_sha, signature_sha256=signature)


def verify_event(*, envelope: SignedEventEnvelope, key: bytes, now: datetime, seen_event_ids: set[str]) -> MinimizedEvent:
    if hashlib.sha256(envelope.body.encode()).hexdigest() != envelope.body_sha256:
        raise ValueError("human_event_body_digest_invalid")
    expected = hmac.new(key, envelope.body.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, envelope.signature_sha256):
        raise ValueError("human_event_signature_invalid")
    try:
        data = json.loads(envelope.body); occurred = datetime.fromisoformat(data["occurred_at"])
        event = MinimizedEvent(event_id=data["event_id"], campaign_id=data["campaign_id"],
            message_id=data["message_id"], category=data["category"], occurred_at=occurred)
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("human_event_schema_invalid") from exc
    if now.tzinfo is None or now.utcoffset() is None or abs(now - event.occurred_at) > timedelta(minutes=5):
        raise ValueError("human_event_expired")
    if event.event_id in seen_event_ids:
        raise ValueError("human_event_replay")
    seen_event_ids.add(event.event_id)
    return event
