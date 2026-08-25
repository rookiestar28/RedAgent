"""Network-free connector delivery, idempotency, and callback contracts."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
import hashlib
import hmac
import json


@dataclass(frozen=True, kw_only=True)
class ConnectorProfile:
    profile_id: str
    tenant_id: str
    allowed_fields: tuple[str, ...]
    destination_prefix: str
    network_enabled: bool
    credential_reference: str | None
    enabled: bool

    @classmethod
    def fixture(cls, *, profile_id: str, tenant_id: str, allowed_fields: tuple[str, ...]) -> "ConnectorProfile":
        return cls(profile_id=profile_id, tenant_id=tenant_id, allowed_fields=allowed_fields,
                   destination_prefix="fixture-project:", network_enabled=False,
                   credential_reference=None, enabled=True)


@dataclass(frozen=True, kw_only=True)
class Delivery:
    delivery_id: str
    profile_id: str
    snapshot_sha256: str
    destination_object_key: str
    fields_sha256: str
    idempotency_key: str
    state: str
    attempt_count: int
    network_contact_count: int
    occurred_at: datetime


@dataclass(frozen=True, kw_only=True)
class DeliveryLedger:
    deliveries: tuple[Delivery, ...]

    @classmethod
    def empty(cls) -> "DeliveryLedger":
        return cls(deliveries=())


def create_delivery(ledger: DeliveryLedger, *, profile: ConnectorProfile, delivery_id: str,
                    snapshot_sha256: str, destination_object_key: str, fields: dict[str, str],
                    idempotency_key: str, occurred_at: datetime) -> DeliveryLedger:
    if not profile.enabled:
        raise ValueError("connector_profile_disabled")
    if profile.network_enabled:
        raise ValueError("connector_external_network_not_qualified")
    if not destination_object_key.startswith(profile.destination_prefix):
        raise ValueError("connector_destination_not_allowlisted")
    if any(field not in profile.allowed_fields for field in fields):
        raise ValueError("connector_field_not_allowlisted")
    replay = next((item for item in ledger.deliveries if item.idempotency_key == idempotency_key), None)
    if replay is not None:
        expected = _sha({"snapshot": snapshot_sha256, "destination": destination_object_key, "fields": fields})
        if replay.fields_sha256 != expected:
            raise ValueError("connector_idempotency_conflict")
        return ledger
    digest = _sha({"snapshot": snapshot_sha256, "destination": destination_object_key, "fields": fields})
    delivery = Delivery(delivery_id=delivery_id, profile_id=profile.profile_id,
                        snapshot_sha256=snapshot_sha256, destination_object_key=destination_object_key,
                        fields_sha256=digest, idempotency_key=idempotency_key, state="queued",
                        attempt_count=0, network_contact_count=0, occurred_at=occurred_at)
    return replace(ledger, deliveries=ledger.deliveries + (delivery,))


def attempt_fixture_delivery(ledger: DeliveryLedger, *, delivery_id: str, outcome: str,
                             occurred_at: datetime) -> DeliveryLedger:
    del occurred_at
    delivery = _delivery(ledger, delivery_id)
    if delivery.state in {"dead_letter", "delivered", "reconciled"}:
        raise ValueError("connector_delivery_terminal")
    attempts = delivery.attempt_count + 1
    if outcome == "success":
        state = "delivered"
    elif outcome == "transient_failure":
        state = "dead_letter" if attempts >= 3 else "retrying"
    else:
        state = "dead_letter"
    updated = replace(delivery, state=state, attempt_count=attempts, network_contact_count=0)
    return _replace_delivery(ledger, updated)


def revoke_profile(profile: ConnectorProfile) -> ConnectorProfile:
    return replace(profile, enabled=False)


@dataclass(frozen=True, kw_only=True)
class CallbackEnvelope:
    delivery_id: str
    state: str
    nonce: str
    occurred_at: datetime
    signature_sha256: str

    @classmethod
    def sign(cls, *, delivery_id: str, state: str, nonce: str, occurred_at: datetime,
             key: bytes) -> "CallbackEnvelope":
        signature = hmac.new(key, _callback_bytes(delivery_id, state, nonce, occurred_at), hashlib.sha256).hexdigest()
        return cls(delivery_id=delivery_id, state=state, nonce=nonce, occurred_at=occurred_at,
                   signature_sha256=signature)


def verify_callback(envelope: CallbackEnvelope, *, key: bytes, now: datetime, seen_nonces: set[str]) -> None:
    expected = hmac.new(key, _callback_bytes(envelope.delivery_id, envelope.state, envelope.nonce,
                                             envelope.occurred_at), hashlib.sha256).hexdigest()
    # CRITICAL: authenticate before consulting replay state to avoid forged nonce poisoning.
    if not hmac.compare_digest(expected, envelope.signature_sha256):
        raise ValueError("connector_callback_signature_invalid")
    if abs(now - envelope.occurred_at) > timedelta(minutes=5):
        raise ValueError("connector_callback_timestamp_invalid")
    if envelope.nonce in seen_nonces:
        raise ValueError("connector_callback_replay")
    seen_nonces.add(envelope.nonce)


def apply_callback(ledger: DeliveryLedger, *, envelope: CallbackEnvelope, key: bytes,
                   now: datetime, seen_nonces: set[str]) -> DeliveryLedger:
    verify_callback(envelope, key=key, now=now, seen_nonces=seen_nonces)
    delivery = _delivery(ledger, envelope.delivery_id)
    if envelope.state not in {"delivered", "failed"}:
        raise ValueError("connector_callback_state_invalid")
    return _replace_delivery(ledger, replace(delivery, state=envelope.state, network_contact_count=0))


def reconcile_delivery(ledger: DeliveryLedger, *, delivery_id: str, external_state: str,
                       occurred_at: datetime) -> DeliveryLedger:
    del occurred_at
    delivery = _delivery(ledger, delivery_id)
    if delivery.state != "delivered" or external_state != "delivered":
        raise ValueError("connector_reconciliation_mismatch")
    return _replace_delivery(ledger, replace(delivery, state="reconciled", network_contact_count=0))


def _delivery(ledger: DeliveryLedger, delivery_id: str) -> Delivery:
    delivery = next((item for item in ledger.deliveries if item.delivery_id == delivery_id), None)
    if delivery is None:
        raise ValueError("connector_delivery_not_found")
    return delivery


def _replace_delivery(ledger: DeliveryLedger, delivery: Delivery) -> DeliveryLedger:
    return replace(ledger, deliveries=tuple(
        delivery if item.delivery_id == delivery.delivery_id else item for item in ledger.deliveries
    ))


def _callback_bytes(delivery_id: str, state: str, nonce: str, occurred_at: datetime) -> bytes:
    return f"{delivery_id}|{state}|{nonce}|{occurred_at.isoformat()}".encode()


def _sha(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
