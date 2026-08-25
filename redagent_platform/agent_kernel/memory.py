"""Encrypted ephemeral memory and reviewed digest-only fact contracts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from redagent_platform.agent_kernel.contracts import TrustLabel


@dataclass(frozen=True, kw_only=True)
class WorkingMemoryRecord:
    tenant_id: str
    memory_id: str
    ciphertext: bytes
    nonce: bytes
    trust_label: TrustLabel
    created_at: datetime
    expires_at: datetime


class WorkingMemoryVault:
    def __init__(self, *, key: bytes, max_plaintext_bytes: int) -> None:
        if len(key) != 32:
            raise ValueError("memory_key_invalid")
        self._cipher = AESGCM(key)
        self._maximum = max_plaintext_bytes
        self._records: dict[str, WorkingMemoryRecord] = {}

    def put(self, *, tenant_id: str, memory_id: str, plaintext: bytes, trust_label: TrustLabel, now: datetime, ttl: timedelta) -> WorkingMemoryRecord:
        if not isinstance(plaintext, bytes) or not plaintext or len(plaintext) > self._maximum:
            raise ValueError("memory_size_exceeded")
        if not timedelta(seconds=1) <= ttl <= timedelta(hours=24):
            raise ValueError("memory_ttl_invalid")
        nonce = os.urandom(12)
        aad = f"{tenant_id}:{memory_id}:{trust_label.value}".encode()
        record = WorkingMemoryRecord(
            tenant_id=tenant_id,
            memory_id=memory_id,
            ciphertext=self._cipher.encrypt(nonce, plaintext, aad),
            nonce=nonce,
            trust_label=trust_label,
            created_at=now,
            expires_at=now + ttl,
        )
        self._records[memory_id] = record
        return record

    def get(self, *, tenant_id: str, memory_id: str, now: datetime) -> bytes:
        record = self._records[memory_id]
        if record.tenant_id != tenant_id:
            raise ValueError("memory_tenant_mismatch")
        if now >= record.expires_at:
            raise ValueError("memory_expired")
        aad = f"{tenant_id}:{memory_id}:{record.trust_label.value}".encode()
        return self._cipher.decrypt(record.nonce, record.ciphertext, aad)


@dataclass(frozen=True, kw_only=True)
class ReviewedFact:
    fact_id: str
    tenant_id: str
    candidate_sha256: str
    provenance_sha256: str
    proposed_by: str
    reviewed_by: str
    reviewed_at: datetime
    expires_at: datetime
    trust_label: str = "reviewed_fact"

    @classmethod
    def from_candidate(cls, **values: object) -> "ReviewedFact":
        if values.get("proposed_by") == values.get("reviewed_by"):
            raise ValueError("fact_review_separation_required")
        return cls(**values)  # type: ignore[arg-type]
