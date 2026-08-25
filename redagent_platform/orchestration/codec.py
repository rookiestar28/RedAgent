"""Authenticated encryption for Temporal payloads."""

from __future__ import annotations

import os
import re
from typing import Iterable

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from temporalio.api.common.v1 import Payload
from temporalio.converter import PayloadCodec


class PayloadCodecError(ValueError):
    """A stable, secret-free codec failure."""


class AesGcmPayloadCodec(PayloadCodec):
    """Encrypt complete serialized Payload messages with AES-256-GCM."""

    _ENCODING = b"binary/encrypted+aesgcm"
    _VERSION = b"1"

    def __init__(self, *, key: bytes, key_id: str) -> None:
        if not isinstance(key, bytes) or len(key) != 32:
            raise PayloadCodecError("temporal_payload_key_invalid")
        if not re.fullmatch(r"[A-Za-z0-9._:-]{1,64}", key_id):
            raise PayloadCodecError("temporal_payload_key_id_invalid")
        self._cipher = AESGCM(key)
        self._key_id = key_id.encode("ascii")

    async def encode(self, payloads: Iterable[Payload]) -> list[Payload]:
        encoded: list[Payload] = []
        for payload in payloads:
            nonce = os.urandom(12)
            aad = self._aad(self._key_id)
            ciphertext = self._cipher.encrypt(nonce, payload.SerializeToString(), aad)
            encoded.append(
                Payload(
                    metadata={
                        "encoding": self._ENCODING,
                        "redagent-codec-version": self._VERSION,
                        "redagent-key-id": self._key_id,
                    },
                    data=nonce + ciphertext,
                )
            )
        return encoded

    async def decode(self, payloads: Iterable[Payload]) -> list[Payload]:
        decoded: list[Payload] = []
        for payload in payloads:
            if payload.metadata.get("encoding") != self._ENCODING:
                raise PayloadCodecError("temporal_payload_encoding_unsupported")
            key_id = payload.metadata.get("redagent-key-id", b"")
            if key_id != self._key_id:
                raise PayloadCodecError("temporal_payload_key_mismatch")
            if payload.metadata.get("redagent-codec-version") != self._VERSION or len(payload.data) < 29:
                raise PayloadCodecError("temporal_payload_envelope_invalid")
            try:
                serialized = self._cipher.decrypt(payload.data[:12], payload.data[12:], self._aad(key_id))
            except InvalidTag as exc:
                raise PayloadCodecError("temporal_payload_authentication_failed") from exc
            original = Payload()
            try:
                original.ParseFromString(serialized)
            except Exception as exc:
                raise PayloadCodecError("temporal_payload_decode_failed") from exc
            decoded.append(original)
        return decoded

    @classmethod
    def _aad(cls, key_id: bytes) -> bytes:
        return b"redagent-temporal-payload\0" + cls._VERSION + b"\0" + key_id
