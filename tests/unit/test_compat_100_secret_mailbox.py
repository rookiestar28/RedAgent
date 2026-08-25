from __future__ import annotations

import asyncio

import pytest

from redagent_platform.runner_service.secret_mailbox import EphemeralSecretMailbox


def test_mailbox_copies_one_attested_delivery_into_one_mutable_execution_material() -> None:
    mailbox = EphemeralSecretMailbox(client_id="client-1", attestation_fingerprint="a" * 64)
    source = bytearray(b"R100-SYNTHETIC-MAILBOX")  # pragma: allowlist secret
    asyncio.run(mailbox.deliver_once(
        client_id="client-1", attestation_fingerprint="a" * 64,
        material={"password": memoryview(source)},
    ))
    source[:] = b"\x00" * len(source)
    material = mailbox.take_once()
    with material.expose_once() as fields:
        assert bytes(fields["password"]) == b"R100-SYNTHETIC-MAILBOX"  # pragma: allowlist secret
    assert material.cleared and "SYNTHETIC" not in repr(mailbox)
    with pytest.raises(RuntimeError, match="already_taken"):
        mailbox.take_once()


def test_mailbox_rejects_wrong_attestation_and_duplicate_delivery() -> None:
    mailbox = EphemeralSecretMailbox(client_id="client-1", attestation_fingerprint="a" * 64)
    with pytest.raises(RuntimeError, match="attestation_mismatch"):
        asyncio.run(mailbox.deliver_once(
            client_id="client-1", attestation_fingerprint="b" * 64,
            material={"password": memoryview(bytearray(b"synthetic"))},
        ))
    asyncio.run(mailbox.deliver_once(
        client_id="client-1", attestation_fingerprint="a" * 64,
        material={"password": memoryview(bytearray(b"synthetic"))},
    ))
    with pytest.raises(RuntimeError, match="duplicate_delivery"):
        asyncio.run(mailbox.deliver_once(
            client_id="client-1", attestation_fingerprint="a" * 64,
            material={"password": memoryview(bytearray(b"synthetic"))},
        ))
