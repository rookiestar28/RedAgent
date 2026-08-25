"""One-shot in-process secret handoff at the ephemeral workload boundary."""

from __future__ import annotations

from typing import Mapping

from redagent_platform.secret_service.contracts import SecretMaterial


class EphemeralSecretMailbox:
    __slots__ = ("client_id", "attestation_fingerprint", "_material", "_delivered", "_taken")

    def __init__(self, *, client_id: str, attestation_fingerprint: str) -> None:
        if not client_id or len(client_id) > 64 or len(attestation_fingerprint) != 64:
            raise ValueError("runner_secret_mailbox_identity_invalid")
        self.client_id = client_id
        self.attestation_fingerprint = attestation_fingerprint
        self._material: SecretMaterial | None = None
        self._delivered = False
        self._taken = False

    async def deliver_once(
        self, *, client_id: str, attestation_fingerprint: str,
        material: Mapping[str, memoryview],
    ) -> None:
        if client_id != self.client_id or attestation_fingerprint != self.attestation_fingerprint:
            raise RuntimeError("runner_secret_mailbox_attestation_mismatch")
        if self._delivered:
            raise RuntimeError("runner_secret_mailbox_duplicate_delivery")
        # CRITICAL: copy only into bounded mutable SecretMaterial owned by this one execution.
        self._material = SecretMaterial({name: bytearray(value) for name, value in material.items()})
        self._delivered = True

    def take_once(self) -> SecretMaterial:
        if self._taken:
            raise RuntimeError("runner_secret_mailbox_already_taken")
        if not self._delivered or self._material is None:
            raise RuntimeError("runner_secret_mailbox_empty")
        self._taken = True
        material, self._material = self._material, None
        return material

    def __repr__(self) -> str:
        return f"<EphemeralSecretMailbox client_id={self.client_id!r} material=<redacted>>"
