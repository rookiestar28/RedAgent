"""Read-only current-authority resolution for compat_123 campaign execution."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
import hashlib
import json
from typing import Protocol
from urllib.parse import urlsplit


_MAX_OBSERVATION_AGE = timedelta(minutes=5)


@dataclass(frozen=True)
class ResolutionRequest:
    tenant_id: str
    principal_id: str
    engagement_id: str
    target_id: str

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("principal_id", self.principal_id),
            ("engagement_id", self.engagement_id),
            ("target_id", self.target_id),
        ):
            _identifier(name, value, 100)


@dataclass(frozen=True)
class CanonicalAuthoritySnapshot:
    tenant_id: str
    principal_id: str
    engagement_id: str
    engagement_version: int
    roe_version_id: str
    roe_revision: int
    roe_sha256: str
    roe_status: str
    roe_revocation_epoch: int
    policy_decision_id: str
    policy_revision: str
    policy_sha256: str
    policy_status: str
    policy_revocation_epoch: int
    target_id: str
    target_revision: int
    target_sha256: str
    target_value: str
    target_resolution_mode: str
    credential_class: str
    credential_reference: str | None
    quota_reference: str
    quota_available: bool
    runner_id: str
    runner_workload_identity: str
    runner_ready: bool
    reservation_id: str
    lease_id: str
    lease_expires_at: datetime
    stop_requested: bool
    observed_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for name, value in (
            ("tenant_id", self.tenant_id),
            ("principal_id", self.principal_id),
            ("engagement_id", self.engagement_id),
            ("roe_version_id", self.roe_version_id),
            ("policy_decision_id", self.policy_decision_id),
            ("policy_revision", self.policy_revision),
            ("target_id", self.target_id),
            ("target_value", self.target_value),
            ("quota_reference", self.quota_reference),
            ("runner_id", self.runner_id),
            ("runner_workload_identity", self.runner_workload_identity),
            ("reservation_id", self.reservation_id),
            ("lease_id", self.lease_id),
        ):
            _identifier(name, value, 500)
        for name, value in (
            ("roe_sha256", self.roe_sha256),
            ("policy_sha256", self.policy_sha256),
            ("target_sha256", self.target_sha256),
        ):
            _sha256(name, value)
        for name, value in (
            ("engagement_version", self.engagement_version),
            ("roe_revision", self.roe_revision),
            ("target_revision", self.target_revision),
        ):
            if isinstance(value, bool) or value < 1:
                raise ValueError(f"{name}_invalid")
        for name, value in (
            ("roe_revocation_epoch", self.roe_revocation_epoch),
            ("policy_revocation_epoch", self.policy_revocation_epoch),
        ):
            if isinstance(value, bool) or value < 0:
                raise ValueError(f"{name}_invalid")
        for name, value in (
            ("quota_available", self.quota_available),
            ("runner_ready", self.runner_ready),
            ("stop_requested", self.stop_requested),
        ):
            if not isinstance(value, bool):
                raise ValueError(f"{name}_invalid")
        for name, value in (
            ("lease_expires_at", self.lease_expires_at),
            ("observed_at", self.observed_at),
            ("expires_at", self.expires_at),
        ):
            _aware(name, value)


@dataclass(frozen=True)
class ResolutionResult:
    allowed: bool
    reason: str
    bindings: CanonicalAuthoritySnapshot | None


class CanonicalAuthorityProvider(Protocol):
    """Canonical-owner facade whose only compat_123 operation is a current-state read."""

    async def read_current_authority(
        self, request: ResolutionRequest
    ) -> CanonicalAuthoritySnapshot | None: ...


class CampaignContextResolver:
    def __init__(self, provider: CanonicalAuthorityProvider) -> None:
        self._provider = provider

    async def resolve(self, request: ResolutionRequest, *, now: datetime) -> ResolutionResult:
        _aware("now", now)
        snapshot = await self._provider.read_current_authority(request)
        if snapshot is None:
            return _deny("canonical_authority_not_found")
        for actual, expected, reason in (
            (snapshot.tenant_id, request.tenant_id, "tenant_binding_mismatch"),
            (snapshot.principal_id, request.principal_id, "principal_binding_mismatch"),
            (snapshot.engagement_id, request.engagement_id, "engagement_binding_mismatch"),
            (snapshot.target_id, request.target_id, "target_binding_mismatch"),
        ):
            if actual != expected:
                return _deny(reason)
        if snapshot.roe_status != "approved":
            return _deny("roe_not_approved")
        if snapshot.policy_status != "allowed":
            return _deny("policy_not_allowed")
        if not snapshot.quota_available:
            return _deny("quota_unavailable")
        if not snapshot.runner_ready:
            return _deny("runner_not_ready")
        if snapshot.stop_requested:
            return _deny("stop_requested")
        if snapshot.observed_at > now or now - snapshot.observed_at > _MAX_OBSERVATION_AGE:
            return _deny("authority_observation_stale")
        if now >= snapshot.expires_at:
            return _deny("authority_expired")
        if now >= snapshot.lease_expires_at:
            return _deny("authority_lease_expired")
        if snapshot.target_resolution_mode not in {
            "owned-loopback",
            "canonical-artifact-binding",
        }:
            return _deny("target_resolution_mode_denied")
        if snapshot.target_sha256 != _target_digest(snapshot):
            return _deny("target_digest_mismatch")
        if (
            snapshot.target_resolution_mode == "owned-loopback"
            and not _is_exact_owned_loopback_target(snapshot.target_value)
        ):
            return _deny("owned_loopback_target_denied")
        if (
            snapshot.target_resolution_mode == "canonical-artifact-binding"
            and snapshot.target_value != snapshot.target_id
        ):
            # CRITICAL: repository campaigns accept only the server-resolved opaque binding.
            return _deny("artifact_binding_target_denied")
        if snapshot.credential_class != "none" or snapshot.credential_reference is not None:
            return _deny("credential_class_denied")
        return ResolutionResult(allowed=True, reason="resolved", bindings=snapshot)


def _deny(reason: str) -> ResolutionResult:
    return ResolutionResult(allowed=False, reason=reason, bindings=None)


def _target_digest(snapshot: CanonicalAuthoritySnapshot) -> str:
    document = {
        "target_id": snapshot.target_id,
        "revision": snapshot.target_revision,
        "target_type": (
            "repository"
            if snapshot.target_resolution_mode == "canonical-artifact-binding"
            else "url"
        ),
        "normalized_value": snapshot.target_value,
    }
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(canonical).hexdigest()


def _is_exact_owned_loopback_target(value: str) -> bool:
    """CRITICAL: accept only the exact IP-literal root endpoint owned by the lab lease."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        return False
    return (
        parsed.scheme == "http"
        and parsed.hostname == "127.0.0.1"
        and port is not None
        and 1 <= port <= 65535
        and parsed.username is None
        and parsed.password is None
        and parsed.path == ""
        and parsed.query == ""
        and parsed.fragment == ""
    )


def _identifier(name: str, value: str, maximum: int) -> None:
    if not isinstance(value, str) or value != value.strip() or not value or len(value) > maximum:
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")
