"""Credential broker references, scoped leases, and leak checks."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import Mapping

from redagent_platform.domain import TestMode
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.redaction import RedactionArtifactClass, RedactionConfig, assert_no_sensitive_output
from redagent_platform.scope_authorization import ScopeTarget


class CredentialKind(str, Enum):
    API_TOKEN_REFERENCE = "api_token_reference"
    COOKIE_JAR_REFERENCE = "cookie_jar_reference"
    BASIC_AUTH_REFERENCE = "basic_auth_reference"
    OAUTH_SESSION_REFERENCE = "oauth_session_reference"
    CLOUD_ROLE_REFERENCE = "cloud_role_reference"
    SSH_KEY_REFERENCE = "ssh_key_reference"


class CredentialStatus(str, Enum):
    ACTIVE = "active"
    ROTATION_DUE = "rotation_due"
    REVOKED = "revoked"
    EXPIRED = "expired"


class CredentialRevocationReason(str, Enum):
    CANCELLATION = "cancellation"
    KILL_SWITCH = "kill_switch"
    CLEANUP_FAILURE = "cleanup_failure"
    POLICY_EXPIRY = "policy_expiry"


@dataclass(frozen=True, kw_only=True)
class CredentialScope:
    organization_id: str
    engagement_id: str
    allowed_targets: tuple[ScopeTarget, ...]
    allowed_modes: tuple[TestMode, ...]
    allowed_permissions: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class CredentialReference:
    id: str
    kind: CredentialKind
    storage_provider: str
    external_reference: str
    owner_user_id: str
    scope: CredentialScope
    created_at: datetime
    expires_at: datetime
    rotation_due_at: datetime
    status: CredentialStatus
    redaction_label: str


@dataclass(frozen=True, kw_only=True)
class CredentialLeaseRequest:
    lease_id: str
    job_id: str
    runner_id: str
    target: ScopeTarget
    mode: TestMode
    requested_permissions: tuple[str, ...]
    requested_at: datetime
    ttl_seconds: int


@dataclass(frozen=True, kw_only=True)
class CredentialLease:
    id: str
    credential_reference_id: str
    job_id: str
    runner_id: str
    target: ScopeTarget
    mode: TestMode
    scoped_permissions: tuple[str, ...]
    issued_at: datetime
    expires_at: datetime
    redaction_label: str

    @property
    def contains_secret_value(self) -> bool:
        return False


@dataclass(frozen=True, kw_only=True)
class CredentialRuntimeBinding:
    lease_id: str
    credential_reference_id: str
    job_id: str
    runner_id: str
    target: ScopeTarget
    mode: TestMode
    scoped_permissions: tuple[str, ...]
    expires_at: datetime
    redaction_label: str

    @property
    def contains_secret_value(self) -> bool:
        return False

    def to_job_metadata(self) -> dict[str, object]:
        return {
            "credential_lease_id": self.lease_id,
            "credential_reference_id": self.credential_reference_id,
            "permission_count": len(self.scoped_permissions),
            "expires_at": self.expires_at.isoformat(),
            "redaction_label": self.redaction_label,
        }


@dataclass(frozen=True, kw_only=True)
class CredentialLeaseRevocation:
    revocation_id: str
    lease_id: str
    reason: CredentialRevocationReason
    revoked_at: datetime
    actor_user_id: str


@dataclass(frozen=True)
class CredentialBroker:
    audit_chain: EvidenceChain = EvidenceChain()
    max_lease_ttl_seconds: int = 900

    def issue_lease(
        self,
        reference: CredentialReference,
        request: CredentialLeaseRequest,
        *,
        actor_user_id: str,
        audit_event_id: str,
    ) -> tuple["CredentialBroker", CredentialLease]:
        _validate_reference(reference, request.requested_at)
        _validate_request(reference, request, self.max_lease_ttl_seconds)
        lease = CredentialLease(
            id=request.lease_id.strip(),
            credential_reference_id=reference.id,
            job_id=request.job_id.strip(),
            runner_id=request.runner_id.strip(),
            target=request.target.normalized(),
            mode=request.mode,
            scoped_permissions=tuple(request.requested_permissions),
            issued_at=request.requested_at,
            expires_at=request.requested_at + timedelta(seconds=request.ttl_seconds),
            redaction_label=reference.redaction_label,
        )
        next_chain = self.audit_chain.append_audit_event(
            event_id=audit_event_id,
            organization_id=reference.scope.organization_id,
            actor_user_id=actor_user_id,
            action=AuditAction.CREDENTIAL_LEASE,
            subject_type="credential_reference",
            subject_id=reference.id,
            occurred_at=request.requested_at,
            details={
                "job_id": request.job_id,
                "runner_id": request.runner_id,
                "mode": request.mode.value,
                "permission_count": len(request.requested_permissions),
                "lease_ttl_seconds": request.ttl_seconds,
            },
        )
        return CredentialBroker(audit_chain=next_chain, max_lease_ttl_seconds=self.max_lease_ttl_seconds), lease

    def revoke_lease(
        self,
        lease: CredentialLease,
        *,
        reason: CredentialRevocationReason,
        actor_user_id: str,
        audit_event_id: str,
        revoked_at: datetime,
    ) -> tuple["CredentialBroker", CredentialLeaseRevocation]:
        _require_non_empty("actor_user_id", actor_user_id)
        _require_non_empty("audit_event_id", audit_event_id)
        _require_timezone(revoked_at)
        record = CredentialLeaseRevocation(
            revocation_id=audit_event_id.strip(),
            lease_id=lease.id,
            reason=reason,
            revoked_at=revoked_at,
            actor_user_id=actor_user_id.strip(),
        )
        next_chain = self.audit_chain.append_audit_event(
            event_id=audit_event_id,
            organization_id="credential-runtime",
            actor_user_id=actor_user_id,
            action=AuditAction.CREDENTIAL_LEASE,
            subject_type="credential_lease",
            subject_id=lease.id,
            occurred_at=revoked_at,
            details={"revocation_reason": reason.value, "job_id": lease.job_id, "runner_id": lease.runner_id},
        )
        return CredentialBroker(audit_chain=next_chain, max_lease_ttl_seconds=self.max_lease_ttl_seconds), record


def build_runtime_binding(
    lease: CredentialLease,
    *,
    job_id: str,
    runner_id: str,
    target: ScopeTarget,
    mode: TestMode,
    requested_permissions: tuple[str, ...],
    now: datetime,
) -> CredentialRuntimeBinding:
    _require_timezone(now)
    for field_name, value in (("job_id", job_id), ("runner_id", runner_id), ("redaction_label", lease.redaction_label)):
        _require_non_empty(field_name, value)
    if now >= lease.expires_at:
        raise ValueError("credential_lease_expired")
    if lease.job_id != job_id:
        raise ValueError("credential_lease_job_mismatch")
    if lease.runner_id != runner_id:
        raise ValueError("credential_lease_runner_mismatch")
    if lease.target.normalized() != target.normalized():
        raise ValueError("credential_lease_target_mismatch")
    if lease.mode is not mode:
        raise ValueError("credential_lease_mode_mismatch")
    if not requested_permissions or not set(requested_permissions).issubset(set(lease.scoped_permissions)):
        raise ValueError("credential_lease_permission_mismatch")
    return CredentialRuntimeBinding(
        lease_id=lease.id,
        credential_reference_id=lease.credential_reference_id,
        job_id=lease.job_id,
        runner_id=lease.runner_id,
        target=lease.target,
        mode=lease.mode,
        scoped_permissions=tuple(requested_permissions),
        expires_at=lease.expires_at,
        redaction_label=lease.redaction_label,
    )


def assert_no_credential_material(outputs: Mapping[str, str], forbidden_values: tuple[str, ...]) -> None:
    config = RedactionConfig(canary_markers=forbidden_values)
    for name, output in outputs.items():
        try:
            assert_no_sensitive_output(output, RedactionArtifactClass.COMMAND_LOG, config)
        except ValueError as exc:
            raise ValueError(f"credential_material_leaked:{name}") from exc


def assert_no_canary_markers(outputs: Mapping[str, str], canary_markers: tuple[str, ...]) -> None:
    for name, output in outputs.items():
        for marker in canary_markers:
            if marker and marker in output:
                raise ValueError(f"canary_marker_leaked:{name}")


def redact_canary_markers(value: str, canary_markers: tuple[str, ...]) -> str:
    redacted = value
    for marker in canary_markers:
        if marker:
            redacted = redacted.replace(marker, "[REDACTED-CANARY]")
    return redacted


def _validate_reference(reference: CredentialReference, now: datetime) -> None:
    for field_name, value in (
        ("credential_reference_id", reference.id),
        ("storage_provider", reference.storage_provider),
        ("external_reference", reference.external_reference),
        ("owner_user_id", reference.owner_user_id),
        ("redaction_label", reference.redaction_label),
        ("organization_id", reference.scope.organization_id),
        ("engagement_id", reference.scope.engagement_id),
    ):
        _require_non_empty(field_name, value)
    _require_timezone(now)
    _require_timezone(reference.created_at)
    _require_timezone(reference.expires_at)
    _require_timezone(reference.rotation_due_at)
    if reference.status is not CredentialStatus.ACTIVE:
        raise ValueError("credential_reference_not_active")
    if now >= reference.expires_at:
        raise ValueError("credential_reference_expired")
    if now >= reference.rotation_due_at:
        raise ValueError("credential_reference_rotation_due")
    if not reference.scope.allowed_targets:
        raise ValueError("credential_scope_missing_targets")
    if not reference.scope.allowed_modes:
        raise ValueError("credential_scope_missing_modes")
    if not reference.scope.allowed_permissions:
        raise ValueError("credential_scope_missing_permissions")


def _validate_request(reference: CredentialReference, request: CredentialLeaseRequest, max_ttl_seconds: int) -> None:
    for field_name, value in (
        ("lease_id", request.lease_id),
        ("job_id", request.job_id),
        ("runner_id", request.runner_id),
    ):
        _require_non_empty(field_name, value)
    if request.ttl_seconds <= 0 or request.ttl_seconds > max_ttl_seconds:
        raise ValueError("credential_lease_ttl_invalid")
    if request.requested_at + timedelta(seconds=request.ttl_seconds) > reference.expires_at:
        raise ValueError("credential_lease_exceeds_reference_expiry")
    if request.mode not in reference.scope.allowed_modes:
        raise ValueError("credential_mode_not_allowed")
    if not _contains_target(reference.scope.allowed_targets, request.target):
        raise ValueError("credential_target_not_allowed")
    allowed_permissions = set(reference.scope.allowed_permissions)
    if not request.requested_permissions or not set(request.requested_permissions).issubset(allowed_permissions):
        raise ValueError("credential_permissions_not_allowed")


def _contains_target(targets: tuple[ScopeTarget, ...], requested: ScopeTarget) -> bool:
    normalized_requested = requested.normalized()
    return any(target.normalized() == normalized_requested for target in targets)


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
