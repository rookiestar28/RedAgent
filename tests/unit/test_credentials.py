from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import credentials, domain, evidence_chain
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 8, 14, 0, tzinfo=timezone.utc)


def target() -> ScopeTarget:
    return ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://example.com")


def scope(**overrides: object) -> credentials.CredentialScope:
    values = {
        "organization_id": "org-1",
        "engagement_id": "eng-1",
        "allowed_targets": (target(),),
        "allowed_modes": (domain.TestMode.PASSIVE_SCAN,),
        "allowed_permissions": ("http:read", "session:read"),
    }
    values.update(overrides)
    return credentials.CredentialScope(**values)  # type: ignore[arg-type]


def reference(**overrides: object) -> credentials.CredentialReference:
    values = {
        "id": "cred-ref-1",
        "kind": credentials.CredentialKind.OAUTH_SESSION_REFERENCE,
        "storage_provider": "approved-vault",
        "external_reference": "vault://redteam/eng-1/cred-ref-1",
        "owner_user_id": "owner-1",
        "scope": scope(),
        "created_at": NOW - timedelta(days=1),
        "expires_at": NOW + timedelta(hours=1),
        "rotation_due_at": NOW + timedelta(minutes=30),
        "status": credentials.CredentialStatus.ACTIVE,
        "redaction_label": "credential:cred-ref-1",
    }
    values.update(overrides)
    return credentials.CredentialReference(**values)  # type: ignore[arg-type]


def lease_request(**overrides: object) -> credentials.CredentialLeaseRequest:
    values = {
        "lease_id": "lease-1",
        "job_id": "job-1",
        "runner_id": "runner-1",
        "target": target(),
        "mode": domain.TestMode.PASSIVE_SCAN,
        "requested_permissions": ("http:read",),
        "requested_at": NOW,
        "ttl_seconds": 300,
    }
    values.update(overrides)
    return credentials.CredentialLeaseRequest(**values)  # type: ignore[arg-type]


def test_broker_issues_short_lived_scoped_lease_without_secret_value() -> None:
    broker, lease = credentials.CredentialBroker().issue_lease(
        reference(),
        lease_request(),
        actor_user_id="operator-1",
        audit_event_id="audit-1",
    )

    assert lease.credential_reference_id == "cred-ref-1"
    assert lease.job_id == "job-1"
    assert lease.runner_id == "runner-1"
    assert lease.target == target().normalized()
    assert lease.mode is domain.TestMode.PASSIVE_SCAN
    assert lease.scoped_permissions == ("http:read",)
    assert lease.expires_at == NOW + timedelta(seconds=300)
    assert not lease.contains_secret_value
    assert broker.audit_chain.audit_events[0].action is evidence_chain.AuditAction.CREDENTIAL_LEASE


def test_lease_rejects_permissions_outside_scope() -> None:
    with pytest.raises(ValueError, match="credential_permissions_not_allowed"):
        credentials.CredentialBroker().issue_lease(
            reference(),
            lease_request(requested_permissions=("http:read", "admin:write")),
            actor_user_id="operator-1",
            audit_event_id="audit-1",
        )


def test_lease_rejects_target_or_mode_outside_scope() -> None:
    with pytest.raises(ValueError, match="credential_target_not_allowed"):
        credentials.CredentialBroker().issue_lease(
            reference(),
            lease_request(target=ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://other.example")),
            actor_user_id="operator-1",
            audit_event_id="audit-1",
        )
    with pytest.raises(ValueError, match="credential_mode_not_allowed"):
        credentials.CredentialBroker().issue_lease(
            reference(),
            lease_request(mode=domain.TestMode.ACTIVE_SCAN),
            actor_user_id="operator-1",
            audit_event_id="audit-1",
        )


def test_expired_rotation_due_or_revoked_references_are_rejected() -> None:
    with pytest.raises(ValueError, match="credential_reference_expired"):
        credentials.CredentialBroker().issue_lease(
            reference(expires_at=NOW),
            lease_request(),
            actor_user_id="operator-1",
            audit_event_id="audit-1",
        )
    with pytest.raises(ValueError, match="credential_reference_rotation_due"):
        credentials.CredentialBroker().issue_lease(
            reference(rotation_due_at=NOW),
            lease_request(),
            actor_user_id="operator-1",
            audit_event_id="audit-1",
        )
    with pytest.raises(ValueError, match="credential_reference_not_active"):
        credentials.CredentialBroker().issue_lease(
            reference(status=credentials.CredentialStatus.REVOKED),
            lease_request(),
            actor_user_id="operator-1",
            audit_event_id="audit-1",
        )


def test_lease_ttl_must_be_short_and_within_reference_expiry() -> None:
    with pytest.raises(ValueError, match="credential_lease_ttl_invalid"):
        credentials.CredentialBroker(max_lease_ttl_seconds=300).issue_lease(
            reference(),
            lease_request(ttl_seconds=301),
            actor_user_id="operator-1",
            audit_event_id="audit-1",
        )
    with pytest.raises(ValueError, match="credential_lease_exceeds_reference_expiry"):
        credentials.CredentialBroker(max_lease_ttl_seconds=900).issue_lease(
            reference(expires_at=NOW + timedelta(seconds=100)),
            lease_request(ttl_seconds=300),
            actor_user_id="operator-1",
            audit_event_id="audit-1",
        )


def test_canary_marker_output_check_fails_on_leak() -> None:
    canary = "canary-marker-redacted-value"

    with pytest.raises(ValueError, match="canary_marker_leaked:command_log"):
        credentials.assert_no_canary_markers(
            {"command_log": f"unexpected output {canary}"},
            (canary,),
        )


def test_canary_marker_redaction_allows_clean_output_check() -> None:
    canary = "canary-marker-redacted-value"
    output = credentials.redact_canary_markers(f"sanitized {canary}", (canary,))

    credentials.assert_no_canary_markers({"report": output}, (canary,))
    assert output == "sanitized [REDACTED-CANARY]"
