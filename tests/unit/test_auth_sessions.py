from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import auth_sessions, domain
from redagent_platform.credentials import CredentialLease
from redagent_platform.evidence_chain import EvidenceChain, RedactionStatus
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc)
TARGET = ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value="https://www.agentique.io")


def lease(**overrides: object) -> CredentialLease:
    values = {
        "id": "lease-1",
        "credential_reference_id": "cred-ref-1",
        "job_id": "job-1",
        "runner_id": "runner-1",
        "target": TARGET,
        "mode": domain.TestMode.PASSIVE_SCAN,
        "scoped_permissions": ("session:read",),
        "issued_at": NOW,
        "expires_at": NOW + timedelta(minutes=10),
        "redaction_label": "session-secret",
    }
    values.update(overrides)
    return CredentialLease(**values)  # type: ignore[arg-type]


def session(role: str = "viewer", session_id: str = "session-1") -> auth_sessions.AuthenticatedSessionContext:
    return auth_sessions.build_authenticated_session_context(
        session_id=session_id,
        organization_id="org-1",
        engagement_id="eng-1",
        lease=lease(),
        role_label=role,
        created_at=NOW,
    )


def capture() -> auth_sessions.SessionExchangeCapture:
    return auth_sessions.SessionExchangeCapture(
        session_id="session-1",
        captured_at=NOW,
        method="GET",
        url="https://www.agentique.io/admin",
        request_headers=(
            auth_sessions.HeaderPair(name="Authorization", value="Bearer canary-token"),
            auth_sessions.HeaderPair(name="Cookie", value="session=canary-cookie"),
        ),
        response_status=403,
        response_headers=(auth_sessions.HeaderPair(name="Set-Cookie", value="refresh=canary-refresh"),),
        body_excerpt="User ray@example.com token=canary-token",
    )


def test_session_context_uses_credential_lease_reference_only() -> None:
    context = session()

    assert context.credential_lease_id == "lease-1"
    assert not context.contains_secret_value
    assert not hasattr(context, "cookie")
    assert not hasattr(context, "token")


def test_expired_credential_lease_cannot_create_session_context() -> None:
    with pytest.raises(ValueError, match="credential_lease_expired"):
        auth_sessions.build_authenticated_session_context(
            session_id="session-expired",
            organization_id="org-1",
            engagement_id="eng-1",
            lease=lease(expires_at=NOW),
            role_label="viewer",
            created_at=NOW,
        )


def test_session_capture_redacts_cookies_tokens_and_personal_data() -> None:
    sanitized = auth_sessions.sanitize_session_capture(capture())

    assert sanitized.redacted
    assert sanitized.content["request_headers"] == (
        {"name": "authorization", "value": "[redacted]"},
        {"name": "cookie", "value": "[redacted]"},
    )
    assert sanitized.content["response_headers"] == ({"name": "set-cookie", "value": "[redacted]"},)
    assert sanitized.content["body_excerpt"] == "User [redacted-email] token=[redacted]"


def test_redacted_session_capture_creates_evidence() -> None:
    result = auth_sessions.append_session_capture_evidence(
        chain=EvidenceChain(),
        capture=capture(),
        evidence_id="evidence-session-1",
        organization_id="org-1",
        source_job_id="job-1",
    )

    assert result.record.redaction_status is RedactionStatus.REDACTED
    assert result.record.kind is domain.EvidenceKind.HTTP_METADATA
    assert result.sanitized_capture.redacted


def test_role_authorization_case_compares_without_secrets() -> None:
    lower = session(role="viewer", session_id="session-viewer")
    higher = session(role="admin", session_id="session-admin")
    case = auth_sessions.build_role_authorization_case(
        case_id="role-case-1",
        target=TARGET,
        operation_label="GET /admin",
        lower_session=lower,
        higher_session=higher,
    )
    evidence = auth_sessions.append_session_capture_evidence(
        chain=EvidenceChain(),
        capture=capture(),
        evidence_id="evidence-session-2",
        organization_id="org-1",
        source_job_id="job-1",
    ).record
    comparison = auth_sessions.compare_role_authorization(
        case=case,
        lower_status=403,
        higher_status=200,
        evidence_records=(evidence,),
    )

    assert comparison.expected_difference_observed
    assert case.lower_session_id == "session-viewer"
    assert case.higher_session_id == "session-admin"
    assert "canary" not in repr(case)


def test_secret_canaries_are_rejected_from_outputs() -> None:
    with pytest.raises(ValueError, match="canary_marker_leaked:report"):
        auth_sessions.assert_no_session_secret_leak(
            {"report": "accidental canary-cookie"},
            ("canary-cookie",),
        )
