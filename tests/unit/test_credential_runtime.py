from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import credentials, domain, job_queue, runner_execution
from redagent_platform.scope_authorization import ScopeTarget


NOW = datetime(2026, 7, 9, 16, 0, tzinfo=timezone.utc)


def target(value: str = "https://example.test") -> ScopeTarget:
    return ScopeTarget(target_type=domain.TargetType.WEB_ORIGIN, value=value)


def scope() -> credentials.CredentialScope:
    return credentials.CredentialScope(
        organization_id="org-1",
        engagement_id="eng-1",
        allowed_targets=(target(),),
        allowed_modes=(domain.TestMode.PASSIVE_SCAN,),
        allowed_permissions=("http:read", "session:read"),
    )


def reference() -> credentials.CredentialReference:
    return credentials.CredentialReference(
        id="cred-ref-runtime",
        kind=credentials.CredentialKind.OAUTH_SESSION_REFERENCE,
        storage_provider="approved-vault",
        external_reference="vault://redagent/eng-1/cred-ref-runtime",
        owner_user_id="owner-1",
        scope=scope(),
        created_at=NOW - timedelta(days=1),
        expires_at=NOW + timedelta(hours=1),
        rotation_due_at=NOW + timedelta(minutes=30),
        status=credentials.CredentialStatus.ACTIVE,
        redaction_label="credential:cred-ref-runtime",
    )


def lease() -> credentials.CredentialLease:
    _, issued = credentials.CredentialBroker().issue_lease(
        reference(),
        credentials.CredentialLeaseRequest(
            lease_id="lease-runtime",
            job_id="job-runtime",
            runner_id="runner-1",
            target=target(),
            mode=domain.TestMode.PASSIVE_SCAN,
            requested_permissions=("http:read",),
            requested_at=NOW,
            ttl_seconds=300,
        ),
        actor_user_id="operator-1",
        audit_event_id="audit-lease",
    )
    return issued


def runner_contract() -> job_queue.RunnerContract:
    return job_queue.RunnerContract(
        runner_id="runner-1",
        organization_id="org-1",
        capabilities=(domain.TestMode.PASSIVE_SCAN,),
        policy_token_reference="policy-ref-1",
        target_scope=target(),
        timeout_seconds=30,
        heartbeat_interval_seconds=5,
        result_schema=("stdout", "stderr", "evidence_ids"),
        cleanup_callback="cleanup://runner-1/job-runtime",
        credential_lease_id="lease-runtime",
    )


def job() -> job_queue.JobRecord:
    return job_queue.JobRecord(
        job_id="job-runtime",
        organization_id="org-1",
        engagement_id="eng-1",
        test_definition_id="test-runtime",
        target=target(),
        mode=domain.TestMode.PASSIVE_SCAN,
        status=domain.JobStatus.QUEUED,
        projected_interactions=1,
        timeout_seconds=30,
        cleanup_required=True,
        max_attempts=1,
        policy_decision_id="decision-1",
        policy_expires_at=NOW + timedelta(minutes=10),
    )


def test_runtime_binding_contains_only_scoped_lease_metadata() -> None:
    binding = credentials.build_runtime_binding(
        lease(),
        job_id="job-runtime",
        runner_id="runner-1",
        target=target(),
        mode=domain.TestMode.PASSIVE_SCAN,
        requested_permissions=("http:read",),
        now=NOW,
    )

    metadata = binding.to_job_metadata()
    assert binding.lease_id == "lease-runtime"
    assert not binding.contains_secret_value
    assert metadata["credential_lease_id"] == "lease-runtime"
    assert metadata["permission_count"] == 1
    assert "vault://" not in str(metadata)


def test_runtime_binding_validates_target_mode_permission_expiration_and_redaction_label() -> None:
    issued = lease()

    cases = (
        ({"target": target("https://other.example.test")}, "credential_lease_target_mismatch"),
        ({"mode": domain.TestMode.ACTIVE_SCAN}, "credential_lease_mode_mismatch"),
        ({"requested_permissions": ("admin:write",)}, "credential_lease_permission_mismatch"),
        ({"now": issued.expires_at}, "credential_lease_expired"),
    )
    for overrides, reason in cases:
        values = {
            "lease": issued,
            "job_id": "job-runtime",
            "runner_id": "runner-1",
            "target": target(),
            "mode": domain.TestMode.PASSIVE_SCAN,
            "requested_permissions": ("http:read",),
            "now": NOW,
        }
        values.update(overrides)
        with pytest.raises(ValueError, match=reason):
            credentials.build_runtime_binding(**values)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="missing_redaction_label"):
        credentials.build_runtime_binding(
            credentials.CredentialLease(**{**issued.__dict__, "redaction_label": ""}),
            job_id="job-runtime",
            runner_id="runner-1",
            target=target(),
            mode=domain.TestMode.PASSIVE_SCAN,
            requested_permissions=("http:read",),
            now=NOW,
        )


def test_runner_job_spec_carries_only_credential_lease_reference() -> None:
    spec = runner_execution.build_runner_job_spec(
        spec_id="spec-runtime",
        job=job(),
        runner=runner_contract(),
        adapter=runner_execution.RunnerAdapterKind.DRY_RUN,
        requested_at=NOW,
        evidence_id="evidence-runtime",
        operator_user_id="operator-1",
    )

    assert spec.credential_lease_id == "lease-runtime"
    assert "vault://" not in str(spec)
    runner_execution.verify_runner_job_spec(spec)


def test_lease_revocation_records_required_runtime_reasons() -> None:
    broker = credentials.CredentialBroker()
    issued = lease()

    reasons = (
        credentials.CredentialRevocationReason.CANCELLATION,
        credentials.CredentialRevocationReason.KILL_SWITCH,
        credentials.CredentialRevocationReason.CLEANUP_FAILURE,
        credentials.CredentialRevocationReason.POLICY_EXPIRY,
    )
    for index, reason in enumerate(reasons, start=1):
        broker, record = broker.revoke_lease(
            issued,
            reason=reason,
            actor_user_id="operator-1",
            audit_event_id=f"audit-revoke-{index}",
            revoked_at=NOW + timedelta(seconds=index),
        )
        assert record.reason is reason
        assert record.lease_id == issued.id

    assert len(broker.audit_chain.audit_events) == len(reasons)


def test_raw_credential_material_is_rejected_from_lower_trust_outputs() -> None:
    raw_value = "LIVE-CREDENTIAL-VALUE"

    with pytest.raises(ValueError, match="credential_material_leaked:ui_log"):
        credentials.assert_no_credential_material({"ui_log": f"unexpected {raw_value}"}, (raw_value,))

    credentials.assert_no_credential_material(
        {
            "command_log": "credential:cred-ref-runtime",
            "evidence_record": "lease-runtime",
            "report": "redaction label credential:cred-ref-runtime",
            "failure": "credential value withheld",
        },
        (raw_value,),
    )
