from datetime import datetime, timezone

import pytest

from redagent_platform import policy_simulator


NOW = datetime(2026, 7, 9, 14, 45, tzinfo=timezone.utc)


def pack(
    status: policy_simulator.PolicyPackStatus = policy_simulator.PolicyPackStatus.REVIEWED,
) -> policy_simulator.PolicyPack:
    return policy_simulator.build_default_assurance_policy_pack(
        pack_id="assurance-pack",
        version="2026.07.09",
        status=status,
        created_at=NOW,
        reviewed_by_user_id="reviewer-1"
        if status in {policy_simulator.PolicyPackStatus.REVIEWED, policy_simulator.PolicyPackStatus.ACTIVE}
        else None,
        reviewed_at=NOW
        if status in {policy_simulator.PolicyPackStatus.REVIEWED, policy_simulator.PolicyPackStatus.ACTIVE}
        else None,
        activated_by_user_id="approver-1" if status is policy_simulator.PolicyPackStatus.ACTIVE else None,
        activated_at=NOW if status is policy_simulator.PolicyPackStatus.ACTIVE else None,
    )


def subject(
    domain: policy_simulator.PolicyDomain = policy_simulator.PolicyDomain.SCOPE,
    **context: object,
) -> policy_simulator.SimulationSubject:
    values = {"scope_ledger_current": True}
    values.update(context)
    return policy_simulator.SimulationSubject(
        subject_id=f"subject-{domain.value}",
        domain=domain,
        context=values,
    )


def request(**overrides: object) -> policy_simulator.PolicySimulationRequest:
    values = {
        "simulation_id": "simulation-1",
        "policy_pack": pack(),
        "subjects": (subject(),),
        "requested_at": NOW,
        "actor_user_id": "operator-1",
        "dry_run": True,
        "expected_decision_hashes": None,
        "regression_cases": (),
    }
    values.update(overrides)
    return policy_simulator.PolicySimulationRequest(**values)  # type: ignore[arg-type]


def test_dry_run_allows_reviewed_pack_without_live_enforcement() -> None:
    result = policy_simulator.simulate_policy(request())

    assert result.allowed
    assert result.reason == "policy_simulation_allowed"
    assert not result.live_enforcement_enabled
    assert result.decisions[0].allowed
    assert result.traces[0].outcome is policy_simulator.TraceOutcome.ALLOW


def test_live_enforcement_requires_active_pack() -> None:
    reviewed_live = policy_simulator.simulate_policy(request(dry_run=False))
    active_live = policy_simulator.simulate_policy(request(policy_pack=pack(policy_simulator.PolicyPackStatus.ACTIVE), dry_run=False))

    assert not reviewed_live.allowed
    assert reviewed_live.reason == "policy_pack_not_active"
    assert active_live.allowed
    assert active_live.live_enforcement_enabled


def test_denial_returns_structured_reason_without_context_value_leakage() -> None:
    denied_subject = subject(scope_ledger_current=False, raw_target="https://sensitive.example.test", secret_value="token=abc123")

    result = policy_simulator.simulate_policy(request(subjects=(denied_subject,)))

    assert not result.allowed
    assert result.reason == "policy_denied"
    assert result.decisions[0].reason == "scope_ledger_not_current"
    assert result.traces[0].reason == "scope_ledger_not_current"
    assert result.traces[0].context_hash
    assert "sensitive.example" not in result.traces[0].reason
    assert "abc123" not in result.traces[0].reason


def test_default_pack_covers_required_assurance_domains() -> None:
    subjects = (
        subject(policy_simulator.PolicyDomain.SCOPE, scope_ledger_current=True),
        subject(policy_simulator.PolicyDomain.ROE, roe_current=True),
        subject(policy_simulator.PolicyDomain.AUTHORIZATION, authorization_current=True),
        subject(policy_simulator.PolicyDomain.ACTIVE_TESTING, operator_confirmed=True),
        subject(policy_simulator.PolicyDomain.ADAPTER, adapter_certified=True),
        subject(policy_simulator.PolicyDomain.CREDENTIAL, credential_lease_valid=True),
        subject(policy_simulator.PolicyDomain.REDACTION, redaction_passed=True),
        subject(policy_simulator.PolicyDomain.REPORTING, publication_gate_allowed=True),
    )

    result = policy_simulator.simulate_policy(request(subjects=subjects))

    assert result.allowed
    assert {decision.domain for decision in result.decisions} == set(policy_simulator.PolicyDomain)


def test_policy_drift_is_detected_from_expected_decision_hashes() -> None:
    baseline = policy_simulator.simulate_policy(request())
    expected = {"subject-scope": "0" * 64}
    matching = {"subject-scope": baseline.decisions[0].decision_hash}

    drifted = policy_simulator.simulate_policy(request(expected_decision_hashes=expected))
    stable = policy_simulator.simulate_policy(request(expected_decision_hashes=matching))

    assert not drifted.allowed
    assert drifted.reason == "policy_drift_detected"
    assert drifted.drifted_subject_ids == ("subject-scope",)
    assert stable.allowed


def test_policy_regression_cases_fail_closed_on_behavior_change() -> None:
    regression = policy_simulator.PolicyRegressionCase(
        case_id="regression-1",
        subject=subject(scope_ledger_current=False),
        expected_allowed=True,
        expected_reason="policy_subject_allowed",
    )

    result = policy_simulator.simulate_policy(request(regression_cases=(regression,)))

    assert not result.allowed
    assert result.reason == "policy_regression_failed"
    assert result.regression_failures[0].case_id == "regression-1"
    assert result.regression_failures[0].actual_reason == "scope_ledger_not_current"


def test_missing_policy_pack_and_disabled_pack_fail_closed() -> None:
    missing = policy_simulator.simulate_policy(request(policy_pack=None))
    disabled = policy_simulator.simulate_policy(
        request(policy_pack=pack(policy_simulator.PolicyPackStatus.DISABLED))
    )

    assert not missing.allowed
    assert missing.reason == "policy_pack_missing"
    assert not disabled.allowed
    assert disabled.reason == "policy_pack_disabled"


def test_secret_like_policy_reason_is_rejected() -> None:
    unsafe_pack = policy_simulator.PolicyPack(
        pack_id="unsafe-pack",
        version="1",
        status=policy_simulator.PolicyPackStatus.REVIEWED,
        created_at=NOW,
        reviewed_by_user_id="reviewer-1",
        reviewed_at=NOW,
        rules=(
            policy_simulator.PolicyRule(
                rule_id="unsafe",
                domain=policy_simulator.PolicyDomain.SCOPE,
                description="Unsafe rule",
                required_context_key="safe",
                expected_value=True,
                deny_reason="token=abc123",
            ),
        ),
    )

    with pytest.raises(ValueError, match="sensitive_policy_output_forbidden"):
        policy_simulator.simulate_policy(request(policy_pack=unsafe_pack, subjects=(subject(safe=False),)))
