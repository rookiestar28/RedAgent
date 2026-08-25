"""Local policy-as-code simulation contracts for assurance gates.

The simulator evaluates supplied context only. It does not execute Rego/OPA,
dispatch runners, publish reports, retrieve credentials, or call adapters.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Mapping

from redagent_platform.redaction import RedactionArtifactClass, assert_no_sensitive_output


class PolicyDomain(str, Enum):
    SCOPE = "scope"
    ROE = "roe"
    AUTHORIZATION = "authorization"
    ACTIVE_TESTING = "active_testing"
    ADAPTER = "adapter"
    CREDENTIAL = "credential"
    REDACTION = "redaction"
    REPORTING = "reporting"


class PolicyPackStatus(str, Enum):
    DRAFT = "draft"
    REVIEWED = "reviewed"
    ACTIVE = "active"
    DISABLED = "disabled"
    DEPRECATED = "deprecated"


class TraceOutcome(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    NOT_APPLICABLE = "not_applicable"


@dataclass(frozen=True, kw_only=True)
class PolicyRule:
    rule_id: str
    domain: PolicyDomain
    description: str
    required_context_key: str
    expected_value: object
    deny_reason: str


@dataclass(frozen=True, kw_only=True)
class PolicyPack:
    pack_id: str
    version: str
    status: PolicyPackStatus
    rules: tuple[PolicyRule, ...]
    created_at: datetime
    reviewed_by_user_id: str | None = None
    reviewed_at: datetime | None = None
    activated_by_user_id: str | None = None
    activated_at: datetime | None = None


@dataclass(frozen=True, kw_only=True)
class SimulationSubject:
    subject_id: str
    domain: PolicyDomain
    context: Mapping[str, object]


@dataclass(frozen=True, kw_only=True)
class PolicyDecisionTrace:
    subject_id: str
    subject_hash: str
    rule_id: str
    domain: PolicyDomain
    outcome: TraceOutcome
    reason: str
    context_keys: tuple[str, ...]
    context_hash: str


@dataclass(frozen=True, kw_only=True)
class SimulatedPolicyDecision:
    subject_id: str
    domain: PolicyDomain
    allowed: bool
    reason: str
    trace_hash: str
    decision_hash: str


@dataclass(frozen=True, kw_only=True)
class PolicyRegressionCase:
    case_id: str
    subject: SimulationSubject
    expected_allowed: bool
    expected_reason: str


@dataclass(frozen=True, kw_only=True)
class PolicyRegressionFailure:
    case_id: str
    expected_allowed: bool
    actual_allowed: bool
    expected_reason: str
    actual_reason: str


@dataclass(frozen=True, kw_only=True)
class PolicySimulationRequest:
    simulation_id: str
    policy_pack: PolicyPack | None
    subjects: tuple[SimulationSubject, ...]
    requested_at: datetime
    actor_user_id: str
    dry_run: bool
    expected_decision_hashes: Mapping[str, str] | None = None
    regression_cases: tuple[PolicyRegressionCase, ...] = ()


@dataclass(frozen=True, kw_only=True)
class PolicySimulationResult:
    simulation_id: str
    pack_id: str | None
    pack_version: str | None
    dry_run: bool
    live_enforcement_enabled: bool
    allowed: bool
    reason: str
    decisions: tuple[SimulatedPolicyDecision, ...]
    traces: tuple[PolicyDecisionTrace, ...]
    drifted_subject_ids: tuple[str, ...]
    regression_failures: tuple[PolicyRegressionFailure, ...]
    result_hash: str


def build_default_assurance_policy_pack(
    *,
    pack_id: str,
    version: str,
    status: PolicyPackStatus,
    created_at: datetime,
    reviewed_by_user_id: str | None = None,
    reviewed_at: datetime | None = None,
    activated_by_user_id: str | None = None,
    activated_at: datetime | None = None,
) -> PolicyPack:
    return PolicyPack(
        pack_id=pack_id,
        version=version,
        status=status,
        created_at=created_at,
        reviewed_by_user_id=reviewed_by_user_id,
        reviewed_at=reviewed_at,
        activated_by_user_id=activated_by_user_id,
        activated_at=activated_at,
        rules=(
            _rule(PolicyDomain.SCOPE, "scope_ledger_current", "scope_ledger_not_current"),
            _rule(PolicyDomain.ROE, "roe_current", "roe_not_current"),
            _rule(PolicyDomain.AUTHORIZATION, "authorization_current", "authorization_not_current"),
            _rule(PolicyDomain.ACTIVE_TESTING, "operator_confirmed", "operator_confirmation_missing"),
            _rule(PolicyDomain.ADAPTER, "adapter_certified", "adapter_not_certified"),
            _rule(PolicyDomain.CREDENTIAL, "credential_lease_valid", "credential_lease_invalid"),
            _rule(PolicyDomain.REDACTION, "redaction_passed", "redaction_gate_failed"),
            _rule(PolicyDomain.REPORTING, "publication_gate_allowed", "publication_gate_denied"),
        ),
    )


def simulate_policy(request: PolicySimulationRequest) -> PolicySimulationResult:
    _validate_request(request)
    if request.policy_pack is None:
        return _failed_result(request, "policy_pack_missing")
    pack = request.policy_pack
    pack_denial = _pack_denial(pack, request.dry_run)
    if pack_denial:
        return _failed_result(request, pack_denial, pack=pack)
    decisions, traces = _evaluate_subjects(pack, request.subjects)
    drifted = _drifted_subjects(decisions, request.expected_decision_hashes or {})
    regression_failures = _regression_failures(pack, request.regression_cases)
    allowed = all(decision.allowed for decision in decisions) and not drifted and not regression_failures
    if not all(decision.allowed for decision in decisions):
        reason = "policy_denied"
    elif drifted:
        reason = "policy_drift_detected"
    elif regression_failures:
        reason = "policy_regression_failed"
    else:
        reason = "policy_simulation_allowed"
    return _result(
        request=request,
        pack=pack,
        live_enforcement_enabled=not request.dry_run and pack.status is PolicyPackStatus.ACTIVE,
        allowed=allowed,
        reason=reason,
        decisions=decisions,
        traces=traces,
        drifted_subject_ids=drifted,
        regression_failures=regression_failures,
    )


def decision_hash(decision: SimulatedPolicyDecision) -> str:
    return _canonical_sha256(
        {
            "subject_id": decision.subject_id,
            "domain": decision.domain.value,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "trace_hash": decision.trace_hash,
        }
    )


def _evaluate_subjects(
    pack: PolicyPack,
    subjects: tuple[SimulationSubject, ...],
) -> tuple[tuple[SimulatedPolicyDecision, ...], tuple[PolicyDecisionTrace, ...]]:
    decisions: list[SimulatedPolicyDecision] = []
    traces: list[PolicyDecisionTrace] = []
    for subject in subjects:
        applicable = tuple(rule for rule in pack.rules if rule.domain is subject.domain)
        if not applicable:
            trace = _trace(subject, "no_applicable_rule", subject.domain, TraceOutcome.DENY, "policy_rule_missing")
            traces.append(trace)
            decisions.append(_decision(subject, False, "policy_rule_missing", (trace,)))
            continue
        subject_traces = tuple(_evaluate_rule(rule, subject) for rule in applicable)
        traces.extend(subject_traces)
        denials = tuple(trace for trace in subject_traces if trace.outcome is TraceOutcome.DENY)
        if denials:
            decisions.append(_decision(subject, False, denials[0].reason, subject_traces))
        else:
            decisions.append(_decision(subject, True, "policy_subject_allowed", subject_traces))
    return tuple(decisions), tuple(traces)


def _evaluate_rule(rule: PolicyRule, subject: SimulationSubject) -> PolicyDecisionTrace:
    _validate_rule(rule)
    _validate_subject(subject)
    if rule.required_context_key not in subject.context:
        return _trace(subject, rule.rule_id, rule.domain, TraceOutcome.DENY, rule.deny_reason)
    actual = subject.context[rule.required_context_key]
    if actual != rule.expected_value:
        return _trace(subject, rule.rule_id, rule.domain, TraceOutcome.DENY, rule.deny_reason)
    return _trace(subject, rule.rule_id, rule.domain, TraceOutcome.ALLOW, "rule_satisfied")


def _regression_failures(
    pack: PolicyPack,
    cases: tuple[PolicyRegressionCase, ...],
) -> tuple[PolicyRegressionFailure, ...]:
    failures: list[PolicyRegressionFailure] = []
    for case in cases:
        _require_non_empty("case_id", case.case_id)
        decisions, _ = _evaluate_subjects(pack, (case.subject,))
        decision = decisions[0]
        if decision.allowed != case.expected_allowed or decision.reason != case.expected_reason:
            failures.append(
                PolicyRegressionFailure(
                    case_id=case.case_id,
                    expected_allowed=case.expected_allowed,
                    actual_allowed=decision.allowed,
                    expected_reason=case.expected_reason,
                    actual_reason=decision.reason,
                )
            )
    return tuple(failures)


def _drifted_subjects(
    decisions: tuple[SimulatedPolicyDecision, ...],
    expected_hashes: Mapping[str, str],
) -> tuple[str, ...]:
    drifted = []
    for decision in decisions:
        expected = expected_hashes.get(decision.subject_id)
        if expected is not None and expected != decision.decision_hash:
            drifted.append(decision.subject_id)
    return tuple(sorted(drifted))


def _failed_result(
    request: PolicySimulationRequest,
    reason: str,
    *,
    pack: PolicyPack | None = None,
) -> PolicySimulationResult:
    _ensure_secret_free_reason(reason)
    return _result(
        request=request,
        pack=pack,
        live_enforcement_enabled=False,
        allowed=False,
        reason=reason,
        decisions=(),
        traces=(),
        drifted_subject_ids=(),
        regression_failures=(),
    )


def _result(
    *,
    request: PolicySimulationRequest,
    pack: PolicyPack | None,
    live_enforcement_enabled: bool,
    allowed: bool,
    reason: str,
    decisions: tuple[SimulatedPolicyDecision, ...],
    traces: tuple[PolicyDecisionTrace, ...],
    drifted_subject_ids: tuple[str, ...],
    regression_failures: tuple[PolicyRegressionFailure, ...],
) -> PolicySimulationResult:
    _ensure_secret_free_reason(reason)
    payload = {
        "simulation_id": request.simulation_id,
        "pack_id": pack.pack_id if pack else None,
        "pack_version": pack.version if pack else None,
        "dry_run": request.dry_run,
        "live_enforcement_enabled": live_enforcement_enabled,
        "allowed": allowed,
        "reason": reason,
        "decisions": tuple(_decision_payload(decision) for decision in decisions),
        "traces": tuple(_trace_payload(trace) for trace in traces),
        "drifted_subject_ids": drifted_subject_ids,
        "regression_failures": tuple(_regression_payload(failure) for failure in regression_failures),
    }
    return PolicySimulationResult(
        simulation_id=request.simulation_id.strip(),
        pack_id=pack.pack_id if pack else None,
        pack_version=pack.version if pack else None,
        dry_run=request.dry_run,
        live_enforcement_enabled=live_enforcement_enabled,
        allowed=allowed,
        reason=reason,
        decisions=decisions,
        traces=traces,
        drifted_subject_ids=drifted_subject_ids,
        regression_failures=regression_failures,
        result_hash=_canonical_sha256(payload),
    )


def _decision(
    subject: SimulationSubject,
    allowed: bool,
    reason: str,
    traces: tuple[PolicyDecisionTrace, ...],
) -> SimulatedPolicyDecision:
    _ensure_secret_free_reason(reason)
    trace_hash = _canonical_sha256({"traces": tuple(_trace_payload(trace) for trace in traces)})
    decision = SimulatedPolicyDecision(
        subject_id=subject.subject_id.strip(),
        domain=subject.domain,
        allowed=allowed,
        reason=reason,
        trace_hash=trace_hash,
        decision_hash="",
    )
    return SimulatedPolicyDecision(
        subject_id=decision.subject_id,
        domain=decision.domain,
        allowed=decision.allowed,
        reason=decision.reason,
        trace_hash=decision.trace_hash,
        decision_hash=decision_hash(decision),
    )


def _trace(
    subject: SimulationSubject,
    rule_id: str,
    domain: PolicyDomain,
    outcome: TraceOutcome,
    reason: str,
) -> PolicyDecisionTrace:
    _ensure_secret_free_reason(reason)
    _require_non_empty("rule_id", rule_id)
    _validate_subject(subject)
    context_keys = tuple(sorted(str(key) for key in subject.context))
    return PolicyDecisionTrace(
        subject_id=subject.subject_id.strip(),
        subject_hash=_canonical_sha256({"subject_id": subject.subject_id.strip(), "domain": subject.domain.value}),
        rule_id=rule_id.strip(),
        domain=domain,
        outcome=outcome,
        reason=reason,
        context_keys=context_keys,
        context_hash=_context_hash(subject.context),
    )


def _pack_denial(pack: PolicyPack, dry_run: bool) -> str | None:
    _validate_pack(pack)
    if pack.status in {PolicyPackStatus.DISABLED, PolicyPackStatus.DEPRECATED}:
        return "policy_pack_disabled"
    if not dry_run and pack.status is not PolicyPackStatus.ACTIVE:
        return "policy_pack_not_active"
    return None


def _validate_pack(pack: PolicyPack) -> None:
    for field_name, value in (("pack_id", pack.pack_id), ("version", pack.version)):
        _require_non_empty(field_name, value)
    _require_timezone(pack.created_at)
    if not pack.rules:
        raise ValueError("policy_pack_rules_required")
    if pack.status in {PolicyPackStatus.REVIEWED, PolicyPackStatus.ACTIVE}:
        _require_non_empty("reviewed_by_user_id", pack.reviewed_by_user_id or "")
        if pack.reviewed_at is None:
            raise ValueError("review_timestamp_required")
        _require_timezone(pack.reviewed_at)
    if pack.status is PolicyPackStatus.ACTIVE:
        _require_non_empty("activated_by_user_id", pack.activated_by_user_id or "")
        if pack.activated_at is None:
            raise ValueError("activation_timestamp_required")
        _require_timezone(pack.activated_at)


def _validate_request(request: PolicySimulationRequest) -> None:
    _require_non_empty("simulation_id", request.simulation_id)
    _require_non_empty("actor_user_id", request.actor_user_id)
    _require_timezone(request.requested_at)
    if not request.subjects:
        raise ValueError("simulation_subjects_required")


def _validate_rule(rule: PolicyRule) -> None:
    for field_name, value in (
        ("rule_id", rule.rule_id),
        ("description", rule.description),
        ("required_context_key", rule.required_context_key),
        ("deny_reason", rule.deny_reason),
    ):
        _require_non_empty(field_name, value)
    _ensure_secret_free_reason(rule.description)
    _ensure_secret_free_reason(rule.deny_reason)


def _validate_subject(subject: SimulationSubject) -> None:
    _require_non_empty("subject_id", subject.subject_id)
    if subject.domain not in PolicyDomain:
        raise ValueError("invalid_policy_domain")
    for key in subject.context:
        _require_non_empty("context_key", str(key))
        _ensure_secret_free_reason(str(key))


def _rule(domain: PolicyDomain, required_key: str, deny_reason: str) -> PolicyRule:
    return PolicyRule(
        rule_id=f"{domain.value}:{required_key}",
        domain=domain,
        description=f"{domain.value} gate requires {required_key}.",
        required_context_key=required_key,
        expected_value=True,
        deny_reason=deny_reason,
    )


def _context_hash(context: Mapping[str, object]) -> str:
    return _canonical_sha256({"context": {str(key): _value_fingerprint(value) for key, value in context.items()}})


def _value_fingerprint(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _decision_payload(decision: SimulatedPolicyDecision) -> dict[str, object]:
    return {
        "subject_id": decision.subject_id,
        "domain": decision.domain.value,
        "allowed": decision.allowed,
        "reason": decision.reason,
        "trace_hash": decision.trace_hash,
        "decision_hash": decision.decision_hash,
    }


def _trace_payload(trace: PolicyDecisionTrace) -> dict[str, object]:
    return {
        "subject_id": trace.subject_id,
        "subject_hash": trace.subject_hash,
        "rule_id": trace.rule_id,
        "domain": trace.domain.value,
        "outcome": trace.outcome.value,
        "reason": trace.reason,
        "context_keys": trace.context_keys,
        "context_hash": trace.context_hash,
    }


def _regression_payload(failure: PolicyRegressionFailure) -> dict[str, object]:
    return {
        "case_id": failure.case_id,
        "expected_allowed": failure.expected_allowed,
        "actual_allowed": failure.actual_allowed,
        "expected_reason": failure.expected_reason,
        "actual_reason": failure.actual_reason,
    }


def _ensure_secret_free_reason(value: str) -> None:
    try:
        assert_no_sensitive_output(value, RedactionArtifactClass.COMMAND_LOG)
    except ValueError as exc:
        raise ValueError("sensitive_policy_output_forbidden") from exc


def _canonical_sha256(payload: Mapping[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
