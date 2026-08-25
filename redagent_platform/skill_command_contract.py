"""Structured command contract for future RedAgent operator skills.

This module is execution-adjacent but non-scanning by default. It validates a
skill-collected assessment request and returns a structured decision. Real tool
or wrapper invocation is intentionally injectable so tests can prove delegation
without contacting targets.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
from pathlib import PurePosixPath
from typing import Any, Callable, Mapping

from redagent_platform.domain import PolicyDecisionOutcome, TargetType


CONTRACT_VERSION = "r047.skill-command-contract.v1"


class ContractMode(str, Enum):
    DRY_RUN = "dry_run"
    EXECUTE = "execute"


class SkillClient(str, Enum):
    CODEX = "codex"
    CLAUDE = "claude"


class AssessmentType(str, Enum):
    PASSIVE_METADATA = "passive_metadata"
    PROGRESSIVE_WEB = "progressive_web"
    REPORT_DRAFTING = "report_drafting"
    EVIDENCE_REVIEW = "evidence_review"
    API_LAB = "api_lab"
    AI_AGENTIC = "ai_agentic"


class CredentialRequirement(str, Enum):
    FORBIDDEN = "forbidden"
    NOT_REQUIRED = "not_required"
    BROKERED_SESSION = "brokered_session"
    APPROVED_REFERENCE = "approved_reference"


class ExitClassification(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    INVALID_INPUT = "invalid_input"


Delegate = Callable[[Mapping[str, Any]], Mapping[str, Any]]


@dataclass(frozen=True)
class ContractDecision:
    decision: PolicyDecisionOutcome
    reason: str
    exit_classification: ExitClassification
    payload: Mapping[str, Any]

    @property
    def allowed(self) -> bool:
        return self.decision is PolicyDecisionOutcome.ALLOW

    def to_jsonable(self) -> dict[str, Any]:
        return {
            "contract_version": CONTRACT_VERSION,
            "decision": self.decision.value,
            "reason": self.reason,
            "exit_classification": self.exit_classification.value,
            **dict(self.payload),
        }


def evaluate_skill_assessment_request(
    request: Mapping[str, Any],
    *,
    mode_override: str | None = None,
    delegate: Delegate | None = None,
) -> ContractDecision:
    """Validate and optionally delegate a skill assessment request.

    Delegation is only performed when a caller supplies a delegate callback.
    The CLI in compat_047 does not call the existing assessment wrapper.
    """

    mode_text = mode_override or str(request.get("mode") or ContractMode.DRY_RUN.value)
    try:
        mode = ContractMode(mode_text)
    except ValueError:
        return _deny("unsupported_mode", ExitClassification.INVALID_INPUT, mode=mode_text)

    malformed = _first_malformed_reason(request)
    if malformed:
        return _deny(malformed, ExitClassification.INVALID_INPUT, mode=mode.value)

    assessment_type = AssessmentType(str(request["assessment_type"]))
    requested_at = _parse_datetime(str(request["requested_at"]))
    window_start = _parse_datetime(str(_mapping(request["window"])["start"]))
    window_end = _parse_datetime(str(_mapping(request["window"])["end"]))
    output_paths = _mapping(request["output_paths"])
    limits = _mapping(request["limits"])
    data_handling = _mapping(request["data_handling"])

    denial = _first_policy_denial(
        request=request,
        mode=mode,
        assessment_type=assessment_type,
        requested_at=requested_at,
        window_start=window_start,
        window_end=window_end,
        limits=limits,
        output_paths=output_paths,
        data_handling=data_handling,
    )
    base_payload = _base_payload(
        request=request,
        mode=mode,
        assessment_type=assessment_type,
        requested_at=requested_at,
        output_paths=output_paths,
        limits=limits,
    )
    if denial:
        return _deny(denial, ExitClassification.DENY, **base_payload)

    if mode is ContractMode.DRY_RUN:
        next_action = "ready_for_final_confirmation"
        if _confirmation_is_valid(request, requested_at):
            next_action = "ready_for_execute_mode"
        return _allow(
            "dry_run_ready",
            delegated=False,
            next_action=next_action,
            **base_payload,
        )

    if delegate is None:
        return _allow(
            "contract_authorized_delegate_not_invoked",
            delegated=False,
            next_action="invoke_approved_wrapper",
            **base_payload,
        )

    delegate_payload = _delegate_payload(request, assessment_type, output_paths, limits)
    delegate_result = dict(delegate(delegate_payload))
    return _allow(
        "delegate_completed",
        delegated=True,
        next_action="review_delegate_result",
        delegate_result=delegate_result,
        **base_payload,
    )


def load_request_json(raw: str) -> tuple[Mapping[str, Any] | None, ContractDecision | None]:
    """Parse a JSON request without raising into agent-facing CLI code."""
    try:
        parsed = json.loads(raw.lstrip("\ufeff"))
    except json.JSONDecodeError:
        return None, _deny("malformed_json", ExitClassification.INVALID_INPUT)
    if not isinstance(parsed, dict):
        return None, _deny("request_must_be_json_object", ExitClassification.INVALID_INPUT)
    return parsed, None


def _first_malformed_reason(request: Mapping[str, Any]) -> str | None:
    for field_name in (
        "request_id",
        "skill_client",
        "assessment_type",
        "requested_at",
        "organization_id",
        "engagement_id",
        "owner_label",
        "approver_label",
        "operator_label",
        "authorization_label",
        "environment",
        "sensitivity",
        "emergency_stop_method",
        "credential_requirement",
    ):
        if not _non_empty_string(request.get(field_name)):
            return f"missing_{field_name}"

    for field_name in ("window", "limits", "output_paths", "data_handling"):
        if not isinstance(request.get(field_name), Mapping):
            return f"missing_{field_name}"

    for field_name in ("authorized_targets", "requested_targets", "excluded_targets", "allowed_categories", "forbidden_actions"):
        if not isinstance(request.get(field_name), list):
            return f"missing_{field_name}"
    if not request["authorized_targets"]:
        return "missing_authorized_targets"
    if not request["requested_targets"]:
        return "missing_requested_targets"
    if not request["allowed_categories"]:
        return "missing_allowed_categories"

    try:
        SkillClient(str(request["skill_client"]))
    except ValueError:
        return "unsupported_skill_client"
    try:
        AssessmentType(str(request["assessment_type"]))
    except ValueError:
        return "unsupported_assessment_type"
    try:
        CredentialRequirement(str(request["credential_requirement"]))
    except ValueError:
        return "unsupported_credential_requirement"
    try:
        _parse_datetime(str(request["requested_at"]))
        _parse_datetime(str(_mapping(request["window"])["start"]))
        _parse_datetime(str(_mapping(request["window"])["end"]))
    except (KeyError, TypeError, ValueError):
        return "invalid_time_window"
    return None


def _first_policy_denial(
    *,
    request: Mapping[str, Any],
    mode: ContractMode,
    assessment_type: AssessmentType,
    requested_at: datetime,
    window_start: datetime,
    window_end: datetime,
    limits: Mapping[str, Any],
    output_paths: Mapping[str, Any],
    data_handling: Mapping[str, Any],
) -> str | None:
    if str(request.get("roe_status")) != "approved":
        return "roe_not_approved"
    if request.get("authorization_confirmed") is not True:
        return "authorization_not_confirmed"
    if window_start > window_end:
        return "invalid_time_window"
    if not (window_start <= requested_at <= window_end):
        return "outside_time_window"

    target_denial = _target_scope_denial(request)
    if target_denial:
        return target_denial

    if assessment_type.value not in set(map(str, request["allowed_categories"])):
        return "assessment_type_not_allowed"
    limit_denial = _limits_denial(limits)
    if limit_denial:
        return limit_denial
    path_denial = _output_path_denial(output_paths)
    if path_denial:
        return path_denial
    if data_handling.get("redaction_required") is not True:
        return "redaction_required"
    if not _non_empty_string(str(data_handling.get("retention_class", ""))):
        return "missing_retention_class"

    if mode is ContractMode.EXECUTE:
        if not _confirmation_is_valid(request, requested_at):
            return "confirmation_required"
        policy_denial = _policy_decision_denial(request, requested_at)
        if policy_denial:
            return policy_denial
    return None


def _target_scope_denial(request: Mapping[str, Any]) -> str | None:
    try:
        authorized = {_target_key(target) for target in request["authorized_targets"]}
        requested = {_target_key(target) for target in request["requested_targets"]}
        excluded = {_target_key(target) for target in request["excluded_targets"]}
    except (KeyError, TypeError, ValueError):
        return "invalid_target_scope"
    if requested & excluded:
        return "target_forbidden"
    if not requested <= authorized:
        return "target_not_in_allowlist"
    return None


def _limits_denial(limits: Mapping[str, Any]) -> str | None:
    for field_name in ("rate_limit_per_second", "max_concurrency", "max_interactions", "timeout_seconds"):
        try:
            value = float(limits[field_name])
        except (KeyError, TypeError, ValueError):
            return f"invalid_{field_name}"
        if value <= 0:
            return f"invalid_{field_name}"
    if int(limits["max_concurrency"]) > 1:
        return "concurrency_limit_exceeded"
    return None


def _output_path_denial(output_paths: Mapping[str, Any]) -> str | None:
    required_roots = {
        "command_log_path": (".local", ".tmp"),
        "evidence_dir": (".tmp", "reports"),
        "report_path": ("reports", ".tmp"),
    }
    for field_name, roots in required_roots.items():
        value = output_paths.get(field_name)
        if not _safe_repo_relative_path(value, roots):
            return f"invalid_{field_name}"
    return None


def _confirmation_is_valid(request: Mapping[str, Any], requested_at: datetime) -> bool:
    confirmation = request.get("user_confirmation")
    if not isinstance(confirmation, Mapping):
        return False
    if confirmation.get("confirmed") is not True:
        return False
    if not _non_empty_string(confirmation.get("confirmed_by")):
        return False
    try:
        confirmed_at = _parse_datetime(str(confirmation["confirmed_at"]))
    except (KeyError, ValueError):
        return False
    return confirmed_at <= requested_at


def _policy_decision_denial(request: Mapping[str, Any], requested_at: datetime) -> str | None:
    policy = request.get("policy_decision")
    if not isinstance(policy, Mapping):
        return "policy_decision_required"
    if str(policy.get("outcome")) != PolicyDecisionOutcome.ALLOW.value:
        return "policy_decision_not_allow"
    if not _non_empty_string(policy.get("decision_id")):
        return "missing_policy_decision_id"
    try:
        expires_at = _parse_datetime(str(policy["expires_at"]))
    except (KeyError, ValueError):
        return "invalid_policy_expiry"
    if expires_at <= requested_at:
        return "policy_expired"
    return None


def _base_payload(
    *,
    request: Mapping[str, Any],
    mode: ContractMode,
    assessment_type: AssessmentType,
    requested_at: datetime,
    output_paths: Mapping[str, Any],
    limits: Mapping[str, Any],
) -> dict[str, Any]:
    requested_targets = tuple(_jsonable_target(target) for target in request["requested_targets"])
    specification_fingerprint = _specification_fingerprint(request)
    return {
        "request_id": str(request["request_id"]),
        "skill_client": str(request["skill_client"]),
        "mode": mode.value,
        "assessment_type": assessment_type.value,
        "requested_at": requested_at.isoformat(),
        "policy_decision": {
            "outcome": PolicyDecisionOutcome.ALLOW.value,
            "reason": "contract_inputs_valid",
        },
        "refusal_reason": None,
        "requested_targets": list(requested_targets),
        "request_counts": {
            "max_interactions": int(limits["max_interactions"]),
            "max_concurrency": int(limits["max_concurrency"]),
            "rate_limit_per_second": float(limits["rate_limit_per_second"]),
            "timeout_seconds": int(limits["timeout_seconds"]),
        },
        "evidence": {
            "command_log_path": str(output_paths["command_log_path"]),
            "evidence_dir": str(output_paths["evidence_dir"]),
            "report_path": str(output_paths["report_path"]),
        },
        "specification_fingerprint": specification_fingerprint,
    }


def _delegate_payload(
    request: Mapping[str, Any],
    assessment_type: AssessmentType,
    output_paths: Mapping[str, Any],
    limits: Mapping[str, Any],
) -> dict[str, Any]:
    wrapper_mode = {
        AssessmentType.PASSIVE_METADATA: "passive",
        AssessmentType.PROGRESSIVE_WEB: "progressive",
    }.get(assessment_type, "unsupported")
    return {
        "wrapper": "authorized_web_assessment",
        "wrapper_mode": wrapper_mode,
        "targets": [target["value"] for target in map(_jsonable_target, request["requested_targets"])],
        "window": dict(request["window"]),
        "authorization_label": str(request["authorization_label"]),
        "limits": {
            "max_interactions": int(limits["max_interactions"]),
            "min_delay_seconds": _min_delay_from_rate(float(limits["rate_limit_per_second"])),
        },
        "output_paths": dict(output_paths),
        "dry_run": False,
    }


def _deny(reason: str, exit_classification: ExitClassification, **payload: Any) -> ContractDecision:
    base = {
        "policy_decision": {
            "outcome": PolicyDecisionOutcome.DENY.value,
            "reason": reason,
        },
        "refusal_reason": reason,
        "delegated": False,
        "next_action": "fix_request_and_retry",
    }
    base.update(payload)
    return ContractDecision(
        decision=PolicyDecisionOutcome.DENY,
        reason=reason,
        exit_classification=exit_classification,
        payload=base,
    )


def _allow(reason: str, **payload: Any) -> ContractDecision:
    return ContractDecision(
        decision=PolicyDecisionOutcome.ALLOW,
        reason=reason,
        exit_classification=ExitClassification.ALLOW,
        payload=payload,
    )


def _target_key(raw: Any) -> tuple[str, str]:
    if not isinstance(raw, Mapping):
        raise ValueError("target_must_be_object")
    target_type = TargetType(str(raw["target_type"]))
    return target_type.value, _normalize_target_value(str(raw["value"]))


def _jsonable_target(raw: Any) -> dict[str, str]:
    target_type, value = _target_key(raw)
    return {"target_type": target_type, "value": value}


def _normalize_target_value(value: str) -> str:
    return value.strip().lower().rstrip("/")


def _safe_repo_relative_path(value: Any, allowed_roots: tuple[str, ...]) -> bool:
    if not _non_empty_string(value):
        return False
    text = str(value).replace("\\", "/")
    path = PurePosixPath(text)
    if path.is_absolute() or ".." in path.parts:
        return False
    if not path.parts:
        return False
    return path.parts[0] in allowed_roots


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timezone_required")
    return parsed


def _mapping(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise TypeError("expected_mapping")
    return value


def _non_empty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _specification_fingerprint(request: Mapping[str, Any]) -> str:
    stable = json.dumps(request, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(stable.encode("utf-8")).hexdigest()


def _min_delay_from_rate(rate_limit_per_second: float) -> int:
    delay = 1 / rate_limit_per_second
    return max(1, int(delay))
