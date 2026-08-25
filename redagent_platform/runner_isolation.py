"""Runner isolation design contracts for agentless, ephemeral, and persistent models."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class RunnerExecutionModel(str, Enum):
    AGENTLESS = "agentless"
    EPHEMERAL_RUNNER = "ephemeral_runner"
    PERSISTENT_AGENT = "persistent_agent"


class RunnerRecommendation(str, Enum):
    RECOMMENDED = "recommended"
    ACCEPTABLE_WITH_LIMITS = "acceptable_with_limits"
    BLOCKED_PENDING_THREAT_MODEL = "blocked_pending_threat_model"


class RunnerAbuseCase(str, Enum):
    ROGUE_RUNNER = "rogue_runner"
    STOLEN_RUNNER_TOKEN = "stolen_runner_token"
    COMMAND_INJECTION = "command_injection"
    LATERAL_MOVEMENT = "lateral_movement"


REQUIRED_ABUSE_CASES: frozenset[RunnerAbuseCase] = frozenset(RunnerAbuseCase)
REQUIRED_DESIGN_FIELDS: tuple[str, ...] = (
    "trust_boundaries",
    "registration",
    "authentication",
    "command_authorization",
    "telemetry",
    "payload_storage",
    "revocation",
    "uninstall",
)


@dataclass(frozen=True, kw_only=True)
class RunnerModelAssessment:
    model: RunnerExecutionModel
    trust_boundary: str
    persistence: str
    revocation_complexity: str
    operational_complexity: str
    recommendation: RunnerRecommendation
    rationale: str


@dataclass(frozen=True, kw_only=True)
class KaliLabNodePolicy:
    allowed_as_controlled_lab_node: bool
    primary_development_root: bool
    may_run_against_project_tree: bool
    artifact_exchange: tuple[str, ...]
    requires_runner_policy_gate: bool


@dataclass(frozen=True, kw_only=True)
class RunnerIsolationDesign:
    design_id: str
    selected_model: RunnerExecutionModel
    trust_boundaries: str
    registration: str
    authentication: str
    command_authorization: str
    telemetry: str
    payload_storage: str
    revocation: str
    uninstall: str
    abuse_cases: tuple[RunnerAbuseCase, ...]
    kali_lab_node_policy: KaliLabNodePolicy
    threat_model_review_id: str | None = None
    persistent_agent_code_shipped: bool = False


@dataclass(frozen=True, kw_only=True)
class RunnerIsolationValidation:
    accepted: bool
    reason: str
    gaps: tuple[str, ...] = ()


def compare_runner_models() -> tuple[RunnerModelAssessment, ...]:
    return (
        RunnerModelAssessment(
            model=RunnerExecutionModel.AGENTLESS,
            trust_boundary="control-plane-to-approved-api-or-local-manual-operation",
            persistence="none",
            revocation_complexity="low",
            operational_complexity="low",
            recommendation=RunnerRecommendation.ACCEPTABLE_WITH_LIMITS,
            rationale="Best for passive and read-only workflows but limited for endpoint telemetry validation.",
        ),
        RunnerModelAssessment(
            model=RunnerExecutionModel.EPHEMERAL_RUNNER,
            trust_boundary="short-lived-runner-with-policy-token-and-scoped-target",
            persistence="short-lived",
            revocation_complexity="medium",
            operational_complexity="medium",
            recommendation=RunnerRecommendation.RECOMMENDED,
            rationale="Preferred default for controlled execution because runtime state can expire and cleanup is bounded.",
        ),
        RunnerModelAssessment(
            model=RunnerExecutionModel.PERSISTENT_AGENT,
            trust_boundary="long-lived-endpoint-agent-with-remote-command-channel",
            persistence="long-lived",
            revocation_complexity="high",
            operational_complexity="high",
            recommendation=RunnerRecommendation.BLOCKED_PENDING_THREAT_MODEL,
            rationale="Blocked until threat-model review covers persistence, command authorization, revocation, uninstall, and lateral-movement risk.",
        ),
    )


def validate_runner_isolation_design(design: RunnerIsolationDesign) -> RunnerIsolationValidation:
    gaps = list(_missing_design_fields(design))
    missing_abuse = REQUIRED_ABUSE_CASES - set(design.abuse_cases)
    gaps.extend(f"missing_abuse_case:{case.value}" for case in sorted(missing_abuse, key=lambda item: item.value))
    kali_gap = _kali_policy_gap(design.kali_lab_node_policy)
    if kali_gap:
        gaps.append(kali_gap)
    persistent_denial = _persistent_agent_denial(design)
    if persistent_denial:
        gaps.append(persistent_denial)
    if gaps:
        return RunnerIsolationValidation(accepted=False, reason="runner_isolation_design_incomplete", gaps=tuple(gaps))
    return RunnerIsolationValidation(accepted=True, reason="runner_isolation_design_accepted")


def evaluate_persistent_agent_gate(design: RunnerIsolationDesign) -> RunnerIsolationValidation:
    denial = _persistent_agent_denial(design)
    if denial:
        return RunnerIsolationValidation(accepted=False, reason=denial, gaps=(denial,))
    return RunnerIsolationValidation(accepted=True, reason="persistent_agent_design_reviewed")


def _missing_design_fields(design: RunnerIsolationDesign) -> tuple[str, ...]:
    missing = []
    for field_name in REQUIRED_DESIGN_FIELDS:
        value = getattr(design, field_name)
        if not isinstance(value, str) or not value.strip():
            missing.append(field_name)
    if not design.design_id.strip():
        missing.append("design_id")
    return tuple(missing)


def _kali_policy_gap(policy: KaliLabNodePolicy) -> str | None:
    if policy.primary_development_root:
        return "kali_must_not_be_primary_development_root"
    if policy.may_run_against_project_tree:
        return "kali_must_not_run_against_project_tree"
    if policy.allowed_as_controlled_lab_node and not policy.requires_runner_policy_gate:
        return "kali_runner_policy_gate_required"
    if not policy.artifact_exchange:
        return "kali_artifact_exchange_required"
    return None


def _persistent_agent_denial(design: RunnerIsolationDesign) -> str | None:
    if design.persistent_agent_code_shipped:
        return "persistent_agent_code_forbidden_before_review"
    if design.selected_model is RunnerExecutionModel.PERSISTENT_AGENT and not design.threat_model_review_id:
        return "persistent_agent_threat_model_required"
    return None
