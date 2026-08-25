"""Versioned, bounded values permitted to cross the Temporal history boundary."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re


CONTRACT_SCHEMA_VERSION = "1.0"
_OPAQUE_ID = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")
_REFERENCE = re.compile(r"^[A-Za-z0-9._:/-]{1,100}$")
_SENSITIVE = re.compile(r"(?:password|secret|token|credential|private[_ -]?key)\s*[=:]", re.IGNORECASE)


class WorkflowState(str, Enum):
    DISPATCH_PENDING = "dispatch_pending"
    AWAITING_APPROVAL = "awaiting_approval"
    READY = "ready"
    DISPATCHING = "dispatching"
    SUCCEEDED = "succeeded"
    PAUSED = "paused"
    FAILED = "failed"
    CANCEL_REQUESTED = "cancel_requested"
    CANCELLED = "cancelled"
    STOP_REQUESTED = "stop_requested"


class CommandAction(str, Enum):
    APPROVE = "approve"
    PAUSE = "pause"
    RESUME = "resume"
    RETRY = "retry"
    CANCEL = "cancel"


@dataclass(frozen=True, slots=True)
class JobWorkflowInput:
    schema_version: str
    tenant_id: str
    job_id: str
    engagement_id: str
    roe_version_id: str
    policy_reference: str
    expected_job_version: int
    approval_timeout_seconds: int
    max_activity_attempts: int
    runner_dispatch_enabled: bool = False

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("tenant_id", self.tenant_id)
        _identifier("job_id", self.job_id)
        _identifier("engagement_id", self.engagement_id)
        _identifier("roe_version_id", self.roe_version_id)
        _reference("policy_reference", self.policy_reference)
        if isinstance(self.expected_job_version, bool) or self.expected_job_version < 1:
            raise ValueError("expected_job_version_invalid")
        if isinstance(self.approval_timeout_seconds, bool) or not 1 <= self.approval_timeout_seconds <= 604_800:
            raise ValueError("approval_timeout_invalid")
        if isinstance(self.max_activity_attempts, bool) or not 1 <= self.max_activity_attempts <= 5:
            raise ValueError("activity_attempts_invalid")
        if not isinstance(self.runner_dispatch_enabled, bool):
            raise ValueError("runner_dispatch_enabled_invalid")


@dataclass(frozen=True, slots=True)
class OperatorCommand:
    schema_version: str
    command_id: str
    action: str
    actor_user_id: str
    expected_revision: int
    policy_reference: str
    reason: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("command_id", self.command_id)
        _identifier("actor_user_id", self.actor_user_id)
        action = self.action.value if isinstance(self.action, CommandAction) else self.action
        if not isinstance(action, str) or action not in {item.value for item in CommandAction}:
            raise ValueError("command_action_invalid")
        object.__setattr__(self, "action", action)
        if isinstance(self.expected_revision, bool) or self.expected_revision < 1:
            raise ValueError("expected_revision_invalid")
        _reference("policy_reference", self.policy_reference)
        if not isinstance(self.reason, str) or not 10 <= len(self.reason.strip()) <= 500 or _SENSITIVE.search(self.reason):
            raise ValueError("command_reason_invalid")


@dataclass(frozen=True, slots=True)
class JobSnapshot:
    schema_version: str
    job_id: str
    state: str
    revision: int
    current_gate: str
    failure_code: str | None
    retry_count: int
    dispatch_blocked: bool
    stop_requested: bool
    last_command_id: str | None


@dataclass(frozen=True, slots=True)
class ActivityCommand:
    schema_version: str
    tenant_id: str
    job_id: str
    command_id: str
    action: str
    actor_user_id: str
    expected_revision: int
    policy_reference: str
    request_hash: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("tenant_id", self.tenant_id)
        _identifier("job_id", self.job_id)
        _identifier("command_id", self.command_id)
        _identifier("actor_user_id", self.actor_user_id)
        _reference("policy_reference", self.policy_reference)
        if not re.fullmatch(r"[0-9a-f]{64}", self.request_hash):
            raise ValueError("activity_request_hash_invalid")


@dataclass(frozen=True, slots=True)
class ActivityResult:
    schema_version: str
    job_id: str
    command_id: str
    state: str
    revision: int
    replayed: bool


@dataclass(frozen=True, slots=True)
class RunnerDispatchCommand:
    """Metadata-only compat_100 command safe for durable Temporal history."""

    schema_version: str
    tenant_id: str
    job_id: str
    engagement_id: str
    roe_version_id: str
    policy_reference: str
    expected_revision: int
    dispatch_id: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name in ("tenant_id", "job_id", "engagement_id", "roe_version_id", "dispatch_id"):
            _identifier(name, getattr(self, name))
        if not isinstance(self.policy_reference, str) or _SENSITIVE.search(self.policy_reference):
            raise ValueError("runner_dispatch_reference_invalid")
        try:
            _reference("policy_reference", self.policy_reference)
        except ValueError as exc:
            raise ValueError("runner_dispatch_reference_invalid") from exc
        if isinstance(self.expected_revision, bool) or self.expected_revision < 1:
            raise ValueError("runner_dispatch_revision_invalid")


@dataclass(frozen=True, slots=True)
class RunnerDispatchResult:
    """Bounded terminal metadata; executable content is intentionally absent."""

    schema_version: str
    job_id: str
    execution_id: str
    manifest_sha256: str
    evidence_ids: tuple[str, ...]
    state: str
    cleanup_completed: bool
    failure_code: str | None

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name in ("job_id", "execution_id"):
            _identifier(name, getattr(self, name))
        if not re.fullmatch(r"[0-9a-f]{64}", self.manifest_sha256):
            raise ValueError("runner_dispatch_manifest_hash_invalid")
        if (
            not isinstance(self.evidence_ids, tuple) or len(self.evidence_ids) > 16
            or len(set(self.evidence_ids)) != len(self.evidence_ids)
        ):
            raise ValueError("runner_dispatch_evidence_ids_invalid")
        for value in self.evidence_ids:
            _identifier("evidence_id", value)
        if self.state not in {"succeeded", "failed"} or not isinstance(self.cleanup_completed, bool):
            raise ValueError("runner_dispatch_result_invalid")
        if self.state == "succeeded" and (not self.cleanup_completed or not self.evidence_ids or self.failure_code is not None):
            raise ValueError("runner_dispatch_success_cleanup_required")
        if self.state == "failed" and (not self.failure_code or len(self.failure_code) > 100):
            raise ValueError("runner_dispatch_failure_code_required")


@dataclass(frozen=True, slots=True)
class ContainmentActivityCommand:
    """Metadata-only compat_101 command; runtime identifiers and secrets are excluded."""

    schema_version: str
    tenant_id: str
    job_id: str
    stop_id: str
    control_id: str
    actor_user_id: str
    policy_reference: str
    expected_revision: int
    reason_hash: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name in ("tenant_id", "job_id", "stop_id", "control_id", "actor_user_id"):
            _identifier(name, getattr(self, name))
        _reference("policy_reference", self.policy_reference)
        if isinstance(self.expected_revision, bool) or self.expected_revision < 1:
            raise ValueError("containment_revision_invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.reason_hash):
            raise ValueError("containment_reason_hash_invalid")


@dataclass(frozen=True, slots=True)
class ContainmentActivityResult:
    schema_version: str
    job_id: str
    stop_id: str
    action_id: str
    outcome: str
    acknowledgement_ms: int
    residual_risk_codes: tuple[str, ...]

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name in ("job_id", "stop_id", "action_id"):
            _identifier(name, getattr(self, name))
        if self.outcome not in {"contained", "contained_with_residual_risk", "containment_failed"}:
            raise ValueError("containment_outcome_invalid")
        if (
            isinstance(self.acknowledgement_ms, bool)
            or not 0 <= self.acknowledgement_ms <= 10_000
        ):
            raise ValueError("containment_acknowledgement_invalid")
        if (
            not isinstance(self.residual_risk_codes, tuple)
            or len(self.residual_risk_codes) > 32
            or len(set(self.residual_risk_codes)) != len(self.residual_risk_codes)
        ):
            raise ValueError("containment_residual_risks_invalid")
        for value in self.residual_risk_codes:
            _identifier("residual_risk_code", value)


@dataclass(frozen=True, slots=True)
class CampaignActivityResult:
    schema_version: str
    campaign_id: str
    state: str
    revision: int


@dataclass(frozen=True, slots=True)
class EmergencyStopSignal:
    schema_version: str
    signal_id: str
    actor_user_id: str
    policy_reference: str
    reason: str
    control_id: str | None = None

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("signal_id", self.signal_id)
        _identifier("actor_user_id", self.actor_user_id)
        _reference("policy_reference", self.policy_reference)
        if not isinstance(self.reason, str) or not 10 <= len(self.reason.strip()) <= 500 or _SENSITIVE.search(self.reason):
            raise ValueError("stop_reason_invalid")
        if self.control_id is not None:
            _identifier("control_id", self.control_id)


@dataclass(frozen=True, slots=True)
class CampaignWorkflowInput:
    schema_version: str
    tenant_id: str
    campaign_id: str
    jobs: tuple[JobWorkflowInput, ...]

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("tenant_id", self.tenant_id)
        _identifier("campaign_id", self.campaign_id)
        if not isinstance(self.jobs, tuple) or not 1 <= len(self.jobs) <= 100:
            raise ValueError("campaign_jobs_invalid")
        if any(job.tenant_id != self.tenant_id for job in self.jobs):
            raise ValueError("campaign_job_tenant_mismatch")


@dataclass(frozen=True, slots=True)
class CampaignSnapshot:
    schema_version: str
    campaign_id: str
    child_workflow_ids: tuple[str, ...]
    state: str


@dataclass(frozen=True, slots=True)
class R123CampaignWorkflowInput:
    schema_version: str
    tenant_id: str
    campaign_id: str
    strategy_revision_id: str
    envelope_sha256: str
    max_depth: int
    max_replan_count: int
    max_activity_attempts: int

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name in ("tenant_id", "campaign_id", "strategy_revision_id"):
            _identifier(name, getattr(self, name))
        _digest("r123_envelope_sha256", self.envelope_sha256)
        if isinstance(self.max_depth, bool) or not 1 <= self.max_depth <= 2:
            raise ValueError("r123_max_depth_invalid")
        if isinstance(self.max_replan_count, bool) or not 0 <= self.max_replan_count <= 1:
            raise ValueError("r123_max_replan_count_invalid")
        if isinstance(self.max_activity_attempts, bool) or not 1 <= self.max_activity_attempts <= 5:
            raise ValueError("activity_attempts_invalid")


@dataclass(frozen=True, slots=True)
class R123CampaignSnapshot:
    schema_version: str
    campaign_id: str
    strategy_revision_id: str
    workflow_request_sha256: str
    state: str
    revision: int
    depth: int
    replan_count: int
    current_node_id: str | None
    terminal_reason: str | None
    stop_requested: bool


@dataclass(frozen=True, slots=True)
class R123ReconcileActivityCommand:
    schema_version: str
    tenant_id: str
    campaign_id: str
    strategy_revision_id: str
    envelope_sha256: str
    workflow_request_sha256: str
    revision: int
    stop_requested: bool

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name in ("tenant_id", "campaign_id", "strategy_revision_id"):
            _identifier(name, getattr(self, name))
        _digest("r123_envelope_sha256", self.envelope_sha256)
        _digest("r123_workflow_request_sha256", self.workflow_request_sha256)
        if isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("r123_revision_invalid")
        if not isinstance(self.stop_requested, bool):
            raise ValueError("r123_stop_requested_invalid")


@dataclass(frozen=True, slots=True)
class R123ReconcileActivityResult:
    schema_version: str
    campaign_id: str
    strategy_revision_id: str
    revision: int
    depth: int
    replan_count: int
    node_id: str | None
    effect_id: str | None
    outcome: str
    terminal: bool
    reason: str
    retry_delay_seconds: int | None

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("campaign_id", self.campaign_id)
        _identifier("strategy_revision_id", self.strategy_revision_id)
        if isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("r123_revision_invalid")
        if isinstance(self.depth, bool) or not 0 <= self.depth <= 2:
            raise ValueError("r123_depth_invalid")
        if isinstance(self.replan_count, bool) or not 0 <= self.replan_count <= 1:
            raise ValueError("r123_replan_count_invalid")
        outcomes = {
            "settled",
            "dispatch_once",
            "retry_at",
            "blocked",
            "contained",
            "terminal_failure",
        }
        if self.outcome not in outcomes:
            raise ValueError("r123_reconcile_outcome_invalid")
        terminal_outcomes = {"settled", "blocked", "contained", "terminal_failure"}
        if not isinstance(self.terminal, bool) or self.terminal != (self.outcome in terminal_outcomes):
            raise ValueError("r123_reconcile_terminal_invalid")
        if self.node_id is not None:
            _identifier("node_id", self.node_id)
        if self.effect_id is not None:
            _identifier("effect_id", self.effect_id)
        if self.outcome == "dispatch_once" and (self.node_id is None or self.effect_id is None):
            raise ValueError("r123_dispatch_identity_required")
        _reference("r123_reconcile_reason", self.reason)
        if self.outcome == "retry_at":
            if (
                isinstance(self.retry_delay_seconds, bool)
                or not isinstance(self.retry_delay_seconds, int)
                or not 1 <= self.retry_delay_seconds <= 300
            ):
                raise ValueError("r123_retry_delay_required")
        elif self.retry_delay_seconds is not None:
            raise ValueError("r123_retry_delay_unexpected")


@dataclass(frozen=True, slots=True)
class R123DispatchActivityCommand:
    schema_version: str
    tenant_id: str
    campaign_id: str
    strategy_revision_id: str
    node_id: str
    effect_id: str
    envelope_sha256: str
    expected_revision: int

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name in (
            "tenant_id",
            "campaign_id",
            "strategy_revision_id",
            "node_id",
            "effect_id",
        ):
            _identifier(name, getattr(self, name))
        _digest("r123_envelope_sha256", self.envelope_sha256)
        if isinstance(self.expected_revision, bool) or self.expected_revision < 1:
            raise ValueError("r123_revision_invalid")


@dataclass(frozen=True, slots=True)
class R123DispatchActivityResult:
    schema_version: str
    campaign_id: str
    effect_id: str
    state: str
    revision: int
    failure_code: str | None

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("campaign_id", self.campaign_id)
        _identifier("effect_id", self.effect_id)
        if self.state not in {"dispatched", "reconciliation_required", "blocked"}:
            raise ValueError("r123_dispatch_state_invalid")
        if isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("r123_revision_invalid")
        if self.failure_code is not None:
            _reference("r123_dispatch_failure", self.failure_code)


@dataclass(frozen=True, slots=True)
class R123StopSignal:
    schema_version: str
    signal_id: str
    actor_user_id: str
    reason_sha256: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("signal_id", self.signal_id)
        _identifier("actor_user_id", self.actor_user_id)
        _digest("r123_stop_reason_sha256", self.reason_sha256)


@dataclass(frozen=True, slots=True)
class R123ContainActivityCommand:
    schema_version: str
    tenant_id: str
    campaign_id: str
    strategy_revision_id: str
    signal_id: str
    actor_user_id: str
    reason_sha256: str
    expected_revision: int

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        for name in (
            "tenant_id",
            "campaign_id",
            "strategy_revision_id",
            "signal_id",
            "actor_user_id",
        ):
            _identifier(name, getattr(self, name))
        _digest("r123_stop_reason_sha256", self.reason_sha256)
        if isinstance(self.expected_revision, bool) or self.expected_revision < 1:
            raise ValueError("r123_revision_invalid")


@dataclass(frozen=True, slots=True)
class R123ContainActivityResult:
    schema_version: str
    campaign_id: str
    state: str
    revision: int
    reason: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("campaign_id", self.campaign_id)
        if self.state not in {"contained", "manual_review_required", "containment_failed"}:
            raise ValueError("r123_containment_state_invalid")
        if isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("r123_revision_invalid")
        _reference("r123_containment_reason", self.reason)



def deterministic_job_workflow_id(tenant_id: str, job_id: str) -> str:
    _identifier("tenant_id", tenant_id)
    _identifier("job_id", job_id)
    digest = hashlib.sha256(f"{tenant_id}\0{job_id}".encode("utf-8")).hexdigest()[:40]
    return f"redagent-job-v1-{digest}"


def deterministic_campaign_workflow_id(tenant_id: str, campaign_id: str) -> str:
    _identifier("tenant_id", tenant_id)
    _identifier("campaign_id", campaign_id)
    digest = hashlib.sha256(f"{tenant_id}\0{campaign_id}".encode("utf-8")).hexdigest()[:35]
    return f"redagent-campaign-v1-{digest}"


def deterministic_r123_campaign_workflow_id(tenant_id: str, campaign_id: str) -> str:
    _identifier("tenant_id", tenant_id)
    _identifier("campaign_id", campaign_id)
    digest = hashlib.sha256(f"r123\0{tenant_id}\0{campaign_id}".encode("utf-8")).hexdigest()[:40]
    return f"redagent-r123-{digest}"


def r123_workflow_request_sha256(request: R123CampaignWorkflowInput) -> str:
    canonical = json.dumps(asdict(request), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def command_request_hash(command: OperatorCommand) -> str:
    canonical = json.dumps(asdict(command), sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def stop_request_hash(request: EmergencyStopSignal) -> str:
    canonical = json.dumps(asdict(request), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def system_request_hash(*, tenant_id: str, job_id: str, action: str, revision: int) -> str:
    _identifier("tenant_id", tenant_id)
    _identifier("job_id", job_id)
    _reference("system_action", action)
    if isinstance(revision, bool) or revision < 1:
        raise ValueError("system_revision_invalid")
    return hashlib.sha256(f"{tenant_id}\0{job_id}\0{action}\0{revision}".encode("utf-8")).hexdigest()


def _schema(value: str) -> None:
    if value != CONTRACT_SCHEMA_VERSION:
        raise ValueError("contract_schema_version_unsupported")


def _identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _OPAQUE_ID.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _reference(name: str, value: str) -> None:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
        raise ValueError(f"{name}_invalid")
