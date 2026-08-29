"""Bounded metadata contracts for durable admitted campaign DAG execution."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
import hashlib
import json
import re
from typing import Mapping


DAG_EXECUTION_SCHEMA_VERSION = "redagent.campaign-dag-execution/v1"

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_REASON = re.compile(r"^[a-z][a-z0-9_]{0,99}$")


class DagExecutionMode(str, Enum):
    DISABLED = "disabled"
    OWNED_LOOPBACK = "owned_loopback"


class DagRunState(str, Enum):
    START_PENDING = "start_pending"
    RUNNING = "running"
    STOPPING = "stopping"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    COMPLETED = "completed"
    CONTAINED = "contained"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    FAILED_BEFORE_IO = "failed_before_io"
    FAILED = "failed"


class DagNodeState(str, Enum):
    PENDING = "pending"
    READY = "ready"
    RESERVED = "reserved"
    CLAIMED = "claimed"
    DISPATCHING = "dispatching"
    RECONCILIATION_REQUIRED = "reconciliation_required"
    NOT_APPLIED = "not_applied"
    CONFIRMED = "confirmed"
    SKIPPED = "skipped"
    CONTAINED = "contained"
    MANUAL_REVIEW_REQUIRED = "manual_review_required"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class DagWorkflowInputV1:
    """Only bounded identifiers and digests are safe for Temporal history."""

    schema_version: str
    tenant_id: str
    execution_run_id: str
    input_sha256: str
    plan_sha256: str
    max_activity_attempts: int
    max_transitions: int

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("dag_workflow_tenant", self.tenant_id)
        _identifier("dag_workflow_execution", self.execution_run_id)
        _digest("dag_workflow_input_sha256", self.input_sha256)
        _digest("dag_workflow_plan_sha256", self.plan_sha256)
        _bounded_int(
            "dag_workflow_activity_attempts", self.max_activity_attempts, 1, 5
        )
        _bounded_int("dag_workflow_transition_budget", self.max_transitions, 1, 10_000)


@dataclass(frozen=True, slots=True)
class DagExecutionSnapshotV1:
    schema_version: str
    execution_run_id: str
    workflow_request_sha256: str
    # Typed as wire strings so Temporal's default converter does not expand str-backed Enums.
    state: str
    revision: int
    transition_count: int
    current_node_id: str | None
    current_node_state: str | None
    stop_requested: bool
    terminal_reason: str | None

    def __post_init__(self) -> None:
        # IMPORTANT: Temporal's JSON converter rehydrates Enum fields as their string values;
        # normalize them here or every Activity result fails workflow-task decoding.
        try:
            state = DagRunState(self.state)
            node_state = (
                None
                if self.current_node_state is None
                else DagNodeState(self.current_node_state)
            )
        except (TypeError, ValueError) as exc:
            raise ValueError("dag_snapshot_state_invalid") from exc
        object.__setattr__(self, "state", state)
        object.__setattr__(self, "current_node_state", node_state)
        _schema(self.schema_version)
        _identifier("dag_snapshot_execution", self.execution_run_id)
        _digest("dag_snapshot_request_sha256", self.workflow_request_sha256)
        if not isinstance(self.state, DagRunState):
            raise ValueError("dag_snapshot_run_state_invalid")
        _bounded_int("dag_snapshot_revision", self.revision, 1, 2_147_483_647)
        _bounded_int(
            "dag_snapshot_transition_count", self.transition_count, 0, 2_147_483_647
        )
        if (self.current_node_id is None) != (self.current_node_state is None):
            raise ValueError("dag_snapshot_node_state_invalid")
        if self.current_node_id is not None:
            _identifier("dag_snapshot_node", self.current_node_id)
            if not isinstance(self.current_node_state, DagNodeState):
                raise ValueError("dag_snapshot_node_state_invalid")
        if type(self.stop_requested) is not bool:
            raise ValueError("dag_snapshot_stop_invalid")
        if self.terminal_reason is not None and not _REASON.fullmatch(
            self.terminal_reason
        ):
            raise ValueError("dag_snapshot_terminal_reason_invalid")


@dataclass(frozen=True, slots=True)
class DagStopSignalV1:
    schema_version: str
    signal_id: str
    actor_user_id: str
    reason_sha256: str

    def __post_init__(self) -> None:
        _schema(self.schema_version)
        _identifier("dag_stop_signal", self.signal_id)
        _identifier("dag_stop_actor", self.actor_user_id)
        _digest("dag_stop_reason_sha256", self.reason_sha256)


@dataclass(frozen=True, slots=True)
class DagContainActivityInputV1:
    request: DagWorkflowInputV1
    stop: DagStopSignalV1
    expected_revision: int

    def __post_init__(self) -> None:
        if not isinstance(self.request, DagWorkflowInputV1) or not isinstance(
            self.stop, DagStopSignalV1
        ):
            raise ValueError("dag_contain_input_invalid")
        _bounded_int(
            "dag_contain_expected_revision", self.expected_revision, 1, 2_147_483_647
        )


def load_dag_execution_mode(env: Mapping[str, str]) -> DagExecutionMode:
    raw = env.get("REDAGENT_DAG_EXECUTION_MODE", DagExecutionMode.DISABLED.value)
    try:
        return DagExecutionMode(raw.strip())
    except (AttributeError, ValueError) as exc:
        raise ValueError("dag_execution_mode_invalid") from exc


def deterministic_dag_workflow_id(tenant_id: str, execution_run_id: str) -> str:
    _identifier("dag_workflow_tenant", tenant_id)
    _identifier("dag_workflow_execution", execution_run_id)
    digest = hashlib.sha256(
        f"campaign-dag-v1\0{tenant_id}\0{execution_run_id}".encode("utf-8")
    ).hexdigest()[:40]
    return f"redagent-campaign-dag-v1-{digest}"


def dag_workflow_request_sha256(request: DagWorkflowInputV1) -> str:
    if not isinstance(request, DagWorkflowInputV1):
        raise ValueError("dag_workflow_input_invalid")
    canonical = json.dumps(
        asdict(request), sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _schema(value: str) -> None:
    if value != DAG_EXECUTION_SCHEMA_VERSION:
        raise ValueError("dag_execution_schema_unsupported")


def _identifier(name: str, value: str) -> None:
    if not isinstance(value, str) or not _IDENTIFIER.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _digest(name: str, value: str) -> None:
    if not isinstance(value, str) or not _SHA256.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _bounded_int(name: str, value: int, minimum: int, maximum: int) -> None:
    if type(value) is not int or not minimum <= value <= maximum:
        raise ValueError(f"{name}_invalid")
