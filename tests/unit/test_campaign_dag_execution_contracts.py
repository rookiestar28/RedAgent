from __future__ import annotations

from dataclasses import FrozenInstanceError, replace

import pytest

from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagExecutionMode,
    DagExecutionSnapshotV1,
    DagNodeState,
    DagRunState,
    DagWorkflowInputV1,
    deterministic_dag_workflow_id,
    dag_workflow_request_sha256,
    load_dag_execution_mode,
)


def workflow_input(**overrides: object) -> DagWorkflowInputV1:
    values: dict[str, object] = {
        "schema_version": DAG_EXECUTION_SCHEMA_VERSION,
        "tenant_id": "tenant-a",
        "execution_run_id": "execution-a",
        "input_sha256": "a" * 64,
        "plan_sha256": "b" * 64,
        "max_activity_attempts": 2,
        "max_transitions": 16,
    }
    values.update(overrides)
    return DagWorkflowInputV1(**values)  # type: ignore[arg-type]


def test_workflow_contract_is_metadata_only_immutable_and_canonical() -> None:
    request = workflow_input()
    assert dag_workflow_request_sha256(request) == dag_workflow_request_sha256(workflow_input())
    assert deterministic_dag_workflow_id("tenant-a", "execution-a").startswith(
        "redagent-campaign-dag-v1-"
    )
    with pytest.raises(FrozenInstanceError):
        request.plan_sha256 = "c" * 64  # type: ignore[misc]
    with pytest.raises(ValueError, match="dag_workflow_transition_budget_invalid"):
        replace(request, max_transitions=0)


def test_execution_mode_is_closed_and_disabled_by_default() -> None:
    assert load_dag_execution_mode({}) is DagExecutionMode.DISABLED
    assert load_dag_execution_mode({"REDAGENT_DAG_EXECUTION_MODE": "owned_loopback"}) is (
        DagExecutionMode.OWNED_LOOPBACK
    )
    with pytest.raises(ValueError, match="dag_execution_mode_invalid"):
        load_dag_execution_mode({"REDAGENT_DAG_EXECUTION_MODE": "public_internet"})


def test_snapshot_state_is_closed_and_revision_bound() -> None:
    snapshot = DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        execution_run_id="execution-a",
        workflow_request_sha256="c" * 64,
        state=DagRunState.RUNNING,
        revision=1,
        transition_count=0,
        current_node_id=None,
        current_node_state=None,
        stop_requested=False,
        terminal_reason=None,
    )
    assert snapshot.state is DagRunState.RUNNING
    with pytest.raises(ValueError, match="dag_snapshot_node_state_invalid"):
        replace(snapshot, current_node_state=DagNodeState.CONFIRMED)
