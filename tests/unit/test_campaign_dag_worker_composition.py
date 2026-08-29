import asyncio

import pytest

from redagent_platform.orchestration.worker import (
    _run_worker_with_relays,
    validate_dag_execution_worker_dependencies,
    worker_registration,
)


def test_dag_worker_mode_is_independent_and_fail_closed() -> None:
    assert validate_dag_execution_worker_dependencies({}) == (None, None)
    with pytest.raises(ValueError, match="dag_activities_required"):
        validate_dag_execution_worker_dependencies(
            {"REDAGENT_DAG_EXECUTION_MODE": "owned_loopback"},
            dag_relay_factory=object(),
        )
    with pytest.raises(ValueError, match="dag_relay_required"):
        validate_dag_execution_worker_dependencies(
            {"REDAGENT_DAG_EXECUTION_MODE": "owned_loopback"},
            dag_activities=object(),
        )
    with pytest.raises(ValueError, match="dag_activities_forbidden_when_disabled"):
        validate_dag_execution_worker_dependencies({}, dag_activities=object())

    activities = object()
    relay = object()
    assert validate_dag_execution_worker_dependencies(
        {
            "REDAGENT_DAG_EXECUTION_MODE": "owned_loopback",
            "REDAGENT_STRATEGY_LOOP_MODE": "disabled",
        },
        dag_activities=activities,
        dag_relay_factory=relay,
    ) == (activities, relay)


def test_disabled_registration_does_not_expose_dag_and_enabled_is_exact() -> None:
    disabled = worker_registration()
    assert "redagent.campaign-dag-execution.v1" not in disabled.workflow_names
    assert not any("campaign-dag" in name for name in disabled.activity_names)

    enabled = worker_registration(dag_execution_enabled=True)
    assert enabled.workflow_names[-1] == "redagent.campaign-dag-execution.v1"
    assert enabled.activity_names[-3:] == (
        "redagent.campaign-dag.reconcile.v1",
        "redagent.campaign-dag.dispatch.v1",
        "redagent.campaign-dag.contain.v1",
    )


def test_worker_and_multiple_enabled_relays_share_one_fail_closed_lifecycle() -> None:
    events = []

    class Worker:
        async def run(self):
            events.append("worker")

    class Relay:
        def __init__(self, name):
            self.name = name

        async def run(self, stop):
            events.append(self.name)
            await stop.wait()
            events.append(f"{self.name}-stopped")

    asyncio.run(_run_worker_with_relays(Worker(), (Relay("r123"), Relay("dag"))))
    assert events[0] == "worker"
    assert set(events[1:]) == {"r123", "dag", "r123-stopped", "dag-stopped"}
    assert events.index("r123") < events.index("r123-stopped")
    assert events.index("dag") < events.index("dag-stopped")
