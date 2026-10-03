"""Fault injection against the actual owned fixture finalizer, without runtime I/O."""

import asyncio
from types import SimpleNamespace

import pytest
from temporalio.service import RPCError, RPCStatusCode

from tests.integration import test_bounded_child_live as fixture


class RecordingWorkflow:
    def __init__(self, label, calls, *, describe_error=None, signal_error=None):
        self.id = label
        self.calls = calls
        self.state = "RUNNING"
        self.describe_error = describe_error
        self.signal_error = signal_error

    async def describe(self):
        self.calls.append("describe-" + self.id)
        if self.describe_error is not None:
            raise self.describe_error
        return SimpleNamespace(status=SimpleNamespace(name=self.state), run_id=self.id + "-exact-run")

    async def signal(self, name, payload):
        assert name == "stop" and payload.actor_user_id == "fixture-owner"
        self.calls.append("stop-" + self.id)
        if self.signal_error is not None:
            raise self.signal_error

    async def result(self):
        self.calls.append("result-" + self.id)
        self.state = "COMPLETED"

    async def terminate(self, *, reason):
        assert reason == "Owned fixture teardown: inert admission bridge"
        self.calls.append("terminate-" + self.id)
        self.state = "TERMINATED"


def setup_teardown(monkeypatch, *, diagnostic_error=None, dag_error=None, describe_error=None):
    calls = []
    dag = RecordingWorkflow("dag", calls, signal_error=dag_error, describe_error=describe_error)
    bridge = RecordingWorkflow("bridge", calls)

    async def diagnostics(prepared, run_id):
        assert run_id == "fixture-execution"
        calls.append("diagnostics")
        if diagnostic_error is not None:
            raise diagnostic_error

    def exact_handle(workflow_id, *, run_id, result_type=None):
        calls.append("pin-" + workflow_id)
        assert run_id == workflow_id + "-exact-run"
        return {"dag": dag, "bridge": bridge}[workflow_id]

    monkeypatch.setattr(fixture, "_execution_diagnostics", diagnostics)
    prepared = SimpleNamespace(command=SimpleNamespace(actor_user_id="fixture-owner"))
    stopper = SimpleNamespace(release=SimpleNamespace(set=lambda: calls.append("release-frontier")))
    client = SimpleNamespace(get_workflow_handle=exact_handle)
    return calls, prepared, dag, stopper, bridge, client


@pytest.mark.parametrize("error", [RuntimeError("diagnostic unavailable"), asyncio.CancelledError("diagnostic cancelled")])
def test_diagnostic_failure_still_contains_dag_before_closing_exact_bridge(monkeypatch, error):
    calls, prepared, dag, stopper, bridge, client = setup_teardown(monkeypatch, diagnostic_error=error)
    with pytest.raises(type(error), match=str(error)):
        asyncio.run(fixture._cleanup_execution(prepared, "fixture-execution", dag, stopper, bridge, client))
    assert calls.index("release-frontier") < calls.index("stop-dag") < calls.index("result-dag") < calls.index("terminate-bridge")
    assert dag.state == "COMPLETED" and bridge.state == "TERMINATED"
    assert "pin-dag" in calls and "pin-bridge" in calls


def test_dag_cleanup_failure_is_visible_and_bridge_cleanup_is_still_attempted(monkeypatch):
    calls, prepared, dag, stopper, bridge, client = setup_teardown(monkeypatch,
        diagnostic_error=RuntimeError("diagnostic unavailable"), dag_error=RuntimeError("native stop failed"))
    with pytest.raises(RuntimeError, match="native stop failed") as raised:
        asyncio.run(fixture._cleanup_execution(prepared, "fixture-execution", dag, stopper, bridge, client))
    assert str(raised.value.__context__) == "diagnostic unavailable"
    assert calls.index("release-frontier") < calls.index("stop-dag") < calls.index("terminate-bridge")
    assert dag.state == "RUNNING" and bridge.state == "TERMINATED"


def test_never_started_dag_does_not_prevent_exact_bridge_cleanup(monkeypatch):
    missing = RPCError("fixture workflow never started", RPCStatusCode.NOT_FOUND, b"")
    calls, prepared, dag, stopper, bridge, client = setup_teardown(monkeypatch, describe_error=missing)
    asyncio.run(fixture._cleanup_execution(prepared, "fixture-execution", dag, stopper, bridge, client))
    assert "release-frontier" in calls and "stop-dag" not in calls
    assert bridge.state == "TERMINATED"


def test_lookup_failure_is_not_treated_as_absent_dag(monkeypatch):
    unavailable = RPCError("fixture workflow lookup unavailable", RPCStatusCode.UNAVAILABLE, b"")
    calls, prepared, dag, stopper, bridge, client = setup_teardown(monkeypatch, describe_error=unavailable)
    with pytest.raises(RPCError):
        asyncio.run(fixture._cleanup_execution(prepared, "fixture-execution", dag, stopper, bridge, client))
    assert "release-frontier" in calls and bridge.state == "TERMINATED"


@pytest.mark.parametrize("status", [RPCStatusCode.NOT_FOUND, RPCStatusCode.UNAVAILABLE])
def test_bridge_lookup_only_accepts_never_started_identity(monkeypatch, status):
    calls, prepared, dag, stopper, bridge, client = setup_teardown(monkeypatch)
    bridge.describe_error = RPCError("bridge lookup failed", status, b"")
    if status is RPCStatusCode.NOT_FOUND:
        asyncio.run(fixture._cleanup_execution(prepared, "fixture-execution", dag, stopper, bridge, client))
    else:
        with pytest.raises(RPCError):
            asyncio.run(fixture._cleanup_execution(prepared, "fixture-execution", dag, stopper, bridge, client))
    assert dag.state == "COMPLETED"
    assert calls.index("result-dag") < calls.index("describe-bridge")
    assert "terminate-bridge" not in calls


def test_bridge_failure_is_visible_after_dag_cleanup(monkeypatch):
    calls, prepared, dag, stopper, bridge, client = setup_teardown(monkeypatch,
        diagnostic_error=RuntimeError("diagnostic unavailable"))

    async def failed_termination(*, reason):
        calls.append("terminate-bridge-failed")
        raise RuntimeError("exact bridge termination failed")

    monkeypatch.setattr(bridge, "terminate", failed_termination)
    with pytest.raises(RuntimeError, match="exact bridge termination failed") as raised:
        asyncio.run(fixture._cleanup_execution(prepared, "fixture-execution", dag, stopper, bridge, client))
    assert str(raised.value.__context__) == "diagnostic unavailable"
    assert dag.state == "COMPLETED" and bridge.state == "RUNNING"
    assert calls.index("result-dag") < calls.index("terminate-bridge-failed")
