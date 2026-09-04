from __future__ import annotations

import asyncio
from pathlib import Path
import subprocess
import sys

from scripts.redagent_workflow_worker import (
    build_runtime_admission_start_relay_factory,
    build_runtime_dag_factory,
    build_runtime_dag_relay_factory,
    build_runtime_r123_factory,
    build_runtime_r123_relay_factory,
    worker_health_response,
)
import pytest

from redagent_platform.orchestration.worker import (
    _run_worker_with_relay,
    validate_strategy_loop_worker_dependencies,
    worker_registration,
)


ROOT = Path(__file__).resolve().parents[2]


def test_worker_registration_preserves_r096_and_adds_versioned_r100_r101_r123_paths() -> None:
    registration = worker_registration()

    assert registration.workflow_names == (
        "redagent.r096.job-lifecycle.v1",
        "redagent.r096.campaign-lifecycle.v1",
        "redagent.r123.campaign-closed-loop.v1",
    )
    assert registration.activity_names == (
        "r096_admit_job",
        "r096_apply_command",
        "r096_record_system_state",
        "r096_admit_campaign",
        "r100_dispatch_synthetic_job",
        "r101_contain_synthetic_job",
        "redagent.r123.reconcile-level.v1",
        "redagent.r123.dispatch-effect.v1",
        "redagent.r123.contain.v1",
    )
    assert registration.max_concurrent_workflow_tasks == 20
    assert registration.max_concurrent_activities == 10
    assert registration.max_workflow_polls == 4
    assert registration.max_activity_polls == 4
    assert registration.runner_capability is True


def test_worker_cli_help_does_not_load_keys_connect_or_start_worker() -> None:
    completed = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "redagent_workflow_worker.py"), "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert completed.returncode == 0, completed.stderr
    assert "--graceful-shutdown-seconds" in completed.stdout
    assert "REDAGENT_TEMPORAL" not in completed.stderr


def test_worker_health_is_live_but_not_ready_until_dependencies_connect() -> None:
    assert worker_health_response("/health/live", ready=False) == (200, b'{"ok":true,"status":"live"}')
    assert worker_health_response("/health/startup", ready=False) == (200, b'{"ok":true,"status":"started"}')
    assert worker_health_response("/health/ready", ready=False) == (503, b'{"ok":false,"status":"not_ready"}')
    assert worker_health_response("/health/ready", ready=True) == (200, b'{"ok":true,"status":"ready"}')
    assert worker_health_response("/unknown", ready=True)[0] == 404


def test_worker_strategy_loop_mode_is_fail_closed_at_construction() -> None:
    assert validate_strategy_loop_worker_dependencies(
        {}, r123_coordinator=None, r123_relay_factory=None
    ) == (None, None)
    with pytest.raises(ValueError, match="r123_coordinator_required"):
        validate_strategy_loop_worker_dependencies(
            {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
            r123_coordinator=None,
            r123_relay_factory=object(),
        )
    with pytest.raises(ValueError, match="r123_coordinator_forbidden_when_disabled"):
        validate_strategy_loop_worker_dependencies(
            {}, r123_coordinator=object(), r123_relay_factory=object()
        )
    coordinator = object()
    relay_factory = object()
    assert (
        validate_strategy_loop_worker_dependencies(
            {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
            r123_coordinator=coordinator,
            r123_relay_factory=relay_factory,
        )
        == (coordinator, relay_factory)
    )

    def factory(sessions):
        return coordinator

    assert (
        validate_strategy_loop_worker_dependencies(
            {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
            r123_coordinator_factory=factory,
            r123_relay_factory=relay_factory,
        )
        == (factory, relay_factory)
    )
    with pytest.raises(ValueError, match="r123_relay_required"):
        validate_strategy_loop_worker_dependencies(
            {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
            r123_coordinator=coordinator,
            r123_relay_factory=None,
        )
    with pytest.raises(ValueError, match="r123_coordinator_ambiguous"):
        validate_strategy_loop_worker_dependencies(
            {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
            r123_coordinator=coordinator,
            r123_coordinator_factory=factory,
        )


def test_stock_worker_entrypoint_selects_r123_factory_from_the_same_environment(
    tmp_path: Path,
) -> None:
    assert build_runtime_r123_factory(tmp_path, {}) is None
    assert build_runtime_r123_relay_factory({}) is None
    assert callable(build_runtime_r123_relay_factory({
        "REDAGENT_STRATEGY_LOOP_MODE": "two_capability",
    }))
    with pytest.raises(ValueError, match="r123_signing_configuration_incomplete"):
        build_runtime_r123_factory(
            tmp_path,
            {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"},
        )


def test_stock_worker_entrypoint_selects_dag_factories_from_the_same_environment(
    tmp_path: Path,
) -> None:
    assert build_runtime_dag_factory(tmp_path, {}) is None
    assert build_runtime_dag_relay_factory({}) is None
    assert callable(build_runtime_dag_relay_factory({
        "REDAGENT_DAG_EXECUTION_MODE": "owned_loopback",
    }))
    with pytest.raises(ValueError, match="r123_signing_configuration_incomplete"):
        build_runtime_dag_factory(
            tmp_path,
            {"REDAGENT_DAG_EXECUTION_MODE": "owned_loopback"},
        )


def test_stock_worker_entrypoint_selects_start_bridge_from_autonomous_mode() -> None:
    assert build_runtime_admission_start_relay_factory(
        {"REDAGENT_AUTONOMOUS_CAMPAIGN_MODE": "disabled"}
    ) is None
    assert callable(build_runtime_admission_start_relay_factory({}))


def test_worker_and_relay_share_one_fail_closed_lifecycle() -> None:
    events: list[str] = []

    class Worker:
        async def run(self):
            events.append("worker")

    class Relay:
        async def run(self, stop):
            events.append("relay")
            await stop.wait()
            events.append("relay-stopped")

    asyncio.run(_run_worker_with_relay(Worker(), Relay()))
    assert events == ["worker", "relay", "relay-stopped"]

    class WaitingWorker:
        async def run(self):
            try:
                await asyncio.Event().wait()
            finally:
                events.append("worker-cancelled")

    class FailedRelay:
        async def run(self, stop):
            del stop
            raise RuntimeError("relay-failed")

    with pytest.raises(RuntimeError, match="relay-failed"):
        asyncio.run(_run_worker_with_relay(WaitingWorker(), FailedRelay()))
    assert events[-1] == "worker-cancelled"
