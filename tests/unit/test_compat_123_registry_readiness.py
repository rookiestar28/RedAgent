from __future__ import annotations

from dataclasses import replace

import pytest

from redagent_platform.campaign_service.registry import (
    ExecutionReadinessFacts,
    StrategyLoopMode,
    closed_execution_registry,
    evaluate_strategy_loop_readiness,
    load_strategy_loop_mode,
)


def _facts(**overrides: bool) -> ExecutionReadinessFacts:
    values = {
        "database_ready": True,
        "temporal_ready": True,
        "resolver_ready": True,
        "policy_ready": True,
        "quota_ready": True,
        "runner_ready": True,
        "evidence_ready": True,
        "finding_import_ready": True,
        "kill_switch_ready": True,
        "zap_adapter_ready": True,
        "nuclei_adapter_ready": True,
    }
    values.update(overrides)
    return ExecutionReadinessFacts(**values)


def test_strategy_loop_mode_defaults_disabled_and_rejects_unknown_values() -> None:
    assert load_strategy_loop_mode({}) is StrategyLoopMode.DISABLED
    assert load_strategy_loop_mode(
        {"REDAGENT_STRATEGY_LOOP_MODE": "two_capability"}
    ) is StrategyLoopMode.TWO_CAPABILITY
    with pytest.raises(ValueError, match="strategy_loop_mode_invalid"):
        load_strategy_loop_mode({"REDAGENT_STRATEGY_LOOP_MODE": "generic_plugins"})


def test_closed_registry_contains_only_exact_noninterchangeable_first_slice_bindings() -> None:
    registry = closed_execution_registry()

    assert tuple(registry) == (
        "nuclei-trusted-runtime@2",
        "zap-controlled-runtime@2",
    )
    zap = registry["zap-controlled-runtime@2"]
    nuclei = registry["nuclei-trusted-runtime@2"]
    assert (zap.adapter_id, zap.adapter_version, zap.profile_id, zap.profile_revision) == (
        "zap-service",
        "2.17.0-r104.2",
        "zap-passive-v1",
        1,
    )
    assert zap.bundle_id is None and zap.bundle_revision is None
    assert (
        nuclei.adapter_id,
        nuclei.adapter_version,
        nuclei.profile_id,
        nuclei.profile_revision,
        nuclei.bundle_id,
        nuclei.bundle_revision,
    ) == (
        "nuclei-service",
        "3.11.1-r105.2",
        "nuclei-http-header-v1",
        1,
        "r105-http-header-bundle",
        2,
    )
    with pytest.raises(KeyError):
        registry["zap-active-runtime@1"]


def test_disabled_mode_never_enables_dispatch_and_does_not_weaken_base_readiness() -> None:
    result = evaluate_strategy_loop_readiness(
        StrategyLoopMode.DISABLED,
        _facts(database_ready=False, temporal_ready=False),
    )

    assert result.ready is True
    assert result.execution_enabled is False
    assert result.reason == "strategy_loop_disabled"


@pytest.mark.parametrize(
    "missing",
    [
        "database_ready",
        "temporal_ready",
        "resolver_ready",
        "policy_ready",
        "quota_ready",
        "runner_ready",
        "evidence_ready",
        "finding_import_ready",
        "kill_switch_ready",
        "zap_adapter_ready",
        "nuclei_adapter_ready",
    ],
)
def test_enabled_mode_fails_closed_for_every_incomplete_dependency(missing: str) -> None:
    result = evaluate_strategy_loop_readiness(
        StrategyLoopMode.TWO_CAPABILITY,
        replace(_facts(), **{missing: False}),
    )

    assert result.ready is False
    assert result.execution_enabled is False
    assert result.reason == f"strategy_loop_dependency_missing:{missing}"


def test_enabled_mode_requires_and_reports_exact_two_capability_registry() -> None:
    result = evaluate_strategy_loop_readiness(
        StrategyLoopMode.TWO_CAPABILITY,
        _facts(),
    )

    assert result.ready is True
    assert result.execution_enabled is True
    assert result.reason == "strategy_loop_two_capability_ready"
    assert result.capability_ids == (
        "nuclei-trusted-runtime@2",
        "zap-controlled-runtime@2",
    )
