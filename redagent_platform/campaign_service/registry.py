"""Closed first-slice execution registry and fail-closed compat_123 readiness."""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
from types import MappingProxyType
from typing import Mapping

from redagent_platform.artifact_pipeline.profiles import (
    canonical_profile_sha256 as canonical_artifact_profile_sha256,
    certified_profiles as certified_artifact_profiles,
)
from redagent_platform.nuclei_service.contracts import (
    CURRENT_R105_HTTP_HEADER_BUNDLE_SHA256,
    NucleiProfileId,
    canonical_profile_sha256 as canonical_nuclei_profile_sha256,
    certified_profiles as certified_nuclei_profiles,
)
from redagent_platform.zap_service.contracts import (
    CertifiedProfileId,
    canonical_profile_sha256 as canonical_zap_profile_sha256,
    certified_profiles as certified_zap_profiles,
)


class StrategyLoopMode(str, Enum):
    DISABLED = "disabled"
    TWO_CAPABILITY = "two_capability"
    THREE_CAPABILITY = "three_capability"


@dataclass(frozen=True, slots=True)
class ClosedExecutionBinding:
    capability_id: str
    capability_revision: int
    adapter_id: str
    adapter_version: str
    profile_id: str
    profile_revision: int
    profile_sha256: str
    bundle_id: str | None
    bundle_revision: int | None
    bundle_sha256: str | None
    approval_tier: int
    requires_secret: bool

    @property
    def capability_key(self) -> str:
        return f"{self.capability_id}@{self.capability_revision}"


@dataclass(frozen=True, slots=True)
class ExecutionReadinessFacts:
    database_ready: bool
    temporal_ready: bool
    resolver_ready: bool
    policy_ready: bool
    quota_ready: bool
    runner_ready: bool
    evidence_ready: bool
    finding_import_ready: bool
    kill_switch_ready: bool
    zap_adapter_ready: bool
    nuclei_adapter_ready: bool
    artifact_adapter_ready: bool = False

    def __post_init__(self) -> None:
        if any(not isinstance(getattr(self, item.name), bool) for item in fields(self)):
            raise ValueError("strategy_loop_readiness_fact_invalid")


@dataclass(frozen=True, slots=True)
class StrategyLoopReadiness:
    ready: bool
    execution_enabled: bool
    reason: str
    capability_ids: tuple[str, ...]


def load_strategy_loop_mode(env: Mapping[str, str]) -> StrategyLoopMode:
    raw = env.get("REDAGENT_STRATEGY_LOOP_MODE", StrategyLoopMode.DISABLED.value)
    try:
        return StrategyLoopMode(raw.strip())
    except (AttributeError, ValueError) as exc:
        raise ValueError("strategy_loop_mode_invalid") from exc


def closed_execution_registry() -> Mapping[str, ClosedExecutionBinding]:
    artifact_profile = certified_artifact_profiles()["r110-repository-snapshot-v1"]
    zap_profile = certified_zap_profiles()[CertifiedProfileId.PASSIVE]
    nuclei_profile = certified_nuclei_profiles()[NucleiProfileId.HTTP_HEADER]
    values = (
        ClosedExecutionBinding(
            capability_id="artifact-posture",
            capability_revision=1,
            adapter_id="redagent-canonical-artifact",
            adapter_version="1.0.0-r110.1",
            profile_id="r110-repository-snapshot-v1",
            profile_revision=1,
            profile_sha256=canonical_artifact_profile_sha256(artifact_profile),
            bundle_id=None,
            bundle_revision=None,
            bundle_sha256=None,
            approval_tier=1,
            requires_secret=False,
        ),
        ClosedExecutionBinding(
            capability_id="nuclei-trusted-runtime",
            capability_revision=3,
            adapter_id="nuclei-service",
            adapter_version="3.11.1-r105.3",
            profile_id="nuclei-http-header-v1",
            profile_revision=1,
            profile_sha256=canonical_nuclei_profile_sha256(nuclei_profile),
            bundle_id="r105-http-header-bundle",
            bundle_revision=3,
            bundle_sha256=CURRENT_R105_HTTP_HEADER_BUNDLE_SHA256,
            approval_tier=1,
            requires_secret=False,
        ),
        ClosedExecutionBinding(
            capability_id="zap-controlled-runtime",
            capability_revision=3,
            adapter_id="zap-service",
            adapter_version="2.17.0-r104.3",
            profile_id="zap-passive-v1",
            profile_revision=1,
            profile_sha256=canonical_zap_profile_sha256(zap_profile),
            bundle_id=None,
            bundle_revision=None,
            bundle_sha256=None,
            approval_tier=1,
            requires_secret=False,
        ),
    )
    return MappingProxyType({item.capability_key: item for item in values})


def closed_execution_binding_for(capability_id: str) -> ClosedExecutionBinding:
    """Resolve one capability ID only when the closed registry has one exact revision."""
    matches = tuple(
        item
        for item in closed_execution_registry().values()
        if item.capability_id == capability_id
    )
    if len(matches) != 1:
        raise ValueError("closed_execution_capability_unknown")
    return matches[0]


def evaluate_strategy_loop_readiness(
    mode: StrategyLoopMode,
    facts: ExecutionReadinessFacts,
) -> StrategyLoopReadiness:
    if not isinstance(mode, StrategyLoopMode) or not isinstance(facts, ExecutionReadinessFacts):
        raise ValueError("strategy_loop_readiness_input_invalid")
    if mode is StrategyLoopMode.DISABLED:
        return StrategyLoopReadiness(
            ready=True,
            execution_enabled=False,
            reason="strategy_loop_disabled",
            capability_ids=(),
        )
    required_fields = tuple(
        item
        for item in fields(facts)
        if mode is StrategyLoopMode.THREE_CAPABILITY
        or item.name != "artifact_adapter_ready"
    )
    for item in required_fields:
        if not getattr(facts, item.name):
            return StrategyLoopReadiness(
                ready=False,
                execution_enabled=False,
                reason=f"strategy_loop_dependency_missing:{item.name}",
                capability_ids=(),
            )
    all_capability_ids = tuple(closed_execution_registry())
    expected_two = (
        "nuclei-trusted-runtime@3",
        "zap-controlled-runtime@3",
    )
    expected_three = ("artifact-posture@1", *expected_two)
    expected = expected_three if mode is StrategyLoopMode.THREE_CAPABILITY else expected_two
    capability_ids = tuple(
        item for item in all_capability_ids if item in expected
    )
    if capability_ids != expected:
        return StrategyLoopReadiness(
            ready=False,
            execution_enabled=False,
            reason="strategy_loop_registry_invalid",
            capability_ids=(),
        )
    return StrategyLoopReadiness(
        ready=True,
        execution_enabled=True,
        reason=(
            "strategy_loop_three_capability_ready"
            if mode is StrategyLoopMode.THREE_CAPABILITY
            else "strategy_loop_two_capability_ready"
        ),
        capability_ids=capability_ids,
    )
