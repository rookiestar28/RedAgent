"""Closed first-slice execution registry and fail-closed compat_123 readiness."""

from __future__ import annotations

from dataclasses import dataclass, fields
from enum import Enum
from types import MappingProxyType
from typing import Mapping

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
    zap_profile = certified_zap_profiles()[CertifiedProfileId.PASSIVE]
    nuclei_profile = certified_nuclei_profiles()[NucleiProfileId.HTTP_HEADER]
    values = (
        ClosedExecutionBinding(
            capability_id="nuclei-trusted-runtime",
            capability_revision=2,
            adapter_id="nuclei-service",
            adapter_version="3.11.1-r105.2",
            profile_id="nuclei-http-header-v1",
            profile_revision=1,
            profile_sha256=canonical_nuclei_profile_sha256(nuclei_profile),
            bundle_id="r105-http-header-bundle",
            bundle_revision=2,
            bundle_sha256=CURRENT_R105_HTTP_HEADER_BUNDLE_SHA256,
            approval_tier=1,
            requires_secret=False,
        ),
        ClosedExecutionBinding(
            capability_id="zap-controlled-runtime",
            capability_revision=2,
            adapter_id="zap-service",
            adapter_version="2.17.0-r104.2",
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
    for item in fields(facts):
        if not getattr(facts, item.name):
            return StrategyLoopReadiness(
                ready=False,
                execution_enabled=False,
                reason=f"strategy_loop_dependency_missing:{item.name}",
                capability_ids=(),
            )
    capability_ids = tuple(closed_execution_registry())
    if capability_ids != (
        "nuclei-trusted-runtime@2",
        "zap-controlled-runtime@2",
    ):
        return StrategyLoopReadiness(
            ready=False,
            execution_enabled=False,
            reason="strategy_loop_registry_invalid",
            capability_ids=(),
        )
    return StrategyLoopReadiness(
        ready=True,
        execution_enabled=True,
        reason="strategy_loop_two_capability_ready",
        capability_ids=capability_ids,
    )
