from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace

from redagent_platform.campaign_service.activity_store import (
    ResolverActivitySafetyGate,
    _Common,
    _current_action_and_effect,
)
from redagent_platform.campaign_service.registry import ExecutionReadinessFacts


NOW = datetime(2026, 8, 24, 2, tzinfo=timezone.utc)


class _Resolver:
    def __init__(self, *, allowed: bool = True) -> None:
        self.allowed = allowed
        self.requests = []

    async def resolve(self, request, *, now):
        self.requests.append((request, now))
        return SimpleNamespace(allowed=self.allowed, bindings=object() if self.allowed else None)


class _FactsOwner:
    def __init__(self, facts: ExecutionReadinessFacts) -> None:
        self.facts = facts
        self.calls = []

    async def read(self, **values):
        self.calls.append(values)
        return self.facts


class _Rows:
    def __init__(self, rows):
        self._rows = rows

    def mappings(self):
        return self

    def all(self):
        return self._rows

    def one_or_none(self):
        if self._rows is None:
            return None
        if isinstance(self._rows, list):
            return self._rows[0] if self._rows else None
        return self._rows


class _EffectSession:
    def __init__(self, rows, *, coverage_state: str = "complete") -> None:
        self.results = [
            _Rows(rows),
            _Rows(
                {
                    "coverage_state": coverage_state,
                    "adapter_id": "zap-service",
                    "import_state": "accepted",
                }
            ),
        ]

    async def execute(self, statement):
        return self.results.pop(0)


def _common(successor_condition: str) -> _Common:
    return _Common(
        tenant_id="tenant-r123",
        campaign_id="campaign-r123",
        engagement_id="engagement-r123",
        target_id="target-r123",
        principal_id="principal-r123",
        strategy_record_id="strategy-record-r123",
        strategy_revision_id="strategy-r123",
        envelope_sha256="a" * 64,
        workflow_request_sha256="b" * 64,
        aggregate_sequence=1,
        replan_count=0,
        context_payload={},
        plan_payload={
            "primary": {"capability_id": "zap-controlled-runtime"},
            "successor": {
                "condition": successor_condition,
                "action": {"capability_id": "nuclei-trusted-runtime"},
            },
        },
        status="running",
    )


def _confirmed_primary():
    return {
        "effect_id": "effect-primary",
        "effect_state": "confirmed",
        "external_receipt_id": "execution-primary",
        "effect_intent_payload": {"capability_id": "zap-controlled-runtime@3"},
    }


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


def test_activity_safety_gate_rechecks_authority_and_complete_readiness() -> None:
    resolver = _Resolver()
    facts = _FactsOwner(_facts())
    gate = ResolverActivitySafetyGate(resolver, facts)

    result = asyncio.run(
        gate.check(
            tenant_id="tenant-r123",
            principal_id="principal-r123",
            engagement_id="engagement-r123",
            target_id="target-r123",
            capability_id="zap-controlled-runtime",
            now=NOW,
        )
    )

    assert result == (True, True)
    assert resolver.requests[0][0].target_id == "target-r123"
    assert facts.calls == [
        {
            "tenant_id": "tenant-r123",
            "capability_id": "zap-controlled-runtime",
            "now": NOW,
        }
    ]


def test_activity_safety_gate_denies_execution_when_temporal_health_is_lost() -> None:
    resolver = _Resolver()
    facts = _FactsOwner(_facts(temporal_ready=False))
    gate = ResolverActivitySafetyGate(resolver, facts)

    result = asyncio.run(
        gate.check(
            tenant_id="tenant-r123",
            principal_id="principal-r123",
            engagement_id="engagement-r123",
            target_id="target-r123",
            capability_id="zap-controlled-runtime",
            now=NOW,
        )
    )

    assert result == (True, False)


def test_activity_safety_gate_keeps_authority_and_infrastructure_failures_distinct() -> None:
    resolver = _Resolver(allowed=False)
    facts = _FactsOwner(_facts(evidence_ready=False))
    gate = ResolverActivitySafetyGate(resolver, facts)

    result = asyncio.run(
        gate.check(
            tenant_id="tenant-r123",
            principal_id="principal-r123",
            engagement_id="engagement-r123",
            target_id="target-r123",
            capability_id="nuclei-trusted-runtime",
            now=NOW,
        )
    )

    assert result == (False, False)


def test_activity_safety_gate_rejects_capabilities_outside_closed_registry() -> None:
    resolver = _Resolver()
    facts = _FactsOwner(_facts())
    gate = ResolverActivitySafetyGate(resolver, facts)

    result = asyncio.run(
        gate.check(
            tenant_id="tenant-r123",
            principal_id="principal-r123",
            engagement_id="engagement-r123",
            target_id="target-r123",
            capability_id="generic-command",
            now=NOW,
        )
    )

    assert result == (False, False)
    assert resolver.requests == [] and facts.calls == []


def test_pending_retest_never_reinterprets_fresh_observation_successor_condition() -> None:
    primary = _confirmed_primary()

    action, effect = asyncio.run(
        _current_action_and_effect(
            _EffectSession([primary], coverage_state="complete"),
            _common("fresh_inconclusive_or_insufficient_observation"),
        )
    )

    assert action["capability_id"] == "zap-controlled-runtime"
    assert effect is primary


def test_explicit_corroboration_selects_only_the_bounded_successor_after_primary() -> None:
    primary = _confirmed_primary()

    action, effect = asyncio.run(
        _current_action_and_effect(
            _EffectSession([primary]),
            _common("explicit_corroboration"),
        )
    )

    assert action["capability_id"] == "nuclei-trusted-runtime"
    assert effect is None


def test_fresh_partial_observation_selects_the_bounded_successor() -> None:
    primary = _confirmed_primary()

    action, effect = asyncio.run(
        _current_action_and_effect(
            _EffectSession([primary], coverage_state="partial"),
            _common("fresh_inconclusive_or_insufficient_observation"),
        )
    )

    assert action["capability_id"] == "nuclei-trusted-runtime"
    assert effect is None
