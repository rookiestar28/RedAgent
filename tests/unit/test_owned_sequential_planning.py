from __future__ import annotations

from dataclasses import replace
import importlib

import pytest

from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1, ValidationResult
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.validation import validate_candidate_plan, VALIDATOR_VERSION
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_planning_contracts import NOW
from tests.unit.test_child_replan_subset import owned_parent_child, owned_planning_material


def _closed():
    try:
        return importlib.import_module("redagent_platform.campaign_service.planning.owned_sequential")
    except ModuleNotFoundError:
        pytest.fail("No independently identified closed sequential profile exists")


def test_generic_profile_remains_conservative_and_closed_profile_proves_whole_minute_request_bound():
    current_domain, human, initial, _ = owned_planning_material()
    old = plan_attack_path(current_domain, human, initial, search_limits())
    assert old.revision is None
    closed = _closed()
    parent = closed.plan_owned_sequential_attack_path(current_domain, human, initial, search_limits()).revision
    assert parent is not None and parent.node_count == 2
    limits = ValidationLimitsV1(2, 1, 32)
    generic = validate_candidate_plan(parent.candidate_plan, current_domain, human, limits=limits, validated_at=NOW)
    assert generic.result is ValidationResult.INVALID
    assert generic.validator_version == VALIDATOR_VERSION
    assert any(c.code == "authority_bound_exceeded:max_rate_per_minute" for c in generic.counterexamples)
    verified = closed.validate_owned_sequential_candidate_plan(parent.candidate_plan, current_domain, human,
                                                               limits=limits, validated_at=NOW)
    assert verified.admissible
    assert verified.validator_version == closed.OWNED_SEQUENTIAL_VALIDATOR_VERSION
    assert verified.validator_sha256 == closed.OWNED_SEQUENTIAL_VALIDATOR_SHA256
    assert verified.validator_version != generic.validator_version


@pytest.mark.parametrize("field,value", [("max_rate_per_minute", 61), ("max_requests", 21),
    ("concurrency_weight", 2), ("max_retries", 1), ("max_duration_seconds", 61)])
def test_closed_profile_cannot_raise_or_understate_fixed_effect_bounds(field, value):
    current_domain, human, initial, _ = owned_planning_material()
    changed = replace(current_domain.operators[0], **{field: value})
    altered = replace(current_domain, operators=(changed, *current_domain.operators[1:]))
    with pytest.raises(ValueError, match="owned_sequential"):
        _closed().plan_owned_sequential_attack_path(altered, human, initial, search_limits())


def test_closed_profile_requires_aggregate_requests_within_one_human_rate_window():
    current_domain, human, initial, _ = owned_planning_material()
    human = replace(human, bounds=replace(human.bounds, max_rate_per_minute=39))
    with pytest.raises(ValueError, match="owned_sequential"):
        _closed().plan_owned_sequential_attack_path(current_domain, human, initial, search_limits())


def test_independent_closed_validator_refuses_parallel_or_missing_chain():
    current_domain, human, parent, _, _ = owned_parent_child()
    parallel = replace(parent.candidate_plan, edges=())
    certificate = _closed().validate_owned_sequential_candidate_plan(parallel, current_domain, human,
        limits=ValidationLimitsV1(2, 1, 32), validated_at=NOW)
    assert not certificate.admissible
    assert any(c.code == "owned_sequential_chain_required" for c in certificate.counterexamples)


@pytest.mark.parametrize("kind", ["multi_target", "extra_parameter", "human_rate", "human_concurrency", "evidence", "data", "opaque"])
def test_closed_catalog_refuses_expanded_or_under_reserved_contract(kind):
    current_domain, human, initial, _ = owned_planning_material()
    op = current_domain.operators[0]
    if kind == "multi_target":
        human = replace(human, target_ids=("target-a", "target-b"))
    elif kind == "human_rate":
        human = replace(human, bounds=replace(human.bounds, max_rate_per_minute=120))
    elif kind == "human_concurrency":
        human = replace(human, bounds=replace(human.bounds, max_concurrency=2, max_width=2, max_frontier=2))
    elif kind == "extra_parameter":
        extra = replace(op.parameters[0], name="extra", binds_target=False, required=False)
        op = replace(op, parameters=(extra, *op.parameters))
    elif kind == "evidence":
        op = replace(op, max_evidence_bytes=1)
    elif kind == "data":
        op = replace(op, max_data_bytes=1)
    else:
        op = replace(op, unsupported_condition_ids=("opaque-test",))
    current_domain = replace(current_domain, operators=(op, *current_domain.operators[1:]))
    with pytest.raises(ValueError, match="owned_sequential"):
        _closed().plan_owned_sequential_attack_path(current_domain, human, initial, search_limits())


def test_closed_search_limits_bound_catalog_work_independently_from_execution_width():
    current_domain, human, initial, _ = owned_planning_material()
    function = getattr(_closed(), "derive_owned_sequential_search_limits", None)
    assert callable(function)
    limits = function(current_domain, human)
    assert limits.max_action_variants == 2 and limits.max_frontier == 1
    assert limits.max_expanded_states == 2 and limits.max_generated_states == 4
    assert limits.max_memory_units == 16
    result = _closed().plan_owned_sequential_attack_path(current_domain, human, initial, limits)
    assert result.revision is not None and result.revision.width == 1


@pytest.mark.parametrize("field,value", [
    ("adapter_id", "other-adapter"), ("adapter_version", "999"),
    ("profile_sha256", "b" * 64), ("bundle_id", "other-bundle"),
    ("bundle_revision", 99), ("bundle_sha256", "b" * 64),
])
def test_closed_profile_rejects_stale_or_substituted_registry_identity(field, value):
    current_domain, human, initial, _ = owned_planning_material()
    operator = current_domain.operators[0]
    altered = replace(current_domain, operators=(
        replace(operator, capability=replace(operator.capability, **{field: value})),
        *current_domain.operators[1:],
    ))
    with pytest.raises(ValueError, match="owned_sequential_capability_invalid"):
        _closed().plan_owned_sequential_attack_path(altered, human, initial, search_limits())
