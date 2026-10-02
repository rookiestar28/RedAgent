from copy import deepcopy

import pytest

from redagent_platform.campaign_service.owned_execution import OwnedExecutionDenied, validate_owned_execution_input


def _input():
    return {
        "revision": {"candidate_plan": {"nodes": [{"operator_id": "passive", "environment": "synthetic_loopback"}]}},
        "domain": {"operators": [{
            "operator_id": "passive",
            "capability": {"capability_id": "zap-controlled-runtime", "capability_revision": 2},
            "max_duration_seconds": 60, "max_rate_per_minute": 60,
            "concurrency_weight": 1, "max_retries": 1,
            "max_requests": 20, "max_evidence_bytes": 10 * 1024 * 1024,
            "max_data_bytes": 20 * 1024 * 1024,
        }]},
    }


@pytest.mark.parametrize("capability", ["zap-controlled-runtime", "nuclei-trusted-runtime"])
def test_only_current_closed_root_capabilities_fit_owned_slice(capability):
    payload = _input()
    payload["domain"]["operators"][0]["capability"]["capability_id"] = capability
    validate_owned_execution_input(payload)


@pytest.mark.parametrize("mutate", [
    lambda p: p["revision"]["candidate_plan"]["nodes"].extend([deepcopy(p["revision"]["candidate_plan"]["nodes"][0])] * 2),
    lambda p: p["revision"]["candidate_plan"]["nodes"][0].update(environment="owned_staging"),
    lambda p: p["revision"]["candidate_plan"]["nodes"][0].update(environment="internet"),
    lambda p: p["domain"]["operators"][0]["capability"].update(capability_id="arbitrary-shell"),
    lambda p: p["domain"]["operators"][0]["capability"].update(capability_revision=3),
    lambda p: p["domain"]["operators"][0].update(concurrency_weight=2),
    lambda p: p["domain"]["operators"][0].update(max_duration_seconds=61),
    lambda p: p["domain"]["operators"][0].update(max_rate_per_minute=61),
    lambda p: p["domain"]["operators"][0].update(max_retries=2),
    lambda p: p["domain"]["operators"][0].update(max_retries=True),
])
def test_broader_authority_cannot_expand_the_certified_execution_slice(mutate):
    payload = _input()
    mutate(payload)
    with pytest.raises(OwnedExecutionDenied):
        validate_owned_execution_input(payload)


@pytest.mark.parametrize("field,value", [("max_requests", 19), ("max_duration_seconds", 59), ("max_rate_per_minute", 59), ("max_evidence_bytes", 1024), ("max_data_bytes", 1024)])
def test_smaller_signed_budget_cannot_authorize_the_fixed_profile(field, value):
    payload = _input()
    payload["domain"]["operators"][0][field] = value
    with pytest.raises(OwnedExecutionDenied, match="profile_budget"):
        validate_owned_execution_input(payload)
