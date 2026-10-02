from __future__ import annotations

from dataclasses import asdict
import importlib
import json

import pytest

from redagent_platform.campaign_service.contracts import CapabilityBindingKeyV1
from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1, canonical_planning_bytes
from redagent_platform.campaign_service.planning.owned_sequential import validate_owned_sequential_candidate_plan
from tests.unit.test_campaign_planning_contracts import NOW
from tests.unit.test_owned_bounded_replanning import _inputs


def _material():
    values = _inputs()
    parent, domain = values["parent_revision"], values["domain"]
    certificate = validate_owned_sequential_candidate_plan(parent.candidate_plan, domain, values["authority"],
                                                          limits=ValidationLimitsV1(2, 1, 32), validated_at=NOW)
    return values, certificate, json.loads(canonical_planning_bytes(certificate))


def test_parent_certificate_recomputes_closed_validation_and_exact_admission_binding():
    values, certificate, payload = _material()
    owner = importlib.import_module("redagent_platform.campaign_service.child_replan_store")
    owner._assert_parent_certificate(payload, revision=values["parent_revision"], domain=values["domain"],
        authority=values["authority"], admission=values["parent_admission_receipt"],
        expected_sha256=certificate.certificate_sha256)


@pytest.mark.parametrize("field,value", [("tenant_id", "other-tenant"), ("engagement_id", "other-engagement"),
    ("authority_sha256", "b" * 64), ("domain_sha256", "b" * 64), ("plan_sha256", "b" * 64),
    ("validator_version", "other-validator"), ("validator_sha256", "b" * 64)])
def test_parent_certificate_cannot_reuse_other_scope_or_validator(field, value):
    values, certificate, payload = _material()
    payload[field] = value
    owner = importlib.import_module("redagent_platform.campaign_service.child_replan_store")
    with pytest.raises(owner.ChildParentConflict, match="certificate"):
        owner._assert_parent_certificate(payload, revision=values["parent_revision"], domain=values["domain"],
            authority=values["authority"], admission=values["parent_admission_receipt"],
            expected_sha256=certificate.certificate_sha256)


def test_capability_projection_matches_full_binding_without_discarding_capability_identity():
    values, _, _ = _material()
    capability = values["domain"].operators[0].capability
    binding = CapabilityBindingKeyV1(**asdict(capability), schema_version="redagent.r119-capability-binding/v1",
        semantics_revision=1, semantics_sha256="a" * 64, normalized_output_sha256="a" * 64,
        projection_revision=1, projection_sha256="a" * 64)
    owner = importlib.import_module("redagent_platform.campaign_service.child_replan_store")
    assert owner._capability_matches_binding(capability, binding)
    altered = dict(asdict(binding), adapter_version="other-version")
    assert not owner._capability_matches_binding(capability, CapabilityBindingKeyV1(**altered))
