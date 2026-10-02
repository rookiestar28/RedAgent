from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import importlib

import pytest

from redagent_platform.campaign_service.approval_contracts import AutonomousCampaignApprovalContextV1
from redagent_platform.campaign_service.child_replan_contracts import CHILD_REQUEST_SCHEMA_VERSION, PrepareAutonomousCampaignChildV1
from redagent_platform.campaign_service.child_replan_store import CompletedOwnedParentV1
from tests.unit.test_campaign_plan_admission import _signed_authority
from tests.unit.test_campaign_planning_contracts import NOW
from tests.unit.test_owned_bounded_replanning import _inputs
from tests.unit.test_owned_completion_observations import _source


def _material():
    values = _inputs()
    source = _source()
    receipt = replace(source.effect_receipt, envelope_sha256=values["authority"].authority_sha256,
                      started_at=NOW, completed_at=NOW + timedelta(seconds=1))
    source = _source(effect_receipt=receipt, verified_at=NOW + timedelta(seconds=2))
    signed, lifecycle, keys = _signed_authority(values["authority"])
    admission = replace(values["parent_admission_receipt"], signed_authority_sha256=signed.signed_authority_sha256)
    parent = CompletedOwnedParentV1(source, values["domain"], values["parent_revision"], admission)
    context = AutonomousCampaignApprovalContextV1(tenant_id="tenant-a", campaign_id="campaign-a",
        signed_authority=signed, authority_lifecycle=lifecycle)
    command = PrepareAutonomousCampaignChildV1(schema_version=CHILD_REQUEST_SCHEMA_VERSION,
        tenant_id="tenant-a", campaign_id="campaign-a", actor_user_id="operator-a", expected_revision=8,
        idempotency_key="child-request-a", correlation_id="child-correlation-a", occurred_at=NOW + timedelta(seconds=3))
    return dict(command=command, parent=parent, context=context, residual_budget=values["residual_budget"],
                consumed_replans=0, trusted_keys=keys)


def _prepare(values):
    return importlib.import_module("redagent_platform.campaign_service.child_replan_service").prepare_canonical_child_proposal(**values)


def test_canonical_child_uses_only_verified_completion_with_clipped_ttl_and_exact_remaining_node():
    values = _material()
    prepared = _prepare(values)
    assert prepared.promotion.trusted_observation is not None
    candidate = prepared.promotion.trusted_observation.candidate
    assert candidate.observed_at == values["parent"].source.effect_receipt.completed_at
    assert candidate.expires_at <= values["context"].authority_lifecycle.valid_until
    assert prepared.proposal.replan_sequence == 1
    assert len(prepared.proposal.child_revision.candidate_plan.nodes) == 1
    assert prepared.strict_subset.child_revision_sha256 == prepared.proposal.child_revision.revision_sha256


def test_completed_parent_evidence_survives_its_expired_execution_grant_without_transferring_it():
    values = _material()
    parent = values["parent"]
    admission = replace(parent.admission_receipt, expires_at=NOW + timedelta(seconds=2))
    values["parent"] = replace(parent, admission_receipt=admission)
    assert values["command"].occurred_at > admission.expires_at > parent.source.effect_receipt.completed_at
    assert _prepare(values).proposal.parent_admission_receipt_sha256 == admission.receipt_sha256


def test_completion_at_or_after_parent_grant_expiry_is_never_authorized_evidence():
    values = _material()
    parent = values["parent"]
    values["parent"] = replace(parent, admission_receipt=replace(parent.admission_receipt,
        expires_at=parent.source.effect_receipt.completed_at))
    with pytest.raises((ValueError, RuntimeError)):
        _prepare(values)


def test_effect_started_before_parent_admission_cannot_become_authorized_completion():
    values = _material()
    parent = values["parent"]
    source = _source(effect_receipt=replace(parent.source.effect_receipt,
        started_at=parent.admission_receipt.issued_at - timedelta(seconds=1)),
        verified_at=values["command"].occurred_at)
    values["parent"] = replace(parent, source=source)
    with pytest.raises((ValueError, RuntimeError), match="parent_binding"):
        _prepare(values)


@pytest.mark.parametrize("kind", ["scope", "epochs", "revoked", "expired", "exhausted", "before_admission"])
def test_canonical_child_denies_untrusted_current_context_and_parent_timing(kind):
    values = _material()
    if kind == "scope":
        values["command"] = replace(values["command"], campaign_id="another-campaign")
    elif kind == "epochs":
        context = values["context"]
        values["context"] = replace(context, authority_lifecycle=replace(context.authority_lifecycle,
            lifecycle_epoch=context.authority_lifecycle.lifecycle_epoch + 1))
    elif kind == "revoked":
        values["trusted_keys"] = {}
    elif kind == "expired":
        values["command"] = replace(values["command"], occurred_at=NOW + timedelta(seconds=60))
    elif kind == "exhausted":
        values["consumed_replans"] = 1
    else:
        parent = values["parent"]
        source = _source(effect_receipt=replace(parent.source.effect_receipt,
            started_at=NOW - timedelta(seconds=2), completed_at=NOW - timedelta(seconds=1)), verified_at=NOW)
        values["parent"] = replace(parent, source=source)
    with pytest.raises((ValueError, RuntimeError)):
        _prepare(values)
