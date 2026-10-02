from __future__ import annotations

from dataclasses import replace
from datetime import timedelta
import importlib

import pytest

from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION, DagExecutionSnapshotV1, DagNodeState, DagRunState,
)
from redagent_platform.campaign_service.execution import ReconciliationState
from redagent_platform.campaign_service.planning.contracts import ScalarType
from tests.unit.test_campaign_planning_contracts import NOW, scalar
from tests.unit.test_child_replan_subset import owned_parent_child
from tests.unit.test_trusted_observations import _candidate, _effect_receipt


def _source_inputs():
    current_domain, human, parent, _, fact = owned_parent_child()
    node = parent.candidate_plan.nodes[0]
    op = next(op for op in current_domain.operators if op.operator_id == node.operator_id)
    receipt = _effect_receipt(ReconciliationState.CONFIRMED)
    snapshot = DagExecutionSnapshotV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION, execution_run_id="run-parent",
        workflow_request_sha256="c" * 64, state=DagRunState.CONTAINED, revision=5,
        transition_count=4, current_node_id=None, current_node_state=None,
        stop_requested=True, terminal_reason="operator_stop",
    )
    values = dict(tenant_id=human.tenant_id, campaign_id="campaign-a", engagement_id=human.engagement_id,
        target_id=node.target_id, authority_sha256=human.authority_sha256,
        lifecycle_epoch=human.lifecycle_epoch, policy_revocation_epoch=human.policy_revocation_epoch,
        roe_revocation_epoch=human.roe_revocation_epoch, kill_switch_epoch=human.kill_switch_epoch,
        snapshot=snapshot, parent_revision_sha256=parent.revision_sha256,
        domain_sha256=current_domain.domain_sha256, plan_sha256=parent.candidate_plan.plan_sha256,
        node_id=node.node_id, persisted_node_state=DagNodeState.CONFIRMED,
        capability=op.capability, effect_receipt=receipt, report_artifact_id=receipt.evidence_ids[0],
        report_sha256="d" * 64, report_size_bytes=100, evidence_owner_sha256="e" * 64,
        cleanup_owner_sha256="f" * 64, verified_at=NOW - timedelta(seconds=1))
    candidate = _candidate(
        authority_sha256=human.authority_sha256, fact_id=fact.fact_id, value=fact.value,
        lifecycle_epoch=human.lifecycle_epoch, policy_revocation_epoch=human.policy_revocation_epoch,
        roe_revocation_epoch=human.roe_revocation_epoch, kill_switch_epoch=human.kill_switch_epoch,
        source_result_sha256=receipt.receipt_sha256, evidence_sha256=receipt.receipt_sha256,
        observed_at=receipt.completed_at, received_at=NOW - timedelta(seconds=1),
    )
    return values, candidate, current_domain, parent


def _module():
    return importlib.import_module("redagent_platform.campaign_service.trusted_observations")


def _source(**overrides):
    values, _, _, _ = _source_inputs()
    values.update(overrides)
    module = _module()
    source_type = getattr(module, "OwnedCompletionSourceV1", None)
    assert source_type is not None, "Actual completed-owned source needs a sealed server-owner material type"
    return source_type(**values, _validation_token=module._OWNED_COMPLETION_SOURCE_TOKEN)


def _verify(**overrides):
    _, candidate, domain, parent = _source_inputs()
    values = dict(candidate=candidate, source=_source(), domain=domain, revision=parent, verified_at=NOW)
    values.update(overrides)
    function = getattr(_module(), "verify_completed_owned_node_observation_evidence", None)
    assert callable(function), "Terminal parent verification must use its real snapshot and persisted node"
    return function(**values)


def test_owned_completion_provenance_binds_actual_terminal_snapshot_report_and_cleanup():
    evidence = _verify()
    assert evidence.source_execution_run_id == "run-parent"
    assert evidence.source_node_id == _source().node_id
    assert evidence.value.value is True
    assert evidence.verification_sha256 != _verify(source=_source(report_sha256="a" * 64)).verification_sha256
    assert evidence.verification_sha256 != _verify(source=_source(cleanup_owner_sha256="b" * 64)).verification_sha256


def test_caller_cannot_construct_owned_completion_source():
    values, _, _, _ = _source_inputs()
    source_type = getattr(_module(), "OwnedCompletionSourceV1", None)
    assert source_type is not None
    with pytest.raises(ValueError, match="owner_factory_required"):
        source_type(**values)


@pytest.mark.parametrize("kind", ["active", "current_node", "unconfirmed", "wrong_scope", "wrong_fact", "false_fact", "receipt_hash", "observed_time", "parent", "capability", "future"])
def test_owned_completion_refuses_asserted_or_mismatched_terminal_truth(kind):
    values, candidate, domain, parent = _source_inputs()
    if kind == "active":
        values["snapshot"] = replace(values["snapshot"], state=DagRunState.RUNNING)
    elif kind == "current_node":
        values["snapshot"] = replace(values["snapshot"], current_node_id=values["node_id"], current_node_state=DagNodeState.CONFIRMED)
    elif kind == "unconfirmed":
        values["persisted_node_state"] = DagNodeState.NOT_APPLIED
    elif kind == "wrong_scope":
        candidate = replace(candidate, tenant_id="tenant-b")
    elif kind == "wrong_fact":
        candidate = replace(candidate, fact_id="authorized")
    elif kind == "false_fact":
        candidate = replace(candidate, value=scalar(ScalarType.BOOLEAN, False))
    elif kind == "receipt_hash":
        candidate = replace(candidate, source_result_sha256="a" * 64)
    elif kind == "observed_time":
        candidate = replace(candidate, observed_at=candidate.observed_at + timedelta(seconds=1))
    elif kind == "parent":
        values["parent_revision_sha256"] = "a" * 64
    elif kind == "capability":
        values["capability"] = replace(values["capability"], adapter_version="wrong-version")
    else:
        values["verified_at"] = NOW + timedelta(seconds=1)
    with pytest.raises(ValueError, match="owned_completion"):
        source_type = getattr(_module(), "OwnedCompletionSourceV1", None)
        assert source_type is not None
        source = source_type(**values, _validation_token=_module()._OWNED_COMPLETION_SOURCE_TOKEN)
        _verify(candidate=candidate, source=source, domain=domain, revision=parent)
