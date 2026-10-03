from redagent_platform.campaign_service.operator_repository import project_operator_result
from redagent_platform.campaign_service.execution import ReconciliationState
from redagent_platform.campaign_service.planning.contracts import canonical_planning_bytes
from tests.unit.test_trusted_observations import NOW, _effect_receipt
from datetime import timedelta
import json
import pytest


def test_cleanup_identifier_and_completed_execution_do_not_verify_missing_native_result_owners():
    result = project_operator_result(
        ({"effect_id": "effect-a", "effect_state": "confirmed", "cleanup_receipt_id": "cleanup-a",
          "evidence_ids": ["artifact-a"]},), (), run_state="completed",
    )
    assert result == {
        "cleanup_state": "incomplete", "evidence_state": "pending", "verified_effect_count": 0,
        "effect_count": 1, "export_state": "unavailable_without_verified_bundle",
    }


def test_zero_io_plan_has_no_cleanup_claim_or_export_authority():
    result = project_operator_result((), (), run_state=None)
    assert result["cleanup_state"] == "not_started"
    assert result["evidence_state"] == "not_started"
    assert result["export_state"] == "unavailable_without_verified_bundle"


@pytest.mark.parametrize("loss", ["expired", "artifact_missing", "import_incomplete"])
def test_evidence_loss_does_not_erase_a_verified_native_cleanup_receipt(loss):
    receipt = _effect_receipt(ReconciliationState.CONFIRMED)
    effect = {"effect_id": receipt.effect_id, "effect_state": "confirmed", "effect_receipt_sha256": receipt.receipt_sha256,
        "effect_intent_sha256": receipt.effect_intent_sha256, "envelope_sha256": receipt.envelope_sha256,
        "external_receipt_id": receipt.external_receipt_id, "cleanup_receipt_id": receipt.cleanup_receipt_id,
        "effect_receipt_payload": json.loads(canonical_planning_bytes(receipt))}
    artifact = {"id": receipt.evidence_ids[0], "content_sha256": "d" * 64, "artifact_class": "report_safe",
        "redaction_state": "report_safe", "quarantine_reason": None, "finalized_at": NOW,
        "retain_until": NOW if loss == "expired" else NOW + timedelta(days=1), "legal_hold": False}
    owned = {"effect_id": receipt.effect_id, "receipt": {"execution_id": receipt.external_receipt_id,
        "evidence_artifact_id": receipt.evidence_ids[0], "outcome": "succeeded", "cleanup_completed": True,
        "residual_risk": None, "evidence_sha256": "d" * 64},
        "artifact": None if loss == "artifact_missing" else artifact,
        "import": {"run_id": receipt.external_receipt_id, "import_state": "accepted",
                   "coverage_state": "incomplete" if loss == "import_incomplete" else "complete"}}
    result = project_operator_result((effect,), (owned,), run_state="completed", now=NOW)
    assert result["cleanup_state"] == "complete"
    assert result["evidence_state"] == "pending" and result["verified_effect_count"] == 0
    assert result["export_state"] == "unavailable_without_verified_bundle"
