import pytest

from redagent_platform.campaign_service.application_contracts import AutonomousCampaignLifecycle
from redagent_platform.campaign_service.owned_execution import owned_execution_attention


@pytest.mark.parametrize("reason,expected", [
    ("campaign_stop_active_cleanup_required", AutonomousCampaignLifecycle.CLEANUP_INCOMPLETE),
    ("cleanup_receipt_missing", AutonomousCampaignLifecycle.CLEANUP_INCOMPLETE),
    ("evidence_output_incomplete", AutonomousCampaignLifecycle.EVIDENCE_INCOMPLETE),
    ("adapter_receipt_commit_unknown", AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED),
    (None, None),
])
def test_attention_preserves_cleanup_evidence_and_unknown_truth(reason, expected):
    assert owned_execution_attention(reason) is expected
