from __future__ import annotations

from redagent_platform.deployment_release.qualification import qualify_deployment_release


def test_qualification_is_adversarial_offline_and_cannot_claim_production() -> None:
    receipt = qualify_deployment_release()
    assert receipt["status"] == "passed"
    assert receipt["adversarial_case_count"] == receipt["denied_case_count"]
    assert receipt["adversarial_case_count"] >= 24
    assert receipt["drill_case_count"] == receipt["passed_drill_count"]
    assert receipt["drill_case_count"] >= 6
    assert receipt["qualification_case_count"] == receipt["adversarial_case_count"] + receipt["drill_case_count"]
    assert receipt["failed_cases"] == []
    assert len(str(receipt["outcome_sha256"])) == 64
    assert receipt["network_contact_count"] == 0
    assert receipt["external_execution_count"] == 0
    assert receipt["real_cluster_contact_count"] == 0
    assert receipt["production_qualified"] is False
    assert len(str(receipt["receipt_sha256"])) == 64
