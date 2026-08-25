from __future__ import annotations

from redagent_platform.mcp_broker.qualification import qualify_mcp_workbench


def test_fixture_only_qualification_denies_transport_drift_injection_and_authority_escape() -> None:
    receipt = qualify_mcp_workbench()
    assert receipt["schema"] == "redagent.r114-qualification/v1"
    assert receipt["status"] == "passed"
    assert receipt["protocol_version"] == "2025-11-25"
    assert receipt["fixture_inventory_count"] == 2
    assert receipt["adversarial_case_count"] == receipt["denied_case_count"]
    assert receipt["adversarial_case_count"] >= 16
    for counter in ("network_contact_count", "process_launch_count", "credential_access_count",
                    "direct_dispatch_count", "sensitive_retention_count"):
        assert receipt[counter] == 0
    assert receipt["remote_http_enabled"] is False
    assert receipt["stdio_enabled"] is False
    assert receipt["provider_mcp_enabled"] is False
    assert receipt["receipt_sha256"]
