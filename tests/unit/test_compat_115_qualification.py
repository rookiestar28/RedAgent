from redagent_platform.finding_operations.qualification import qualify_finding_operations


def test_fixture_qualification_denies_publication_delivery_and_tenant_escape() -> None:
    receipt = qualify_finding_operations()
    assert receipt["schema"] == "redagent.r115-qualification/v1" and receipt["status"] == "passed"
    assert receipt["adversarial_case_count"] == receipt["denied_case_count"]
    assert receipt["adversarial_case_count"] >= 24
    for counter in ("network_contact_count", "credential_access_count", "sensitive_retention_count",
                    "ai_approval_count", "generator_publication_count", "external_delivery_count"):
        assert receipt[counter] == 0
    assert receipt["external_connectors_enabled"] is False
    assert receipt["arbitrary_destination_enabled"] is False
    assert receipt["production_qualified"] is False and receipt["receipt_sha256"]
