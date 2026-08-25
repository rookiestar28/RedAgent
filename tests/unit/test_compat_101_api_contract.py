from redagent_platform.api.app import create_app


def test_r101_stop_and_containment_status_routes_are_typed_and_separate() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    stop = schema["paths"]["/api/v1/jobs/{job_id}/emergency-stop"]["post"]
    status = schema["paths"]["/api/v1/jobs/{job_id}/containment"]["get"]
    assert stop["operationId"] == "emergency_stop_job"
    assert stop["responses"]["202"]["content"]["application/json"]["schema"]["$ref"].endswith("JobStopResponse")
    assert status["operationId"] == "get_job_containment"
    assert status["responses"]["200"]["content"]["application/json"]["schema"]["$ref"].endswith("JobContainmentResponse")


def test_public_containment_contract_exposes_receipts_and_risk_not_runtime_handles() -> None:
    properties = create_app(test_issuer_enabled=True).openapi()["components"]["schemas"]["JobContainmentData"]["properties"]
    assert {"phases", "residual_risk_codes", "open_incident_ids", "containment_complete"} <= set(properties)
    assert not {
        "command", "argv", "shell", "image", "token", "credential",
        "provider_lease_reference", "process_id", "container_id",
    }.intersection(properties)


def test_control_hierarchy_approval_recovery_and_quota_routes_are_typed() -> None:
    schema = create_app(test_issuer_enabled=True).openapi()
    paths = schema["paths"]
    assert paths["/api/v1/containment-controls"]["get"]["operationId"] == "list_containment_controls"
    assert paths["/api/v1/containment-controls"]["post"]["operationId"] == "request_containment_control"
    assert paths["/api/v1/containment-controls/{control_id}/approve"]["post"]["operationId"] == "approve_containment_control"
    assert paths["/api/v1/containment-controls/{control_id}/recover"]["post"]["operationId"] == "recover_containment_control"
    assert paths["/api/v1/quotas/status"]["get"]["operationId"] == "get_quota_status"


def test_control_request_schema_is_closed_and_has_no_execution_surface() -> None:
    properties = create_app(test_issuer_enabled=True).openapi()["components"]["schemas"]["ContainmentStopRequest"]["properties"]
    assert set(properties) == {"stop_id", "scope_kind", "scope_id", "expected_version", "reason"}
    assert not {"command", "argv", "shell", "image", "url", "token", "credential"}.intersection(properties)
