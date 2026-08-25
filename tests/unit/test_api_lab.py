from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform import api_lab, domain, lab_harness
from redagent_platform.evidence_chain import (
    EvidenceAccessPolicy,
    EvidenceChain,
    RedactionStatus,
    RetentionClass,
)


NOW = datetime(2026, 7, 8, 10, 0, tzinfo=timezone.utc)


def openapi_spec() -> dict[str, object]:
    return {
        "openapi": "3.0.3",
        "info": {"title": "crAPI sample", "version": "1.0.0"},
        "security": [{"bearerAuth": []}],
        "components": {
            "securitySchemes": {
                "bearerAuth": {"type": "http", "scheme": "bearer"},
            }
        },
        "paths": {
            "/cars/{carId}": {
                "get": {
                    "operationId": "getCar",
                    "parameters": [
                        {"name": "carId", "in": "path", "required": True, "schema": {"type": "string"}},
                    ],
                    "responses": {"200": {"description": "ok"}, "404": {"description": "missing"}},
                }
            },
            "/cars": {
                "post": {
                    "operationId": "createCar",
                    "requestBody": {"content": {"application/json": {"schema": {"type": "object"}}}},
                    "responses": {"201": {"description": "created"}, "400": {"description": "bad request"}},
                }
            },
            "/status": {
                "get": {
                    "operationId": "status",
                    "security": [],
                    "responses": {"200": {"description": "ok"}},
                }
            },
        },
    }


def approval() -> lab_harness.SandboxApproval:
    return lab_harness.SandboxApproval(
        approval_id="sandbox-approval-1",
        organization_id="org-1",
        approved_by_user_id="lead-1",
        approved_at=NOW - timedelta(hours=1),
        expires_at=NOW + timedelta(hours=1),
        allowed_kinds=(lab_harness.LabTargetKind.CRAPI,),
        allowed_actions=(lab_harness.LabHarnessAction.CONNECT_EXISTING,),
        plan_reference="PUBLIC_RELEASE.md",
        emergency_contact_method="email",
    )


def lab_registration() -> lab_harness.LabTargetRegistration:
    return lab_harness.register_lab_target(
        lab_harness.LabTargetRequest(
            target_id="lab-crapi-local",
            organization_id="org-1",
            engagement_id="eng-lab-1",
            owner_label="Security Lab",
            kind=lab_harness.LabTargetKind.CRAPI,
            action=lab_harness.LabHarnessAction.CONNECT_EXISTING,
            base_url="http://localhost:8888",
            requested_at=NOW,
        ),
        approval(),
    )


def test_openapi_import_stores_operations_auth_parameters_and_responses() -> None:
    document = api_lab.import_openapi_document(
        document_id="crapi-openapi",
        source_reference="local-lab-fixture",
        spec=openapi_spec(),
    )
    get_car = next(operation for operation in document.operations if operation.operation_id == "getCar")

    assert document.title == "crAPI sample"
    assert get_car.path == "/cars/{carId}"
    assert get_car.method is api_lab.HttpMethod.GET
    assert get_car.auth_requirements[0].scheme_name == "bearerAuth"
    assert get_car.auth_requirements[0].scheme_type == "http"
    assert get_car.parameters[0].name == "carId"
    assert get_car.parameters[0].location == "path"
    assert get_car.response_classes == ("2xx", "4xx")


def test_openapi_import_rejects_missing_schema_or_responses() -> None:
    invalid = openapi_spec()
    invalid.pop("openapi")
    with pytest.raises(ValueError, match="unsupported_or_missing_openapi_version"):
        api_lab.import_openapi_document(document_id="bad", source_reference="fixture", spec=invalid)

    invalid_operation = openapi_spec()
    paths = invalid_operation["paths"]
    assert isinstance(paths, dict)
    status = paths["/status"]
    assert isinstance(status, dict)
    operation = status["get"]
    assert isinstance(operation, dict)
    operation.pop("responses")
    with pytest.raises(ValueError, match="missing_responses"):
        api_lab.import_openapi_document(document_id="bad", source_reference="fixture", spec=invalid_operation)


def test_lab_workflow_maps_cases_to_owasp_api_top10_categories() -> None:
    document = api_lab.import_openapi_document(
        document_id="crapi-openapi",
        source_reference="local-lab-fixture",
        spec=openapi_spec(),
    )
    cases = api_lab.generate_lab_api_cases(document, lab_registration())
    categories = {case.owasp_category for case in cases}
    case_types = {case.case_type for case in cases}

    assert api_lab.OwaspApiTop10Category.API1_BROKEN_OBJECT_LEVEL_AUTHORIZATION in categories
    assert api_lab.OwaspApiTop10Category.API2_BROKEN_AUTHENTICATION in categories
    assert api_lab.OwaspApiTop10Category.API3_BROKEN_OBJECT_PROPERTY_LEVEL_AUTHORIZATION in categories
    assert api_lab.ApiLabCaseType.AUTHORIZATION_DIFFERENTIAL in case_types
    assert api_lab.ApiLabCaseType.OBJECT_PROPERTY in case_types


def test_generated_api_cases_remain_lab_only_and_disabled() -> None:
    document = api_lab.import_openapi_document(
        document_id="crapi-openapi",
        source_reference="local-lab-fixture",
        spec=openapi_spec(),
    )
    cases = api_lab.generate_lab_api_cases(document, lab_registration())

    assert cases
    assert all(case.lab_only for case in cases)
    assert all(case.mode is domain.TestMode.LAB_ONLY_RUN for case in cases)
    assert all(not case.execution_enabled for case in cases)
    assert all(not case.active_enterprise_enabled for case in cases)


def test_lab_workflow_rejects_non_lab_registration() -> None:
    document = api_lab.import_openapi_document(
        document_id="crapi-openapi",
        source_reference="local-lab-fixture",
        spec=openapi_spec(),
    )
    bad_registration = replace(lab_registration(), labels=())

    with pytest.raises(ValueError, match="lab_only_label_required"):
        api_lab.generate_lab_api_cases(document, bad_registration)


def test_api_lab_result_maps_case_endpoint_operation_and_evidence() -> None:
    document = api_lab.import_openapi_document(
        document_id="crapi-openapi",
        source_reference="local-lab-fixture",
        spec=openapi_spec(),
    )
    case = api_lab.generate_lab_api_cases(document, lab_registration())[0]
    chain = EvidenceChain().append_evidence_record(
        evidence_id="evidence-api-1",
        organization_id="org-1",
        source_job_id="job-api-1",
        kind=domain.EvidenceKind.OPENAPI_METADATA,
        created_at=NOW,
        redaction_status=RedactionStatus.NOT_APPLICABLE,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=b'{"operation":"getCar"}',
        contains_sensitive_capture=False,
        metadata={"operation_id": case.operation_id},
    )

    result = api_lab.build_api_lab_result(
        result_id="api-result-1",
        case=case,
        evidence_records=(chain.evidence_records[0],),
    )

    assert result.case_id == case.case_id
    assert result.endpoint_path == case.path
    assert result.method is case.method
    assert result.operation_id == case.operation_id
    assert result.evidence_links[0].evidence_id == "evidence-api-1"
