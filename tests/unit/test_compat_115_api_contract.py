import pytest
from pydantic import ValidationError

from redagent_platform.api.app import create_app


def _schema(name: str):
    try:
        from redagent_platform.api import schemas
        return getattr(schemas, name)
    except (ImportError, AttributeError):
        pytest.fail(f"compat_115 RED: strict API schema {name} is not implemented")


def test_finding_operations_routes_are_registered_once() -> None:
    paths = [route.path for route in create_app().routes]
    expected = {
        "/api/v1/finding-operations/dashboard", "/api/v1/finding-operations/imports",
        "/api/v1/finding-operations/issues/{issue_id}/review", "/api/v1/finding-operations/reports",
        "/api/v1/finding-operations/deliveries", "/api/v1/finding-operations/reports/{report_id}/publish",
    }
    assert expected <= set(paths) and all(paths.count(path) == 1 for path in expected)


def test_import_schema_is_stored_id_only_and_rejects_raw_transport_or_evidence() -> None:
    schema = _schema("FindingOperationsImportRequest")
    payload = {
        "import_id": "import-r115", "run_id": "run-r115", "source_record_id": "source-r115",
        "resource_id": "resource-r115", "evidence_id": "evidence-r115",
        "evidence_sha256": "a" * 64, "coverage_state": "complete",
        "confirmation": "--confirm-r115-fixture-import",
    }
    assert schema(**payload).run_id == "run-r115"
    for field in (
        "raw_evidence", "payload", "url", "destination_url", "command", "args", "environment",
        "headers", "token", "credential", "prompt", "reasoning", "scanner_flags",
    ):
        with pytest.raises(ValidationError):
            schema(**(payload | {field: "forbidden"}))


def test_review_report_delivery_schemas_are_closed_and_no_ai_publish_or_arbitrary_destination() -> None:
    review = _schema("FindingOperationsReviewRequest")
    report = _schema("FindingOperationsReportRequest")
    delivery = _schema("FindingOperationsDeliveryRequest")
    publish = _schema("FindingOperationsPublishRequest")
    assert review(
        operation_id="review-r115", disposition="false_positive", reason_code="verified-fixture-false-positive",
        confirmation="--confirm-r115-reviewed-disposition",
    ).disposition == "false_positive"
    assert report(
        report_id="report-r115", audience="technical", reviewed_snapshot_sha256="b" * 64,
        evidence_sha256="a" * 64, confirmation="--confirm-r115-deterministic-report",
    ).audience == "technical"
    assert delivery(
        delivery_id="delivery-r115", profile_id="fixture-ticket-v1", report_id="report-r115",
        report_sha256="c" * 64, destination_object_id="SEC",
        confirmation="--confirm-r115-fixture-delivery",
    ).destination_object_id == "SEC"
    assert publish(
        publication_id="publication-r115", report_sha256="c" * 64,
        confirmation="--confirm-r115-independent-publication",
    ).publication_id == "publication-r115"
    with pytest.raises(ValidationError):
        report(
            report_id="report-r115", audience="technical", reviewed_snapshot_sha256="b" * 64,
            evidence_sha256="a" * 64, ai_approved=True,
            confirmation="--confirm-r115-deterministic-report",
        )
    with pytest.raises(ValidationError):
        delivery(
            delivery_id="delivery-r115", profile_id="fixture-ticket-v1", report_id="report-r115",
            report_sha256="c" * 64, destination_object_id="SEC", destination_url="https://example.invalid",
            confirmation="--confirm-r115-fixture-delivery",
        )


def test_dashboard_requires_authentication() -> None:
    from fastapi.testclient import TestClient

    response = TestClient(create_app()).get("/api/v1/finding-operations/dashboard")
    assert response.status_code == 401
