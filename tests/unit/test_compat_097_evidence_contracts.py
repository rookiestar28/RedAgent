from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.evidence_service.contracts import (
    ArtifactClass,
    ArtifactWriteRequest,
    DataClassification,
    EvidenceDerivativeRequest,
    RetentionMode,
    content_sha256,
    deterministic_object_key,
)


NOW = datetime(2026, 7, 10, 15, 0, tzinfo=timezone.utc)


def request(**overrides: object) -> ArtifactWriteRequest:
    values: dict[str, object] = {
        "tenant_id": "tenant-1",
        "artifact_id": "artifact-1",
        "engagement_id": "engagement-1",
        "job_id": "job-1",
        "producer_id": "evidence-service",
        "content": b"synthetic sanitized evidence\n",
        "content_type": "text/plain",
        "artifact_class": ArtifactClass.REDACTED,
        "classification": DataClassification.CONFIDENTIAL,
        "redaction_state": "redacted",
        "retention_mode": RetentionMode.GOVERNANCE,
        "retain_until": NOW + timedelta(days=30),
        "legal_hold": False,
        "kms_reference": "kms:redagent:evidence-v1",
        "policy_reference": "policy:compat_097:1",
        "idempotency_key": "artifact-create-1",
    }
    values.update(overrides)
    return ArtifactWriteRequest(**values)  # type: ignore[arg-type]


def test_contract_is_closed_bounded_and_has_no_provider_or_executable_inputs() -> None:
    item = request()
    assert item.content_hash == content_sha256(item.content)
    assert set(asdict(item)) == {
        "tenant_id", "artifact_id", "engagement_id", "job_id", "producer_id", "content",
        "content_type", "artifact_class", "classification", "redaction_state", "retention_mode",
        "retain_until", "legal_hold", "kms_reference", "policy_reference", "idempotency_key",
        "content_hash",
    }
    for forbidden in ("bucket", "key", "endpoint", "credential", "delete", "bypass", "path", "url", "command"):
        assert forbidden not in asdict(item)


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"content": b""}, "evidence_content_invalid"),
        ({"content": b"x" * (1_048_576 + 1)}, "evidence_content_invalid"),
        ({"content_type": "application/x-executable"}, "evidence_content_type_unsupported"),
        ({"artifact_id": "../escape"}, "artifact_id_invalid"),
        ({"retain_until": NOW.replace(tzinfo=None)}, "retain_until_timezone_required"),
        ({"redaction_state": "raw", "artifact_class": ArtifactClass.EXPORT_SAFE}, "artifact_redaction_class_mismatch"),
        ({"classification": DataClassification.PUBLIC, "artifact_class": ArtifactClass.RAW, "redaction_state": "raw"}, "raw_artifact_must_be_restricted"),
    ],
)
def test_contract_rejects_unbounded_unsafe_or_inconsistent_values(override: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        request(**override)


def test_object_key_is_server_derived_content_addressed_and_tenant_scoped() -> None:
    first = request()
    key = deterministic_object_key(first)
    assert key == f"tenants/tenant-1/engagements/engagement-1/jobs/job-1/artifacts/artifact-1/sha256/{first.content_hash}"
    assert deterministic_object_key(request(content=b"different synthetic evidence")) != key


def test_derivative_contract_is_closed_deterministic_and_requires_quality_approval() -> None:
    derivative = EvidenceDerivativeRequest(
        source_artifact_id="artifact-raw-1",
        artifact_id="artifact-report-1",
        artifact_class=ArtifactClass.REPORT_SAFE,
        transform_name="central-redaction",
        transform_version="1",
        quality_approved=True,
        idempotency_key="derive-report-1",
    )
    values = {name: getattr(derivative, name) for name in derivative.__slots__}
    assert len(derivative.transform_config_hash) == 64
    assert derivative.transform_config_hash == EvidenceDerivativeRequest(**values).transform_config_hash
    with pytest.raises(ValueError, match="derivative_quality_approval_required"):
        EvidenceDerivativeRequest(**{**values, "quality_approved": False})
    with pytest.raises(ValueError, match="raw_derivative_forbidden"):
        EvidenceDerivativeRequest(**{**values, "artifact_class": ArtifactClass.RAW})
