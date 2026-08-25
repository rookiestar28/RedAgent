from __future__ import annotations

import base64
from datetime import datetime, timezone
from io import BytesIO

import pytest

from redagent_platform.evidence_service.backends import CapabilityError, S3ObjectBackend
from redagent_platform.evidence_service.contracts import ObjectPutRequest, content_sha256


CONTENT = b"synthetic S3 evidence"
CHECKSUM = base64.b64encode(bytes.fromhex(content_sha256(CONTENT))).decode("ascii")


class FakeS3Client:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []
        self.versioning = {"Status": "Enabled"}
        self.lock = {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}

    def put_object(self, **kwargs):
        self.calls.append(("put_object", kwargs))
        return {"VersionId": "version-1", "ChecksumSHA256": CHECKSUM}

    def get_object(self, **kwargs):
        self.calls.append(("get_object", kwargs))
        return {
            "Body": BytesIO(CONTENT), "ContentLength": len(CONTENT), "ContentType": "text/plain",
            "ChecksumSHA256": CHECKSUM, "ObjectLockMode": "GOVERNANCE",
            "ObjectLockRetainUntilDate": datetime(2026, 8, 10, tzinfo=timezone.utc),
            "ObjectLockLegalHoldStatus": "OFF", "SSEKMSKeyId": "kms:fixture",
            "Metadata": {"operation-id": "operation-1", "content-sha256": content_sha256(CONTENT)},
        }

    def get_bucket_versioning(self, **kwargs):
        self.calls.append(("get_bucket_versioning", kwargs))
        return self.versioning

    def get_object_lock_configuration(self, **kwargs):
        self.calls.append(("get_object_lock_configuration", kwargs))
        return self.lock

    def put_object_legal_hold(self, **kwargs):
        self.calls.append(("put_object_legal_hold", kwargs))
        return {}

    def get_object_legal_hold(self, **kwargs):
        self.calls.append(("get_object_legal_hold", kwargs))
        return {"LegalHold": {"Status": "ON"}}

    def list_object_versions(self, **kwargs):
        self.calls.append(("list_object_versions", kwargs))
        return {"Versions": [{"Key": kwargs["Prefix"], "VersionId": "version-1"}]}


def put_request() -> ObjectPutRequest:
    return ObjectPutRequest(
        object_key="tenants/tenant-1/artifacts/artifact-1/sha256/" + content_sha256(CONTENT),
        content=CONTENT,
        content_type="text/plain",
        content_sha256=content_sha256(CONTENT),
        retention_mode="GOVERNANCE",
        retain_until="2026-08-10T00:00:00+00:00",
        legal_hold=False,
        kms_reference="kms:fixture",
        operation_id="operation-1",
    )


def test_s3_put_requires_sha256_lock_kms_metadata_and_exact_version_readback() -> None:
    client = FakeS3Client()
    backend = S3ObjectBackend(client, bucket="redagent-evidence", kms_reference="kms:fixture")
    stored = backend.put(put_request())

    method, payload = client.calls[0]
    assert method == "put_object"
    assert payload["ChecksumSHA256"] == CHECKSUM
    assert payload["ObjectLockMode"] == "GOVERNANCE"
    assert payload["ObjectLockLegalHoldStatus"] == "OFF"
    assert payload["ServerSideEncryption"] == "aws:kms"
    assert payload["SSEKMSKeyId"] == "kms:fixture"
    assert payload["Metadata"] == {"operation-id": "operation-1", "content-sha256": content_sha256(CONTENT)}
    assert stored.version_id == "version-1"
    assert backend.get_exact(stored.object_key, stored.version_id) == CONTENT
    assert client.calls[-1][1]["VersionId"] == "version-1"
    assert client.calls[-1][1]["ChecksumMode"] == "ENABLED"


def test_s3_capability_check_fails_closed_without_versioning_or_object_lock() -> None:
    client = FakeS3Client()
    backend = S3ObjectBackend(client, bucket="redagent-evidence", kms_reference="kms:fixture")
    assert backend.assess_capabilities().production_ready
    client.versioning = {"Status": "Suspended"}
    with pytest.raises(CapabilityError, match="s3_versioning_required"):
        backend.assess_capabilities()
    client.versioning = {"Status": "Enabled"}
    client.lock = {"ObjectLockConfiguration": {}}
    with pytest.raises(CapabilityError, match="s3_object_lock_required"):
        backend.assess_capabilities()


def test_s3_rejects_missing_version_or_provider_checksum_and_never_uses_etag() -> None:
    class Incomplete(FakeS3Client):
        def put_object(self, **kwargs):
            return {"ETag": '"not-a-content-hash"'}

    with pytest.raises(CapabilityError, match="s3_put_version_or_checksum_missing"):
        S3ObjectBackend(Incomplete(), bucket="redagent-evidence", kms_reference="kms:fixture").put(put_request())


def test_s3_legal_hold_targets_exact_version_and_verifies_provider_state() -> None:
    client = FakeS3Client()
    backend = S3ObjectBackend(client, bucket="redagent-evidence", kms_reference="kms:fixture")
    backend.place_legal_hold(put_request().object_key, "version-1")
    assert client.calls[-2] == (
        "put_object_legal_hold",
        {
            "Bucket": "redagent-evidence",
            "Key": put_request().object_key,
            "VersionId": "version-1",
            "LegalHold": {"Status": "ON"},
        },
    )
    assert client.calls[-1][0] == "get_object_legal_hold"


def test_s3_reconciliation_lists_and_reads_only_exact_matching_versions() -> None:
    client = FakeS3Client()
    backend = S3ObjectBackend(client, bucket="redagent-evidence", kms_reference="kms:fixture")
    versions = backend.find_versions(put_request().object_key)
    assert len(versions) == 1
    assert versions[0].version_id == "version-1"
    assert versions[0].content_sha256 == content_sha256(CONTENT)
    assert any(method == "get_object" and payload["VersionId"] == "version-1" for method, payload in client.calls)


def test_s3_reconciliation_rejects_delete_markers_and_truncated_inventory() -> None:
    class UnsafeInventory(FakeS3Client):
        def __init__(self, response):
            super().__init__()
            self.response = response

        def list_object_versions(self, **kwargs):
            return self.response

    key = put_request().object_key
    with pytest.raises(CapabilityError, match="s3_delete_marker_inventory_conflict"):
        S3ObjectBackend(
            UnsafeInventory({"DeleteMarkers": [{"Key": key, "VersionId": "marker-1"}]}),
            bucket="redagent-evidence",
            kms_reference="kms:fixture",
        ).find_versions(key)
    with pytest.raises(CapabilityError, match="s3_version_inventory_truncated"):
        S3ObjectBackend(
            UnsafeInventory({"IsTruncated": True}),
            bucket="redagent-evidence",
            kms_reference="kms:fixture",
        ).find_versions(key)
