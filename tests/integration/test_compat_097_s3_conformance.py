from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
import time
from uuid import uuid4

import boto3
from botocore.client import Config
from botocore.exceptions import ClientError

from redagent_platform.evidence_service.backends import S3ObjectBackend
from redagent_platform.evidence_service.contracts import ObjectPutRequest, content_sha256


ROOT = Path(__file__).resolve().parents[2]


def test_real_local_s3_version_lock_hold_checksum_delete_marker_and_exact_restore() -> None:
    env = _runtime_env()
    client = boto3.client(
        "s3",
        endpoint_url=env["REDAGENT_EVIDENCE_ENDPOINT"],
        region_name=env["REDAGENT_EVIDENCE_REGION"],
        aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"],
        config=Config(signature_version="s3v4", s3={"addressing_style": "path"}),
    )
    bucket = f"redagent-r097-{uuid4().hex[:20]}"
    client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    backend = S3ObjectBackend(
        client,
        bucket=bucket,
        kms_reference="sse-s3:local-fixture",
        encryption="AES256",
        require_download_checksum=False,
    )
    versions: list[tuple[str, str]] = []
    markers: list[tuple[str, str]] = []
    try:
        capabilities = backend.assess_capabilities()
        assert capabilities.versioning_enabled and capabilities.object_lock_enabled
        assert capabilities.checksum_sha256 is False and capabilities.production_ready is False
        retained_until = datetime.now(timezone.utc) + timedelta(seconds=3)
        content = b"synthetic compat_097 governance evidence"
        stored = backend.put(_request("governance", content, retained_until, legal_hold=False))
        versions.append((stored.object_key, stored.version_id))
        assert backend.get_exact(stored.object_key, stored.version_id) == content
        assert backend.verify_exact(stored).ok
        _assert_delete_denied(client, bucket, stored.object_key, stored.version_id)

        backup = backend.get_exact(stored.object_key, stored.version_id)
        restored_until = datetime.now(timezone.utc) + timedelta(seconds=2)
        restored = backend.put(_request("restored-backup", backup, restored_until, legal_hold=False))
        versions.append((restored.object_key, restored.version_id))
        assert restored.object_key != stored.object_key
        assert restored.content_sha256 == stored.content_sha256
        assert backend.verify_exact(restored).ok
        _wait_until(restored_until)
        _delete_after_retention(client, bucket, restored.object_key, restored.version_id)
        versions.remove((restored.object_key, restored.version_id))

        _wait_until(retained_until)
        marker = client.delete_object(Bucket=bucket, Key=stored.object_key)
        markers.append((stored.object_key, marker["VersionId"]))
        listed = client.list_object_versions(Bucket=bucket, Prefix=stored.object_key)
        assert any(row["VersionId"] == stored.version_id for row in listed.get("Versions", []))
        assert any(row["VersionId"] == marker["VersionId"] for row in listed.get("DeleteMarkers", []))
        assert backend.get_exact(stored.object_key, stored.version_id) == content

        hold_until = datetime.now(timezone.utc) + timedelta(seconds=2)
        held_content = b"synthetic compat_097 legal hold evidence"
        held = backend.put(_request("legal-hold", held_content, hold_until, legal_hold=True))
        versions.append((held.object_key, held.version_id))
        _wait_until(hold_until)
        _assert_delete_denied(client, bucket, held.object_key, held.version_id)
        client.put_object_legal_hold(
            Bucket=bucket,
            Key=held.object_key,
            VersionId=held.version_id,
            LegalHold={"Status": "OFF"},
        )
        _delete_after_retention(client, bucket, held.object_key, held.version_id)
        versions.remove((held.object_key, held.version_id))
    finally:
        for key, version in markers:
            client.delete_object(Bucket=bucket, Key=key, VersionId=version)
        for key, version in versions:
            try:
                client.delete_object(Bucket=bucket, Key=key, VersionId=version)
            except ClientError:
                pass
        try:
            client.delete_bucket(Bucket=bucket)
        except ClientError:
            # A failed conformance assertion must preserve the fixture for diagnosis, never bypass retention.
            pass


def _request(label: str, content: bytes, retain_until: datetime, *, legal_hold: bool) -> ObjectPutRequest:
    return ObjectPutRequest(
        object_key=f"tenants/tenant-1/artifacts/{label}/sha256/{content_sha256(content)}",
        content=content,
        content_type="text/plain",
        content_sha256=content_sha256(content),
        retention_mode="GOVERNANCE",
        retain_until=retain_until.isoformat(),
        legal_hold=legal_hold,
        kms_reference="sse-s3:local-fixture",
        operation_id=f"operation-{label}",
    )


def _assert_delete_denied(client, bucket: str, key: str, version_id: str) -> None:
    try:
        client.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] in {"AccessDenied", "InvalidRequest", "MethodNotAllowed"}
    else:
        raise AssertionError("protected_object_version_delete_succeeded")


def _wait_until(moment: datetime) -> None:
    delay = max(0.0, (moment - datetime.now(timezone.utc)).total_seconds()) + 0.75
    time.sleep(delay)


def _delete_after_retention(client, bucket: str, key: str, version_id: str) -> None:
    # IMPORTANT: local S3 retention clocks can trail the test host; retry exact-version delete without bypassing governance.
    deadline = time.monotonic() + 5
    while True:
        try:
            client.delete_object(Bucket=bucket, Key=key, VersionId=version_id)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in {"AccessDenied", "InvalidRequest"} or time.monotonic() >= deadline:
                raise
            time.sleep(0.25)


def _runtime_env() -> dict[str, str]:
    path = ROOT / ".local" / "redagent" / "runtime" / "local-stack.env"
    values = dict(
        line.partition("=")[::2]
        for line in path.read_text(encoding="utf-8").splitlines()
        if "=" in line
    )
    required = {
        "REDAGENT_EVIDENCE_ENDPOINT", "REDAGENT_EVIDENCE_REGION",
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    }
    if not required <= set(values):
        raise RuntimeError("r097_local_s3_runtime_not_configured")
    return values
