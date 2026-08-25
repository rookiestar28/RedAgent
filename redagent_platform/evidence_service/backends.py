"""Backend-neutral append-only evidence object implementations."""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from redagent_platform.evidence_service.contracts import (
    ObjectPutRequest,
    ObjectVerification,
    MAX_EVIDENCE_BYTES,
    StoredObjectVersion,
    content_sha256,
)


class ObjectConflict(RuntimeError):
    """An immutable key/version contract would be violated."""


class CapabilityError(RuntimeError):
    """The object backend cannot satisfy the accepted evidence boundary."""


@dataclass(frozen=True, slots=True)
class BackendCapabilities:
    versioning_enabled: bool
    object_lock_enabled: bool
    checksum_sha256: bool
    exact_version_reads: bool
    production_ready: bool


class S3ObjectBackend:
    """AWS S3 contract adapter; credentials and endpoints remain runtime configuration."""

    def __init__(
        self,
        client: Any,
        *,
        bucket: str,
        kms_reference: str,
        encryption: str = "aws:kms",
        require_download_checksum: bool = True,
    ) -> None:
        if not bucket or len(bucket) > 63 or not kms_reference or encryption not in {"aws:kms", "AES256"}:
            raise ValueError("s3_backend_config_invalid")
        self.client = client
        self.bucket = bucket
        self.kms_reference = kms_reference
        self.encryption = encryption
        self.require_download_checksum = require_download_checksum

    def assess_capabilities(self) -> BackendCapabilities:
        versioning = self.client.get_bucket_versioning(Bucket=self.bucket)
        if versioning.get("Status") != "Enabled":
            raise CapabilityError("s3_versioning_required")
        lock = self.client.get_object_lock_configuration(Bucket=self.bucket)
        if lock.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") != "Enabled":
            raise CapabilityError("s3_object_lock_required")
        return BackendCapabilities(
            versioning_enabled=True,
            object_lock_enabled=True,
            checksum_sha256=self.require_download_checksum,
            exact_version_reads=True,
            production_ready=self.require_download_checksum,
        )

    def put(self, request: ObjectPutRequest) -> StoredObjectVersion:
        if request.kms_reference != self.kms_reference:
            raise CapabilityError("s3_kms_reference_mismatch")
        checksum = base64.b64encode(bytes.fromhex(request.content_sha256)).decode("ascii")
        encryption = {"ServerSideEncryption": self.encryption}
        if self.encryption == "aws:kms":
            encryption["SSEKMSKeyId"] = request.kms_reference
        response = self.client.put_object(
            Bucket=self.bucket,
            Key=request.object_key,
            Body=request.content,
            ContentLength=len(request.content),
            ContentType=request.content_type,
            ChecksumSHA256=checksum,
            ObjectLockMode=request.retention_mode,
            ObjectLockRetainUntilDate=datetime.fromisoformat(request.retain_until),
            ObjectLockLegalHoldStatus="ON" if request.legal_hold else "OFF",
            Metadata={"operation-id": request.operation_id, "content-sha256": request.content_sha256},
            **encryption,
        )
        version_id = response.get("VersionId")
        provider_checksum = response.get("ChecksumSHA256")
        if not isinstance(version_id, str) or not version_id or not isinstance(provider_checksum, str) or provider_checksum != checksum:
            raise CapabilityError("s3_put_version_or_checksum_missing")
        return StoredObjectVersion(
            object_key=request.object_key,
            version_id=version_id,
            storage_name=hashlib.sha256(request.object_key.encode("utf-8")).hexdigest(),
            content_sha256=request.content_sha256,
            provider_checksum=provider_checksum,
            size_bytes=len(request.content),
            content_type=request.content_type,
            retention_mode=request.retention_mode,
            retain_until=request.retain_until,
            legal_hold=request.legal_hold,
            kms_reference=request.kms_reference,
        )

    def get_exact(self, object_key: str, version_id: str) -> bytes:
        response, content = self._get_response(object_key, version_id)
        checksum = response.get("ChecksumSHA256")
        expected = base64.b64encode(hashlib.sha256(content).digest()).decode("ascii")
        if checksum is not None and checksum != expected:
            raise CapabilityError("s3_get_checksum_mismatch")
        if checksum is None and self.require_download_checksum:
            raise CapabilityError("s3_get_checksum_missing")
        return content

    def _get_response(self, object_key: str, version_id: str) -> tuple[dict[str, Any], bytes]:
        response = self.client.get_object(
            Bucket=self.bucket,
            Key=object_key,
            VersionId=version_id,
            ChecksumMode="ENABLED",
        )
        body = response.get("Body")
        if body is None or not hasattr(body, "read"):
            raise CapabilityError("s3_get_body_missing")
        content = body.read(MAX_EVIDENCE_BYTES + 1)
        if not isinstance(content, bytes) or len(content) > MAX_EVIDENCE_BYTES:
            raise CapabilityError("s3_get_content_invalid")
        return response, content

    def verify_exact(self, stored: StoredObjectVersion) -> ObjectVerification:
        try:
            content = self.get_exact(stored.object_key, stored.version_id)
        except CapabilityError as exc:
            return ObjectVerification(stored.object_key, stored.version_id, False, str(exc))
        if content_sha256(content) != stored.content_sha256:
            return ObjectVerification(stored.object_key, stored.version_id, False, "content_hash_mismatch")
        if len(content) != stored.size_bytes:
            return ObjectVerification(stored.object_key, stored.version_id, False, "object_size_mismatch")
        return ObjectVerification(stored.object_key, stored.version_id, True, "verified")

    def find_versions(self, object_key: str) -> tuple[StoredObjectVersion, ...]:
        listing = self.client.list_object_versions(Bucket=self.bucket, Prefix=object_key)
        if listing.get("IsTruncated"):
            raise CapabilityError("s3_version_inventory_truncated")
        if any(marker.get("Key") == object_key for marker in listing.get("DeleteMarkers", [])):
            raise CapabilityError("s3_delete_marker_inventory_conflict")
        found: list[StoredObjectVersion] = []
        for row in listing.get("Versions", []):
            if row.get("Key") != object_key or not isinstance(row.get("VersionId"), str):
                continue
            version_id = row["VersionId"]
            response, content = self._get_response(object_key, version_id)
            digest = content_sha256(content)
            checksum = response.get("ChecksumSHA256")
            expected_checksum = base64.b64encode(bytes.fromhex(digest)).decode("ascii")
            if checksum is None:
                if self.require_download_checksum:
                    raise CapabilityError("s3_get_checksum_missing")
                checksum = expected_checksum
            elif checksum != expected_checksum:
                raise CapabilityError("s3_get_checksum_mismatch")
            retained = response.get("ObjectLockRetainUntilDate")
            if not isinstance(retained, datetime):
                raise CapabilityError("s3_retention_metadata_missing")
            found.append(
                StoredObjectVersion(
                    object_key=object_key,
                    version_id=version_id,
                    storage_name=hashlib.sha256(object_key.encode("utf-8")).hexdigest(),
                    content_sha256=digest,
                    provider_checksum=checksum,
                    size_bytes=len(content),
                    content_type=str(response.get("ContentType", "application/octet-stream")),
                    retention_mode=str(response.get("ObjectLockMode", "")),
                    retain_until=retained.isoformat(),
                    legal_hold=response.get("ObjectLockLegalHoldStatus") == "ON",
                    kms_reference=self.kms_reference,
                )
            )
        return tuple(found)

    def place_legal_hold(self, object_key: str, version_id: str) -> None:
        # CRITICAL: legal hold is always version-specific; latest-version mutation is forbidden.
        self.client.put_object_legal_hold(
            Bucket=self.bucket,
            Key=object_key,
            VersionId=version_id,
            LegalHold={"Status": "ON"},
        )
        verified = self.client.get_object_legal_hold(
            Bucket=self.bucket,
            Key=object_key,
            VersionId=version_id,
        )
        if verified.get("LegalHold", {}).get("Status") != "ON":
            raise CapabilityError("s3_legal_hold_verification_failed")

class LocalAppendOnlyBackend:
    """Workspace-local append-only backend for explicit synthetic profiles only."""

    def __init__(self, root: Path, *, profile: str) -> None:
        if profile != "synthetic-local":
            raise ValueError("local_evidence_backend_synthetic_only")
        self.root = root.resolve()
        self.objects = self.root / "objects"
        self.metadata = self.root / "metadata"
        self.holds = self.root / "holds"
        if self.root.is_symlink():
            raise ValueError("local_evidence_root_symlink_forbidden")
        self.objects.mkdir(parents=True, exist_ok=True)
        self.metadata.mkdir(parents=True, exist_ok=True)
        self.holds.mkdir(parents=True, exist_ok=True)

    def put(self, request: ObjectPutRequest) -> StoredObjectVersion:
        storage_name = hashlib.sha256(request.object_key.encode("utf-8")).hexdigest()
        version_id = hashlib.sha256(
            f"{request.object_key}\0{request.content_sha256}\0{request.operation_id}".encode("utf-8")
        ).hexdigest()
        object_path = self.objects / storage_name
        metadata_path = self.metadata / f"{storage_name}.json"
        if object_path.exists() or metadata_path.exists():
            raise ObjectConflict("object_key_already_exists")
        stored = StoredObjectVersion(
            object_key=request.object_key,
            version_id=version_id,
            storage_name=storage_name,
            content_sha256=request.content_sha256,
            provider_checksum=request.content_sha256,
            size_bytes=len(request.content),
            content_type=request.content_type,
            retention_mode=request.retention_mode,
            retain_until=request.retain_until,
            legal_hold=request.legal_hold,
            kms_reference=request.kms_reference,
        )
        try:
            with object_path.open("xb") as handle:
                handle.write(request.content)
            with metadata_path.open("x", encoding="utf-8", newline="\n") as handle:
                json.dump({name: getattr(stored, name) for name in stored.__slots__}, handle, sort_keys=True)
                handle.write("\n")
        except Exception:
            if object_path.exists():
                object_path.unlink()
            if metadata_path.exists():
                metadata_path.unlink()
            raise
        return stored

    def get_exact(self, object_key: str, version_id: str) -> bytes:
        stored = self._read_metadata(object_key)
        if stored.version_id != version_id:
            raise FileNotFoundError("object_version_not_found")
        return (self.objects / stored.storage_name).read_bytes()

    def verify_exact(self, stored: StoredObjectVersion) -> ObjectVerification:
        try:
            content = self.get_exact(stored.object_key, stored.version_id)
        except FileNotFoundError:
            return ObjectVerification(stored.object_key, stored.version_id, False, "object_version_missing")
        if content_sha256(content) != stored.content_sha256:
            return ObjectVerification(stored.object_key, stored.version_id, False, "content_hash_mismatch")
        if len(content) != stored.size_bytes:
            return ObjectVerification(stored.object_key, stored.version_id, False, "object_size_mismatch")
        return ObjectVerification(stored.object_key, stored.version_id, True, "verified")

    def find_versions(self, object_key: str) -> tuple[StoredObjectVersion, ...]:
        try:
            return (self._read_metadata(object_key),)
        except FileNotFoundError:
            return ()

    def place_legal_hold(self, object_key: str, version_id: str) -> None:
        stored = self._read_metadata(object_key)
        if stored.version_id != version_id:
            raise FileNotFoundError("object_version_not_found")
        marker = self.holds / f"{stored.storage_name}.{stored.version_id}.hold"
        if marker.exists():
            if marker.read_text(encoding="utf-8") != "ON\n":
                raise ObjectConflict("legal_hold_marker_mismatch")
            return
        with marker.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write("ON\n")

    def _read_metadata(self, object_key: str) -> StoredObjectVersion:
        storage_name = hashlib.sha256(object_key.encode("utf-8")).hexdigest()
        path = self.metadata / f"{storage_name}.json"
        if not path.exists():
            raise FileNotFoundError("object_key_not_found")
        payload = json.loads(path.read_text(encoding="utf-8"))
        if payload.get("object_key") != object_key or payload.get("storage_name") != storage_name:
            raise ObjectConflict("object_metadata_mismatch")
        return StoredObjectVersion(**payload)
