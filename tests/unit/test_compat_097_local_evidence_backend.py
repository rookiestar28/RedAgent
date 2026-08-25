from __future__ import annotations

from pathlib import Path

import pytest

from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend, ObjectConflict
from redagent_platform.evidence_service.contracts import ObjectPutRequest, content_sha256


def test_local_backend_writes_once_reads_exact_version_and_detects_tamper(tmp_path: Path) -> None:
    backend = LocalAppendOnlyBackend(tmp_path, profile="synthetic-local")
    content = b"synthetic append-only evidence"
    request = ObjectPutRequest(
        object_key="tenants/tenant-1/artifacts/artifact-1/sha256/" + content_sha256(content),
        content=content,
        content_type="text/plain",
        content_sha256=content_sha256(content),
        retention_mode="GOVERNANCE",
        retain_until="2026-08-10T00:00:00+00:00",
        legal_hold=False,
        kms_reference="kms:local:fixture",
        operation_id="operation-1",
    )

    stored = backend.put(request)
    assert stored.version_id
    assert backend.get_exact(stored.object_key, stored.version_id) == content
    assert backend.verify_exact(stored).ok
    backend.place_legal_hold(stored.object_key, stored.version_id)
    backend.place_legal_hold(stored.object_key, stored.version_id)
    assert (tmp_path / "holds" / f"{stored.storage_name}.{stored.version_id}.hold").read_text(encoding="utf-8") == "ON\n"
    with pytest.raises(ObjectConflict, match="object_key_already_exists"):
        backend.put(request)

    object_path = tmp_path / "objects" / stored.storage_name
    object_path.write_bytes(b"tampered")
    assert backend.verify_exact(stored).reason == "content_hash_mismatch"


def test_local_backend_is_synthetic_only_and_rejects_traversal_or_symlink_root(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="local_evidence_backend_synthetic_only"):
        LocalAppendOnlyBackend(tmp_path, profile="production")
    with pytest.raises(ValueError, match="object_key_invalid"):
        LocalAppendOnlyBackend(tmp_path, profile="synthetic-local").put(ObjectPutRequest(
            object_key="../escape", content=b"x", content_type="text/plain", content_sha256=content_sha256(b"x"),
            retention_mode="GOVERNANCE", retain_until="2026-08-10T00:00:00+00:00", legal_hold=False,
            kms_reference="kms:local:fixture", operation_id="operation-2",
        ))
