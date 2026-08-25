from __future__ import annotations

import pytest

from redagent_platform.evidence_service.contracts import StoredObjectVersion
from redagent_platform.evidence_service.repository import EvidenceOperationPending, EvidenceRecordConflict
from redagent_platform.evidence_service.service import reconcile_pending_version


def test_pending_reconciliation_requires_one_total_exact_hash_matching_version() -> None:
    expected = _stored("version-1", "a" * 64)
    assert reconcile_pending_version((expected,), expected_content_hash="a" * 64) is expected
    with pytest.raises(EvidenceOperationPending, match="evidence_operation_pending_no_object"):
        reconcile_pending_version((), expected_content_hash="a" * 64)
    with pytest.raises(EvidenceRecordConflict, match="evidence_pending_operation_requires_reconciliation"):
        reconcile_pending_version((_stored("version-other", "b" * 64),), expected_content_hash="a" * 64)
    with pytest.raises(EvidenceRecordConflict, match="evidence_pending_operation_requires_reconciliation"):
        reconcile_pending_version((expected, _stored("unknown-version", "b" * 64)), expected_content_hash="a" * 64)


def _stored(version_id: str, digest: str) -> StoredObjectVersion:
    return StoredObjectVersion(
        object_key="tenants/tenant-1/evidence/artifact-1",
        version_id=version_id,
        storage_name="storage",
        content_sha256=digest,
        provider_checksum=digest,
        size_bytes=1,
        content_type="text/plain",
        retention_mode="GOVERNANCE",
        retain_until="2026-08-10T00:00:00+00:00",
        legal_hold=False,
        kms_reference="kms:fixture",
    )
