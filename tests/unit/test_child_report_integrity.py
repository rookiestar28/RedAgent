from __future__ import annotations

import asyncio
from dataclasses import asdict
from datetime import timedelta
import json

import pytest

from redagent_platform.campaign_service.child_replan_store import ChildParentConflict, _verify_report
from redagent_platform.evidence_service.backends import LocalAppendOnlyBackend
from redagent_platform.evidence_service.contracts import ObjectPutRequest, content_sha256
from tests.unit.test_campaign_planning_contracts import NOW


class EmptyImports:
    def __init__(self):
        self.reads = 0

    async def execute(self, statement):
        self.reads += 1
        return self

    def mappings(self):
        return self

    def all(self):
        return []


def _read(*args):
    return asyncio.run(_verify_report(*args))


def _material(tmp_path, **changes):
    payload = {"schema": "redagent.r123-result/v1", "adapter_id": "zap-controlled-runtime",
               "output_complete": True, "findings": []}
    payload.update(changes)
    content = json.dumps(payload, sort_keys=True).encode()
    backend = LocalAppendOnlyBackend(tmp_path, profile="synthetic-local")
    stored = backend.put(ObjectPutRequest(
        object_key="tenants/tenant-a/artifacts/report-a/sha256/" + content_sha256(content),
        content=content, content_type="application/json", content_sha256=content_sha256(content),
        retention_mode="GOVERNANCE", retain_until=(NOW + timedelta(days=1)).isoformat(),
        legal_hold=False, kms_reference="kms:local:fixture", operation_id="operation-a",
    ))
    artifact = dict(asdict(stored), id="report-a", tenant_id="tenant-a", artifact_class="report_safe",
                    redaction_state="report_safe", object_version_id=stored.version_id)
    imported = {"id": "import-a", "record_count": 0, "imported_at": NOW}
    return backend, stored, artifact, imported


def test_child_report_requires_exact_stored_bytes_and_matching_import_inventory(tmp_path):
    backend, stored, artifact, imported = _material(tmp_path)
    session = EmptyImports()
    assert _read(session, backend, artifact, imported, "zap-controlled-runtime") == stored.content_sha256
    assert session.reads == 1
    imported["record_count"] = 1
    with pytest.raises(ChildParentConflict, match="report_import_binding_mismatch"):
        _read(session, backend, artifact, imported, "zap-controlled-runtime")


@pytest.mark.parametrize("changes", [
    {"adapter_id": "another-adapter"}, {"output_complete": False},
    {"schema": "unknown-result"}, {"findings": None}, {"extra": "unclassified"},
])
def test_hash_valid_report_cannot_supply_incomplete_or_other_adapter_truth(tmp_path, changes):
    backend, _, artifact, imported = _material(tmp_path, **changes)
    session = EmptyImports()
    with pytest.raises(ChildParentConflict, match="report_(payload_invalid|semantics_mismatch)"):
        _read(session, backend, artifact, imported, "zap-controlled-runtime")
    assert session.reads == 0


def test_child_report_rechecks_bytes_if_object_changes_after_successful_backend_verification(tmp_path):
    backend, stored, artifact, imported = _material(tmp_path)

    class ChangedAfterCheck:
        def verify_exact(self, value):
            result = backend.verify_exact(value)
            assert result.ok
            (tmp_path / "objects" / stored.storage_name).write_bytes(b"changed after verification")
            return result

        def get_exact(self, key, version):
            return backend.get_exact(key, version)

    session = EmptyImports()
    with pytest.raises(ChildParentConflict, match="report_bytes_mismatch"):
        _read(session, ChangedAfterCheck(), artifact, imported, "zap-controlled-runtime")
    assert session.reads == 0


@pytest.mark.parametrize("kind", ["tamper", "owner_digest", "owner_size", "version"])
def test_child_report_denies_tampered_or_mismatched_immutable_object_owner(tmp_path, kind):
    backend, stored, artifact, imported = _material(tmp_path)
    if kind == "tamper":
        (tmp_path / "objects" / stored.storage_name).write_bytes(b"tampered report")
    elif kind == "owner_digest":
        artifact["content_sha256"] = "b" * 64
    elif kind == "owner_size":
        artifact["size_bytes"] += 1
    else:
        artifact["object_version_id"] = "other-version"
    session = EmptyImports()
    with pytest.raises(ChildParentConflict, match="report_backend_verification_failed"):
        _read(session, backend, artifact, imported, "zap-controlled-runtime")
    assert session.reads == 0
