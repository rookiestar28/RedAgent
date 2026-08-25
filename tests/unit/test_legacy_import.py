from __future__ import annotations

from pathlib import Path

import pytest

from redagent_platform.control_plane import ControlPlaneRecordType, JsonlControlPlaneStore
from redagent_platform.persistence.legacy_import import LegacyImportError, load_legacy_import_bundle


def test_legacy_bundle_is_hash_verified_bounded_and_read_only(tmp_path: Path) -> None:
    source = tmp_path / "legacy.jsonl"
    store = JsonlControlPlaneStore(source)
    store.append(
        ControlPlaneRecordType.ENGAGEMENT,
        "eng-legacy",
        {
            "engagement_id": "eng-legacy",
            "organization_id": "tenant-legacy",
            "name": "Legacy synthetic",
            "owner_user_id": "user-legacy",
            "created_at": "2026-07-10T08:00:00+00:00",
        },
    )
    before = source.read_bytes()

    bundle = load_legacy_import_bundle(tmp_path, source, max_bytes=4096, max_records=10)

    assert bundle.source_sha256
    assert len(bundle.records) == 1
    assert bundle.records[0].record_id == "eng-legacy"
    assert source.read_bytes() == before


def test_legacy_bundle_rejects_tampering_oversize_and_outside_workspace(tmp_path: Path) -> None:
    source = tmp_path / "legacy.jsonl"
    store = JsonlControlPlaneStore(source)
    store.append(ControlPlaneRecordType.ENGAGEMENT, "eng-legacy", {"name": "before"})
    source.write_text(source.read_text(encoding="utf-8").replace("before", "after"), encoding="utf-8")

    with pytest.raises(LegacyImportError, match="legacy_record_integrity_invalid"):
        load_legacy_import_bundle(tmp_path, source)
    with pytest.raises(LegacyImportError, match="legacy_source_too_large"):
        load_legacy_import_bundle(tmp_path, source, max_bytes=1)

    outside = tmp_path.parent / "outside-legacy.jsonl"
    outside.write_text("\n", encoding="utf-8")
    try:
        with pytest.raises(LegacyImportError, match="legacy_source_outside_workspace"):
            load_legacy_import_bundle(tmp_path, outside)
    finally:
        outside.unlink(missing_ok=True)
