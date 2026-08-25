import json

import pytest

from redagent_platform.artifact_pipeline.manifest import ManifestEntry, validate_manifest
from redagent_platform.artifact_pipeline.secret_scan import match_redacted_finding


def test_manifest_is_canonical_and_rejects_traversal_links_devices_collisions_and_bombs():
    entries = (ManifestEntry(path="src/app.py", kind="file", size=20, sha256="a" * 64, compressed_size=10),)
    first = validate_manifest(entries=entries, max_files=8, max_bytes=1024, max_depth=4, max_expansion_ratio=20)
    assert first == validate_manifest(entries=entries, max_files=8, max_bytes=1024, max_depth=4, max_expansion_ratio=20)
    for entry, reason in (
        (ManifestEntry(path="../escape", kind="file", size=1, sha256="a" * 64, compressed_size=1), "artifact_path_traversal"),
        (ManifestEntry(path="/absolute", kind="file", size=1, sha256="a" * 64, compressed_size=1), "artifact_absolute_path"),
        (ManifestEntry(path="link", kind="symlink", size=1, sha256="a" * 64, compressed_size=1), "artifact_entry_kind_denied"),
        (ManifestEntry(path="bomb", kind="file", size=1000, sha256="a" * 64, compressed_size=1), "artifact_expansion_ratio_exceeded"),
    ):
        with pytest.raises(ValueError, match=reason): validate_manifest(entries=(entry,), max_files=8, max_bytes=2048, max_depth=4, max_expansion_ratio=20)
    with pytest.raises(ValueError, match="artifact_path_collision"):
        validate_manifest(entries=(entries[0], ManifestEntry(path="SRC/APP.PY", kind="file", size=20, sha256="b" * 64, compressed_size=10)), max_files=8, max_bytes=1024, max_depth=4, max_expansion_ratio=20)


def test_raw_match_never_leaves_secret_finding_or_serialized_evidence():
    raw_match = "compat_110" + "-synthetic-canary-material"
    finding = match_redacted_finding(artifact_sha256="a" * 64, path="config/example.env", line=7,
        rule_id="synthetic-token", classification="credential-like", raw_match=raw_match, fingerprint_key=b"r110-fixture-key")
    encoded = json.dumps(finding.__dict__, sort_keys=True)
    assert raw_match not in encoded
    assert finding.redacted_fragment == "[REDACTED]"
    assert len(finding.fingerprint) == 64
    assert not hasattr(finding, "raw_match")
