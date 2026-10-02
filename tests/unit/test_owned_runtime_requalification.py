"""Deterministic public-only assembly boundaries for owned runtime artifacts."""

import io
import tarfile
import os
import json
import hashlib
from datetime import datetime, timedelta, timezone

import pytest

from scripts import owned_runtime_requalification as qualification


def test_context_bytes_do_not_depend_on_public_source_mtime_or_mode(tmp_path, monkeypatch):
    monkeypatch.setattr(qualification, "ROOT", tmp_path)
    source = tmp_path / "containers/fixture.py"
    source.parent.mkdir()
    source.write_bytes(b"print('owned fixture')\n")
    first = qualification.normalized_context((source,))
    os.utime(source, (123, 456))
    source.chmod(0o600)
    assert qualification.normalized_context((source,)) == first
    with tarfile.open(fileobj=io.BytesIO(first)) as archive:
        member = archive.getmember("containers/fixture.py")
        assert member.mtime == qualification.SOURCE_DATE_EPOCH
        assert (member.uid, member.gid, member.mode) == (0, 0, 0o644)
        assert archive.extractfile(member).read() == source.read_bytes()


def test_context_rejects_content_outside_the_public_root(tmp_path, monkeypatch):
    root = tmp_path / "public"
    root.mkdir()
    other = tmp_path / "private-evidence.txt"
    other.write_text("private")
    monkeypatch.setattr(qualification, "ROOT", root)
    with pytest.raises(qualification.RequalificationError, match="context_outside_public_root"):
        qualification.normalized_context((other,))


def test_mutually_equal_wrong_images_cannot_be_tagged_as_a_frozen_candidate():
    calls = []
    with pytest.raises(qualification.RequalificationError, match="locked_image_mismatch"):
        qualification.freeze_pair("sha256:" + "a" * 64, "sha256:" + "a" * 64,
                                  "sha256:" + "b" * 64, "owned:fixed", calls.append)
    assert not calls


def test_non_reproducible_images_cannot_be_frozen():
    calls = []
    with pytest.raises(qualification.RequalificationError, match="not_reproducible"):
        qualification.freeze_pair("sha256:" + "a" * 64, "sha256:" + "b" * 64,
                                  "sha256:" + "b" * 64, "owned:fixed", calls.append)
    assert not calls


@pytest.mark.parametrize("age", (timedelta(days=3), -timedelta(seconds=1)))
def test_stale_or_future_database_is_not_current_supply_chain_evidence(age):
    now = datetime(2026, 10, 2, tzinfo=timezone.utc)
    with pytest.raises(qualification.RequalificationError, match="database_not_current"):
        qualification.validate_database({"Version": 2, "UpdatedAt": (now - age).isoformat()}, now)


def test_critical_vulnerability_is_rejected_even_if_tool_exit_status_was_zero():
    report = {"Metadata": {"ImageID": "sha256:" + "a" * 64}, "Results": [
        {"Vulnerabilities": [{"VulnerabilityID": "synthetic-critical", "Severity": "CRITICAL"}]}
    ]}
    with pytest.raises(qualification.RequalificationError, match="critical_image_rejected"):
        qualification.validate_report(report, "sha256:" + "a" * 64)


def test_zero_critical_report_for_another_image_is_rejected():
    with pytest.raises(qualification.RequalificationError, match="scan_image_identity_mismatch"):
        qualification.validate_report({"Metadata": {"ImageID": "sha256:" + "b" * 64},
                                       "Results": []}, "sha256:" + "a" * 64)


def test_canonical_evidence_redacts_json_encoded_workstation_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(qualification, "ROOT", tmp_path)
    image = "sha256:" + "a" * 64
    value = {"Metadata": {"ImageID": image}, "ArtifactName": str(tmp_path / "owned.tar")}
    encoded = qualification.public_evidence_text(json.dumps(value))
    result = json.loads(encoded)
    assert result["ArtifactName"] == "<repo>/owned.tar"
    assert result["Metadata"]["ImageID"] == image


def test_oci_manifest_binds_trivy_config_and_layer_chain(tmp_path):
    config = {"architecture": "amd64", "rootfs": {"diff_ids": ["sha256:" + "c" * 64]}}
    config_bytes = json.dumps(config).encode()
    config_id = "sha256:" + hashlib.sha256(config_bytes).hexdigest()
    layer_bytes = b"synthetic owned layer"
    layer_id = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    manifest = {"config": {"digest": config_id}, "layers": [{"digest": layer_id}]}
    manifest_bytes = json.dumps(manifest).encode()
    image_id = "sha256:" + hashlib.sha256(manifest_bytes).hexdigest()
    archive_path = tmp_path / "owned.tar"
    with tarfile.open(archive_path, "w") as archive:
        index = json.dumps({"manifests": [{"digest": image_id}]}).encode()
        member = tarfile.TarInfo("index.json")
        member.size = len(index)
        archive.addfile(member, io.BytesIO(index))
        for digest, content in ((config_id, config_bytes), (image_id, manifest_bytes),
                                (layer_id, layer_bytes)):
            member = tarfile.TarInfo("blobs/sha256/" + digest.removeprefix("sha256:"))
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))
    report = {"Metadata": {"ImageID": config_id, "DiffIDs": config["rootfs"]["diff_ids"]},
              "Results": [{"Target": "synthetic-owned-os"}]}
    assert qualification.validate_archive_report(archive_path, report, image_id) == config_id
    report["Metadata"]["DiffIDs"] = ["sha256:" + "d" * 64]
    with pytest.raises(qualification.RequalificationError, match="scan_layer_identity_mismatch"):
        qualification.validate_archive_report(archive_path, report, image_id)


def test_helper_package_tampering_denies_before_build_context(tmp_path, monkeypatch):
    monkeypatch.setattr(qualification, "ROOT", tmp_path)
    source = tmp_path / ".tmp/runtime-requalification-v3/packages/libcrypto3-3.5.9-r0.apk"
    source.parent.mkdir(parents=True)
    source.write_bytes(b"tampered signed package")
    manifest = {"packages": [{"name": "libcrypto3", "version": "3.5.9-r0",
                              "path": source.relative_to(tmp_path).as_posix(),
                              "sha256": "a" * 64}]}
    with pytest.raises(qualification.RequalificationError, match="helper_package_digest_mismatch"):
        qualification.helper_package_inputs(manifest)
