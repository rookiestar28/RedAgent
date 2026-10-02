"""Source identity guard for the existing local runtime controller."""

import json
import hashlib

import pytest

from scripts import compat_104_requalify, compat_104_zap, compat_105_requalify


def test_local_zap_controller_is_the_current_public_source_and_matches_the_lock(monkeypatch, tmp_path):
    value = compat_104_zap.lock()
    value["controller_sha256"] = hashlib.sha256(compat_104_zap.CONTROLLER.read_bytes()).hexdigest()
    lock_path = tmp_path / "runtime-lock.json"
    lock_path.write_text(json.dumps(value), encoding="utf-8")
    monkeypatch.setattr(compat_104_zap, "LOCK_FILE", lock_path)
    assert compat_104_zap.validate()["ok"]
    assert compat_104_zap.CONTROLLER.name == "compat_104_zap_controller.py"


@pytest.mark.parametrize("builder", (compat_104_requalify, compat_105_requalify))
def test_reproducible_wrong_image_cannot_replace_the_operational_tag(builder, monkeypatch, tmp_path):
    commands = []
    monkeypatch.setattr(builder, "RUNTIME", tmp_path)
    monkeypatch.setattr(builder, "_build_once", lambda *args: "sha256:" + "f" * 64)
    monkeypatch.setattr(builder, "_run", lambda args: commands.append(args))
    with pytest.raises(RuntimeError, match="requalification_locked_image_mismatch:engine"):
        builder.build()
    assert not commands


@pytest.mark.parametrize("builder", (compat_104_requalify, compat_105_requalify))
def test_non_reproducible_image_cannot_replace_the_operational_tag(builder, monkeypatch, tmp_path):
    commands = []
    monkeypatch.setattr(builder, "RUNTIME", tmp_path)
    images = iter(("sha256:" + "a" * 64, "sha256:" + "b" * 64))
    monkeypatch.setattr(builder, "_build_once", lambda *args: next(images))
    monkeypatch.setattr(builder, "_run", lambda args: commands.append(args))
    with pytest.raises(RuntimeError, match="requalification_build_not_reproducible:engine"):
        builder.build()
    assert not commands


@pytest.mark.parametrize("builder", (compat_104_requalify, compat_105_requalify))
def test_exact_locked_builds_promote_only_the_three_fixed_tags(builder, monkeypatch, tmp_path):
    lock_path = getattr(builder, "LEGACY_ZAP_RUNTIME_LOCK", None) or builder.LEGACY_NUCLEI_RUNTIME_LOCK
    lock = json.loads(lock_path.read_text(encoding="utf-8"))
    images = iter(lock[f"{name}_image_id"] for name in ("engine", "target", "gateway") for _ in range(2))
    commands = []
    monkeypatch.setattr(builder, "_build_once", lambda *args: next(images))
    monkeypatch.setattr(builder, "_run", lambda args: commands.append(args))
    monkeypatch.setattr(builder, "RUNTIME", tmp_path)
    receipt = builder.build()
    assert receipt["images"] == {name: lock[f"{name}_image_id"] for name in ("engine", "target", "gateway")}
    assert [args[-1] for args in commands if args[:2] == ["docker", "tag"]] == [spec[3] for spec in builder.SPECS]
