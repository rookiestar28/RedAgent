"""Additive current authority must bind the freshly qualified closed artifact tuple."""

import hashlib
import json
from pathlib import Path
import subprocess

import pytest

from redagent_platform.zap_service import authority as zap_authority, contracts as zap_contracts
from redagent_platform.nuclei_service import authority as nuclei_authority, contracts as nuclei_contracts
from scripts import compat_104_zap, compat_105_nuclei
from scripts import owned_runtime_requalification as assembler


ROOT = Path(__file__).resolve().parents[2]


def test_current_selection_uses_additive_revision_three():
    assert zap_authority.CURRENT_ZAP_RUNTIME_LOCK.name == "r104-zap-runtime-v3.json"
    assert nuclei_authority.CURRENT_NUCLEI_RUNTIME_LOCK.name == "r105-nuclei-runtime-v3.json"
    assert nuclei_authority.CURRENT_NUCLEI_BUNDLE_MANIFEST.name == "bundle-manifest-v3.json"
    for authority in (zap_authority.CURRENT_ZAP_ARTIFACT_PROMOTION,
                      nuclei_authority.CURRENT_NUCLEI_ARTIFACT_PROMOTION,
                      nuclei_authority.CURRENT_NUCLEI_BUNDLE_PROMOTION):
        assert "261002-" in authority.signature.name and "_V3" in authority.signature.name


def test_current_qualifier_sources_and_contracts_match_locked_tuple():
    zap = compat_104_zap.lock()
    nuclei = compat_105_nuclei.lock()
    assert zap["schema"].endswith("/v3") and nuclei["schema"].endswith("/v3")
    assert zap_contracts.CURRENT_R104_TARGET_IMAGE_ID == zap["target_image_id"]
    assert nuclei_contracts.CURRENT_R105_TARGET_IMAGE_ID == nuclei["target_image_id"]
    for value, module, engine in ((zap, zap_contracts, "ZAP"), (nuclei, nuclei_contracts, "NUCLEI")):
        assert getattr(module, f"CURRENT_{engine}_IMAGE_DIGEST_BY_PLATFORM")["linux/amd64"] == value["engine_image_id"]
        assert getattr(module, f"CURRENT_{engine}_SBOM_SHA256") == value["sbom_sha256"]
        assert getattr(module, f"CURRENT_{engine}_CRITICAL_REPORT_SHA256") == value["critical_report_sha256"]
    assert compat_104_zap.validate()["ok"]
    for qualifier in (compat_104_zap, compat_105_nuclei):
        for name in ("TARGET_DOCKERFILE", "GATEWAY_DOCKERFILE"):
            assert getattr(qualifier, name).name == "Dockerfile-v3"


def test_historical_authority_files_remain_byte_stable():
    snapshot = json.loads((ROOT / "config/owned-runtime-authority-history.json").read_text())
    for name, digest in snapshot.items():
        assert hashlib.sha256((ROOT / name).read_bytes()).hexdigest() == digest


@pytest.mark.parametrize("mutation", ("missing_proof", "wrong_pair", "critical_report"))
def test_activation_denies_drift_before_any_operational_tag(monkeypatch, tmp_path, mutation):
    canonical = tmp_path / "runtime-assets/supply-chain/owned-runtime-v3"
    canonical.mkdir(parents=True)
    config = tmp_path / "config"
    config.mkdir()
    image = "sha256:" + "a" * 64
    receipt = {"image_id": image, "build_image_ids": [image, image],
               "local_tag": assembler.SPECS["zap-engine"][1], "sources": {}}
    proof = {"image_id": image, "critical_vulnerability_count": 0}
    if mutation == "wrong_pair":
        receipt["build_image_ids"] = ["sha256:" + "b" * 64] * 2
    binding = {}
    for label, value in (("build", receipt), ("supply_chain", proof)):
        path = canonical / f"zap-engine-{label}.json"
        path.write_text(json.dumps(value))
        binding[f"{label}_path"] = path.relative_to(tmp_path).as_posix()
        binding[f"{label}_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    if mutation == "missing_proof":
        (canonical / "zap-engine-supply_chain.json").unlink()
    elif mutation == "critical_report":
        (canonical / "zap-engine-supply_chain.json").write_text('{"critical_vulnerability_count":1}')
    (config / "r104-zap-runtime-v3.json").write_text(json.dumps({
        "owned_artifact_proofs": {"engine": binding}, "engine_image_id": image,
        "engine_local_tag": receipt["local_tag"],
    }))
    commands = []
    monkeypatch.setattr(assembler, "ROOT", tmp_path)
    monkeypatch.setattr(assembler, "_run", lambda args: commands.append(args))
    with pytest.raises((assembler.RequalificationError, FileNotFoundError)):
        assembler.activate()
    assert commands == []


@pytest.mark.parametrize("mutation", ("external_network", "published_port", "stopped_worker", "wrong_helper"))
def test_live_zap_qualification_requires_observed_isolation(monkeypatch, mutation):
    lock = compat_104_zap.lock()
    observed = {
        "no_direct_zap_target_route": True,
        "resources": {name: {"running": True, "published_ports": False, "image_id": image}
                      for name, image in ((compat_104_zap.ZAP, lock["engine_image_id"]),
                                          (compat_104_zap.GATEWAY, lock["gateway_image_id"]),
                                          (compat_104_zap.TARGET, lock["target_image_id"]))},
        "networks": {name: {"exists": True, "internal": True}
                     for name in (compat_104_zap.ZAP_NET, compat_104_zap.TARGET_NET)},
    }
    if mutation == "external_network":
        observed["networks"][compat_104_zap.ZAP_NET]["internal"] = False
    elif mutation == "published_port":
        observed["resources"][compat_104_zap.GATEWAY]["published_ports"] = True
    elif mutation == "stopped_worker":
        observed["resources"][compat_104_zap.ZAP]["running"] = False
    else:
        observed["resources"][compat_104_zap.TARGET]["image_id"] = "sha256:" + "f" * 64
    monkeypatch.setattr(compat_104_zap, "status", lambda: observed)
    with pytest.raises(compat_104_zap.R104Error, match="qualification_isolation_invalid"):
        compat_104_zap._qualification_boundary()


def test_zap_tag_drift_denied_before_startup_mutation(monkeypatch):
    lock = compat_104_zap.lock()
    calls = []
    def docker(*args, **kwargs):
        calls.append(args)
        image = lock["engine_image_id"] if args[2] == lock["engine_local_tag"] else "sha256:" + "f" * 64
        return subprocess.CompletedProcess(args, 0, stdout=image, stderr="")
    monkeypatch.setattr(compat_104_zap, "docker", docker)
    with pytest.raises(compat_104_zap.R104Error, match="owned_image_identity_mismatch"):
        compat_104_zap._assert_current_images(lock)
    assert all(args[:2] == ("image", "inspect") for args in calls)
