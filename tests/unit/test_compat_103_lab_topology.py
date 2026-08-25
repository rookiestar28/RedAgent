from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts import compat_103_lab


ROOT = Path(__file__).resolve().parents[2]


def test_fixture_is_repo_owned_digest_pinned_and_runtime_hardened() -> None:
    dockerfile = (ROOT / "containers/lab-synthetic/Dockerfile").read_text(encoding="utf-8")
    lock = json.loads((ROOT / "config/lab-conformance-image.json").read_text(encoding="utf-8"))
    lifecycle = (ROOT / "scripts/compat_103_lab.py").read_text(encoding="utf-8")
    assert lock["base_linux_amd64_digest"] in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert lock["source"].startswith("repository-owned:")
    assert lock["production_qualified"] is False
    for boundary in (
        '"--internal"', '"--read-only"', '"--cap-drop", "ALL"',
        '"no-new-privileges:true"', '"--pids-limit", "32"', '"--memory", "128m"',
        '"--cpus", "0.5"', '"--user", "65532:65532"',
    ):
        assert boundary in lifecycle
    assert '"--publish"' not in lifecycle
    assert '"--network", "host"' not in lifecycle
    assert '"redagent-r103-sbom/v1"' in lifecycle
    assert '"redagent-r103-provenance/v1"' in lifecycle
    assert "lab_supply_chain_attestation_mismatch" in lifecycle


def test_fixture_has_only_fixed_benign_read_routes() -> None:
    source = (ROOT / "containers/lab-synthetic/fixture_server.py").read_text(encoding="utf-8")
    for route in ("/health/ready", "/api/v1/profile", "/api/v1/expected-findings", "/artifact/manifest"):
        assert route in source
    for forbidden in ("subprocess", "os.system", "eval(", "exec(", "urllib.request", "socket.connect"):
        assert forbidden not in source


def test_confirmation_is_mandatory_and_derived_lock_is_closed() -> None:
    with pytest.raises(SystemExit):
        compat_103_lab.main(["validate"])
    lock = json.loads((ROOT / "config/lab-conformance-image.json").read_text(encoding="utf-8"))
    if str(lock["derived_image_id"]).startswith("sha256:"):
        assert compat_103_lab.validate()["ok"] is True
