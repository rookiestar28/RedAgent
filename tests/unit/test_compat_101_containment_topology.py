from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_containment_fixture_is_fixed_non_root_bounded_and_internal_only() -> None:
    dockerfile = (ROOT / "containers" / "containment-synthetic" / "Dockerfile").read_text(encoding="utf-8")
    script = (ROOT / "scripts" / "containment_conformance.py").read_text(encoding="utf-8")
    lock = json.loads((ROOT / "config" / "containment-conformance-image.json").read_text(encoding="utf-8"))
    assert lock["derived_image_id"] == "sha256:3ff5480810e463fbcf12987d7dfd6df2c0ddeacadfdbe4e322ec9aa4c1cf9be2"
    assert lock["source_date_epoch"] == 1760544000
    assert lock["buildkit_compatibility_version"] == "20"
    assert lock["base_linux_amd64_digest"] in dockerfile
    assert "USER 65532:65532" in dockerfile
    assert "COPY --chown=0:0 --chmod=0555 containment_entry.py" in dockerfile
    assert 'str(values["base_linux_amd64_digest"]) not in dockerfile_source' in script
    for required in (
        'builder.build_prefix', "attest_docker_image_config", '"--no-cache", "--network", "none", "--provenance=false"',
        '"type=docker"', '"rewrite-timestamp=true"', '"compatibility-version={compatibility_version}"',
        '"SOURCE_DATE_EPOCH={source_date_epoch}"',
        '"--internal"', '"--read-only"', '"--cap-drop", "ALL"',
        '"no-new-privileges:true"', '"--pids-limit", "32"',
        '"--memory", "128m"', '"--cpus", "0.5"', '"--restart", "no"',
        '"network", "disconnect", "--force"', '"stop", "--time", "2"',
    ):
        assert required in script
    for forbidden in ("shell=True", "os.system", "public target", "--privileged", "/var/run/docker.sock"):
        assert forbidden not in script
