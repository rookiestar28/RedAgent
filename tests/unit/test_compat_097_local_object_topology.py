from __future__ import annotations

import json
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[2]
INDEX_DIGEST = "sha256:103dd40b84d5aa3d5ab02f3a693797eb1d14cb842554b222dfbb589f364aa47f"


def test_reviewed_rustfs_fixture_is_exact_digest_and_explicitly_nonproduction() -> None:
    manifest = json.loads((ROOT / "config" / "local-stack-images.json").read_text(encoding="utf-8"))
    image = next(item for item in manifest["images"] if item["service"] == "rustfs")
    assert image["registry"] == "docker.io/rustfs/rustfs"
    assert image["tag"] == "1.0.0-alpha.99"
    assert image["index_digest"] == INDEX_DIGEST
    assert image["platform_digest"] == "sha256:a92846f09d9f1ccc41aeb9a9f1e8049093cc23b055d2b5a144e77525c1de1b41"
    assert image["purpose"] == "local-conformance-only"
    assert image["production_qualified"] is False


def test_compose_object_store_is_loopback_nonroot_persistent_and_has_no_console_or_bypass() -> None:
    compose = yaml.safe_load((ROOT / "compose.yaml").read_text(encoding="utf-8"))
    service = compose["services"]["rustfs"]
    assert service["image"] == "${REDAGENT_RUSTFS_IMAGE:?REDAGENT_RUSTFS_IMAGE is required}"
    assert service["user"] == "10001:10001"
    assert service["ports"] == ["${REDAGENT_BIND_HOST:-127.0.0.1}:${REDAGENT_RUSTFS_PORT:-59000}:9000"]
    assert service["environment"]["RUSTFS_CONSOLE_ENABLE"] == "false"
    assert service["environment"]["RUSTFS_ACCESS_KEY"] == "${AWS_ACCESS_KEY_ID:?AWS_ACCESS_KEY_ID is required}"
    assert service["environment"]["RUSTFS_SECRET_KEY"] == "${AWS_SECRET_ACCESS_KEY:?AWS_SECRET_ACCESS_KEY is required}"
    assert service["volumes"] == ["redagent_rustfs_data:/data"]
    assert service["security_opt"] == ["no-new-privileges:true"]
    assert service["cap_drop"] == ["ALL"]
    assert service["read_only"] is True
    rendered = json.dumps(service).lower()
    for forbidden in ("latest", "privileged", "bypassgovernance", "9001:", "0.0.0.0"):
        assert forbidden not in rendered


def test_local_stack_config_exposes_bounded_object_endpoint_without_secrets() -> None:
    source = (ROOT / "redagent_platform" / "local_stack_config.py").read_text(encoding="utf-8")
    runtime = (ROOT / "redagent_platform" / "local_stack.py").read_text(encoding="utf-8")
    assert "rustfs_port" in source
    assert "rustfs" in source
    assert "REDAGENT_RUSTFS_PORT" in runtime
    assert "REDAGENT_EVIDENCE_ENDPOINT" in runtime
    assert "AWS_ACCESS_KEY_ID" in runtime and "AWS_SECRET_ACCESS_KEY" in runtime
    assert "AWS_SECRET_ACCESS_KEY=rustfsadmin" not in runtime
