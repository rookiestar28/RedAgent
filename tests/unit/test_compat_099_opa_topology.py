from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_opa_conformance_image_is_digest_pinned_and_not_production_qualified() -> None:
    lock = json.loads((ROOT / "config" / "opa-conformance-image.json").read_text(encoding="utf-8"))
    assert lock["tag"] == "1.18.2-static"
    assert lock["index_digest"] == "sha256:57f7d06808fff6de3ea1d698e6430990973ca1370be0e54975f0083d615521da"
    assert lock["platform_digest"] == "sha256:3ece20d3a58eb4051db71c0b84fc962bca2a6f9aa74ee8ea3d027d693fdc2d1a"
    assert lock["reference"] == f"docker.io/openpolicyagent/opa:1.18.2-static@{lock['index_digest']}"
    assert lock["purpose"] == "local-conformance-only"
    assert lock["production_qualified"] is False


def test_opa_bundle_server_image_is_digest_pinned_and_local_only() -> None:
    lock = json.loads((ROOT / "config" / "opa-bundle-server-image.json").read_text(encoding="utf-8"))
    assert lock["tag"] == "3.13-alpine"
    assert lock["reference"] == f"docker.io/library/python:3.13-alpine@{lock['index_digest']}"
    assert lock["platform"] == "linux/amd64"
    assert lock["purpose"] == "local-conformance-only"
    assert lock["production_qualified"] is False


def test_policy_source_is_snapshot_only_default_deny_and_owns_closed_roots() -> None:
    root = ROOT / "config" / "opa" / "policy"
    manifest = json.loads((root / ".manifest").read_text(encoding="utf-8"))
    decision = (root / "redagent" / "decision.rego").read_text(encoding="utf-8")
    authz = (root / "system" / "authz.rego").read_text(encoding="utf-8")
    masking = (root / "system" / "log.rego").read_text(encoding="utf-8")
    assert manifest == {"revision": "r099-v1", "roots": ["redagent", "system"], "rego_version": 1}
    assert "default decision" in decision
    for boundary in ("api", "workflow", "evidence", "secret"):
        assert f'input.boundary == "{boundary}"' in decision
    assert "default allow := false" in authz
    assert 'input.path == ["v1", "data", "redagent", "decision"]' in authz
    for forbidden in ('["v1", "policies"]', '["v1", "compile"]', '["v1", "query"]'):
        assert forbidden not in authz
    assert "/input/roles" in masking and "/input/permissions" in masking


def test_opa_compose_is_loopback_nonroot_readonly_and_has_no_source_mount() -> None:
    compose = (ROOT / "compose.opa-conformance.yaml").read_text(encoding="utf-8")
    assert "REDAGENT_OPA_IMAGE" in compose
    assert "REDAGENT_OPA_BUNDLE_SERVER_IMAGE" in compose
    assert "127.0.0.1:${REDAGENT_OPA_HOST_PORT:-58181}:8181" in compose
    assert compose.count("platform: linux/amd64") == 2
    assert "read_only: true" in compose
    assert "user: \"65532:65532\"" in compose
    assert "no-new-privileges:true" in compose and "cap_drop:" in compose
    assert "internal: true" not in compose
    assert "host.docker.internal" not in compose
    assert "restart:" not in compose
    assert "config/opa/policy" not in compose
    assert ".local/redagent/opa" in compose


def test_conformance_runner_has_closed_commands_and_no_remote_or_generic_policy_api() -> None:
    source = (ROOT / "scripts" / "opa_conformance.py").read_text(encoding="utf-8")
    for command in ('"fmt"', '"check"', '"test"', '"build"'):
        assert command in source
    for route in ("/health?bundles&plugins", "/v1/status", "/v1/data/redagent/decision"):
        assert route in source
    for forbidden in ("/v1/policies", "/v1/compile", "/v1/query", "git clone", "shell=True"):
        assert forbidden not in source
    assert "DETACHED_PROCESS" not in source
