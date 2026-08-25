from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.nuclei_service.compiler import compile_nuclei_plan
from redagent_platform.nuclei_service.contracts import (
    NUCLEI_IMAGE_DIGEST_BY_PLATFORM,
    NucleiAuthorization,
    NucleiBundleManifest,
    NucleiProfileId,
    NucleiTargetBinding,
    certified_profiles,
    validate_template_document,
)
from redagent_platform.nuclei_service.normalization import normalize_nuclei_jsonl


NOW = datetime(2026, 7, 11, 8, 0, tzinfo=timezone.utc)


def bundle(**overrides: object) -> NucleiBundleManifest:
    values: dict[str, object] = {
        "bundle_id": "r105-http-header-bundle",
        "revision": 1,
        "template_id": "redagent-r105-missing-header",
        "template_relative_path": "templates/redagent-r105-missing-header.yaml",
        "template_sha256": "a" * 64,
        "bundle_sha256": "b" * 64,
        "signature_verified": True,
        "reviewer_user_id": "reviewer-r105",
        "protocol": "http",
        "method": "GET",
        "paths": ("/nuclei/missing-header",),
        "severity": "low",
        "tags": ("redagent", "synthetic"),
        "expected_matcher_names": ("missing-security-header",),
        "file_inventory": ("templates/redagent-r105-missing-header.yaml",),
        "promoted_at": NOW,
        "expires_at": NOW + timedelta(days=30),
    }
    values.update(overrides)
    return NucleiBundleManifest(**values)  # type: ignore[arg-type]


def target() -> NucleiTargetBinding:
    return NucleiTargetBinding(
        target_id="r105-owned-http-fixture", attestation_sha256="c" * 64,
        endpoint="http://redagent-r105-gateway:8080",
        allowed_paths=("/nuclei/missing-header",), network_id="redagent-r105-gateway-target",
        non_production=True, issued_at=NOW, expires_at=NOW + timedelta(minutes=15),
    )


def authorization() -> NucleiAuthorization:
    return NucleiAuthorization(
        tenant_id="tenant-r105", policy_decision_id="decision-r105",
        policy_revision="r099-v1", roe_version_id="roe-r105",
        approved_profile_ids=(NucleiProfileId.HTTP_HEADER,), approved_bundle_id=bundle().bundle_id,
        approved_at=NOW, expires_at=NOW + timedelta(minutes=10),
    )


def test_certified_profile_and_engine_identity_are_closed() -> None:
    profiles = certified_profiles()
    assert set(profiles) == {NucleiProfileId.HTTP_HEADER}
    assert NUCLEI_IMAGE_DIGEST_BY_PLATFORM == {
        "linux/amd64": "sha256:4e95c15953fe894bda1a8a16ecde958497e335a7a0b1f6fdb17b06af38630871",
    }
    profile = profiles[NucleiProfileId.HTTP_HEADER]
    assert profile.allowed_protocols == ("http",)
    assert profile.allowed_methods == ("GET",)
    assert profile.request_limit <= 20 and profile.concurrency == 1
    assert profile.oast_allowed is False and profile.runtime_update_allowed is False


def test_template_semantics_reject_every_elevated_or_ambiguous_surface() -> None:
    safe = {
        "id": "redagent-r105-missing-header",
        "info": {"name": "compat_105 missing header", "author": "redagent", "severity": "low", "tags": "redagent,synthetic"},
        "http": [{
            "method": "GET", "path": ["{{BaseURL}}/nuclei/missing-header"],
            "redirects": False, "max-redirects": 0,
            "matchers-condition": "and",
            "matchers": [
                {"type": "status", "status": [200]},
                {"type": "word", "name": "missing-security-header", "part": "header", "negative": True, "words": ["X-Content-Type-Options"]},
            ],
        }],
    }
    assert validate_template_document(safe) == "redagent-r105-missing-header"
    for key in (
        "code", "javascript", "headless", "file", "network", "dns", "ssl",
        "websocket", "whois", "workflow", "flow", "variables", "payloads", "self-contained",
    ):
        with pytest.raises(ValueError, match="nuclei_template_forbidden"):
            validate_template_document({**safe, key: [{}]})
    with pytest.raises(ValueError, match="nuclei_template_method_forbidden"):
        validate_template_document({**safe, "http": [{**safe["http"][0], "method": "POST"}]})
    with pytest.raises(ValueError, match="nuclei_template_path_forbidden"):
        validate_template_document({**safe, "http": [{**safe["http"][0], "path": ["https://example.test/"]}]})


def test_compiler_emits_fixed_argv_and_rejects_binding_drift() -> None:
    compiled = compile_nuclei_plan(
        profile_id=NucleiProfileId.HTTP_HEADER, bundle=bundle(), target=target(),
        authorization=authorization(), now=NOW,
    )
    assert compiled.argv == (
        "-target", "http://redagent-r105-gateway:8080",
        "-templates", "/opt/redagent/bundle/templates/redagent-r105-missing-header.yaml",
        "-template-id", "redagent-r105-missing-header", "-disable-unsigned-templates",
        "-disable-update-check", "-no-interactsh", "-no-stdin", "-jsonl-export",
        "/work/results.jsonl", "-omit-raw", "-omit-template", "-rate-limit", "2",
        "-concurrency", "1", "-bulk-size", "1", "-timeout", "5", "-retries", "0",
        "-response-size-read", "1048576", "-response-size-save", "0", "-silent", "-no-color",
    )
    assert len(compiled.plan_sha256) == 64
    with pytest.raises(ValueError, match="nuclei_bundle_expired"):
        compile_nuclei_plan(
            profile_id=NucleiProfileId.HTTP_HEADER,
            bundle=replace(bundle(), expires_at=NOW + timedelta(seconds=1)), target=target(),
            authorization=authorization(), now=NOW + timedelta(seconds=1),
        )
    with pytest.raises(ValueError, match="nuclei_target_binding_mismatch"):
        compile_nuclei_plan(
            profile_id=NucleiProfileId.HTTP_HEADER, bundle=bundle(),
            target=replace(target(), endpoint="http://other:8080"),
            authorization=authorization(), now=NOW,
        )


def test_jsonl_parser_is_bounded_scope_bound_and_redacted() -> None:
    line = b'{"template-id":"redagent-r105-missing-header","matcher-name":"missing-security-header","type":"http","host":"redagent-r105-gateway","url":"http://redagent-r105-gateway:8080","matched-at":"http://redagent-r105-gateway:8080/nuclei/missing-header","info":{"name":"compat_105 missing header","severity":"low"}}\n'
    result = normalize_nuclei_jsonl(line, bundle=bundle(), target=target())
    assert len(result) == 1
    assert result[0].template_id == bundle().template_id
    assert result[0].affected_resource == "/nuclei/missing-header"
    assert len(result[0].fingerprint) == 64
    assert "redagent-r105-gateway" not in result[0].affected_resource
    with pytest.raises(ValueError, match="nuclei_result_template_mismatch"):
        normalize_nuclei_jsonl(line.replace(b"redagent-r105-missing-header", b"unknown-template"), bundle=bundle(), target=target())
    with pytest.raises(ValueError, match="nuclei_result_too_large"):
        normalize_nuclei_jsonl(b"x" * (1024 * 1024 + 1), bundle=bundle(), target=target())
    with pytest.raises(ValueError, match="nuclei_result_json_invalid"):
        normalize_nuclei_jsonl(line + b'{"partial":', bundle=bundle(), target=target())


def test_jsonl_parser_accepts_exact_v380_shape_but_drops_curl_and_infers_single_matcher() -> None:
    line = b'{"template-id":"redagent-r105-missing-header","template-path":"/opt/redagent/bundle/templates/redagent-r105-missing-header.yaml","info":{"name":"compat_105 Missing Security Header","author":["redagent"],"tags":["redagent","synthetic"],"severity":"low"},"type":"http","host":"redagent-r105-gateway","port":"8080","scheme":"http","url":"http://redagent-r105-gateway:8080","matched-at":"http://redagent-r105-gateway:8080/nuclei/missing-header","ip":"172.21.0.2","timestamp":"2026-07-11T00:00:00Z","curl-command":"curl fixed-certified-target","matcher-status":true}\n'
    result = normalize_nuclei_jsonl(line, bundle=bundle(), target=target())
    assert result[0].matcher_name == "missing-security-header"
    assert "curl" not in repr(result[0]) and "172.21.0.2" not in repr(result[0])
