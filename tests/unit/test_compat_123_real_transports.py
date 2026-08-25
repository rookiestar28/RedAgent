from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path

import pytest
import yaml

from redagent_platform.nuclei_service.compat_123_adapter import (
    NUCLEI_FIXED_ARGV,
    NucleiFixedInvocation,
)
from redagent_platform.nuclei_service.compat_123_transport import (
    NUCLEI_EXECUTION_TIMEOUT_SECONDS,
    NUCLEI_RESPONSE_BYTES_LIMIT,
    NucleiDockerTransport,
    build_nuclei_worker_command,
    nuclei_docker_resources,
)
from redagent_platform.zap_service.compat_123_adapter import ZapFixedInvocation
from redagent_platform.zap_service.compat_123_transport import (
    ZAP_EXECUTION_TIMEOUT_SECONDS,
    ZAP_GATEWAY_TIMEOUT_SECONDS,
    ZAP_RESPONSE_BYTES_LIMIT,
    ZapDockerTransport,
    build_zap_worker_command,
    zap_docker_resources,
    _canonical_zap_alerts,
)


ROOT = Path(__file__).resolve().parents[2]


def test_nuclei_real_transport_is_fixed_read_only_internal_and_signed_bundle_only() -> None:
    invocation = NucleiFixedInvocation(
        invocation_id="invocation-nuclei-r123",
        effect_id="effect-nuclei-r123",
        profile_id="nuclei-http-header-v1",
        bundle_id="r105-http-header-bundle",
        bundle_revision=2,
        bundle_sha256="a" * 64,
        argv=NUCLEI_FIXED_ARGV,
        envelope_sha256="b" * 64,
        manifest_v2_sha256="c" * 64,
    )
    results = ROOT / ".tmp" / "r123-transport-test" / "nuclei-results.jsonl"
    resources = nuclei_docker_resources(invocation.invocation_id)

    command = build_nuclei_worker_command(
        ROOT,
        invocation=invocation,
        network=resources.worker_network,
        results_path=results,
    )

    rendered = " ".join(command)
    assert command[:3] == ("docker", "run", "--name")
    assert f"--network {resources.worker_network}" in rendered
    assert command[3] == resources.worker
    assert f"redagent.invocation={invocation.invocation_id}" in command
    assert "--read-only" in command and "--cap-drop ALL" in rendered
    assert "no-new-privileges" in rendered
    assert "config/trust/r105-nuclei-user.crt" in rendered.replace("\\", "/")
    assert "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml" in rendered.replace("\\", "/")
    assert command[-len(NUCLEI_FIXED_ARGV) :] == NUCLEI_FIXED_ARGV
    assert all(value not in command for value in ("-headless", "-code", "-list", "-update-templates"))

    with pytest.raises(ValueError, match="r123_nuclei_transport_binding_invalid"):
        build_nuclei_worker_command(
            ROOT,
            invocation=replace(invocation, argv=NUCLEI_FIXED_ARGV + ("-headless",)),
            network=resources.worker_network,
            results_path=results,
        )


def test_zap_real_transport_is_fixed_read_only_internal_and_passive_only() -> None:
    invocation = ZapFixedInvocation(
        invocation_id="invocation-zap-r123",
        effect_id="effect-zap-r123",
        profile_id="zap-passive-v1",
        allowed_paths=("/passive/missing-header",),
        argv=("/zap/zap.sh", "-cmd", "-autorun", "/run/redagent/r123-zap-passive.yaml"),
        envelope_sha256="b" * 64,
        manifest_v2_sha256="c" * 64,
    )
    runtime = ROOT / ".tmp" / "r123-transport-test" / "zap"
    resources = zap_docker_resources(invocation.invocation_id)

    command = build_zap_worker_command(
        ROOT,
        invocation=invocation,
        network=resources.worker_network,
        runtime=runtime,
    )

    rendered = " ".join(command)
    assert command[:3] == ("docker", "run", "--name")
    assert f"--network {resources.worker_network}" in rendered
    assert command[3] == resources.worker
    assert f"redagent.invocation={invocation.invocation_id}" in command
    assert "--read-only" in command and "--cap-drop ALL" in rendered
    assert "no-new-privileges" in rendered
    assert "config/r123-zap-passive.yaml" in rendered.replace("\\", "/")
    entrypoint = command.index("--entrypoint")
    assert command[entrypoint + 1] == invocation.argv[0]
    assert command[-3:] == invocation.argv[1:]
    assert "activeScan" not in rendered and "-daemon" not in command


def test_r123_transport_timeouts_do_not_exceed_the_signed_effect_budget() -> None:
    assert ZAP_EXECUTION_TIMEOUT_SECONDS == 60
    assert ZAP_GATEWAY_TIMEOUT_SECONDS == 60
    assert NUCLEI_EXECUTION_TIMEOUT_SECONDS == 60
    assert ZAP_RESPONSE_BYTES_LIMIT == 1_048_576
    assert NUCLEI_RESPONSE_BYTES_LIMIT == 1_048_576

    zap_plan = yaml.safe_load((ROOT / "config/r123-zap-passive.yaml").read_text())
    assert zap_plan["env"]["parameters"] == {
        "failOnError": True,
        "failOnWarning": False,
        "progressToStdout": False,
    }
    assert not {"failOnError", "failOnWarning", "progressToStdout"}.intersection(
        zap_plan["env"]
    )
    assert zap_plan["parameters"]["timeoutSeconds"] == 60
    assert zap_plan["parameters"]["responseBytesLimit"] == 1_048_576


def test_r123_transports_run_only_current_revision_two_helper_tags() -> None:
    zap_source = (ROOT / "redagent_platform/zap_service/compat_123_transport.py").read_text()
    nuclei_source = (ROOT / "redagent_platform/nuclei_service/compat_123_transport.py").read_text()
    assert "redagent/r104-target:1.0.1" in zap_source
    assert "redagent/r104-gateway:1.0.1" in zap_source
    assert "redagent/r105-target:1.0.1" in nuclei_source
    assert "redagent/r105-gateway:1.0.1" in nuclei_source
    assert "target:1.0.0" not in zap_source + nuclei_source
    assert "gateway:1.0.0" not in zap_source + nuclei_source


def test_nuclei_dynamic_network_is_attested_under_the_certified_policy_identity() -> None:
    transport = NucleiDockerTransport(ROOT)
    now = datetime(2026, 8, 24, tzinfo=timezone.utc)

    binding = transport._trusted_target(
        now,
        "172.31.0.2",
        "redagent-r123-nuclei-target-net-invocation",
    )

    assert binding.network_id == "redagent-r105-gateway-target"
    assert binding.endpoint == "http://redagent-r105-gateway:8080"


def test_nuclei_transport_uses_manifest_revision_for_runtime_receipt() -> None:
    source = (ROOT / "redagent_platform/nuclei_service/compat_123_transport.py").read_text()

    assert "bundle_revision=bundle.revision" in source
    assert "bundle_revision=bundle.bundle_revision" not in source


def test_zap_traditional_json_is_strictly_mapped_before_normalization() -> None:
    mapped = _canonical_zap_alerts([{
        "pluginid": "10021",
        "name": "X-Content-Type-Options Header Missing",
        "riskcode": "1",
        "confidence": "2",
        "instances": [{
            "uri": "http://redagent-r104-gateway:8080/passive/missing-header",
            "method": "GET",
        }],
    }], rule_id="10021")
    assert mapped == [{
        "pluginId": "10021",
        "name": "X-Content-Type-Options Header Missing",
        "risk": "low",
        "confidence": "medium",
        "method": "GET",
        "url": "http://redagent-r104-gateway:8080/passive/missing-header",
    }]

    with pytest.raises(ValueError, match="r123_zap_alert_rule_ambiguous"):
        _canonical_zap_alerts([{
            "pluginId": "10021",
            "pluginid": "10036",
        }], rule_id="10021")


def test_invocation_derived_resources_are_stable_bounded_and_non_interchangeable() -> None:
    zap_first = zap_docker_resources("invocation-zap-first")
    zap_replay = zap_docker_resources("invocation-zap-first")
    zap_other = zap_docker_resources("invocation-zap-other")
    nuclei = nuclei_docker_resources("invocation-zap-first")

    assert zap_first == zap_replay
    assert zap_first != zap_other
    assert zap_first.worker != nuclei.worker
    for resources in (zap_first, zap_other, nuclei):
        assert all(
            1 <= len(value) <= 63
            for value in (
                resources.worker,
                resources.target,
                resources.gateway,
                resources.worker_network,
                resources.target_network,
            )
        )


@pytest.mark.parametrize(
    ("transport", "invocation", "error"),
    (
        (
            ZapDockerTransport(ROOT),
            ZapFixedInvocation(
                invocation_id="invocation-zap-expired",
                effect_id="effect-zap-expired",
                profile_id="zap-passive-v1",
                allowed_paths=("/passive/missing-header",),
                argv=(
                    "/zap/zap.sh",
                    "-cmd",
                    "-autorun",
                    "/run/redagent/r123-zap-passive.yaml",
                ),
                envelope_sha256="b" * 64,
                manifest_v2_sha256="c" * 64,
            ),
            "zap_current_promotion_expired",
        ),
        (
            NucleiDockerTransport(ROOT),
            NucleiFixedInvocation(
                invocation_id="invocation-nuclei-expired",
                effect_id="effect-nuclei-expired",
                profile_id="nuclei-http-header-v1",
                bundle_id="r105-http-header-bundle",
                bundle_revision=2,
                bundle_sha256="6903c7fe75c14c67e3b3fe0d41ab52da9ef9e6790b5062d79fcf68ce7950affc",
                argv=NUCLEI_FIXED_ARGV,
                envelope_sha256="b" * 64,
                manifest_v2_sha256="c" * 64,
            ),
            "nuclei_current_artifact_expired",
        ),
    ),
)
def test_real_transport_denies_expired_promotion_before_any_docker_call(
    monkeypatch,
    transport,
    invocation,
    error,
) -> None:
    docker_calls: list[tuple[str, ...]] = []

    def forbid_docker(*args: str, **kwargs: object):
        docker_calls.append(args)
        raise AssertionError("docker must not run after promotion expiry")

    monkeypatch.setattr(transport, "_docker", forbid_docker)

    with pytest.raises(ValueError, match=error):
        transport._validate_locked_inputs(
            invocation,
            now=datetime(2026, 8, 24, tzinfo=timezone.utc),
        )

    assert docker_calls == []
