from __future__ import annotations

from dataclasses import replace
from copy import deepcopy
from datetime import UTC, datetime, timedelta
import json
from pathlib import Path

from redagent_platform.deployment_release.topology import (
    ProfileKind,
    QualificationLevel,
    ReviewedException,
    build_supported_profile,
    compile_profile,
    validate_profile,
)
from redagent_platform.deployment_release.kubernetes import (
    compile_kubernetes_manifests,
    validate_kubernetes_manifests,
)


NOW = datetime(2026, 7, 12, 8, tzinfo=UTC)
ROOT = Path(__file__).resolve().parents[2]


def test_enterprise_profile_is_deterministic_restricted_and_truthful() -> None:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    validation = validate_profile(profile, now=NOW)
    first = compile_profile(profile)
    second = compile_profile(profile)

    assert validation.accepted and validation.gaps == ()
    assert first == second
    assert first["qualification_level"] == QualificationLevel.STRUCTURALLY_CONFORMANT.value
    assert first["production_qualified"] is False
    bundled = [component for component in first["components"] if component["deployment_mode"] == "bundled"]
    managed = [component for component in first["components"] if component["deployment_mode"] == "operator_managed"]
    assert {component["name"] for component in bundled} == {"api", "worker"}
    assert {component["image"] for component in bundled} == {
        "redagent/r116-app@sha256:d8b1f9b8a60e8dc4820553d36799f18f07268d1f8d53e2a02b20c9f722c9ae19"
    }
    assert all(component["image"] is None and component["operator_contract"] for component in managed)
    assert all(component["service_account"] != "default" for component in first["components"])
    assert all(component["security_context"]["run_as_non_root"] for component in first["components"])
    assert all(component["security_context"]["read_only_root_filesystem"] for component in first["components"])
    assert all(component["security_context"]["capabilities_drop"] == ["ALL"] for component in first["components"])
    assert all(component["security_context"]["seccomp_profile"] == "RuntimeDefault" for component in first["components"])
    assert {policy["direction"] for policy in first["network_policies"]} == {"ingress", "egress"}


def test_single_node_profile_cannot_claim_ha_or_production_qualification() -> None:
    profile = build_supported_profile(ProfileKind.SINGLE_NODE)
    assert profile.availability_claim == "local_private_non_ha"
    assert max(component.replicas for component in profile.components) == 1

    unsafe = replace(profile, availability_claim="multi_zone_ha")
    result = validate_profile(unsafe, now=NOW)
    assert not result.accepted
    assert "single_node_ha_claim_forbidden" in result.gaps


def test_unsafe_workload_and_incomplete_network_policy_fail_closed() -> None:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    component = replace(
        profile.components[0],
        image="registry.invalid/redagent/api:latest",
        service_account="default",
        run_as_non_root=False,
        read_only_root_filesystem=False,
        capabilities_drop=(),
        seccomp_profile="Unconfined",
        readiness_probe=None,
        cpu_request=None,
    )
    unsafe = replace(profile, components=(component, *profile.components[1:]), network_policies=profile.network_policies[:1])
    result = validate_profile(unsafe, now=NOW)
    assert not result.accepted
    assert {
        "digest_pinned_image_required:api",
        "dedicated_service_account_required:api",
        "run_as_non_root_required:api",
        "read_only_root_filesystem_required:api",
        "drop_all_capabilities_required:api",
        "runtime_default_seccomp_required:api",
        "readiness_probe_required:api",
        "resource_request_required:api",
        "default_deny_egress_required",
    }.issubset(result.gaps)


def test_exception_requires_review_scope_expiry_and_cannot_waive_forbidden_controls() -> None:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    expired = ReviewedException(
        exception_id="exception-1",
        component="runner",
        control="read_only_root_filesystem",
        rationale="Owned disposable workspace requires a bounded writable emptyDir.",
        reviewer="security-reviewer",
        approved_at=NOW - timedelta(days=2),
        expires_at=NOW - timedelta(days=1),
    )
    result = validate_profile(replace(profile, exceptions=(expired,)), now=NOW)
    assert not result.accepted
    assert "deployment_exception_expired:exception-1" in result.gaps


def test_kubernetes_compiler_emits_restricted_admitted_namespaces_and_complete_workloads() -> None:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    manifests = compile_kubernetes_manifests(profile, now=NOW)
    result = validate_kubernetes_manifests(manifests)

    assert result.accepted
    namespaces = [item for item in manifests if item["kind"] == "Namespace"]
    assert {item["metadata"]["name"] for item in namespaces} == set(profile.required_namespaces)
    assert all(item["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted" for item in namespaces)
    assert all(item["metadata"]["labels"]["policy.sigstore.dev/include"] == "true" for item in namespaces)
    policies = [item for item in manifests if item["kind"] == "NetworkPolicy"]
    assert len(policies) > len(profile.required_namespaces) * 2
    assert {tuple(item["spec"]["policyTypes"]) for item in policies} == {("Ingress",), ("Egress",)}
    workloads = [item for item in manifests if item["kind"] in {"Deployment", "StatefulSet"}]
    assert {item["metadata"]["name"] for item in workloads} == {"api", "worker"}
    for workload in workloads:
        pod = workload["spec"]["template"]["spec"]
        container = pod["containers"][0]
        assert pod["automountServiceAccountToken"] is False
        assert container["image"].count("@sha256:") == 1
        assert container["securityContext"]["capabilities"]["drop"] == ["ALL"]
        assert container["securityContext"]["seccompProfile"]["type"] == "RuntimeDefault"
        assert container["resources"]["requests"] and container["resources"]["limits"]
    api = next(item for item in workloads if item["metadata"]["name"] == "api")
    api_container = api["spec"]["template"]["spec"]["containers"][0]
    assert api_container["command"] == ["python", "scripts/redagent_control_plane_api.py"]
    assert "--private-cluster-bind" in api_container["args"]
    volume = api["spec"]["template"]["spec"]["volumes"][0]
    volume_source = next(value for key, value in volume.items() if key != "name")
    assert volume_source["secretName"] == "redagent-api-tls"
    assert api_container["startupProbe"]["httpGet"]["path"] == "/health/live"
    assert api_container["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    assert api_container["livenessProbe"]["httpGet"]["path"] == "/health/live"
    assert api["spec"]["template"]["metadata"]["annotations"]["redagent.io/tls-rotation-contract"] == (
        "rollout-on-secret-version-change"
    )
    worker = next(item for item in workloads if item["metadata"]["name"] == "worker")
    worker_container = worker["spec"]["template"]["spec"]["containers"][0]
    assert worker_container["command"] == [
        "python",
        "scripts/redagent_workflow_worker.py",
    ]
    assert worker_container["startupProbe"]["httpGet"]["path"] == "/health/startup"
    assert worker_container["readinessProbe"]["httpGet"]["path"] == "/health/ready"
    assert worker_container["livenessProbe"]["httpGet"]["path"] == "/health/live"
    allow_names = {item["metadata"]["name"] for item in policies if item["metadata"]["name"].startswith("allow-")}
    assert {"allow-api-egress", "allow-api-ingress", "allow-worker-egress", "allow-dns-egress"}.issubset(allow_names)


def test_operator_managed_components_are_contracts_not_fake_workloads() -> None:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    manifests = compile_kubernetes_manifests(profile, now=NOW)

    workload_names = {
        item["metadata"]["name"] for item in manifests if item["kind"] in {"Deployment", "StatefulSet"}
    }
    assert workload_names == {"api", "worker"}
    prerequisites = next(
        item for item in manifests
        if item["kind"] == "ConfigMap" and item["metadata"]["name"] == "redagent-operator-prerequisites"
    )
    contracts = json.loads(prerequisites["data"]["components.json"])
    assert {item["name"] for item in contracts} == {
        "identity", "object-store", "opa", "openbao", "postgresql", "runner", "telemetry", "temporal"
    }
    assert all(item["operator_contract"] for item in contracts)


def test_kubernetes_validator_rejects_unexpected_or_broad_allow_policy() -> None:
    profile = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE)
    manifests = list(compile_kubernetes_manifests(profile, now=NOW))
    broad = deepcopy(next(item for item in manifests if item["metadata"]["name"] == "allow-api-egress"))
    broad["metadata"]["name"] = "allow-any-egress"
    broad["spec"]["podSelector"] = {}
    broad["spec"]["egress"] = [{"to": [{}]}]

    result = validate_kubernetes_manifests(tuple([*manifests, broad]))

    assert not result.accepted
    assert "network_policy_closed_set_required:redagent-control" in result.gaps
    assert "allow_policy_peer_invalid:allow-any-egress" in result.gaps


def test_committed_profiles_match_deterministic_compiler_output() -> None:
    for kind, filename in (
        (ProfileKind.SINGLE_NODE, "r116-single-node.json"),
        (ProfileKind.KUBERNETES_ENTERPRISE, "r116-kubernetes-enterprise.json"),
    ):
        profile = build_supported_profile(kind)
        expected = {"ok": True, **compile_profile(profile)}
        if kind is ProfileKind.KUBERNETES_ENTERPRISE:
            expected["kubernetes_manifests"] = list(compile_kubernetes_manifests(profile, now=NOW))
        observed = json.loads((ROOT / "deploy/profiles" / filename).read_text(encoding="utf-8"))
        assert observed == expected
