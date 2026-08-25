"""Deterministic hardened Kubernetes resource compiler and validator."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from redagent_platform.deployment_release.topology import (
    ComponentSpec,
    DeploymentMode,
    DeploymentProfile,
    NetworkFlowSpec,
    ProfileKind,
    build_supported_profile,
    validate_profile,
)


Manifest = dict[str, Any]


@dataclass(frozen=True, kw_only=True)
class KubernetesManifestValidation:
    accepted: bool
    gaps: tuple[str, ...]


def compile_kubernetes_manifests(profile: DeploymentProfile, *, now: datetime) -> tuple[Manifest, ...]:
    if profile.kind is not ProfileKind.KUBERNETES_ENTERPRISE:
        raise ValueError("kubernetes_enterprise_profile_required")
    validation = validate_profile(profile, now=now)
    if not validation.accepted:
        raise ValueError("kubernetes_profile_invalid:" + ",".join(validation.gaps))
    resources: list[Manifest] = []
    for namespace in sorted(profile.required_namespaces):
        resources.extend(
            (
                _namespace(namespace),
                _default_deny(namespace, "Ingress"),
                _default_deny(namespace, "Egress"),
                _allow_dns(namespace),
            )
        )
    resources.append(_operator_prerequisites(profile))
    for component in sorted(profile.components, key=lambda item: item.name):
        resources.extend(_flow_policies(component, profile.network_flows))
        if component.deployment_mode is not DeploymentMode.BUNDLED:
            continue
        namespace = _namespace_for(component.name)
        resources.extend(
            (
                _service_account(component, namespace),
                _workload(component, namespace),
                _service(component, namespace),
                _pdb(component, namespace),
            )
        )
    return tuple(resources)


def validate_kubernetes_manifests(manifests: tuple[Manifest, ...]) -> KubernetesManifestValidation:
    gaps: list[str] = []
    namespaces: set[str] = set()
    directions: dict[str, set[str]] = {}
    service_accounts = {
        (str(item.get("metadata", {}).get("namespace", "")), str(item.get("metadata", {}).get("name", "")))
        for item in manifests
        if item.get("kind") == "ServiceAccount"
    }
    observed_policy_names: dict[str, set[str]] = {}
    for resource in manifests:
        kind = resource.get("kind")
        metadata = resource.get("metadata", {})
        name = metadata.get("name", "unknown")
        namespace = metadata.get("namespace")
        if kind == "Namespace":
            namespaces.add(name)
            labels = metadata.get("labels", {})
            if labels.get("pod-security.kubernetes.io/enforce") != "restricted":
                gaps.append(f"restricted_namespace_label_required:{name}")
            if labels.get("policy.sigstore.dev/include") != "true":
                gaps.append(f"signature_admission_namespace_required:{name}")
        elif kind == "NetworkPolicy":
            policy_types = resource.get("spec", {}).get("policyTypes", [])
            if namespace and len(policy_types) == 1:
                directions.setdefault(namespace, set()).add(policy_types[0])
                observed_policy_names.setdefault(namespace, set()).add(str(name))
            gaps.extend(_network_policy_gaps(resource))
        elif kind == "ServiceAccount":
            if resource.get("automountServiceAccountToken") is not False:
                gaps.append(f"service_account_automount_forbidden:{name}")
        elif kind in {"Deployment", "StatefulSet"}:
            gaps.extend(_workload_gaps(resource, service_accounts))
    for namespace in namespaces:
        if directions.get(namespace) != {"Ingress", "Egress"}:
            gaps.append(f"complete_default_deny_required:{namespace}")
        if not any(
            item.get("kind") == "NetworkPolicy"
            and item.get("metadata", {}).get("namespace") == namespace
            and item.get("metadata", {}).get("name") == "allow-dns-egress"
            for item in manifests
        ):
            gaps.append(f"dns_egress_policy_required:{namespace}")
        expected_names = _expected_policy_names(namespace)
        if observed_policy_names.get(namespace, set()) != expected_names:
            gaps.append(f"network_policy_closed_set_required:{namespace}")
    for component in ("api", "worker"):
        for direction in ("ingress", "egress"):
            name = f"allow-{component}-{direction}"
            if direction == "ingress" and component == "worker":
                continue
            if not any(item.get("kind") == "NetworkPolicy" and item.get("metadata", {}).get("name") == name for item in manifests):
                gaps.append(f"component_flow_policy_required:{component}:{direction}")
    unique = tuple(dict.fromkeys(gaps))
    return KubernetesManifestValidation(accepted=not unique, gaps=unique)


def _expected_policy_names(namespace: str) -> set[str]:
    component_names = {
        name
        for name in (
            "api",
            "worker",
            "postgresql",
            "temporal",
            "openbao",
            "object-store",
            "identity",
            "opa",
            "telemetry",
            "runner",
        )
        if _namespace_for(name) == namespace
    }
    flows = build_supported_profile(ProfileKind.KUBERNETES_ENTERPRISE).network_flows
    names = {"default-deny-ingress", "default-deny-egress", "allow-dns-egress"}
    for component in component_names:
        if any(flow.destination == component for flow in flows):
            names.add(f"allow-{component}-ingress")
        if any(flow.source == component for flow in flows):
            names.add(f"allow-{component}-egress")
    return names


def _network_policy_gaps(resource: Manifest) -> list[str]:
    gaps: list[str] = []
    metadata = resource.get("metadata", {})
    name = str(metadata.get("name", "unknown"))
    spec = resource.get("spec", {})
    policy_types = spec.get("policyTypes", [])
    if len(policy_types) != 1 or policy_types[0] not in {"Ingress", "Egress"}:
        return [f"network_policy_direction_invalid:{name}"]
    direction = str(policy_types[0])
    field = direction.lower()
    rules = spec.get(field)
    if name.startswith("default-deny-"):
        if spec.get("podSelector") != {} or rules != []:
            gaps.append(f"default_deny_policy_invalid:{name}")
        return gaps
    if not isinstance(rules, list) or not rules:
        gaps.append(f"allow_policy_rules_required:{name}")
        return gaps
    if name == "allow-dns-egress":
        if direction != "Egress" or spec.get("podSelector") != {}:
            gaps.append(f"dns_policy_scope_invalid:{name}")
        return gaps
    component = name.removeprefix("allow-").removesuffix(f"-{field}")
    if spec.get("podSelector") != {"matchLabels": {"app.kubernetes.io/name": component}}:
        gaps.append(f"allow_policy_selector_invalid:{name}")
    peer_field = "from" if direction == "Ingress" else "to"
    for rule in rules:
        peers = rule.get(peer_field)
        ports = rule.get("ports")
        if not isinstance(peers, list) or not peers or any(not peer or "ipBlock" in peer for peer in peers):
            gaps.append(f"allow_policy_peer_invalid:{name}")
        if not isinstance(ports, list) or not ports or any(
            port.get("protocol") != "TCP" or not isinstance(port.get("port"), int) for port in ports
        ):
            gaps.append(f"allow_policy_port_invalid:{name}")
    return gaps


def _namespace(name: str) -> Manifest:
    return {
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": name,
            "labels": {
                "pod-security.kubernetes.io/enforce": "restricted",
                "pod-security.kubernetes.io/enforce-version": "latest",
                "policy.sigstore.dev/include": "true",
                "redagent.io/profile": "r116-enterprise",
            },
        },
    }


def _default_deny(namespace: str, direction: str) -> Manifest:
    field = direction.lower()
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": f"default-deny-{field}", "namespace": namespace},
        "spec": {"podSelector": {}, "policyTypes": [direction], field: []},
    }


def _allow_dns(namespace: str) -> Manifest:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": "allow-dns-egress", "namespace": namespace},
        "spec": {
            "podSelector": {},
            "policyTypes": ["Egress"],
            "egress": [
                {
                    "to": [
                        {
                            "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": "kube-system"}},
                            "podSelector": {"matchLabels": {"k8s-app": "kube-dns"}},
                        }
                    ],
                    "ports": [
                        {"protocol": "UDP", "port": 53},
                        {"protocol": "TCP", "port": 53},
                    ],
                }
            ],
        },
    }


def _flow_policies(component: ComponentSpec, flows: tuple[NetworkFlowSpec, ...]) -> tuple[Manifest, ...]:
    policies: list[Manifest] = []
    incoming = tuple(flow for flow in flows if flow.destination == component.name)
    outgoing = tuple(flow for flow in flows if flow.source == component.name)
    if incoming:
        policies.append(_allow_component_direction(component, "Ingress", incoming))
    if outgoing:
        policies.append(_allow_component_direction(component, "Egress", outgoing))
    return tuple(policies)


def _allow_component_direction(
    component: ComponentSpec,
    direction: str,
    flows: tuple[NetworkFlowSpec, ...],
) -> Manifest:
    field = direction.lower()
    rules: list[Manifest] = []
    for flow in flows:
        peer_name = flow.source if direction == "Ingress" else flow.destination
        peer = _network_peer(peer_name)
        rules.append(
            {
                "from" if direction == "Ingress" else "to": [peer],
                "ports": [{"protocol": "TCP", "port": port} for port in flow.ports],
            }
        )
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": f"allow-{component.name}-{field}", "namespace": _namespace_for(component.name)},
        "spec": {
            "podSelector": {"matchLabels": {"app.kubernetes.io/name": component.name}},
            "policyTypes": [direction],
            field: rules,
        },
    }


def _network_peer(name: str) -> Manifest:
    if name == "trusted-edge":
        return {"namespaceSelector": {"matchLabels": {"redagent.io/trusted-edge": "true"}}}
    return {
        "namespaceSelector": {"matchLabels": {"kubernetes.io/metadata.name": _namespace_for(name)}},
        "podSelector": {"matchLabels": {"app.kubernetes.io/name": name}},
    }


def _operator_prerequisites(profile: DeploymentProfile) -> Manifest:
    import json

    contracts = [
        {
            "name": component.name,
            "namespace": _namespace_for(component.name),
            "service": component.name,
            "ports": list(component.ports),
            "replicas": component.replicas,
            "failure_domains": list(component.failure_domains),
            "operator_contract": component.operator_contract,
            "required_pod_label": f"app.kubernetes.io/name={component.name}",
        }
        for component in sorted(profile.components, key=lambda item: item.name)
        if component.deployment_mode is DeploymentMode.OPERATOR_MANAGED
    ]
    return {
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {"name": "redagent-operator-prerequisites", "namespace": "redagent-control"},
        "data": {"components.json": json.dumps(contracts, sort_keys=True, separators=(",", ":"))},
    }


def _service_account(component: ComponentSpec, namespace: str) -> Manifest:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": component.service_account, "namespace": namespace},
        "automountServiceAccountToken": False,
    }


def _workload(component: ComponentSpec, namespace: str) -> Manifest:
    if component.image is None:
        raise ValueError(f"bundled_component_image_required:{component.name}")
    kind = "StatefulSet" if component.persistent_volumes else "Deployment"
    container: Manifest = {
        "name": component.name,
        "image": component.image,
        "imagePullPolicy": "IfNotPresent",
        "ports": [{"containerPort": port, "protocol": "TCP"} for port in component.ports],
        "securityContext": {
            "runAsNonRoot": component.run_as_non_root,
            "readOnlyRootFilesystem": component.read_only_root_filesystem,
            "allowPrivilegeEscalation": component.allow_privilege_escalation,
            "privileged": component.privileged,
            "capabilities": {"drop": list(component.capabilities_drop)},
            "seccompProfile": {"type": component.seccomp_profile},
        },
        "resources": {
            "requests": {"cpu": component.cpu_request, "memory": component.memory_request},
            "limits": {"cpu": component.cpu_limit, "memory": component.memory_limit},
        },
        "startupProbe": _probe(component, "startup", component.startup_probe.timeout_seconds),
        "readinessProbe": _probe(component, "readiness", component.readiness_probe.timeout_seconds),
        "livenessProbe": _probe(component, "liveness", component.liveness_probe.timeout_seconds),
    }
    if component.command:
        container["command"] = list(component.command)
    if component.arguments:
        container["args"] = list(component.arguments)
    if component.tls_bundle_name:
        container.setdefault("volumeMounts", []).append(
            {"name": "service-tls", "mountPath": "/var/run/redagent/tls", "readOnly": True}
        )
    if component.persistent_volumes:
        container["volumeMounts"] = [
            {"name": volume, "mountPath": f"/var/lib/redagent/{component.name}/{index}"}
            for index, volume in enumerate(component.persistent_volumes)
        ]
    pod_spec: Manifest = {
        "serviceAccountName": component.service_account,
        "automountServiceAccountToken": False,
        "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
        "containers": [container],
        "nodeSelector": {"redagent.io/node-class": component.node_class},
        "topologySpreadConstraints": [
            {
                "maxSkew": 1,
                "topologyKey": "topology.kubernetes.io/zone",
                "whenUnsatisfiable": "DoNotSchedule",
                "labelSelector": {"matchLabels": {"app.kubernetes.io/name": component.name}},
            }
        ],
    }
    if component.tls_bundle_name:
        pod_spec["volumes"] = [
            {"name": "service-tls", "secret": {"secretName": component.tls_bundle_name, "optional": False}}
        ]
    spec: Manifest = {
        "replicas": component.replicas,
        "selector": {"matchLabels": {"app.kubernetes.io/name": component.name}},
        "template": {
            "metadata": {
                "labels": {"app.kubernetes.io/name": component.name},
                **(
                    {"annotations": {"redagent.io/tls-rotation-contract": "rollout-on-secret-version-change"}}
                    if component.tls_bundle_name
                    else {}
                ),
            },
            "spec": pod_spec,
        },
    }
    if kind == "StatefulSet":
        spec["serviceName"] = component.name
        spec["volumeClaimTemplates"] = [
            {
                "metadata": {"name": volume},
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "resources": {"requests": {"storage": "20Gi"}},
                },
            }
            for volume in component.persistent_volumes
        ]
    return {
        "apiVersion": "apps/v1",
        "kind": kind,
        "metadata": {"name": component.name, "namespace": namespace},
        "spec": spec,
    }


def _service(component: ComponentSpec, namespace: str) -> Manifest:
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {"name": component.name, "namespace": namespace},
        "spec": {
            "type": "ClusterIP",
            "selector": {"app.kubernetes.io/name": component.name},
            "ports": [{"name": f"tcp-{port}", "port": port, "targetPort": port} for port in component.ports],
        },
    }


def _pdb(component: ComponentSpec, namespace: str) -> Manifest:
    return {
        "apiVersion": "policy/v1",
        "kind": "PodDisruptionBudget",
        "metadata": {"name": component.name, "namespace": namespace},
        "spec": {
            "maxUnavailable": 1,
            "selector": {"matchLabels": {"app.kubernetes.io/name": component.name}},
        },
    }


def _probe(component: ComponentSpec, purpose: str, timeout_seconds: int) -> Manifest:
    probe_spec = getattr(component, f"{purpose}_probe")
    probe: Manifest = {
        "tcpSocket": {"port": component.ports[0]},
        "periodSeconds": 10,
        "timeoutSeconds": timeout_seconds,
        "failureThreshold": 30 if purpose == "startup" else (3 if purpose == "readiness" else 6),
    }
    if component.name in {"api", "worker"}:
        probe.pop("tcpSocket")
        probe["httpGet"] = {
            "path": probe_spec.path,
            "port": component.ports[0],
            "scheme": "HTTPS" if component.name == "api" else "HTTP",
        }
    return probe


def _namespace_for(component: str) -> str:
    if component == "runner":
        return "redagent-runners"
    if component in {"postgresql", "temporal", "openbao", "object-store", "identity"}:
        return "redagent-data"
    return "redagent-control"


def _workload_gaps(resource: Manifest, service_accounts: set[tuple[str, str]]) -> list[str]:
    gaps: list[str] = []
    metadata = resource.get("metadata", {})
    name = str(metadata.get("name", "unknown"))
    namespace = str(metadata.get("namespace", ""))
    pod = resource.get("spec", {}).get("template", {}).get("spec", {})
    account = str(pod.get("serviceAccountName", ""))
    if (namespace, account) not in service_accounts or account == "default":
        gaps.append(f"workload_service_account_invalid:{name}")
    if pod.get("automountServiceAccountToken") is not False:
        gaps.append(f"workload_token_automount_forbidden:{name}")
    containers = pod.get("containers", [])
    if len(containers) != 1:
        gaps.append(f"single_reviewed_container_required:{name}")
        return gaps
    container = containers[0]
    security = container.get("securityContext", {})
    if "@sha256:" not in str(container.get("image", "")):
        gaps.append(f"workload_digest_required:{name}")
    if security.get("runAsNonRoot") is not True or security.get("readOnlyRootFilesystem") is not True:
        gaps.append(f"workload_restricted_context_required:{name}")
    if security.get("allowPrivilegeEscalation") is not False or security.get("privileged") is not False:
        gaps.append(f"workload_privilege_forbidden:{name}")
    if security.get("capabilities", {}).get("drop") != ["ALL"]:
        gaps.append(f"workload_drop_all_required:{name}")
    if security.get("seccompProfile", {}).get("type") != "RuntimeDefault":
        gaps.append(f"workload_seccomp_required:{name}")
    if not all(container.get(key) for key in ("startupProbe", "readinessProbe", "livenessProbe", "resources")):
        gaps.append(f"workload_probe_resource_required:{name}")
    if name == "api" and resource.get("spec", {}).get("template", {}).get("metadata", {}).get("annotations", {}).get(
        "redagent.io/tls-rotation-contract"
    ) != "rollout-on-secret-version-change":
        gaps.append("api_tls_rotation_contract_required")
    return gaps
