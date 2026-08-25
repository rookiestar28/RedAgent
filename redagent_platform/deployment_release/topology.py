"""Canonical supported deployment profiles and fail-closed conformance."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json


class ProfileKind(str, Enum):
    SINGLE_NODE = "single_node"
    KUBERNETES_ENTERPRISE = "kubernetes_enterprise"


class QualificationLevel(str, Enum):
    STRUCTURALLY_CONFORMANT = "structurally_conformant"
    ENVIRONMENT_QUALIFIED = "environment_qualified"
    PRODUCTION_QUALIFIED = "production_qualified"


class DeploymentMode(str, Enum):
    BUNDLED = "bundled"
    OPERATOR_MANAGED = "operator_managed"


@dataclass(frozen=True, kw_only=True)
class ProbeSpec:
    path: str
    initial_delay_seconds: int
    timeout_seconds: int


@dataclass(frozen=True, kw_only=True)
class ComponentSpec:
    name: str
    owner: str
    image: str | None
    deployment_mode: DeploymentMode
    operator_contract: str | None
    replicas: int
    failure_domains: tuple[str, ...]
    service_account: str
    ports: tuple[int, ...]
    persistent_volumes: tuple[str, ...]
    run_as_non_root: bool
    read_only_root_filesystem: bool
    allow_privilege_escalation: bool
    capabilities_drop: tuple[str, ...]
    seccomp_profile: str
    host_docker_socket: bool
    privileged: bool
    startup_probe: ProbeSpec | None
    readiness_probe: ProbeSpec | None
    liveness_probe: ProbeSpec | None
    cpu_request: str | None
    memory_request: str | None
    cpu_limit: str | None
    memory_limit: str | None
    node_class: str
    network_class: str
    command: tuple[str, ...]
    arguments: tuple[str, ...]
    tls_bundle_name: str | None


@dataclass(frozen=True, kw_only=True)
class NetworkPolicySpec:
    direction: str
    default_deny: bool
    allowed_peers: tuple[str, ...]


@dataclass(frozen=True, kw_only=True)
class NetworkFlowSpec:
    source: str
    destination: str
    ports: tuple[int, ...]
    purpose: str


@dataclass(frozen=True, kw_only=True)
class ReviewedException:
    exception_id: str
    component: str
    control: str
    rationale: str
    reviewer: str
    approved_at: datetime
    expires_at: datetime


@dataclass(frozen=True, kw_only=True)
class DeploymentProfile:
    profile_id: str
    kind: ProfileKind
    availability_claim: str
    trusted_edge_tls: bool
    forwarded_headers_trusted_proxy_only: bool
    management_private: bool
    health_private: bool
    metrics_private: bool
    admission_namespaces: tuple[str, ...]
    required_namespaces: tuple[str, ...]
    components: tuple[ComponentSpec, ...]
    network_policies: tuple[NetworkPolicySpec, ...]
    network_flows: tuple[NetworkFlowSpec, ...]
    exceptions: tuple[ReviewedException, ...] = ()
    qualification_level: QualificationLevel = QualificationLevel.STRUCTURALLY_CONFORMANT
    production_qualified: bool = False


@dataclass(frozen=True, kw_only=True)
class ProfileValidation:
    accepted: bool
    gaps: tuple[str, ...]


_BUNDLED_IMAGE = "redagent/r116-app@sha256:d8b1f9b8a60e8dc4820553d36799f18f07268d1f8d53e2a02b20c9f722c9ae19"
_COMPONENTS = (
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
_BUNDLED_COMPONENTS = frozenset({"api", "worker"})
_OPERATOR_CONTRACTS = {
    "postgresql": "CloudNativePG-compatible HA cluster with TLS, WAL archive, and PITR",
    "temporal": "supported Temporal cluster with TLS and persistence configured",
    "openbao": "OpenBao integrated-storage HA cluster with TLS, auto-unseal, and audit devices",
    "object-store": "S3-compatible versioned object store with TLS and immutable retention",
    "identity": "OIDC provider with TLS, issuer pinning, and administrative access controls",
    "opa": "OPA bundle consumer with TLS-authenticated policy distribution and decision logging",
    "telemetry": "OpenTelemetry collector with authenticated TLS ingestion and durable export",
    "runner": "policy-approved isolated runner pool with authenticated TLS control endpoint",
}


def build_supported_profile(kind: ProfileKind) -> DeploymentProfile:
    enterprise = kind is ProfileKind.KUBERNETES_ENTERPRISE
    replicas = 3 if enterprise else 1
    domains = ("zone-a", "zone-b", "zone-c") if enterprise else ("single-host",)
    components = tuple(
        ComponentSpec(
            name=name,
            owner=_owner(name),
            image=_BUNDLED_IMAGE if name in _BUNDLED_COMPONENTS else None,
            deployment_mode=DeploymentMode.BUNDLED if name in _BUNDLED_COMPONENTS else DeploymentMode.OPERATOR_MANAGED,
            operator_contract=_OPERATOR_CONTRACTS.get(name),
            replicas=replicas if name not in {"runner"} else (2 if enterprise else 1),
            failure_domains=domains if name != "runner" else (("runner-zone-a", "runner-zone-b") if enterprise else domains),
            service_account=f"redagent-{name}",
            ports=_ports(name),
            persistent_volumes=_volumes(name),
            run_as_non_root=True,
            read_only_root_filesystem=True,
            allow_privilege_escalation=False,
            capabilities_drop=("ALL",),
            seccomp_profile="RuntimeDefault",
            host_docker_socket=False,
            privileged=False,
            startup_probe=ProbeSpec(
                path="/health/live" if name == "api" else "/health/startup",
                initial_delay_seconds=5,
                timeout_seconds=3,
            ),
            readiness_probe=ProbeSpec(path="/health/ready", initial_delay_seconds=1, timeout_seconds=2),
            liveness_probe=ProbeSpec(path="/health/live", initial_delay_seconds=30, timeout_seconds=2),
            cpu_request="250m",
            memory_request="256Mi",
            cpu_limit="2",
            memory_limit="2Gi",
            node_class="isolated-runner" if name == "runner" else "control-data",
            network_class="runner-target-gated" if name == "runner" else "private-service",
            command=_command(name),
            arguments=_arguments(name),
            tls_bundle_name="redagent-api-tls" if name == "api" else None,
        )
        for name in _COMPONENTS
    )
    required_namespaces = ("redagent-control", "redagent-data", "redagent-runners") if enterprise else ()
    policies = (
        NetworkPolicySpec(direction="ingress", default_deny=True, allowed_peers=("explicit-service-peers",)),
        NetworkPolicySpec(direction="egress", default_deny=True, allowed_peers=("explicit-service-and-target-peers",)),
    )
    return DeploymentProfile(
        profile_id=f"r116-{kind.value}-v1",
        kind=kind,
        availability_claim="multi_zone_ha_contract" if enterprise else "local_private_non_ha",
        trusted_edge_tls=True,
        forwarded_headers_trusted_proxy_only=True,
        management_private=True,
        health_private=True,
        metrics_private=True,
        admission_namespaces=required_namespaces,
        required_namespaces=required_namespaces,
        components=components,
        network_policies=policies,
        network_flows=_network_flows(),
    )


def validate_profile(profile: DeploymentProfile, *, now: datetime) -> ProfileValidation:
    _aware(now)
    gaps: list[str] = []
    if profile.production_qualified or profile.qualification_level is QualificationLevel.PRODUCTION_QUALIFIED:
        gaps.append("r116_production_qualification_forbidden")
    if profile.kind is ProfileKind.SINGLE_NODE and (
        profile.availability_claim != "local_private_non_ha"
        or any(component.replicas != 1 for component in profile.components)
    ):
        gaps.append("single_node_ha_claim_forbidden")
    if profile.kind is ProfileKind.KUBERNETES_ENTERPRISE:
        if set(profile.admission_namespaces) != set(profile.required_namespaces):
            gaps.append("admission_namespace_coverage_required")
        if any(component.replicas < 2 for component in profile.components):
            gaps.append("enterprise_replica_redundancy_required")
        if any(len(set(component.failure_domains)) < 2 for component in profile.components):
            gaps.append("enterprise_failure_domain_spread_required")
    for field_name, enabled in (
        ("trusted_edge_tls_required", profile.trusted_edge_tls),
        ("trusted_forwarded_headers_required", profile.forwarded_headers_trusted_proxy_only),
        ("private_management_required", profile.management_private),
        ("private_health_required", profile.health_private),
        ("private_metrics_required", profile.metrics_private),
    ):
        if not enabled:
            gaps.append(field_name)
    directions = {policy.direction for policy in profile.network_policies if policy.default_deny}
    if "ingress" not in directions:
        gaps.append("default_deny_ingress_required")
    if "egress" not in directions:
        gaps.append("default_deny_egress_required")
    component_names = {component.name for component in profile.components}
    for flow in profile.network_flows:
        if flow.source not in component_names | {"trusted-edge"}:
            gaps.append(f"network_flow_source_invalid:{flow.source}")
        if flow.destination not in component_names:
            gaps.append(f"network_flow_destination_invalid:{flow.destination}")
        if not flow.ports or any(port < 1 or port > 65535 for port in flow.ports):
            gaps.append(f"network_flow_ports_invalid:{flow.source}:{flow.destination}")
    for component in profile.components:
        gaps.extend(_component_gaps(component))
    for exception in profile.exceptions:
        gaps.extend(_exception_gaps(exception, now=now))
    unique = tuple(dict.fromkeys(gaps))
    return ProfileValidation(accepted=not unique, gaps=unique)


def compile_profile(profile: DeploymentProfile) -> dict[str, object]:
    material: dict[str, object] = {
        "schema": "redagent.deployment-profile/v1",
        "profile_id": profile.profile_id,
        "kind": profile.kind.value,
        "availability_claim": profile.availability_claim,
        "qualification_level": profile.qualification_level.value,
        "production_qualified": profile.production_qualified,
        "edge": {
            "tls": profile.trusted_edge_tls,
            "trusted_proxy_forwarded_headers_only": profile.forwarded_headers_trusted_proxy_only,
            "management_private": profile.management_private,
            "health_private": profile.health_private,
            "metrics_private": profile.metrics_private,
        },
        "admission_namespaces": sorted(profile.admission_namespaces),
        "components": [_component_dict(item) for item in sorted(profile.components, key=lambda value: value.name)],
        "network_policies": [
            {"direction": item.direction, "default_deny": item.default_deny, "allowed_peers": sorted(item.allowed_peers)}
            for item in sorted(profile.network_policies, key=lambda value: value.direction)
        ],
        "network_flows": [_normalize(asdict(item)) for item in profile.network_flows],
        "exceptions": [_normalize(asdict(item)) for item in sorted(profile.exceptions, key=lambda value: value.exception_id)],
    }
    material["profile_sha256"] = _digest(material)
    return material


def _component_gaps(component: ComponentSpec) -> list[str]:
    gaps: list[str] = []
    name = component.name
    if component.deployment_mode is DeploymentMode.BUNDLED:
        if not component.image or "@sha256:" not in component.image or len(component.image.rsplit("@sha256:", 1)[-1]) != 64:
            gaps.append(f"digest_pinned_image_required:{name}")
        if component.operator_contract is not None:
            gaps.append(f"bundled_operator_contract_forbidden:{name}")
    elif component.image is not None or not component.operator_contract:
        gaps.append(f"operator_managed_contract_required:{name}")
    if component.service_account == "default" or not component.service_account:
        gaps.append(f"dedicated_service_account_required:{name}")
    if not component.run_as_non_root:
        gaps.append(f"run_as_non_root_required:{name}")
    if not component.read_only_root_filesystem:
        gaps.append(f"read_only_root_filesystem_required:{name}")
    if component.allow_privilege_escalation:
        gaps.append(f"privilege_escalation_forbidden:{name}")
    if component.capabilities_drop != ("ALL",):
        gaps.append(f"drop_all_capabilities_required:{name}")
    if component.seccomp_profile != "RuntimeDefault":
        gaps.append(f"runtime_default_seccomp_required:{name}")
    if component.host_docker_socket or component.privileged:
        gaps.append(f"host_privilege_forbidden:{name}")
    if component.startup_probe is None:
        gaps.append(f"startup_probe_required:{name}")
    if component.readiness_probe is None:
        gaps.append(f"readiness_probe_required:{name}")
    if component.liveness_probe is None:
        gaps.append(f"liveness_probe_required:{name}")
    if not component.cpu_request or not component.memory_request:
        gaps.append(f"resource_request_required:{name}")
    if not component.cpu_limit or not component.memory_limit:
        gaps.append(f"resource_limit_required:{name}")
    if name == "runner" and (
        component.node_class != "isolated-runner" or component.network_class != "runner-target-gated"
    ):
        gaps.append("runner_isolation_class_required:runner")
    return gaps


def _exception_gaps(exception: ReviewedException, *, now: datetime) -> list[str]:
    gaps: list[str] = []
    if not all((exception.exception_id, exception.component, exception.control, exception.rationale, exception.reviewer)):
        gaps.append(f"deployment_exception_incomplete:{exception.exception_id}")
    if exception.approved_at.tzinfo is None or exception.expires_at.tzinfo is None:
        gaps.append(f"deployment_exception_time_invalid:{exception.exception_id}")
    elif not exception.approved_at < exception.expires_at or now >= exception.expires_at:
        gaps.append(f"deployment_exception_expired:{exception.exception_id}")
    if exception.control in {"privileged", "host_docker_socket", "public_management", "production_qualification"}:
        gaps.append(f"deployment_exception_control_forbidden:{exception.exception_id}")
    return gaps


def _component_dict(component: ComponentSpec) -> dict[str, object]:
    return {
        "name": component.name,
        "owner": component.owner,
        "image": component.image,
        "deployment_mode": component.deployment_mode.value,
        "operator_contract": component.operator_contract,
        "replicas": component.replicas,
        "failure_domains": sorted(component.failure_domains),
        "service_account": component.service_account,
        "ports": list(component.ports),
        "persistent_volumes": list(component.persistent_volumes),
        "security_context": {
            "run_as_non_root": component.run_as_non_root,
            "read_only_root_filesystem": component.read_only_root_filesystem,
            "allow_privilege_escalation": component.allow_privilege_escalation,
            "capabilities_drop": list(component.capabilities_drop),
            "seccomp_profile": component.seccomp_profile,
            "host_docker_socket": component.host_docker_socket,
            "privileged": component.privileged,
        },
        "probes": {
            "startup": _normalize(asdict(component.startup_probe)) if component.startup_probe else None,
            "readiness": _normalize(asdict(component.readiness_probe)) if component.readiness_probe else None,
            "liveness": _normalize(asdict(component.liveness_probe)) if component.liveness_probe else None,
        },
        "resources": {
            "requests": {"cpu": component.cpu_request, "memory": component.memory_request},
            "limits": {"cpu": component.cpu_limit, "memory": component.memory_limit},
        },
        "node_class": component.node_class,
        "network_class": component.network_class,
        "command": list(component.command),
        "arguments": list(component.arguments),
        "tls_bundle_name": component.tls_bundle_name,
    }


def _owner(name: str) -> str:
    if name in {"postgresql", "temporal", "openbao", "object-store", "identity"}:
        return "platform-data"
    if name == "runner":
        return "execution-security"
    return "platform-control"


def _ports(name: str) -> tuple[int, ...]:
    return {
        "api": (8443,), "worker": (9090,), "postgresql": (5432,), "temporal": (7233,),
        "openbao": (8200, 8201), "object-store": (9000,), "identity": (8080,), "opa": (8181,),
        "telemetry": (4317, 4318), "runner": (9443,),
    }[name]


def _volumes(name: str) -> tuple[str, ...]:
    return (f"{name}-data",) if name in {"postgresql", "temporal", "openbao", "object-store", "identity"} else ()


def _command(name: str) -> tuple[str, ...]:
    if name == "api":
        return ("python", "scripts/redagent_control_plane_api.py")
    if name == "worker":
        return ("python", "scripts/redagent_workflow_worker.py")
    return ()


def _arguments(name: str) -> tuple[str, ...]:
    if name != "api":
        return ()
    return (
        "--host",
        "0.0.0.0",
        "--port",
        "8443",
        "--private-cluster-bind",
        "--tls-cert-file",
        "/var/run/redagent/tls/tls.crt",
        "--tls-key-file",
        "/var/run/redagent/tls/tls.key",
    )


def _network_flows() -> tuple[NetworkFlowSpec, ...]:
    raw = (
        ("trusted-edge", "api", (8443,), "trusted ingress to the control-plane API"),
        ("api", "identity", (8080,), "OIDC discovery and token validation"),
        ("api", "opa", (8181,), "authorization decisions"),
        ("api", "postgresql", (5432,), "control-plane persistence"),
        ("api", "temporal", (7233,), "workflow submission and status"),
        ("api", "openbao", (8200,), "bounded secret references"),
        ("api", "object-store", (9000,), "evidence object access"),
        ("worker", "postgresql", (5432,), "workflow state persistence"),
        ("worker", "temporal", (7233,), "workflow task polling"),
        ("worker", "openbao", (8200,), "bounded secret references"),
        ("worker", "opa", (8181,), "execution policy decisions"),
        ("worker", "runner", (9443,), "authorized runner dispatch"),
        ("api", "telemetry", (4317, 4318), "API telemetry export"),
        ("worker", "telemetry", (4317, 4318), "worker telemetry export"),
        ("runner", "telemetry", (4317, 4318), "runner telemetry export"),
    )
    return tuple(NetworkFlowSpec(source=source, destination=destination, ports=ports, purpose=purpose)
                 for source, destination, ports, purpose in raw)


def _normalize(value: object) -> object:
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _normalize(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(item) for item in value]
    return value


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("deployment_time_timezone_required")
