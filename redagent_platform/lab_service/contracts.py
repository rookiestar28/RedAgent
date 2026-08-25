"""Closed local-lab identity, attestation, lease, and dual enforcement contracts."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import ipaddress
import json
import re
from urllib.parse import urlsplit


LAB_SCHEMA = "redagent.local-lab/v1"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_NETWORK = "redagent-r103-lab"


class FixtureKind(str, Enum):
    WEB = "web"
    API = "api"
    NETWORK = "network"
    IDENTITY = "identity"
    ARTIFACT = "artifact"


class TestClass(str, Enum):
    HEALTH = "health"
    HAPPY_PATH = "happy_path"
    AUTHORIZATION = "authorization"
    FINDING_MAPPING = "finding_mapping"
    EVIDENCE = "evidence"
    REDACTION = "redaction"
    CANCELLATION = "cancellation"
    OUTAGE = "outage"
    BACKUP_RESTORE = "backup_restore"
    MIGRATION = "migration"


@dataclass(frozen=True, kw_only=True)
class LabBundleManifest:
    schema: str
    bundle_id: str
    revision: int
    fixture_digest: str
    seed_manifest_sha256: str
    fixture_kinds: tuple[FixtureKind, ...]
    allowed_test_classes: tuple[TestClass, ...]
    network_id: str
    non_production: bool
    created_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        if self.schema != LAB_SCHEMA:
            raise ValueError("lab_bundle_schema_invalid")
        _identifier("lab_bundle_id", self.bundle_id)
        if not isinstance(self.revision, int) or isinstance(self.revision, bool) or self.revision < 1:
            raise ValueError("lab_bundle_revision_invalid")
        _digest("lab_bundle_fixture_digest", self.fixture_digest)
        _sha("lab_bundle_seed_manifest", self.seed_manifest_sha256)
        _closed_unique("lab_bundle_fixture_kinds", self.fixture_kinds, FixtureKind)
        _closed_unique("lab_bundle_test_classes", self.allowed_test_classes, TestClass)
        if self.network_id != _NETWORK:
            raise ValueError("lab_bundle_network_invalid")
        if self.non_production is not True:
            raise ValueError("lab_bundle_non_production_required")
        _window("lab_bundle", self.created_at, self.expires_at)

    @property
    def canonical_sha256(self) -> str:
        return _canonical(self)


@dataclass(frozen=True, kw_only=True)
class LabTargetAttestation:
    attestation_id: str
    tenant_id: str
    target_id: str
    bundle_id: str
    bundle_digest: str
    fixture_kind: FixtureKind
    endpoint: str
    network_id: str
    allowed_test_classes: tuple[TestClass, ...]
    expected_finding_manifest_sha256: str
    non_production: bool
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for name, value in (
            ("lab_attestation_id", self.attestation_id), ("lab_tenant_id", self.tenant_id),
            ("lab_target_id", self.target_id), ("lab_bundle_id", self.bundle_id),
        ):
            _identifier(name, value)
        _digest("lab_target_bundle_digest", self.bundle_digest)
        if not isinstance(self.fixture_kind, FixtureKind):
            raise ValueError("lab_target_fixture_kind_invalid")
        _endpoint(self.endpoint, self.network_id)
        _closed_unique("lab_target_test_classes", self.allowed_test_classes, TestClass)
        _sha("lab_target_expected_finding_manifest", self.expected_finding_manifest_sha256)
        if self.non_production is not True:
            raise ValueError("lab_target_non_production_required")
        _window("lab_target_attestation", self.issued_at, self.expires_at)

    @property
    def canonical_sha256(self) -> str:
        return _canonical(self)


@dataclass(frozen=True, kw_only=True)
class LabTargetLease:
    lease_id: str
    tenant_id: str
    target_id: str
    attestation_sha256: str
    runner_id: str
    test_class: TestClass
    endpoint: str
    issued_at: datetime
    expires_at: datetime
    policy_reference: str
    roe_version_id: str

    def __post_init__(self) -> None:
        for name, value in (
            ("lab_lease_id", self.lease_id), ("lab_tenant_id", self.tenant_id),
            ("lab_target_id", self.target_id), ("lab_runner_id", self.runner_id),
            ("lab_policy_reference", self.policy_reference),
            ("lab_roe_version_id", self.roe_version_id),
        ):
            _identifier(name, value)
        _sha("lab_target_attestation", self.attestation_sha256)
        if not isinstance(self.test_class, TestClass):
            raise ValueError("lab_target_test_class_invalid")
        _endpoint(self.endpoint, _NETWORK)
        _window("lab_target_lease", self.issued_at, self.expires_at)
        if (self.expires_at - self.issued_at).total_seconds() > 900:
            raise ValueError("lab_target_lease_ttl_exceeded")


@dataclass(frozen=True, kw_only=True)
class TargetAccessRequest:
    tenant_id: str
    target_id: str
    runner_id: str
    test_class: TestClass
    endpoint: str
    policy_reference: str
    roe_version_id: str
    requested_at: datetime


@dataclass(frozen=True, kw_only=True)
class TargetAccessDecision:
    allowed: bool
    reason_code: str
    attestation_id: str
    lease_id: str


def authorize_target_access(
    *, manifest: LabBundleManifest, attestation: LabTargetAttestation,
    lease: LabTargetLease, request: TargetAccessRequest,
) -> TargetAccessDecision:
    _aware("lab_target_request_time", request.requested_at)
    if not (manifest.created_at <= request.requested_at < manifest.expires_at):
        raise ValueError("lab_bundle_expired")
    if not (attestation.issued_at <= request.requested_at < attestation.expires_at):
        raise ValueError("lab_target_attestation_expired")
    if not (lease.issued_at <= request.requested_at < lease.expires_at):
        raise ValueError("lab_target_lease_expired")
    if manifest.bundle_id != attestation.bundle_id or manifest.fixture_digest != attestation.bundle_digest:
        raise ValueError("lab_target_bundle_mismatch")
    if lease.attestation_sha256 != attestation.canonical_sha256:
        raise ValueError("lab_target_attestation_mismatch")
    if request.test_class not in manifest.allowed_test_classes or request.test_class not in attestation.allowed_test_classes:
        raise ValueError("lab_target_test_class_denied")
    expected = (
        attestation.tenant_id, attestation.target_id, lease.runner_id, lease.test_class,
        attestation.endpoint, lease.policy_reference, lease.roe_version_id,
    )
    observed = (
        request.tenant_id, request.target_id, request.runner_id, request.test_class,
        request.endpoint, request.policy_reference, request.roe_version_id,
    )
    if observed != expected or lease.tenant_id != attestation.tenant_id or lease.target_id != attestation.target_id:
        raise ValueError("lab_target_request_binding_mismatch")
    if lease.endpoint != attestation.endpoint:
        raise ValueError("lab_target_lease_endpoint_mismatch")
    return TargetAccessDecision(
        allowed=True, reason_code="local_lab_target_authorized",
        attestation_id=attestation.attestation_id, lease_id=lease.lease_id,
    )


def enforce_runner_target(
    *, manifest: LabBundleManifest, attestation: LabTargetAttestation,
    lease: LabTargetLease, observed_endpoint: str, observed_ip: str, occurred_at: datetime,
) -> TargetAccessDecision:
    _aware("runner_lab_enforcement_time", occurred_at)
    authorize_target_access(
        manifest=manifest, attestation=attestation, lease=lease,
        request=TargetAccessRequest(
            tenant_id=lease.tenant_id, target_id=lease.target_id, runner_id=lease.runner_id,
            test_class=lease.test_class, endpoint=lease.endpoint,
            policy_reference=lease.policy_reference, roe_version_id=lease.roe_version_id,
            requested_at=occurred_at,
        ),
    )
    if observed_endpoint != lease.endpoint:
        raise ValueError("runner_lab_endpoint_mismatch")
    parsed = urlsplit(observed_endpoint)
    try:
        observed = ipaddress.ip_address(observed_ip)
    except ValueError as exc:
        raise ValueError("runner_lab_ip_invalid") from exc
    if parsed.hostname == "localhost":
        if not observed.is_loopback:
            raise ValueError("runner_lab_ip_mismatch")
    else:
        try:
            expected = ipaddress.ip_address(str(parsed.hostname))
        except ValueError as exc:
            raise ValueError("runner_lab_hostname_forbidden") from exc
        if observed != expected:
            raise ValueError("runner_lab_ip_mismatch")
    if not (observed.is_loopback or observed.is_private) or observed.is_unspecified or observed.is_multicast:
        raise ValueError("runner_lab_ip_forbidden")
    return TargetAccessDecision(
        allowed=True, reason_code="runner_local_lab_target_enforced",
        attestation_id=attestation.attestation_id, lease_id=lease.lease_id,
    )


def _endpoint(value: object, network_id: str) -> None:
    if not isinstance(value, str) or len(value) > 200:
        raise ValueError("lab_target_endpoint_invalid")
    parsed = urlsplit(value)
    if not parsed.hostname:
        raise ValueError("lab_target_endpoint_invalid")
    if parsed.hostname != "localhost":
        try:
            candidate = ipaddress.ip_address(parsed.hostname)
        except ValueError as exc:
            raise ValueError("lab_target_endpoint_local_required") from exc
        if not (candidate.is_loopback or candidate.is_private) or candidate.is_unspecified or candidate.is_multicast:
            raise ValueError("lab_target_endpoint_local_required")
    if parsed.scheme != "http" or parsed.port is None:
        raise ValueError("lab_target_endpoint_invalid")
    if parsed.username or parsed.password or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("lab_target_endpoint_invalid")
    if network_id != _NETWORK:
        raise ValueError("lab_target_network_invalid")
    if parsed.hostname == "localhost":
        return


def _canonical(value: object) -> str:
    payload = asdict(value)
    for key, item in tuple(payload.items()):
        if isinstance(item, datetime):
            payload[key] = item.isoformat()
        elif isinstance(item, Enum):
            payload[key] = item.value
        elif isinstance(item, tuple):
            payload[key] = [entry.value if isinstance(entry, Enum) else entry for entry in item]
    return hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _closed_unique(name: str, values: tuple[object, ...], enum_type: type[Enum]) -> None:
    if not values or len(values) != len(set(values)) or any(not isinstance(item, enum_type) for item in values):
        raise ValueError(f"{name}_invalid")


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or _ID.fullmatch(value) is None:
        raise ValueError(f"{name}_invalid")


def _sha(name: str, value: object) -> None:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ValueError(f"{name}_sha256_invalid")


def _digest(name: str, value: object) -> None:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_invalid")


def _window(name: str, start: datetime, end: datetime) -> None:
    _aware(f"{name}_start", start); _aware(f"{name}_end", end)
    if end <= start:
        raise ValueError(f"{name}_window_invalid")
