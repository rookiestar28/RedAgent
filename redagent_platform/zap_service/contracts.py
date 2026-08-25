"""Immutable, deny-by-default contracts for the compat_104 controlled ZAP runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit


PASSIVE_RULE_ID = "10021"
ACTIVE_RULE_ID = "40012"
ZAP_VERSION = "2.17.0"
ZAP_ADDON_INVENTORY_COUNT = 48
ZAP_ADDON_INVENTORY_SHA256 = "50293fde751b211ed6432b0b5039e8bf3fec7676a738c635a9c1e6844c511e43"  # pragma: allowlist secret
R104_TARGET_SOURCE_SHA256 = "eadf76b79ea4b64f956cac5f6dc5e004990405f4f4504997fe43002768b7e493"  # pragma: allowlist secret
R104_TARGET_IMAGE_ID = "sha256:db8bf25081f45eb2496cc423a5ff15c4b66813ae9420bc8682cbaead1ce803e0"
CURRENT_R104_TARGET_IMAGE_ID = "sha256:a9196612dd4d48af9f60be06024ac15bd64b39d2fb617b54f2fc66921dda1642"
ZAP_UPSTREAM_BARE_DIGEST = "sha256:627781353231d056d5a6305ec1f2092f54735cc654915f533d2e8d5d9d41bcb2"
ZAP_IMAGE_DIGEST_BY_PLATFORM: Mapping[str, str] = MappingProxyType({
    "linux/amd64": "sha256:ccd16df57aed6724abdafe71b1077099c2b992d0945359d32d84f0939186b0c3",
})
CURRENT_ZAP_IMAGE_DIGEST_BY_PLATFORM: Mapping[str, str] = MappingProxyType({
    "linux/amd64": "sha256:3cd55809bfea0393bc67862eec614091faa873cfb219d28465122f04ae8d266b",
})
CURRENT_ZAP_SBOM_SHA256 = "d049db94f2c81e2885a27f028660eb1e527623b0b0406438042fa89860450574"
CURRENT_ZAP_CRITICAL_REPORT_SHA256 = "431f3676ea80af5139890a6be8806d4040583d0d13f9b364c309bf8adc163856"
GATEWAY_ENDPOINT = "http://redagent-r104-gateway:8080"
TARGET_NETWORK = "redagent-r104-gateway-target"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_SAFE_PATH = re.compile(r"^/(?:[A-Za-z0-9._~-]+/)*[A-Za-z0-9._~-]+$")


class CertifiedProfileId(str, Enum):
    PASSIVE = "zap-passive-v1"
    AUTHENTICATED_CRAWL = "zap-auth-crawl-v1"
    CLIENT_SPIDER = "zap-client-spider-v1"
    ACTIVE_XSS_LAB = "zap-active-xss-lab-v1"


class ApprovalClass(str, Enum):
    LOW_RISK = "low_risk"
    CREDENTIAL = "credential"
    BROWSER = "browser"
    ACTIVE_LAB = "active_lab"


@dataclass(frozen=True, slots=True, kw_only=True)
class CertifiedZapProfile:
    profile_id: CertifiedProfileId
    approval_class: ApprovalClass
    passive_rule_ids: tuple[str, ...]
    active_rule_ids: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    request_limit: int
    request_rate_per_second: int
    concurrency: int
    timeout_seconds: int
    response_bytes_limit: int
    scope_check: str
    browser_count: int
    max_depth: int
    max_children: int
    requires_credential: bool


_PROFILES: Mapping[CertifiedProfileId, CertifiedZapProfile] = MappingProxyType({
    CertifiedProfileId.PASSIVE: CertifiedZapProfile(
        profile_id=CertifiedProfileId.PASSIVE, approval_class=ApprovalClass.LOW_RISK,
        passive_rule_ids=(PASSIVE_RULE_ID,), active_rule_ids=(),
        allowed_paths=("/passive/missing-header",), request_limit=60,
        request_rate_per_second=3, concurrency=2, timeout_seconds=180,
        response_bytes_limit=15 * 1024 * 1024, scope_check="Strict", browser_count=0,
        max_depth=2, max_children=20, requires_credential=False,
    ),
    CertifiedProfileId.AUTHENTICATED_CRAWL: CertifiedZapProfile(
        profile_id=CertifiedProfileId.AUTHENTICATED_CRAWL, approval_class=ApprovalClass.CREDENTIAL,
        passive_rule_ids=(PASSIVE_RULE_ID,), active_rule_ids=(),
        allowed_paths=("/auth/protected",), request_limit=80,
        request_rate_per_second=3, concurrency=2, timeout_seconds=240,
        response_bytes_limit=20 * 1024 * 1024, scope_check="Strict", browser_count=0,
        max_depth=2, max_children=20, requires_credential=True,
    ),
    CertifiedProfileId.CLIENT_SPIDER: CertifiedZapProfile(
        profile_id=CertifiedProfileId.CLIENT_SPIDER, approval_class=ApprovalClass.BROWSER,
        passive_rule_ids=(PASSIVE_RULE_ID,), active_rule_ids=(),
        allowed_paths=("/browser/start", "/browser/client-route"), request_limit=100,
        request_rate_per_second=2, concurrency=2, timeout_seconds=300,
        response_bytes_limit=20 * 1024 * 1024, scope_check="Strict", browser_count=1,
        max_depth=3, max_children=20, requires_credential=False,
    ),
    CertifiedProfileId.ACTIVE_XSS_LAB: CertifiedZapProfile(
        profile_id=CertifiedProfileId.ACTIVE_XSS_LAB, approval_class=ApprovalClass.ACTIVE_LAB,
        passive_rule_ids=(), active_rule_ids=(ACTIVE_RULE_ID,),
        allowed_paths=("/active/reflected-input",), request_limit=150,
        request_rate_per_second=2, concurrency=1, timeout_seconds=300,
        response_bytes_limit=25 * 1024 * 1024, scope_check="Strict", browser_count=0,
        max_depth=1, max_children=1, requires_credential=False,
    ),
})


@dataclass(frozen=True, slots=True, kw_only=True)
class ZapTargetBinding:
    target_id: str
    attestation_sha256: str
    endpoint: str
    allowed_paths: tuple[str, ...]
    network_id: str
    non_production: bool
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _identifier("zap_target_id", self.target_id)
        _sha("zap_target_attestation", self.attestation_sha256)
        parsed = urlsplit(self.endpoint)
        if self.endpoint != GATEWAY_ENDPOINT or parsed.username or parsed.password or parsed.query or parsed.fragment:
            raise ValueError("zap_target_endpoint_invalid")
        if self.network_id != TARGET_NETWORK:
            raise ValueError("zap_target_network_invalid")
        if self.non_production is not True:
            raise ValueError("zap_target_non_production_required")
        if not self.allowed_paths or len(self.allowed_paths) > 16 or len(set(self.allowed_paths)) != len(self.allowed_paths):
            raise ValueError("zap_target_path_invalid")
        if any(not _SAFE_PATH.fullmatch(path) for path in self.allowed_paths):
            raise ValueError("zap_target_path_invalid")
        _window("zap_target", self.issued_at, self.expires_at, 900)


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ZapAuthorization:
    tenant_id: str
    policy_decision_id: str
    policy_revision: str
    roe_version_id: str
    approval_class: ApprovalClass
    approved_profile_ids: tuple[CertifiedProfileId, ...]
    credential_reference_ids: tuple[str, ...]
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for name, value in (
            ("zap_tenant_id", self.tenant_id), ("zap_policy_decision_id", self.policy_decision_id),
            ("zap_policy_revision", self.policy_revision), ("zap_roe_version_id", self.roe_version_id),
        ):
            _identifier(name, value)
        if not isinstance(self.approval_class, ApprovalClass):
            raise ValueError("zap_approval_class_invalid")
        if not self.approved_profile_ids or len(set(self.approved_profile_ids)) != len(self.approved_profile_ids):
            raise ValueError("zap_approved_profiles_invalid")
        if any(not isinstance(item, CertifiedProfileId) for item in self.approved_profile_ids):
            raise ValueError("zap_approved_profiles_invalid")
        if len(self.credential_reference_ids) > 1:
            raise ValueError("zap_credentials_invalid")
        for value in self.credential_reference_ids:
            _identifier("zap_credential_reference", value)
        _window("zap_authorization", self.approved_at, self.expires_at, 600)

    def __repr__(self) -> str:
        return (
            f"ZapAuthorization(tenant_id={self.tenant_id!r}, policy_decision_id={self.policy_decision_id!r}, "
            f"approval_class={self.approval_class.value!r}, approved_profile_ids={self.approved_profile_ids!r}, "
            "credential_reference_ids=<redacted>)"
        )


def certified_profiles() -> Mapping[CertifiedProfileId, CertifiedZapProfile]:
    return _PROFILES


def canonical_profile_sha256(profile: CertifiedZapProfile) -> str:
    """Return the canonical profile digest used by the compat_104 persistence authority."""
    if not isinstance(profile, CertifiedZapProfile):
        raise ValueError("zap_profile_type_invalid")
    payload = asdict(profile)
    normalized = {
        key: (
            [item.value if isinstance(item, Enum) else item for item in value]
            if isinstance(value, tuple)
            else value.value
            if isinstance(value, Enum)
            else value
        )
        for key, value in payload.items()
    }
    encoded = json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _window(name: str, start: datetime, end: datetime, maximum_seconds: int) -> None:
    if start.tzinfo is None or end.tzinfo is None or start.utcoffset() is None or end.utcoffset() is None:
        raise ValueError(f"{name}_timezone_required")
    if not start < end:
        raise ValueError(f"{name}_window_invalid")
    if (end - start).total_seconds() > maximum_seconds:
        raise ValueError(f"{name}_ttl_exceeded")
