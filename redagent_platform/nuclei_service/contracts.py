"""Immutable contracts for the compat_105 trusted Nuclei runtime."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime
from enum import Enum
import hashlib
import json
import re
from types import MappingProxyType
from typing import Mapping


NUCLEI_VERSION = "3.8.0"
NUCLEI_SBOM_SHA256 = "8e82e90208ae3fe8cc613a36aaaa69d85c139329ed41b5466612070bc89747b9"
NUCLEI_CRITICAL_REPORT_SHA256 = "ebb1ada367bcfd5d5d12759ab80bde3261d6265cda68834eb77a02c3cf7eddb8"
R105_HTTP_HEADER_BUNDLE_SHA256 = "6c16355c64475bbea0b647f5a0c8571a461a7382ec9acb9a0aff9800108bc768"
R105_TARGET_SOURCE_SHA256 = "d2012077f8bb7f5e5bef3c1fbd591c9777b2f19e4d45e159692ed182c0bbc6e3"
R105_TARGET_IMAGE_ID = "sha256:cf0aaa75b9a6e4cbbb78af5ca4ed99a0b51c2109cfc7e4df1c2690965f13ab4e"
CURRENT_R105_TARGET_IMAGE_ID = "sha256:b874d619d8e5a9269beb034f339f874a3936e082d68d86c2b69c92d77b1a33f2"
NUCLEI_IMAGE_DIGEST_BY_PLATFORM: Mapping[str, str] = MappingProxyType({
    "linux/amd64": "sha256:4e95c15953fe894bda1a8a16ecde958497e335a7a0b1f6fdb17b06af38630871",
})
CURRENT_NUCLEI_VERSION = "3.11.1"
CURRENT_NUCLEI_SBOM_SHA256 = "57b9aa17c912d9a0003a79b97cf9f72b21f6a75b7192e2db5afadbcfc9d4d865"
CURRENT_NUCLEI_CRITICAL_REPORT_SHA256 = "7b6cd9d14d687aea16fd8ff8abfe709aa4f67b7d1eb0be35d51461dfbab147e9"
CURRENT_NUCLEI_IMAGE_DIGEST_BY_PLATFORM: Mapping[str, str] = MappingProxyType({
    "linux/amd64": "sha256:871c1b17ef594f3cc01cbd20cb6e2632f16e0f19a2c4a7e90f060845b1a6a593",
})
CURRENT_R105_HTTP_HEADER_BUNDLE_SHA256 = "ab8cbe219bb7b886dccd5b638583b374961560d688bd53e7bdc4164b0babc5ef"
GATEWAY_ENDPOINT = "http://redagent-r105-gateway:8080"
TARGET_NETWORK = "redagent-r105-gateway-target"
TEMPLATE_ID = "redagent-r105-missing-header"
TEMPLATE_PATH = "templates/redagent-r105-missing-header.yaml"
_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_FORBIDDEN_TEMPLATE_KEYS = frozenset({
    "code", "javascript", "headless", "file", "network", "dns", "ssl", "tcp", "udp",
    "websocket", "whois", "workflow", "workflows", "flow", "variables", "payloads",
    "self-contained", "self_contained", "global-matchers", "global_matchers",
})


class NucleiProfileId(str, Enum):
    HTTP_HEADER = "nuclei-http-header-v1"


@dataclass(frozen=True, kw_only=True)
class NucleiProfile:
    profile_id: NucleiProfileId
    allowed_protocols: tuple[str, ...]
    allowed_methods: tuple[str, ...]
    allowed_paths: tuple[str, ...]
    request_limit: int
    request_rate_per_second: int
    concurrency: int
    timeout_seconds: int
    response_bytes_limit: int
    result_limit: int
    oast_allowed: bool
    runtime_update_allowed: bool


@dataclass(frozen=True, kw_only=True)
class NucleiBundleManifest:
    bundle_id: str
    revision: int
    template_id: str
    template_relative_path: str
    template_sha256: str
    bundle_sha256: str
    signature_verified: bool
    reviewer_user_id: str
    protocol: str
    method: str
    paths: tuple[str, ...]
    severity: str
    tags: tuple[str, ...]
    expected_matcher_names: tuple[str, ...]
    file_inventory: tuple[str, ...]
    promoted_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (self.bundle_id, self.template_id, self.reviewer_user_id):
            _identifier(value)
        if self.revision not in {1, 2, 3} or self.template_id != TEMPLATE_ID or self.template_relative_path != TEMPLATE_PATH:
            raise ValueError("nuclei_bundle_identity_invalid")
        _sha(self.template_sha256)
        _sha(self.bundle_sha256)
        if self.signature_verified is not True:
            raise ValueError("nuclei_bundle_signature_required")
        if self.protocol != "http" or self.method != "GET":
            raise ValueError("nuclei_bundle_protocol_invalid")
        if self.paths != ("/nuclei/missing-header",):
            raise ValueError("nuclei_bundle_paths_invalid")
        if self.severity != "low" or set(self.tags) != {"redagent", "synthetic"}:
            raise ValueError("nuclei_bundle_classification_invalid")
        if self.expected_matcher_names != ("missing-security-header",):
            raise ValueError("nuclei_bundle_matcher_invalid")
        if self.file_inventory != (TEMPLATE_PATH,):
            raise ValueError("nuclei_bundle_inventory_invalid")
        _aware(self.promoted_at)
        _aware(self.expires_at)
        if not self.promoted_at < self.expires_at <= self.promoted_at.replace(year=self.promoted_at.year + 1):
            raise ValueError("nuclei_bundle_expiry_invalid")


@dataclass(frozen=True, kw_only=True)
class NucleiTargetBinding:
    target_id: str
    attestation_sha256: str
    endpoint: str
    allowed_paths: tuple[str, ...]
    network_id: str
    non_production: bool
    issued_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        _identifier(self.target_id)
        _sha(self.attestation_sha256)
        _aware(self.issued_at)
        _aware(self.expires_at)
        if (
            self.endpoint != GATEWAY_ENDPOINT or self.allowed_paths != ("/nuclei/missing-header",)
            or self.network_id != TARGET_NETWORK or self.non_production is not True
            or not self.issued_at < self.expires_at
        ):
            raise ValueError("nuclei_target_binding_mismatch")


@dataclass(frozen=True, kw_only=True)
class NucleiAuthorization:
    tenant_id: str
    policy_decision_id: str
    policy_revision: str
    roe_version_id: str
    approved_profile_ids: tuple[NucleiProfileId, ...]
    approved_bundle_id: str
    approved_at: datetime
    expires_at: datetime

    def __post_init__(self) -> None:
        for value in (
            self.tenant_id, self.policy_decision_id, self.policy_revision,
            self.roe_version_id, self.approved_bundle_id,
        ):
            _identifier(value)
        _aware(self.approved_at)
        _aware(self.expires_at)
        if not self.approved_at < self.expires_at:
            raise ValueError("nuclei_authorization_expiry_invalid")


def certified_profiles() -> Mapping[NucleiProfileId, NucleiProfile]:
    return MappingProxyType({
        NucleiProfileId.HTTP_HEADER: NucleiProfile(
            profile_id=NucleiProfileId.HTTP_HEADER,
            allowed_protocols=("http",), allowed_methods=("GET",),
            allowed_paths=("/nuclei/missing-header",), request_limit=20,
            request_rate_per_second=2, concurrency=1, timeout_seconds=60,
            response_bytes_limit=2 * 1024 * 1024, result_limit=10,
            oast_allowed=False, runtime_update_allowed=False,
        ),
    })


def canonical_profile_sha256(profile: NucleiProfile) -> str:
    """Return the canonical profile digest used by the compat_105 persistence authority."""
    if not isinstance(profile, NucleiProfile):
        raise ValueError("nuclei_profile_type_invalid")
    payload = asdict(profile)
    payload["profile_id"] = profile.profile_id.value
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_template_document(document: Mapping[str, object]) -> str:
    if _FORBIDDEN_TEMPLATE_KEYS.intersection(document):
        raise ValueError("nuclei_template_forbidden")
    if set(document) != {"id", "info", "http"} or document.get("id") != TEMPLATE_ID:
        raise ValueError("nuclei_template_identity_invalid")
    info = document.get("info")
    http = document.get("http")
    if not isinstance(info, Mapping) or not isinstance(http, list) or len(http) != 1:
        raise ValueError("nuclei_template_shape_invalid")
    if set(info) != {"name", "author", "severity", "tags"}:
        raise ValueError("nuclei_template_info_invalid")
    if info.get("author") != "redagent" or info.get("severity") != "low" or info.get("tags") != "redagent,synthetic":
        raise ValueError("nuclei_template_info_invalid")
    request = http[0]
    if not isinstance(request, Mapping):
        raise ValueError("nuclei_template_shape_invalid")
    if request.get("method") != "GET":
        raise ValueError("nuclei_template_method_forbidden")
    if request.get("path") != ["{{BaseURL}}/nuclei/missing-header"]:
        raise ValueError("nuclei_template_path_forbidden")
    if request.get("redirects") is not False or request.get("max-redirects") != 0:
        raise ValueError("nuclei_template_redirect_forbidden")
    if request.get("matchers-condition") != "and":
        raise ValueError("nuclei_template_matcher_invalid")
    if set(request) != {"method", "path", "redirects", "max-redirects", "matchers-condition", "matchers"}:
        raise ValueError("nuclei_template_request_invalid")
    matchers = request.get("matchers")
    expected = [{"type": "status", "status": [200]}, {
        "type": "word", "name": "missing-security-header", "part": "header",
        "negative": True, "words": ["X-Content-Type-Options"],
    }]
    if matchers != expected:
        raise ValueError("nuclei_template_matcher_invalid")
    return TEMPLATE_ID


def _identifier(value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError("nuclei_identifier_invalid")


def _sha(value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError("nuclei_sha256_invalid")


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("nuclei_time_invalid")

CURRENT_R105_GATEWAY_IMAGE_ID = "sha256:bd7dbb9139b78e447968dc6a06b8c646c71936fe07b962da52b1c35503abdc8a"
