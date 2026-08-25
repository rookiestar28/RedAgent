"""Closed OpenBao provider adapter for R098."""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
from typing import Any, Callable, Mapping, Protocol, runtime_checkable

from redagent_platform.secret_service.contracts import ProviderLeaseEnvelope, SecretMaterial


_REFERENCE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,199}$")
_PATH = re.compile(r"^[a-z0-9][a-z0-9_./-]{0,299}$")
_FIELD = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
_MAX_RESPONSE_BYTES = 65_536
SECRET_PROVIDER_CONTRACT_VERSION = "1.0"


class ProviderCapabilityError(RuntimeError):
    """OpenBao cannot satisfy the closed lease contract."""


@dataclass(frozen=True, slots=True)
class SecretRoleMapping:
    role_reference: str
    issue_path: str
    material_fields: tuple[str, ...]
    max_ttl_seconds: int

    def __post_init__(self) -> None:
        if not _REFERENCE.fullmatch(self.role_reference):
            raise ValueError("secret_role_reference_invalid")
        if not _PATH.fullmatch(self.issue_path) or ".." in self.issue_path.split("/"):
            raise ValueError("secret_issue_path_invalid")
        if (
            not self.issue_path.startswith("database/creds/")
            or not isinstance(self.material_fields, tuple)
            or not 1 <= len(self.material_fields) <= 8
            or len(set(self.material_fields)) != len(self.material_fields)
            or any(not _FIELD.fullmatch(field) for field in self.material_fields)
        ):
            raise ValueError("secret_role_mapping_invalid")
        if isinstance(self.max_ttl_seconds, bool) or not 1 <= self.max_ttl_seconds <= 900:
            raise ValueError("secret_role_max_ttl_invalid")


@dataclass(frozen=True, slots=True)
class ProviderCapabilities:
    version: str
    initialized: bool
    sealed: bool
    standby: bool
    audit_device_count: int
    exact_lease_endpoints: bool
    production_ready: bool


@dataclass(frozen=True, slots=True)
class ProviderRenewal:
    duration_seconds: int
    renewable: bool


@dataclass(frozen=True, slots=True)
class ProviderLeaseStatus:
    active: bool
    ttl_seconds: int
    renewable: bool


@runtime_checkable
class SecretProvider(Protocol):
    """Version 1.0 closed dynamic-lease provider contract."""

    @property
    def max_ttl_seconds(self) -> int: ...

    async def issue(self, role_reference: str) -> ProviderLeaseEnvelope: ...

    async def renew(self, provider_lease_reference: str, *, increment_seconds: int) -> ProviderRenewal: ...

    async def lookup_status(self, provider_lease_reference: str) -> ProviderLeaseStatus: ...

    async def revoke_sync(self, provider_lease_reference: str) -> None: ...


class OpenBaoSecretProvider:
    def __init__(
        self,
        client: Any,
        *,
        endpoint: str,
        token_source: Callable[[], str],
        role_mappings: Mapping[str, SecretRoleMapping],
        minimum_version: tuple[int, int, int],
    ) -> None:
        normalized = endpoint.rstrip("/")
        if not normalized.startswith(("https://", "http://127.0.0.1:", "http://localhost:")):
            raise ValueError("openbao_endpoint_invalid")
        if not callable(token_source) or not role_mappings:
            raise ValueError("openbao_provider_configuration_invalid")
        if set(role_mappings) != {mapping.role_reference for mapping in role_mappings.values()}:
            raise ValueError("openbao_role_mapping_key_mismatch")
        self.client = client
        self.endpoint = normalized
        self.token_source = token_source
        self.role_mappings = dict(role_mappings)
        self.minimum_version = minimum_version

    @property
    def max_ttl_seconds(self) -> int:
        return max(mapping.max_ttl_seconds for mapping in self.role_mappings.values())

    async def assess_capabilities(self) -> ProviderCapabilities:
        health = await self._request("GET", "/sys/health?standbyok=true", authenticated=False, expected=(200, 429))
        if not health.get("initialized"):
            raise ProviderCapabilityError("openbao_uninitialized")
        if health.get("sealed"):
            raise ProviderCapabilityError("openbao_sealed")
        version = str(health.get("version", ""))
        if _version_tuple(version) < self.minimum_version:
            raise ProviderCapabilityError("openbao_version_unsupported")
        seal = await self._request("GET", "/sys/seal-status", authenticated=False, expected=(200,))
        if not seal.get("initialized") or seal.get("sealed"):
            raise ProviderCapabilityError("openbao_seal_status_unready")
        audits = await self._request("GET", "/sys/audit", authenticated=True, expected=(200,))
        devices = audits.get("data", audits)
        device_rows = {
            name: value for name, value in devices.items()
            if isinstance(name, str) and name.endswith("/") and isinstance(value, dict)
        } if isinstance(devices, dict) else {}
        if len(device_rows) < 2:
            raise ProviderCapabilityError("openbao_multiple_audit_devices_required")
        return ProviderCapabilities(
            version=version,
            initialized=True,
            sealed=False,
            standby=bool(health.get("standby")),
            audit_device_count=len(device_rows),
            exact_lease_endpoints=True,
            production_ready=self.endpoint.startswith("https://"),
        )

    async def issue(self, role_reference: str) -> ProviderLeaseEnvelope:
        mapping = self.role_mappings.get(role_reference)
        if mapping is None:
            raise ProviderCapabilityError("openbao_role_reference_unknown")
        payload = await self._request("GET", f"/{mapping.issue_path}", authenticated=True, expected=(200,))
        lease_reference = payload.get("lease_id")
        duration = payload.get("lease_duration")
        renewable = payload.get("renewable")
        data = payload.get("data")
        if (
            not isinstance(lease_reference, str)
            or not _REFERENCE.fullmatch(lease_reference)
            or isinstance(duration, bool)
            or not isinstance(duration, int)
            or not 1 <= duration <= mapping.max_ttl_seconds
            or not isinstance(renewable, bool)
            or not isinstance(data, dict)
        ):
            raise ProviderCapabilityError("openbao_issue_response_invalid")
        material_fields: dict[str, bytearray] = {}
        try:
            for field in mapping.material_fields:
                value = data.get(field)
                if not isinstance(value, str) or not value or len(value.encode("utf-8")) > 16_384:
                    raise ProviderCapabilityError("openbao_issue_material_invalid")
                material_fields[field] = bytearray(value.encode("utf-8"))
        except Exception:
            for buffer in material_fields.values():
                buffer[:] = b"\x00" * len(buffer)
            raise
        return ProviderLeaseEnvelope(
            provider_lease_reference=lease_reference,
            duration_seconds=duration,
            renewable=renewable,
            material=SecretMaterial(material_fields),
        )

    async def renew(self, provider_lease_reference: str, *, increment_seconds: int) -> ProviderRenewal:
        _lease_reference(provider_lease_reference)
        if isinstance(increment_seconds, bool) or not 1 <= increment_seconds <= 900:
            raise ValueError("provider_renew_increment_invalid")
        payload = await self._request(
            "POST",
            "/sys/leases/renew",
            authenticated=True,
            expected=(200,),
            json_body={"lease_id": provider_lease_reference, "increment": increment_seconds},
        )
        duration = payload.get("lease_duration")
        renewable = payload.get("renewable")
        if isinstance(duration, bool) or not isinstance(duration, int) or duration < 1 or not isinstance(renewable, bool):
            raise ProviderCapabilityError("openbao_renew_response_invalid")
        return ProviderRenewal(duration, renewable)

    async def lookup_status(self, provider_lease_reference: str) -> ProviderLeaseStatus:
        _lease_reference(provider_lease_reference)
        payload = await self._request(
            "POST",
            "/sys/leases/lookup",
            authenticated=True,
            expected=(200, 400, 404),
            json_body={"lease_id": provider_lease_reference},
        )
        if payload.get("_status") in {400, 404}:
            return ProviderLeaseStatus(False, 0, False)
        data = payload.get("data")
        if not isinstance(data, dict):
            raise ProviderCapabilityError("openbao_lease_lookup_response_invalid")
        ttl = data.get("ttl")
        renewable = data.get("renewable")
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 0 or not isinstance(renewable, bool):
            raise ProviderCapabilityError("openbao_lease_lookup_response_invalid")
        return ProviderLeaseStatus(ttl > 0, ttl, renewable)

    async def revoke_sync(self, provider_lease_reference: str) -> None:
        _lease_reference(provider_lease_reference)
        await self._request(
            "POST",
            "/sys/leases/revoke",
            authenticated=True,
            expected=(200, 204),
            json_body={"lease_id": provider_lease_reference, "sync": True},
        )

    async def _request(
        self,
        method: str,
        path: str,
        *,
        authenticated: bool,
        expected: tuple[int, ...],
        json_body: dict[str, object] | None = None,
    ) -> dict[str, object]:
        headers = {"Accept": "application/json", "X-Vault-Request": "true"}
        if authenticated:
            token = self.token_source()
            if not isinstance(token, str) or not token or len(token) > 4096:
                raise ProviderCapabilityError("openbao_token_source_invalid")
            headers["X-Vault-Token"] = token
        try:
            response = await self.client.request(
                method,
                f"{self.endpoint}/v1{path}",
                headers=headers,
                timeout=10.0,
                **({"json": json_body} if json_body is not None else {}),
            )
        except Exception as exc:
            raise ProviderCapabilityError("openbao_transport_unavailable") from exc
        content = getattr(response, "content", b"")
        status = getattr(response, "status_code", 0)
        if not isinstance(content, bytes) or len(content) > _MAX_RESPONSE_BYTES:
            raise ProviderCapabilityError("openbao_response_size_invalid")
        if status not in expected:
            raise ProviderCapabilityError(f"openbao_http_status:{status}")
        if status == 204:
            return {"_status": status}
        response_headers = getattr(response, "headers", None)
        if response_headers is not None:
            content_type = str(response_headers.get("content-type", "")).split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise ProviderCapabilityError("openbao_response_content_type_invalid")
        try:
            payload = response.json()
        except Exception as exc:
            raise ProviderCapabilityError("openbao_response_json_invalid") from exc
        if not isinstance(payload, dict):
            raise ProviderCapabilityError("openbao_response_shape_invalid")
        return {**payload, "_status": status}


def _lease_reference(value: str) -> None:
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ValueError("provider_lease_reference_invalid")


def _version_tuple(value: str) -> tuple[int, int, int]:
    match = re.match(r"^v?(\d+)\.(\d+)\.(\d+)", value)
    if not match:
        raise ProviderCapabilityError("openbao_version_invalid")
    return tuple(int(part) for part in match.groups())


def load_role_mappings(path: Path) -> dict[str, SecretRoleMapping]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError("secret_role_mapping_invalid") from exc
    roles = payload.get("roles") if isinstance(payload, dict) and payload.get("schema_version") == "1.0" else None
    if not isinstance(roles, dict) or not roles:
        raise ValueError("secret_role_mapping_invalid")
    parsed: dict[str, SecretRoleMapping] = {}
    for role_reference, value in roles.items():
        if not isinstance(role_reference, str) or not isinstance(value, dict) or set(value) != {
            "issue_path", "material_fields", "max_ttl_seconds",
        }:
            raise ValueError("secret_role_mapping_invalid")
        fields = value["material_fields"]
        if not isinstance(fields, list) or not all(isinstance(field, str) for field in fields):
            raise ValueError("secret_role_mapping_invalid")
        parsed[role_reference] = SecretRoleMapping(
            role_reference=role_reference,
            issue_path=value["issue_path"],
            material_fields=tuple(fields),
            max_ttl_seconds=value["max_ttl_seconds"],
        )
    return parsed
