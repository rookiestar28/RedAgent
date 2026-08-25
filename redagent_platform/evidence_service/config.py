"""Fail-closed compat_097 evidence backend configuration."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping
from urllib.parse import urlsplit


class EvidenceConfigError(ValueError):
    """Evidence storage configuration is incomplete or unsafe."""


@dataclass(frozen=True, slots=True)
class EvidenceSettings:
    profile: str
    backend: str
    local_root: Path | None = None
    endpoint: str | None = None
    bucket: str | None = None
    region: str | None = None
    kms_reference: str | None = None
    capability_record: Path | None = None


def load_evidence_settings(workspace: Path, env: Mapping[str, str]) -> EvidenceSettings:
    workspace = workspace.resolve()
    profile = _required(env, "REDAGENT_EVIDENCE_PROFILE")
    backend = _required(env, "REDAGENT_EVIDENCE_BACKEND")
    if any(key in env for key in ("REDAGENT_EVIDENCE_ACCESS_KEY", "REDAGENT_EVIDENCE_SECRET_KEY")):
        raise EvidenceConfigError("evidence_inline_credentials_forbidden")
    if backend == "local-append-only":
        if profile == "production":
            raise EvidenceConfigError("evidence_production_local_backend_forbidden")
        if profile != "synthetic-local":
            raise EvidenceConfigError("evidence_local_backend_synthetic_only")
        root = Path(_required(env, "REDAGENT_EVIDENCE_LOCAL_ROOT")).resolve()
        try:
            root.relative_to(workspace)
        except ValueError as exc:
            raise EvidenceConfigError("evidence_local_root_outside_workspace") from exc
        return EvidenceSettings(profile=profile, backend=backend, local_root=root)
    if backend != "s3":
        raise EvidenceConfigError("evidence_backend_unsupported")
    endpoint = _required(env, "REDAGENT_EVIDENCE_ENDPOINT")
    parsed = urlsplit(endpoint)
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username or parsed.password:
        raise EvidenceConfigError("evidence_endpoint_path_forbidden")
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise EvidenceConfigError("evidence_endpoint_invalid")
    if profile == "production" and parsed.scheme != "https":
        raise EvidenceConfigError("evidence_production_tls_required")
    if profile == "local-conformance" and (parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}):
        raise EvidenceConfigError("evidence_local_conformance_loopback_required")
    if profile not in {"production", "local-conformance"}:
        raise EvidenceConfigError("evidence_profile_unsupported")
    capability = Path(_required(env, "REDAGENT_EVIDENCE_CAPABILITY_RECORD")).resolve() if profile == "production" else None
    kms_reference = _required(env, "REDAGENT_EVIDENCE_KMS_REFERENCE")
    if profile == "production" and not kms_reference.startswith("kms:"):
        raise EvidenceConfigError("evidence_production_kms_reference_required")
    if profile == "production":
        try:
            capability.relative_to(workspace)  # type: ignore[union-attr]
        except ValueError as exc:
            raise EvidenceConfigError("evidence_capability_record_outside_workspace") from exc
    return EvidenceSettings(
        profile=profile,
        backend=backend,
        endpoint=endpoint,
        bucket=_required(env, "REDAGENT_EVIDENCE_BUCKET"),
        region=_required(env, "REDAGENT_EVIDENCE_REGION"),
        kms_reference=kms_reference,
        capability_record=capability,
    )


def _required(env: Mapping[str, str], name: str) -> str:
    value = env.get(name, "").strip()
    if not value or len(value) > 500:
        raise EvidenceConfigError(f"{name.lower()}_required")
    return value
