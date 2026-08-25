"""Shared fail-closed evidence backend construction for API and worker runtimes."""

from __future__ import annotations

from datetime import datetime, timezone
import json
from typing import Mapping

from redagent_platform.evidence_service.backends import (
    LocalAppendOnlyBackend,
    S3ObjectBackend,
)
from redagent_platform.evidence_service.config import EvidenceSettings


class EvidenceRuntimeError(ValueError):
    """Stable runtime-construction failure for an evidence backend."""


def build_evidence_backend(
    settings: EvidenceSettings,
    env: Mapping[str, str],
):
    if settings.backend == "local-append-only":
        assert settings.local_root is not None
        return LocalAppendOnlyBackend(settings.local_root, profile=settings.profile)
    if settings.profile == "production":
        _validate_production_capability_record(settings)
    import boto3

    access_key = env.get("AWS_ACCESS_KEY_ID", "").strip()
    secret_key = env.get("AWS_SECRET_ACCESS_KEY", "").strip()
    session_token = env.get("AWS_SESSION_TOKEN", "").strip()
    if bool(access_key) != bool(secret_key) or (session_token and not access_key):
        raise EvidenceRuntimeError("evidence_aws_credentials_incomplete")
    session = boto3.Session(**(
        {
            "aws_access_key_id": access_key,
            "aws_secret_access_key": secret_key,
            **({"aws_session_token": session_token} if session_token else {}),
        }
        if access_key and secret_key
        else {}
    ))
    client = session.client(
        "s3",
        endpoint_url=settings.endpoint,
        region_name=settings.region,
    )
    backend = S3ObjectBackend(
        client,
        bucket=str(settings.bucket),
        kms_reference=str(settings.kms_reference),
        encryption="aws:kms" if settings.profile == "production" else "AES256",
        require_download_checksum=settings.profile == "production",
    )
    capabilities = backend.assess_capabilities()
    if settings.profile == "production" and not capabilities.production_ready:
        raise EvidenceRuntimeError("evidence_backend_not_production_ready")
    return backend


def _validate_production_capability_record(settings: EvidenceSettings) -> None:
    path = settings.capability_record
    if path is None:
        raise EvidenceRuntimeError("evidence_capability_record_required")
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        checked_at = datetime.fromisoformat(str(payload["checked_at"]))
        expires_at = datetime.fromisoformat(str(payload["expires_at"]))
    except (OSError, KeyError, ValueError, TypeError, json.JSONDecodeError) as exc:
        raise EvidenceRuntimeError("evidence_capability_record_invalid") from exc
    if checked_at.tzinfo is None or expires_at.tzinfo is None:
        raise EvidenceRuntimeError("evidence_capability_record_invalid")
    if (
        payload.get("schema_version") != "1.0"
        or payload.get("status") != "passed"
        or payload.get("endpoint") != settings.endpoint
        or payload.get("bucket") != settings.bucket
        or not checked_at <= datetime.now(timezone.utc) < expires_at
    ):
        raise EvidenceRuntimeError("evidence_capability_record_not_current")
