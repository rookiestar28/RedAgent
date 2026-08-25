from __future__ import annotations

from pathlib import Path

import pytest

from redagent_platform.evidence_service.config import EvidenceConfigError, load_evidence_settings


ROOT = Path(__file__).resolve().parents[2]


def test_local_backend_requires_explicit_synthetic_profile_and_workspace_root() -> None:
    local_root = ROOT / ".tmp" / "r097-evidence-config"
    settings = load_evidence_settings(ROOT, {
        "REDAGENT_EVIDENCE_PROFILE": "synthetic-local",
        "REDAGENT_EVIDENCE_BACKEND": "local-append-only",
        "REDAGENT_EVIDENCE_LOCAL_ROOT": str(local_root),
    })
    assert settings.profile == "synthetic-local"
    assert settings.backend == "local-append-only"

    with pytest.raises(EvidenceConfigError, match="evidence_local_root_outside_workspace"):
        load_evidence_settings(ROOT, {
            "REDAGENT_EVIDENCE_PROFILE": "synthetic-local",
            "REDAGENT_EVIDENCE_BACKEND": "local-append-only",
            "REDAGENT_EVIDENCE_LOCAL_ROOT": str(ROOT.parent),
        })


def test_production_s3_fails_closed_without_tls_kms_bucket_and_capability_record() -> None:
    base = {
        "REDAGENT_EVIDENCE_PROFILE": "production",
        "REDAGENT_EVIDENCE_BACKEND": "s3",
        "REDAGENT_EVIDENCE_ENDPOINT": "http://objects.example.test",
        "REDAGENT_EVIDENCE_BUCKET": "redagent-evidence",
        "REDAGENT_EVIDENCE_REGION": "us-east-1",
        "REDAGENT_EVIDENCE_KMS_REFERENCE": "kms:redagent:evidence-v1",
        "REDAGENT_EVIDENCE_CAPABILITY_RECORD": str(ROOT / ".local" / "evidence-capabilities.json"),
    }
    with pytest.raises(EvidenceConfigError, match="evidence_production_tls_required"):
        load_evidence_settings(ROOT, base)
    with pytest.raises(EvidenceConfigError, match="evidence_production_local_backend_forbidden"):
        load_evidence_settings(ROOT, {
            "REDAGENT_EVIDENCE_PROFILE": "production",
            "REDAGENT_EVIDENCE_BACKEND": "local-append-only",
            "REDAGENT_EVIDENCE_LOCAL_ROOT": str(ROOT / ".local" / "evidence"),
        })


def test_inline_provider_credentials_and_arbitrary_endpoint_paths_are_forbidden() -> None:
    env = {
        "REDAGENT_EVIDENCE_PROFILE": "local-conformance",
        "REDAGENT_EVIDENCE_BACKEND": "s3",
        "REDAGENT_EVIDENCE_ENDPOINT": "http://127.0.0.1:59000/path",
        "REDAGENT_EVIDENCE_BUCKET": "redagent-evidence",
        "REDAGENT_EVIDENCE_REGION": "us-east-1",
        "REDAGENT_EVIDENCE_KMS_REFERENCE": "kms:local:fixture",
        "REDAGENT_EVIDENCE_ACCESS_KEY": "forbidden",
    }
    with pytest.raises(EvidenceConfigError, match="evidence_inline_credentials_forbidden"):
        load_evidence_settings(ROOT, env)
    env.pop("REDAGENT_EVIDENCE_ACCESS_KEY")
    with pytest.raises(EvidenceConfigError, match="evidence_endpoint_path_forbidden"):
        load_evidence_settings(ROOT, env)
