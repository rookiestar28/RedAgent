from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
from pathlib import Path

import pytest

from redagent_platform.nuclei_service import artifact_promotion as nuclei_artifact
from redagent_platform.nuclei_service import promotion as nuclei_bundle
from redagent_platform.nuclei_service.authority import (
    CURRENT_NUCLEI_ARTIFACT_PROMOTION,
    CURRENT_NUCLEI_BUNDLE_PROMOTION,
    CURRENT_NUCLEI_RUNTIME_LOCK,
)
from redagent_platform.zap_service import promotion as zap_promotion
from redagent_platform.zap_service.authority import (
    CURRENT_ZAP_ARTIFACT_PROMOTION,
    CURRENT_ZAP_RUNTIME_LOCK,
)
from tests.unit.test_compat_104_compat_105_runtime_requalification import _signed_test_promotion


ROOT = Path(__file__).resolve().parents[2]


def _inputs(family):
    if family == "zap":
        module = zap_promotion
        authority = CURRENT_ZAP_ARTIFACT_PROMOTION
        qualification = ROOT / "runtime-assets/attestations/261002-R104_ZAP_RUNTIME_QUALIFICATION_V3.json"
        kwargs = {"runtime_lock_bytes": CURRENT_ZAP_RUNTIME_LOCK.read_bytes()}
        verifier = module.verify_current_zap_promotion
        error = module.ZapPromotionError
        anchor = "CURRENT_ZAP_PUBLIC_KEY_SHA256"
    else:
        module = nuclei_artifact if family == "nuclei" else nuclei_bundle
        authority = CURRENT_NUCLEI_ARTIFACT_PROMOTION if family == "nuclei" else CURRENT_NUCLEI_BUNDLE_PROMOTION
        qualification = ROOT / "runtime-assets/attestations/261002-R105_NUCLEI_RUNTIME_QUALIFICATION_V3.json"
        if family == "nuclei":
            kwargs = {"runtime_lock_bytes": CURRENT_NUCLEI_RUNTIME_LOCK.read_bytes()}
            verifier = module.verify_current_nuclei_artifact_promotion
            error = module.NucleiArtifactPromotionError
            anchor = "CURRENT_NUCLEI_ARTIFACT_PUBLIC_KEY_SHA256"
        else:
            kwargs = {
                "template_bytes": (ROOT / "bundles/r105-nuclei/templates/redagent-r105-missing-header.yaml").read_bytes(),
                "certificate_bytes": (ROOT / "config/trust/r105-nuclei-user.crt").read_bytes(),
            }
            verifier = module.verify_current_nuclei_bundle_promotion
            error = module.NucleiPromotionError
            anchor = "CURRENT_NUCLEI_BUNDLE_PUBLIC_KEY_SHA256"
    document = json.loads(authority.document.read_bytes())
    issued = datetime.fromisoformat(document.get("created_at", document.get("promoted_at")))
    kwargs.update(qualification_bytes=qualification.read_bytes(), now=issued + timedelta(minutes=1))
    return module, anchor, document, kwargs, verifier, error, issued


def _verify(family, document, kwargs, verifier, public_key):
    payload, signature, _ = public_key
    if family == "zap":
        return verifier(promotion_bytes=payload, bundle_bytes=signature, public_key_bytes=public_key[2], **kwargs)
    if family == "nuclei":
        return verifier(promotion_bytes=payload, signature_bundle_bytes=signature, public_key_bytes=public_key[2], **kwargs)
    return verifier(manifest_bytes=payload, signature_bundle_bytes=signature, public_key_bytes=public_key[2], **kwargs)


@pytest.mark.parametrize("family", ("zap", "nuclei", "bundle"))
def test_coherent_replacement_signer_cannot_grant_current_authority(family):
    _, _, document, kwargs, verifier, error, _ = _inputs(family)
    signed = _signed_test_promotion(document)
    with pytest.raises(error, match="anchor_invalid"):
        _verify(family, document, kwargs, verifier, signed)


@pytest.mark.parametrize("family", ("zap", "nuclei", "bundle"))
@pytest.mark.parametrize("defect", (
    "failed", "not_isolated", "stop_unacknowledged", "external_contact", "residual",
    "duplicate", "future", "stale", "naive", "production",
))
def test_trusted_signature_cannot_hide_invalid_profile_qualification(monkeypatch, family, defect):
    module, anchor, document, kwargs, verifier, error, issued = _inputs(family)
    qualification = json.loads(kwargs["qualification_bytes"])
    profile = qualification["profiles"][0]
    if defect in ("failed", "not_isolated", "stop_unacknowledged"):
        field = {"failed": "passed", "not_isolated": "network_isolation_verified", "stop_unacknowledged": "native_stop_acknowledged"}[defect]
        profile[field] = False
    elif defect == "external_contact":
        profile["external_target_contacts"] = 1
    elif defect == "residual":
        profile["cleanup_residual_resource_count"] = 1
    elif defect == "duplicate":
        qualification["profiles"].append(dict(profile))
    elif defect == "production":
        qualification["production_qualified"] = True
    else:
        clock = issued + timedelta(seconds=1) if defect == "future" else issued - timedelta(days=3)
        qualification["qualified_at"] = clock.replace(tzinfo=None).isoformat() if defect == "naive" else clock.isoformat()
    raw = (json.dumps(qualification, sort_keys=True, indent=2) + "\n").encode()
    kwargs["qualification_bytes"] = raw
    document["qualification"]["receipt_sha256"] = hashlib.sha256(raw).hexdigest()
    signed = _signed_test_promotion(document)
    # Explicit synthetic trust reaches the claim guard; production roots remain pinned.
    monkeypatch.setattr(module, anchor, hashlib.sha256(signed[2]).hexdigest(), raising=False)
    with pytest.raises(error, match="qualification_invalid"):
        _verify(family, document, kwargs, verifier, signed)


@pytest.mark.parametrize("field,value", (
    ("scope", "current-candidate-acceptance"),
    ("source_manifest_sha256", "0" * 64),
    ("template_sha256", "0" * 64),
))
def test_inherited_template_review_cannot_expand_or_change_source(monkeypatch, field, value):
    module, anchor, document, kwargs, verifier, error, _ = _inputs("bundle")
    document["review"][field] = value
    signed = _signed_test_promotion(document)
    monkeypatch.setattr(module, anchor, hashlib.sha256(signed[2]).hexdigest(), raising=False)
    with pytest.raises(error, match="nuclei_current_promotion_claim_invalid"):
        _verify("bundle", document, kwargs, verifier, signed)
