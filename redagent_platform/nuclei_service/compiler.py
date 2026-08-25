"""Deterministic closed argv compiler for R105."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json

from redagent_platform.nuclei_service.contracts import (
    GATEWAY_ENDPOINT,
    NucleiAuthorization,
    NucleiBundleManifest,
    NucleiProfileId,
    NucleiTargetBinding,
    certified_profiles,
)


@dataclass(frozen=True, kw_only=True)
class CompiledNucleiPlan:
    profile_id: NucleiProfileId
    bundle_id: str
    target_id: str
    argv: tuple[str, ...]
    plan_sha256: str


def compile_nuclei_plan(
    *, profile_id: NucleiProfileId, bundle: NucleiBundleManifest,
    target: NucleiTargetBinding, authorization: NucleiAuthorization, now: datetime,
) -> CompiledNucleiPlan:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("nuclei_time_invalid")
    profile = certified_profiles()[profile_id]
    if now < bundle.promoted_at:
        raise ValueError("nuclei_bundle_not_yet_valid")
    if bundle.expires_at <= now:
        raise ValueError("nuclei_bundle_expired")
    if now < target.issued_at:
        raise ValueError("nuclei_target_not_yet_valid")
    if target.expires_at <= now:
        raise ValueError("nuclei_target_expired")
    if now < authorization.approved_at:
        raise ValueError("nuclei_authorization_not_yet_valid")
    if authorization.expires_at <= now:
        raise ValueError("nuclei_authorization_expired")
    if profile_id not in authorization.approved_profile_ids:
        raise ValueError("nuclei_profile_not_approved")
    if authorization.approved_bundle_id != bundle.bundle_id:
        raise ValueError("nuclei_bundle_not_approved")
    if target.endpoint != GATEWAY_ENDPOINT or target.allowed_paths != bundle.paths:
        raise ValueError("nuclei_target_binding_mismatch")
    argv = (
        "-target", GATEWAY_ENDPOINT,
        "-templates", f"/opt/redagent/bundle/{bundle.template_relative_path}",
        "-template-id", bundle.template_id, "-disable-unsigned-templates",
        "-disable-update-check", "-no-interactsh", "-no-stdin", "-jsonl-export",
        "/work/results.jsonl", "-omit-raw", "-omit-template", "-rate-limit",
        str(profile.request_rate_per_second), "-concurrency", str(profile.concurrency),
        "-bulk-size", "1", "-timeout", "5", "-retries", "0",
        "-response-size-read", "1048576", "-response-size-save", "0", "-silent", "-no-color",
    )
    canonical = {
        "schema": "redagent.r105-plan/v1", "profile_id": profile_id.value,
        "bundle_id": bundle.bundle_id, "bundle_sha256": bundle.bundle_sha256,
        "target_id": target.target_id, "target_attestation_sha256": target.attestation_sha256,
        "policy_decision_id": authorization.policy_decision_id,
        "policy_revision": authorization.policy_revision, "roe_version_id": authorization.roe_version_id,
        "argv": argv,
    }
    digest = hashlib.sha256(json.dumps(canonical, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return CompiledNucleiPlan(
        profile_id=profile_id, bundle_id=bundle.bundle_id, target_id=target.target_id,
        argv=argv, plan_sha256=digest,
    )
