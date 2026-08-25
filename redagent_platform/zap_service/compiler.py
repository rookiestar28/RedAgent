"""Deterministic compiler from closed compat_104 profiles to reviewed ZAP jobs."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from typing import Any, Mapping

from redagent_platform.zap_service.contracts import (
    ApprovalClass,
    CertifiedProfileId,
    GATEWAY_ENDPOINT,
    ZapAuthorization,
    ZapTargetBinding,
    certified_profiles,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class CompiledZapPlan:
    profile_id: CertifiedProfileId
    target_id: str
    policy_decision_id: str
    plan: Mapping[str, Any]
    plan_sha256: str


def compile_zap_plan(
    *, profile_id: CertifiedProfileId, target: ZapTargetBinding,
    authorization: ZapAuthorization, now: datetime,
) -> CompiledZapPlan:
    if not isinstance(profile_id, CertifiedProfileId):
        raise ValueError("zap_profile_unknown")
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("zap_compile_time_timezone_required")
    if not authorization.approved_at <= now < authorization.expires_at:
        raise ValueError("zap_authorization_expired")
    if not target.issued_at <= now < target.expires_at:
        raise ValueError("zap_target_expired")
    if profile_id not in authorization.approved_profile_ids:
        raise ValueError("zap_profile_not_approved")
    profile = certified_profiles()[profile_id]
    if authorization.approval_class is not profile.approval_class:
        raise ValueError("zap_approval_class_mismatch")
    if tuple(target.allowed_paths) != profile.allowed_paths:
        if profile_id is CertifiedProfileId.ACTIVE_XSS_LAB:
            raise ValueError("zap_active_path_required")
        raise ValueError("zap_target_paths_mismatch")
    if profile.requires_credential and len(authorization.credential_reference_ids) != 1:
        raise ValueError("zap_credential_required")
    if not profile.requires_credential and authorization.credential_reference_ids:
        raise ValueError("zap_credentials_forbidden")

    active = profile_id is CertifiedProfileId.ACTIVE_XSS_LAB
    seed_url = f"{GATEWAY_ENDPOINT}{profile.allowed_paths[0]}" + ("?q=r104-seed" if active else "")
    include_paths = [rf"\Q{GATEWAY_ENDPOINT}{path}\E" for path in profile.allowed_paths]
    if active:
        include_paths = [rf"\Q{GATEWAY_ENDPOINT}{profile.allowed_paths[0]}\E(?:\?q=[^#]{{0,2048}})?"]
    allowed_suffix = "(?:\\?q=[^#]{0,2048})?" if active else ""
    context = {
        "name": f"redagent-{profile_id.value}",
        "urls": [seed_url],
        "includePaths": include_paths,
        "excludePaths": [
            rf"^(?!{_escaped_origin()}(?:{'|'.join(_escaped_path(path) for path in profile.allowed_paths)})"
            rf"{allowed_suffix}$).*$"
        ],
    }
    jobs = _jobs(profile_id)
    plan: dict[str, Any] = {
        "env": {
            "contexts": [context],
            "parameters": {
                "failOnError": True,
                "failOnWarning": False,
                "progressToStdout": False,
            },
        },
        "jobs": jobs,
        "parameters": {
            "requestLimit": profile.request_limit,
            "requestRatePerSecond": profile.request_rate_per_second,
            "concurrency": profile.concurrency,
            "timeoutSeconds": profile.timeout_seconds,
            "responseBytesLimit": profile.response_bytes_limit,
        },
        "redagent": {
            "schema": "redagent.zap-plan/v1", "profileId": profile_id.value,
            "targetId": target.target_id, "targetAttestationSha256": target.attestation_sha256,
            "policyDecisionId": authorization.policy_decision_id,
            "policyRevision": authorization.policy_revision, "roeVersionId": authorization.roe_version_id,
        },
    }
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return CompiledZapPlan(
        profile_id=profile_id, target_id=target.target_id,
        policy_decision_id=authorization.policy_decision_id,
        plan=plan, plan_sha256=hashlib.sha256(encoded).hexdigest(),
    )


def _jobs(profile_id: CertifiedProfileId) -> list[dict[str, Any]]:
    start_url = f"{GATEWAY_ENDPOINT}{certified_profiles()[profile_id].allowed_paths[0]}"
    if profile_id is CertifiedProfileId.ACTIVE_XSS_LAB:
        start_url += "?q=r104-seed"
    if profile_id in {CertifiedProfileId.PASSIVE, CertifiedProfileId.AUTHENTICATED_CRAWL}:
        return [
            {"type": "spider", "parameters": {
                "context": f"redagent-{profile_id.value}", "url": start_url, "maxDuration": 2,
            }},
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}},
        ]
    if profile_id is CertifiedProfileId.CLIENT_SPIDER:
        return [
            {"type": "spider", "parameters": {
                "context": f"redagent-{profile_id.value}", "url": start_url, "maxDuration": 2,
            }},
            {"type": "spiderClient", "parameters": {
                "context": f"redagent-{profile_id.value}", "scopeCheck": "Strict", "url": start_url,
                "maxDuration": 5, "maxCrawlDepth": 3, "maxChildren": 20, "numberOfBrowsers": 1,
            }},
            {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}},
        ]
    return [
        {"type": "spider", "parameters": {
            "context": f"redagent-{profile_id.value}", "url": start_url, "maxDuration": 1,
        }},
        {"type": "passiveScan-wait", "parameters": {"maxDuration": 1}},
        {"type": "activeScan", "parameters": {
            "context": f"redagent-{profile_id.value}", "maxScanDurationInMins": 5,
            "threadPerHost": 1, "maxRuleDurationInMins": 5,
        }, "policyDefinition": {
            "defaultStrength": "Medium", "defaultThreshold": "Off",
            "rules": [{"id": 40012, "name": "Reflected Cross Site Scripting", "threshold": "Medium", "strength": "Medium"}],
        }},
        {"type": "passiveScan-wait", "parameters": {"maxDuration": 2}},
    ]


def _escaped_origin() -> str:
    return r"http://redagent\-r104\-gateway:8080"


def _escaped_path(path: str) -> str:
    return path.replace("-", r"\-")
