"""Fail-closed runtime construction for the pre-identity compat_093 API."""

from __future__ import annotations

import ipaddress
import os
from pathlib import Path
from typing import Mapping

from fastapi import FastAPI

from redagent_platform.api.app import create_app
from redagent_platform.api.schemas import OperatorShellContextData
from redagent_platform.campaign_service.composition import (
    build_stock_campaign_api_service_factory,
)
from redagent_platform.campaign_service.qualification import (
    CampaignQualificationService,
    CampaignStatusService,
)
from redagent_platform.campaign_service.registry import StrategyLoopMode, load_strategy_loop_mode
from redagent_platform.campaign_service.status import CampaignStatusOwner
from redagent_platform.evidence_service.config import load_evidence_settings
from redagent_platform.evidence_service.runtime import (
    EvidenceRuntimeError,
    build_evidence_backend,
)
from redagent_platform.identity.bff import IdentityRuntime
from redagent_platform.identity.config import load_oidc_provider_config
from redagent_platform.identity.http_transport import HttpOidcTransport
from redagent_platform.identity.session_security import SessionCipher
from redagent_platform.orchestration.config import load_temporal_settings
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.policy_service.config import load_policy_settings
from redagent_platform.policy_service.runtime import build_policy_provider


class ApiRuntimeError(ValueError):
    """Raised before server startup when the compat_093 runtime boundary is unsafe."""


def derive_operator_shell_context(env: Mapping[str, str]) -> OperatorShellContextData:
    """Derive bounded display context from server-owned, already governed profiles."""
    environment_value = env.get("REDAGENT_PROFILE", "").strip().lower()
    environment = environment_value if environment_value in {"local", "production"} else "unknown"
    safety_value = env.get("REDAGENT_POLICY_PROFILE", "").strip().lower()
    compatible = (
        environment == "local" and safety_value in {"synthetic-local", "local-conformance"}
    ) or (environment == "production" and safety_value == "production")
    # CRITICAL: missing or cross-environment profile identity must render unavailable, never safe.
    safety_profile = safety_value if compatible else "unknown"
    return OperatorShellContextData(
        environment=environment,
        safety_profile=safety_profile,
        status="ready" if compatible else "unavailable",
    )


def validate_runtime_bind(
    host: str,
    port: int,
    *,
    private_cluster_bind: bool = False,
) -> tuple[str, int]:
    normalized = host.strip()
    try:
        address = ipaddress.ip_address(normalized)
        if not address.is_loopback and not (private_cluster_bind and address.is_unspecified):
            raise ApiRuntimeError("api_bind_must_be_loopback")
    except ValueError as exc:
        raise ApiRuntimeError("api_bind_must_be_loopback") from exc
    if isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ApiRuntimeError("api_port_invalid")
    return normalized, port


def validate_runtime_tls(
    *,
    private_cluster_bind: bool,
    certificate_file: Path | None,
    private_key_file: Path | None,
) -> tuple[str | None, str | None]:
    if (certificate_file is None) != (private_key_file is None):
        raise ApiRuntimeError("api_tls_pair_required")
    if private_cluster_bind and certificate_file is None:
        raise ApiRuntimeError("api_private_cluster_tls_required")
    if certificate_file is None or private_key_file is None:
        return None, None
    if not certificate_file.is_file() or not private_key_file.is_file():
        raise ApiRuntimeError("api_tls_file_unavailable")
    return str(certificate_file), str(private_key_file)


def validate_api_runtime_dependencies(
    env: Mapping[str, str],
    *,
    qualification_service: object | None,
    status_service: CampaignStatusService,
    campaign_status_owner: object | None = None,
    service_factory: object | None = None,
) -> StrategyLoopMode:
    """Keep the configured compat_123 mode and composed API services fail-closed."""
    mode = load_strategy_loop_mode(env)
    if mode is StrategyLoopMode.TWO_CAPABILITY:
        if service_factory is not None:
            if (
                qualification_service is not None
                or status_service.mode is not StrategyLoopMode.DISABLED
                or campaign_status_owner is not None
            ):
                raise ApiRuntimeError("r123_api_runtime_services_ambiguous")
            return mode
        if qualification_service is None or status_service.mode is not mode:
            raise ApiRuntimeError("r123_api_runtime_services_required")
        return mode
    if (
        qualification_service is not None
        or status_service.mode is not mode
        or campaign_status_owner is not None
        or service_factory is not None
    ):
        raise ApiRuntimeError("r123_api_runtime_services_forbidden_when_disabled")
    return mode


def build_runtime_app(
    workspace: Path,
    *,
    env: Mapping[str, str] | None = None,
    test_issuer_enabled: bool = False,
    r123_qualification_service: CampaignQualificationService | None = None,
    r123_status_service: CampaignStatusService | None = None,
    r123_campaign_status_owner: CampaignStatusOwner | None = None,
) -> FastAPI:
    values = dict(os.environ if env is None else env)
    operator_shell_context = derive_operator_shell_context(values)
    selected_r123_status = r123_status_service or CampaignStatusService(
        StrategyLoopMode.DISABLED,
        None,
    )
    settings = load_database_settings(workspace, env=values)
    identity_values = {
        "config": values.get("REDAGENT_IDENTITY_CONFIG_FILE", "").strip(),
        "provider": values.get("REDAGENT_IDENTITY_PROVIDER_ID", "").strip(),
        "key": values.get("REDAGENT_SESSION_KEY_FILE", "").strip(),
        "origin": values.get("REDAGENT_PUBLIC_ORIGIN", "").strip(),
    }
    present = {name for name, value in identity_values.items() if value}
    if present and len(present) != len(identity_values):
        raise ApiRuntimeError("identity_runtime_configuration_incomplete")
    identity_runtime = None
    if present:
        root = workspace.resolve()
        config_path = _workspace_path(root, identity_values["config"], "identity_config")
        key_path = _workspace_path(root, identity_values["key"], "session_key")
        provider = load_oidc_provider_config(root, config_path, provider_id=identity_values["provider"])
        identity_runtime = IdentityRuntime(
            config=provider,
            cipher=SessionCipher.load(root, key_path),
            transport=HttpOidcTransport(),
            public_origin=identity_values["origin"],
        )
    temporal_names = (
        "REDAGENT_TEMPORAL_TARGET",
        "REDAGENT_TEMPORAL_NAMESPACE",
        "REDAGENT_TEMPORAL_TASK_QUEUE",
        "REDAGENT_TEMPORAL_CODEC_KEY_FILE",
        "REDAGENT_TEMPORAL_CODEC_KEY_ID",
        "REDAGENT_TEMPORAL_TLS",
    )
    temporal_present = {name for name in temporal_names if values.get(name, "").strip()}
    if temporal_present and len(temporal_present) != len(temporal_names):
        raise ApiRuntimeError("temporal_runtime_configuration_incomplete")
    temporal_settings = load_temporal_settings(workspace, env=values) if temporal_present else None
    static_value = values.get("REDAGENT_STATIC_DIRECTORY", "").strip()
    static_directory = (
        _workspace_path(workspace.resolve(), static_value, "static_directory")
        if static_value
        else None
    )
    evidence_names = (
        "REDAGENT_EVIDENCE_PROFILE",
        "REDAGENT_EVIDENCE_BACKEND",
    )
    evidence_present = {name for name in evidence_names if values.get(name, "").strip()}
    if evidence_present and len(evidence_present) != len(evidence_names):
        raise ApiRuntimeError("evidence_runtime_configuration_incomplete")
    evidence_settings = load_evidence_settings(workspace, values) if evidence_present else None
    try:
        evidence_backend = (
            build_evidence_backend(evidence_settings, values)
            if evidence_settings
            else None
        )
    except EvidenceRuntimeError as exc:
        raise ApiRuntimeError(str(exc)) from exc
    r123_service_factory = None
    explicit_r123_services = any(
        service is not None
        for service in (
            r123_qualification_service,
            r123_status_service,
            r123_campaign_status_owner,
        )
    )
    if (
        load_strategy_loop_mode(values) is StrategyLoopMode.TWO_CAPABILITY
        and not explicit_r123_services
    ):
        try:
            r123_service_factory = build_stock_campaign_api_service_factory(
                workspace,
                values,
                evidence_backend=evidence_backend,
            )
        except (EvidenceRuntimeError, ValueError) as exc:
            raise ApiRuntimeError(str(exc)) from exc
    validate_api_runtime_dependencies(
        values,
        qualification_service=r123_qualification_service,
        status_service=selected_r123_status,
        campaign_status_owner=r123_campaign_status_owner,
        service_factory=r123_service_factory,
    )
    policy_names = ("REDAGENT_POLICY_PROFILE", "REDAGENT_POLICY_PROVIDER")
    policy_present = {name for name in policy_names if values.get(name, "").strip()}
    if policy_present and len(policy_present) != len(policy_names):
        raise ApiRuntimeError("policy_runtime_configuration_incomplete")
    policy_settings = load_policy_settings(workspace, values) if policy_present else None
    policy_provider = build_policy_provider(policy_settings) if policy_settings else None
    return create_app(
        database_settings=settings,
        test_issuer_enabled=test_issuer_enabled,
        identity_runtime=identity_runtime,
        static_directory=static_directory,
        temporal_settings=temporal_settings,
        evidence_backend=evidence_backend,
        evidence_kms_reference=evidence_settings.kms_reference if evidence_settings else None,
        synthetic_evidence_enabled=bool(
            evidence_settings and evidence_settings.profile in {"synthetic-local", "local-conformance"}
        ),
        policy_provider=policy_provider,
        policy_required_revision=policy_settings.required_revision if policy_settings else None,
        r123_qualification_service=r123_qualification_service,
        r123_status_service=r123_status_service,
        r123_campaign_status_owner=r123_campaign_status_owner,
        r123_service_factory=r123_service_factory,
        operator_shell_context=operator_shell_context,
    )

def _workspace_path(workspace: Path, value: str, name: str) -> Path:
    path = Path(value)
    resolved = (path if path.is_absolute() else workspace / path).resolve()
    if not resolved.is_relative_to(workspace):
        raise ApiRuntimeError(f"{name}_outside_workspace")
    return resolved
