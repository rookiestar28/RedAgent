"""Shared fail-closed construction for configured policy decision providers."""

from __future__ import annotations

import ssl

import httpx

from redagent_platform.policy_service.config import PolicySettings
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider
from redagent_platform.policy_service.providers import OpaPolicyDecisionProvider


def build_policy_provider(
    settings: PolicySettings,
) -> DeterministicFakePolicyProvider | OpaPolicyDecisionProvider:
    if not isinstance(settings, PolicySettings):
        raise ValueError("policy_runtime_settings_invalid")
    if settings.provider == "fake":
        return DeterministicFakePolicyProvider(revision="synthetic-r099-v1")
    if (
        settings.provider != "opa"
        or settings.endpoint is None
        or settings.token_file is None
        or settings.required_revision is None
    ):
        raise ValueError("policy_runtime_configuration_incomplete")
    verify: bool | ssl.SSLContext = True
    if settings.profile == "local-conformance":
        verify = False
    elif settings.ca_file is not None:
        context = ssl.create_default_context(cafile=str(settings.ca_file))
        if settings.client_cert_file is None or settings.client_key_file is None:
            raise ValueError("policy_runtime_mtls_configuration_incomplete")
        context.load_cert_chain(
            str(settings.client_cert_file), str(settings.client_key_file)
        )
        verify = context
    client = httpx.AsyncClient(verify=verify, timeout=2.0)
    token_file = settings.token_file
    return OpaPolicyDecisionProvider(
        client,
        endpoint=settings.endpoint,
        token_source=lambda: token_file.read_text(encoding="utf-8").strip(),
    )
