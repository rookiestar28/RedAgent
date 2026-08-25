"""Promoted compat_109 loopback profiles and disabled external project declarations."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from redagent_platform.identity_saas.contracts import ConsentMode, IdentityDataClass, IdentityOperation, IdentityProvider, IdentityProviderProfile


@dataclass(frozen=True, kw_only=True)
class IdentityAdapterDeclaration:
    adapter_id: str
    source_url: str
    execution_enabled: bool
    production_qualified: bool


def emulator_profiles() -> Mapping[IdentityProvider, IdentityProviderProfile]:
    values = {
        IdentityProvider.MICROSOFT_365: ("tenant-r109-m365", "graph-microsoft-r109", ConsentMode.APPLICATION, IdentityOperation(
            operation_id="m365-organization-get-v1", method="GET", api_version="v1.0",
            permission_scope="Organization.Read.All", effective_role_permission="Organization.Read.All",
            selected_fields=("id", "displayName", "tenantType"), data_class=IdentityDataClass.SECURITY_CONFIGURATION,
            paginated=False, graph_eligible=False,
        )),
        IdentityProvider.GOOGLE_WORKSPACE: ("customer-r109-google", "admin-google-r109", ConsentMode.DOMAIN_WIDE_DELEGATION, IdentityOperation(
            operation_id="google-groups-list-v1", method="GET", api_version="directory-v1",
            permission_scope="admin.directory.group.readonly", effective_role_permission="groups.readonly",
            selected_fields=("id", "name", "directMembersCount"), data_class=IdentityDataClass.DIRECTORY_METADATA,
            paginated=True, graph_eligible=True,
        )),
        IdentityProvider.OKTA: ("org-r109-okta", "okta-api-r109", ConsentMode.APPLICATION, IdentityOperation(
            operation_id="okta-groups-list-v1", method="GET", api_version="v1",
            permission_scope="okta.groups.read", effective_role_permission="okta.groups.read",
            selected_fields=("id", "type", "created"), data_class=IdentityDataClass.DIRECTORY_METADATA,
            paginated=True, graph_eligible=True,
        )),
    }
    return MappingProxyType({provider: IdentityProviderProfile(
        profile_id=f"r109-{provider.value}-emulator-v1", provider=provider, enabled=True, emulator_only=True,
        tenant_id=tenant, audience=audience, consent_mode=consent, operations=(operation,),
        max_calls=8, max_pages=6, max_resources=32, max_bytes=32_768, timeout_seconds=20,
        snapshot_retention_days=7,
    ) for provider, (tenant, audience, consent, operation) in values.items()})


def adapter_declarations() -> tuple[IdentityAdapterDeclaration, ...]:
    # IMPORTANT: external projects are architecture references only and are never imported or executed.
    return (
        IdentityAdapterDeclaration(adapter_id="scubagear", source_url="https://github.com/cisagov/ScubaGear", execution_enabled=False, production_qualified=False),
        IdentityAdapterDeclaration(adapter_id="scubagoggles", source_url="https://github.com/cisagov/ScubaGoggles", execution_enabled=False, production_qualified=False),
        IdentityAdapterDeclaration(adapter_id="prowler", source_url="https://github.com/prowler-cloud/prowler", execution_enabled=False, production_qualified=False),
    )
