"""Promoted compat_108 emulator profiles and disabled external adapter declarations."""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from redagent_platform.cloud_connectors.contracts import (
    DataClass,
    OperationManifest,
    ProviderIdentity,
    ProviderKind,
    ProviderProfile,
)


@dataclass(frozen=True, kw_only=True)
class AdapterDeclaration:
    adapter_id: str
    source_url: str
    license_id: str
    execution_enabled: bool
    production_qualified: bool
    dedicated_service_account_required: bool = False
    host_access_allowed: bool = False


def emulator_profiles() -> Mapping[ProviderKind, ProviderProfile]:
    identities = {
        ProviderKind.AWS: ProviderIdentity(provider=ProviderKind.AWS, tenant="123456789012"),
        ProviderKind.AZURE: ProviderIdentity(provider=ProviderKind.AZURE, tenant="subscription-r108"),
        ProviderKind.GCP: ProviderIdentity(provider=ProviderKind.GCP, tenant="project-r108"),
        ProviderKind.KUBERNETES: ProviderIdentity(provider=ProviderKind.KUBERNETES, tenant="cluster-r108"),
    }
    operations = {
        ProviderKind.AWS: OperationManifest(
            operation_id="aws-iam-list-roles-v1", action="iam:ListRoles",
            resource_scope="arn:aws:iam::123456789012:role/*",
            data_class=DataClass.SECURITY_CONFIGURATION, mutation=False, paginated=True, page_cost=1,
        ),
        ProviderKind.AZURE: OperationManifest(
            operation_id="azure-resource-list-v1", action="Microsoft.Resources/subscriptions/resources/read",
            resource_scope="subscription-r108", data_class=DataClass.RESOURCE_METADATA,
            mutation=False, paginated=True, page_cost=1,
        ),
        ProviderKind.GCP: OperationManifest(
            operation_id="gcp-assets-search-v1", action="cloudasset.assets.searchAllResources",
            resource_scope="project-r108", data_class=DataClass.RESOURCE_METADATA,
            mutation=False, paginated=True, page_cost=1,
        ),
        ProviderKind.KUBERNETES: OperationManifest(
            operation_id="kubernetes-pods-list-v1", action="list:pods",
            resource_scope="namespace:payments", data_class=DataClass.SECURITY_CONFIGURATION,
            mutation=False, paginated=True, page_cost=1,
        ),
    }
    return MappingProxyType({
        provider: ProviderProfile(
            profile_id=f"r108-{provider.value}-emulator-v1",
            provider=provider,
            enabled=True,
            emulator_only=True,
            expected_identity=identity,
            operations=(operations[provider],),
            max_api_calls=8,
            max_pages=6,
            max_resources=32,
            max_response_bytes=32_768,
            timeout_seconds=20,
            allow_redirects=False,
            allow_proxies=False,
            allow_ambient_credentials=False,
        )
        for provider, identity in identities.items()
    })


def adapter_declarations() -> tuple[AdapterDeclaration, ...]:
    # IMPORTANT: declarations are design metadata only; compat_108 never imports or executes these projects.
    return (
        AdapterDeclaration(adapter_id="checkov", source_url="https://github.com/bridgecrewio/checkov", license_id="Apache-2.0", execution_enabled=False, production_qualified=False),
        AdapterDeclaration(adapter_id="kube-bench", source_url="https://github.com/aquasecurity/kube-bench", license_id="Apache-2.0", execution_enabled=False, production_qualified=False, dedicated_service_account_required=True, host_access_allowed=False),
        AdapterDeclaration(adapter_id="prowler", source_url="https://github.com/prowler-cloud/prowler", license_id="Apache-2.0", execution_enabled=False, production_qualified=False),
        AdapterDeclaration(adapter_id="trivy", source_url="https://github.com/aquasecurity/trivy", license_id="Apache-2.0", execution_enabled=False, production_qualified=False),
    )
