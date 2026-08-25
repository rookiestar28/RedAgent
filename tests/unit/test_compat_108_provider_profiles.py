from redagent_platform.cloud_connectors.contracts import ProviderKind
from redagent_platform.cloud_connectors.profiles import adapter_declarations, emulator_profiles


def test_all_provider_shapes_have_exact_enabled_emulator_profiles() -> None:
    profiles = emulator_profiles()
    assert set(profiles) == set(ProviderKind)
    for provider, profile in profiles.items():
        assert profile.provider is provider
        assert profile.enabled is True and profile.emulator_only is True
        assert profile.allow_redirects is False
        assert profile.allow_proxies is False
        assert profile.allow_ambient_credentials is False
        assert profile.operations
        assert all("*" not in operation.action for operation in profile.operations)
        assert all(operation.mutation is False for operation in profile.operations)


def test_external_adapters_are_replaceable_disabled_and_not_production_qualified() -> None:
    declarations = adapter_declarations()
    assert {item.adapter_id for item in declarations} == {
        "checkov",
        "kube-bench",
        "prowler",
        "trivy",
    }
    assert all(item.execution_enabled is False for item in declarations)
    assert all(item.production_qualified is False for item in declarations)
    assert all(item.source_url.startswith("https://github.com/") for item in declarations)
    kube_bench = next(item for item in declarations if item.adapter_id == "kube-bench")
    assert kube_bench.dedicated_service_account_required is True
    assert kube_bench.host_access_allowed is False
