from __future__ import annotations

import importlib

import pytest


def _module(name: str):
    try:
        return importlib.import_module(f"redagent_platform.agent_kernel.{name}")
    except ModuleNotFoundError:
        pytest.fail(f"compat_113 RED: qualification module {name!r} is not implemented")


def test_catalog_projects_all_nine_certified_r104_r112_capabilities_without_broadening() -> None:
    qualification = _module("qualification")
    capabilities = qualification.certified_capability_catalog()
    tools = qualification.build_projection_catalog(capabilities)
    assert len(capabilities) == len(tools) == 9
    assert {item.capability_id for item in capabilities} == {
        "zap-controlled-runtime", "nuclei-trusted-runtime", "api-authorization-differential",
        "network-assessment", "cloud-posture", "identity-posture", "artifact-posture",
        "purple-lab", "human-simulation-sink",
    }
    assert all(tool.source_capability_id in {item.capability_id for item in capabilities} for tool in tools)
    assert all(set(tool.input_schema["properties"]) == {"plan_id"} for tool in tools)
    assert all(tool.tool_kind.value == "proposal" and tool.approval_tier == "high" for tool in tools)


def test_deterministic_qualification_denies_adversarial_calls_and_has_zero_external_authority() -> None:
    qualification = _module("qualification")
    receipt = qualification.qualify_agent_kernel()
    assert receipt["status"] == "passed"
    assert receipt["provider_id"] == "deterministic-fake"
    assert receipt["projected_capability_count"] == 9
    assert receipt["adversarial_case_count"] == receipt["denied_case_count"]
    assert receipt["adversarial_case_count"] >= 12
    assert receipt["external_contact_count"] == 0
    assert receipt["direct_dispatch_count"] == 0
    assert receipt["sensitive_retention_count"] == 0
    assert receipt["provider_storage_enabled"] is False
    assert receipt["parallel_tool_calls_enabled"] is False
    assert receipt["background_enabled"] is False
    assert receipt["registry_sha256"] and receipt["receipt_sha256"]
