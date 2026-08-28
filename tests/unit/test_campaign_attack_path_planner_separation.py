from __future__ import annotations

import ast
from dataclasses import fields, replace
from pathlib import Path
import subprocess
import sys

from redagent_platform.campaign_service.planning.search_contracts import (
    AttackPathDagRevisionV1,
    AttackPathPlannerResultV1,
    SearchReceiptV1,
)
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_planning_contracts import authority, domain, world
from redagent_platform.campaign_service.planning.search import plan_attack_path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def _imports(source: str) -> set[str]:
    tree = ast.parse(source)
    imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported.update(node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))
    return imported


def test_planner_has_no_validator_runner_model_transport_credential_or_external_io_dependency() -> None:
    source_path = ROOT / "redagent_platform" / "campaign_service" / "planning" / "search.py"
    source = source_path.read_text(encoding="utf-8")
    forbidden_fragments = (
        "validation",
        "strategy",
        "runner",
        "transport",
        "connector",
        "credential",
        "persistence",
        "provider",
        "model",
        "requests",
        "httpx",
        "subprocess",
        "socket",
        "pathlib",
        "os",
        "time",
    )
    assert not {
        module for module in _imports(source) if any(fragment in module.casefold() for fragment in forbidden_fragments)
    }
    tree = ast.parse(source)
    called_names = {
        node.func.id for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not called_names.intersection({"open", "exec", "eval", "compile", "__import__"})


def test_accepted_validator_does_not_depend_on_or_delegate_to_planner() -> None:
    source = (ROOT / "redagent_platform" / "campaign_service" / "planning" / "validation.py").read_text(
        encoding="utf-8"
    )
    assert not any("search" in module or "planner" in module for module in _imports(source))


def test_validator_only_import_does_not_indirectly_load_planner_module() -> None:
    script = """
import sys
import redagent_platform.campaign_service.planning.validation
print(int("redagent_platform.campaign_service.planning.search" in sys.modules))
"""
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    assert completed.stdout.strip() == "0"


def test_planner_contracts_cannot_carry_validation_or_admission_authority() -> None:
    field_names = {
        field.name
        for contract in (AttackPathDagRevisionV1, SearchReceiptV1, AttackPathPlannerResultV1)
        for field in fields(contract)
    }
    assert not field_names.intersection(
        {
            "validation_certificate",
            "validator_signature",
            "admission_receipt",
            "admissible",
            "policy_decision",
            "dispatch_command",
            "execution_payload",
        }
    )


def test_revision_rejects_candidate_binding_and_ordering_substitution() -> None:
    result = plan_attack_path(domain(), authority(), world(), search_limits())
    assert result.revision is not None
    revision = result.revision
    with pytest.raises(ValueError, match="attack_path_dag_candidate_binding_mismatch"):
        replace(revision, tenant_id="tenant-b")
    with pytest.raises(ValueError, match="attack_path_dag_ordering_mismatch"):
        replace(
            revision,
            ordering_key=replace(revision.ordering_key, cumulative_cost_microunits=999),
        )


def test_found_result_rejects_receipt_to_revision_binding_substitution() -> None:
    result = plan_attack_path(domain(), authority(), world(), search_limits())
    assert result.revision is not None
    with pytest.raises(ValueError, match="attack_path_planner_result_receipt_binding_mismatch"):
        replace(result, receipt=replace(result.receipt, authority_sha256="f" * 64))


def test_public_planner_sources_contain_no_internal_item_or_planning_trace() -> None:
    for name in ("search.py", "search_contracts.py"):
        source = (ROOT / "redagent_platform" / "campaign_service" / "planning" / name).read_text(encoding="utf-8")
        lowered = source.casefold()
        assert "r157" not in lowered
        assert ".planning/" not in lowered
        assert ".planning\\" not in lowered
        assert "roadmap" not in lowered
