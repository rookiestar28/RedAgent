from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def _imports(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    values = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
    }
    values.update(node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))
    return values


def test_planner_has_no_dag_execution_or_runner_dependency() -> None:
    planner = ROOT / "redagent_platform/campaign_service/planning/search.py"
    assert not {
        item
        for item in _imports(planner)
        if "dag_execution" in item or "runner" in item or "dispatch" in item
    }


def test_dag_reducer_has_no_temporal_database_policy_runner_or_io_dependency() -> None:
    reducer = ROOT / "redagent_platform/campaign_service/dag_execution.py"
    forbidden = ("temporal", "sqlalchemy", "policy", "runner", "http", "socket", "subprocess")
    assert not {item for item in _imports(reducer) if any(part in item for part in forbidden)}
    tree = ast.parse(reducer.read_text(encoding="utf-8"))
    calls = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert not calls.intersection({"open", "exec", "eval", "compile", "__import__"})


def test_public_dag_sources_contain_no_internal_planning_trace() -> None:
    for name in ("dag_execution.py", "dag_execution_contracts.py"):
        source = (ROOT / "redagent_platform/campaign_service" / name).read_text(encoding="utf-8")
        lowered = source.casefold()
        assert ".planning/" not in lowered
        assert "roadmap" not in lowered


def test_public_product_sources_contain_no_current_private_item_code() -> None:
    sources = sorted((ROOT / "redagent_platform").rglob("*.py"))
    sources.extend(
        (
            ROOT / "scripts/redagent_workflow_worker.py",
            ROOT / "migrations/versions/0027_campaign_dag_execution.py",
        )
    )

    traces = [
        path.relative_to(ROOT).as_posix()
        for path in sources
        if "r159" in path.read_text(encoding="utf-8").casefold()
    ]
    assert traces == []
