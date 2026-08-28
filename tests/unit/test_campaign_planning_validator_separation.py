from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def test_validator_has_no_planner_runner_transport_or_external_io_dependency() -> None:
    source_path = ROOT / "redagent_platform" / "campaign_service" / "planning" / "validation.py"
    source = source_path.read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported_modules = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
    imported_modules.update(node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom))
    forbidden_fragments = (
        "strategy",
        "planner",
        "runner",
        "transport",
        "connector",
        "credential",
        "persistence",
        "requests",
        "httpx",
        "subprocess",
        "socket",
    )
    assert not {
        module for module in imported_modules if any(fragment in module.casefold() for fragment in forbidden_fragments)
    }
    assert "execute(" not in source
    assert "callback" not in source.casefold()
