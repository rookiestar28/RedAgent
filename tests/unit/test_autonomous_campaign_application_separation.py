from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    ROOT / "redagent_platform/campaign_service/application_contracts.py",
    ROOT / "redagent_platform/campaign_service/application_service.py",
    ROOT / "redagent_platform/campaign_service/application_repository.py",
)
FORBIDDEN_IMPORT_PARTS = {
    "runner",
    "adapter",
    "transport",
    "credential",
    "provider",
    "plugin",
    "temporal",
    "socket",
    "subprocess",
    "urllib",
    "httpx",
    "requests",
}


def test_r171_application_boundary_has_no_execution_or_network_imports() -> None:
    for path in SOURCES:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        imported: list[str] = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported.extend(alias.name for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                imported.append(node.module)
        parts = {part for name in imported for part in name.lower().replace("-", "_").split(".")}
        assert FORBIDDEN_IMPORT_PARTS.isdisjoint(parts), (path.name, sorted(parts & FORBIDDEN_IMPORT_PARTS))


def test_r171_has_one_application_service_definition_and_no_legacy_fallback_call() -> None:
    source = (ROOT / "redagent_platform/campaign_service/application_service.py").read_text(encoding="utf-8")
    tree = ast.parse(source)
    definitions = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.ClassDef) and node.name == "AutonomousCampaignApplicationService"
    ]
    assert len(definitions) == 1
    assert "CampaignStartService" not in source
    assert "CampaignCoreService" not in source
