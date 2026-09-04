from __future__ import annotations

import ast
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SOURCES = (
    ROOT / "redagent_platform/campaign_service/approval_contracts.py",
    ROOT / "redagent_platform/campaign_service/application_service.py",
    ROOT / "redagent_platform/campaign_service/application_repository.py",
    ROOT / "redagent_platform/campaign_service/approval_api.py",
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


def test_r172_boundary_has_no_execution_admission_or_network_imports() -> None:
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


def test_r172_extends_the_single_application_service_and_has_no_client_trust_fields() -> None:
    service = (ROOT / "redagent_platform/campaign_service/application_service.py").read_text(encoding="utf-8")
    contracts = (ROOT / "redagent_platform/campaign_service/approval_contracts.py").read_text(encoding="utf-8")
    assert service.count("class AutonomousCampaignApplicationService") == 1
    assert "class AutonomousCampaignApprovalService" not in service
    assert "CampaignPlanAdmissionService" not in service
    for forbidden in (
        "client_approved",
        "model_approved",
        "admission_ready=True",
        "start_ready=True",
        "start_workflow",
        "dispatch_runner",
    ):
        assert forbidden not in service
        assert forbidden not in contracts
