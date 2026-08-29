from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
SERVICE = ROOT / "redagent_platform/campaign_service/service.py"
DAG_OWNER = ROOT / "redagent_platform/campaign_service/dag_manifest_lineage.py"
CONTROL = ROOT / "redagent_platform/persistence/repository.py"


def test_manifest_issuer_has_injected_strategy_lineage_owner_by_default() -> None:
    source = SERVICE.read_text(encoding="utf-8")

    assert "class ManifestLineageOwner(Protocol):" in source
    assert "class StrategyManifestLineageOwner:" in source
    assert "lineage_owner: ManifestLineageOwner | None = None" in source
    assert (
        "self._lineage_owner = lineage_owner or StrategyManifestLineageOwner()"
        in source
    )
    assert "await self._lineage_owner.prepare(" in source


def test_dag_manifest_owner_creates_only_execution_lineage_job() -> None:
    source = DAG_OWNER.read_text(encoding="utf-8")

    assert "class PostgresDagManifestLineageOwner:" in source
    assert "create_campaign_execution_runner_job(" in source
    assert "execution_run_id=" in source
    assert "strategy_revision_id=" not in source
    assert "read_effect_manifest_context" not in source


def test_execution_runner_job_repository_rechecks_claimed_shared_effect() -> None:
    source = CONTROL.read_text(encoding="utf-8")
    method = source.split("async def create_campaign_execution_runner_job(", 1)[1]
    method = method.split("\n    async def ", 1)[0]

    assert "effects.c.execution_run_id == normalized_run" in method
    assert "effects.c.strategy_revision_id.is_(None)" in method
    assert "effects.c.effect_state == \"claimed\"" in method
    assert "jobs.c.execution_run_id" not in method
    assert "execution_run_id=normalized_run" in method
    assert "strategy_revision_id=None" in method
