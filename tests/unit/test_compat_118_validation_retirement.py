from __future__ import annotations

from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata
from scripts import run_legacy_full_gate


ROOT = Path(__file__).resolve().parents[2]

RETIRED_VALIDATION_MODULES = (
    "campaign_admission_adapter.py",
    "campaign_admission_transport.py",
    "campaign_authority.py",
    "campaign_controller.py",
    "campaign_controller_deployment.py",
    "campaign_coverage.py",
    "campaign_runner_attestation.py",
    "campaign_runner_authority.py",
    "campaign_runner_observer.py",
    "campaign_trust.py",
    "shadow.py",
    "shadow_oracle.py",
    "shadow_reuse.py",
)

RETIRED_TEST_PREFIXES = (
    "test_r118_campaign_",
    "test_r118_shadow_",
)

ACTIVE_SCAN_ROOTS = (
    ROOT / "redagent_platform",
    ROOT / "scripts",
    ROOT / ".github" / "workflows",
    ROOT / "config",
)

RETIRED_ACTIVE_TOKENS = (
    *(
        Path(filename).stem
        for filename in RETIRED_VALIDATION_MODULES
        if filename not in {"shadow.py", "campaign_authority.py"}
    ),
    # IMPORTANT: ban the retired validation import precisely; campaign_authority is now an active domain contract.
    "redagent_platform.validation.campaign_authority",
    "from .campaign_authority",
    "redagent_platform.validation.shadow",
    "from .shadow",
    "run_r118_shadow_qualification",
    "require_authoritative_shadow_campaign",
    "omitted_full_gate_failures",
    "r118_campaign_controller_records",
    "r118_campaign_controller_artifacts",
)

TEXT_SUFFIXES = frozenset({".json", ".py", ".ps1", ".sh", ".toml", ".yaml", ".yml"})


def test_unconsumed_r118_validation_families_are_absent_from_active_source_and_gate() -> None:
    validation_root = ROOT / "redagent_platform" / "validation"
    for filename in RETIRED_VALIDATION_MODULES:
        assert not (validation_root / filename).exists(), filename

    assert not (ROOT / "scripts" / "run_r118_shadow_qualification.py").exists()
    assert not any(
        path.name.startswith(RETIRED_TEST_PREFIXES) for path in (ROOT / "tests" / "unit").glob("test_r118_*.py")
    )
    assert not (ROOT / "tests" / "integration" / "test_r118_campaign_controller_repository.py").exists()
    assert not any((ROOT / "tests" / "fixtures").glob("r118_campaign_*.json"))

    validation_init = (validation_root / "__init__.py").read_text(encoding="utf-8")
    gate_runtime = (ROOT / "redagent_platform" / "gate_runtime.py").read_text(encoding="utf-8")
    pre_commit = (ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    for retired_name in ("shadow", "campaign_"):
        assert retired_name not in validation_init
    assert "require_authoritative_shadow_campaign" not in gate_runtime
    assert "r118_campaign_" not in pre_commit

    residual_references: list[str] = []
    for scan_root in ACTIVE_SCAN_ROOTS:
        for path in scan_root.rglob("*"):
            if not path.is_file() or path.suffix.casefold() not in TEXT_SUFFIXES:
                continue
            if path == ROOT / "config" / "public-release-residuals.json":
                continue
            source = path.read_text(encoding="utf-8")
            for token in RETIRED_ACTIVE_TOKENS:
                if token in source:
                    residual_references.append(f"{path.relative_to(ROOT).as_posix()}:{token}")
    assert residual_references == []


def test_current_schema_retires_r118_campaign_controller_tables_additively() -> None:
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == ("0028_observation_replanning")
    assert "r118_campaign_controller_records" not in metadata.tables
    assert "r118_campaign_controller_artifacts" not in metadata.tables

    retirement_migration = ROOT / "migrations" / "versions" / "0024_r118_validation_retirement.py"
    migration_source = retirement_migration.read_text(encoding="utf-8")
    assert 'revision = "0024_r118_retirement"' in migration_source
    assert 'down_revision = "0023_r118_controller"' in migration_source


def test_legacy_full_entry_is_a_thin_alias_for_canonical_forced_g2(monkeypatch) -> None:
    delegated: list[list[str]] = []

    monkeypatch.setattr(
        run_legacy_full_gate.run_validation_gate,
        "main",
        lambda arguments: delegated.append(list(arguments)) or 0,
    )

    assert run_legacy_full_gate.main([]) == 0
    assert delegated == [["run", "--force-full", "--legacy-full"]]
