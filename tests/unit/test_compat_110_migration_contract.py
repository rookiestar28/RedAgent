from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0017_r110_artifact_pipeline.py"


def test_revision_0017_is_expected_database_head() -> None:
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0029_autonomous_campaign_app"
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0017_r110_artifact"' in source
    assert 'down_revision = "0016_r109_identity"' in source


def test_revision_0017_owns_artifact_sbom_vex_redaction_mobile_and_cleanup_truth() -> None:
    expected = {
        "artifact_adapter_artifacts", "artifact_pipeline_profiles", "artifact_rule_bundles", "artifact_database_snapshots",
        "artifact_bindings", "artifact_analysis_plans", "artifact_analysis_runs", "artifact_manifest_entries",
        "artifact_components", "artifact_license_observations", "artifact_vulnerability_observations", "artifact_vex_annotations",
        "artifact_credential_findings", "artifact_static_findings", "artifact_mobile_observations", "artifact_cleanup_receipts",
    }
    source = REVISION.read_text(encoding="utf-8")
    assert expected <= set(metadata.tables) and expected <= TENANT_TABLE_NAMES
    assert "FORCE ROW LEVEL SECURITY" in source and "redagent.tenant_id" in source
    for name in expected:
        assert f'"{name}"' in source
        assert {"id", "tenant_id", "version", "created_at", "updated_at"} <= set(metadata.tables[name].c.keys())


def test_credential_finding_schema_has_no_raw_value_column() -> None:
    columns = set(metadata.tables["artifact_credential_findings"].c.keys())
    assert {"fingerprint", "path", "line", "rule_id", "classification", "redacted_fragment"} <= columns
    assert not ({"value", "match", "raw", "content"} & columns)
