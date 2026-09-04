from pathlib import Path

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import TENANT_TABLE_NAMES, metadata


ROOT = Path(__file__).resolve().parents[2]
REVISION = ROOT / "migrations/versions/0019_r112_human_simulation.py"
TABLES = {
    "human_adapter_artifacts", "human_campaign_manifests", "human_consent_rosters", "human_suppression_lists",
    "human_privacy_reviews", "human_message_templates", "human_campaign_approvals", "human_campaign_plans",
    "human_campaign_runs", "human_delivery_receipts", "human_minimized_events", "human_canary_correlations",
    "human_stop_receipts", "human_deletion_receipts", "human_rehearsal_receipts", "human_evidence_records",
}


def test_revision_0019_is_expected_head_and_force_rls_owned():
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == "0029_autonomous_campaign_app"
    source = REVISION.read_text(encoding="utf-8")
    assert 'revision = "0019_r112_human"' in source and 'down_revision = "0018_r111_purple"' in source
    assert "FORCE ROW LEVEL SECURITY" in source and "redagent.tenant_id" in source
    assert TABLES <= set(metadata.tables) and TABLES <= TENANT_TABLE_NAMES
    for name in TABLES:
        assert f'"{name}"' in source
        assert {"id", "tenant_id", "version", "created_at", "updated_at"} <= set(metadata.tables[name].c.keys())


def test_schema_minimizes_event_and_submission_evidence():
    event_columns = set(metadata.tables["human_minimized_events"].c.keys())
    evidence_columns = set(metadata.tables["human_evidence_records"].c.keys())
    assert {"event_id", "event_category", "body_sha256", "signature_verified", "replay_checked"} <= event_columns
    assert {"evidence_kind", "evidence_sha256", "redaction_state"} <= evidence_columns
    forbidden = {"submitted_value", "password", "credential", "raw_body", "user_agent", "ip_address"}
    assert not (forbidden & event_columns) and not (forbidden & evidence_columns)
