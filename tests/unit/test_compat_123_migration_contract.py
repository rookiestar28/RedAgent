from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "versions" / "0025_r123_closed_loop.py"


def test_r123_remains_the_direct_additive_predecessor_of_r158() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    scripts = ScriptDirectory.from_config(config)

    assert scripts.get_revision("0026_campaign_plan_admission").down_revision == "0025_r123_closed_loop"
    source = MIGRATION.read_text(encoding="utf-8")
    assert 'revision = "0025_r123_closed_loop"' in source
    assert 'down_revision = "0024_r118_retirement"' in source
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == (
        "0028_observation_replanning"
    )


def test_r123_adds_only_bounded_campaign_strategy_and_effect_tables() -> None:
    assert {"campaign_strategy_revisions", "campaign_effects"}.issubset(metadata.tables)
    forbidden = {
        "campaign_catalogs",
        "campaign_observations",
        "campaign_eligibility",
        "campaign_plans",
        "campaign_resolvers",
        "campaign_inbox",
        "campaign_events",
        "campaign_lifecycle_kernels",
    }
    assert forbidden.isdisjoint(metadata.tables)

    strategy = metadata.tables["campaign_strategy_revisions"]
    assert {
        "strategy_revision_id",
        "campaign_id",
        "predecessor_revision_id",
        "plan_revision",
        "replan_count",
        "context_schema",
        "context_sha256",
        "context_payload",
        "decision_schema",
        "decision_sha256",
        "decision_payload",
        "plan_sha256",
        "plan_payload",
        "proposal_ceiling_sha256",
        "approval_receipt_id",
        "approval_receipt_revision",
        "approval_receipt_sha256",
        "envelope_core_sha256",
        "envelope_sha256",
        "created_by_user_id",
    }.issubset(strategy.c.keys())

    effects = metadata.tables["campaign_effects"]
    assert {
        "effect_id",
        "campaign_id",
        "strategy_revision_id",
        "node_id",
        "invocation_id",
        "effect_intent_sha256",
        "effect_intent_payload",
        "envelope_sha256",
        "effect_state",
        "claim_owner",
        "claim_expires_at",
        "claim_version",
        "dispatch_attempt",
        "dispatch_generation",
        "runner_id",
        "workload_identity",
        "request_sha256",
        "effect_receipt_sha256",
        "effect_receipt_payload",
        "external_status",
        "external_receipt_id",
        "evidence_ids",
        "cleanup_receipt_id",
        "reconciliation_state",
        "reconciliation_evidence_ids",
        "redispatch_permitted",
        "failure_code",
        "next_retry_at",
        "outbox_sequence",
        "started_at",
        "completed_at",
    }.issubset(effects.c.keys())


def test_existing_campaign_job_and_outbox_are_extended_without_replacement() -> None:
    campaigns = metadata.tables["campaigns"]
    jobs = metadata.tables["jobs"]
    outbox = metadata.tables["outbox_events"]

    assert {
        "intent_sha256",
        "current_strategy_revision_id",
        "aggregate_sequence",
        "replan_count",
        "attention_reason",
        "terminal_receipt_sha256",
    }.issubset(campaigns.c.keys())
    assert {
        "strategy_revision_id",
        "node_id",
        "effect_id",
        "envelope_sha256",
        "manifest_v2_sha256",
    }.issubset(jobs.c.keys())
    assert {
        "schema_revision",
        "aggregate_type",
        "aggregate_sequence",
        "available_at",
        "claim_owner",
        "claim_expires_at",
        "attempt_count",
        "last_error",
        "delivered_at",
        "delivery_state",
        "reconciliation_state",
        "dead_lettered_at",
    }.issubset(outbox.c.keys())
    assert "published" in outbox.c


def test_migration_enables_force_rls_and_immutable_strategy_permissions() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    for table in ("campaign_strategy_revisions", "campaign_effects"):
        assert f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY" in source
        assert f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY" in source
        assert f"CREATE POLICY {table}_tenant_isolation" in source
    assert "REVOKE UPDATE, DELETE ON campaign_strategy_revisions" in source
    assert 'postgresql_where=sa.text("schema_revision = 2")' in source
    assert "workflow.start.requested.v1" in source
