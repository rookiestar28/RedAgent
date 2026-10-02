from __future__ import annotations

import inspect
from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory

from redagent_platform.campaign_service.admission_repository import CampaignAdmissionRepository
from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations" / "versions" / "0026_campaign_plan_admission.py"


def test_admission_migration_is_the_single_additive_head() -> None:
    config = Config(str(ROOT / "alembic.ini"))
    config.set_main_option("script_location", str(ROOT / "migrations"))
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_heads() == ["0033_bounded_child_replanning"]
    source = MIGRATION.read_text(encoding="utf-8")
    assert 'revision = "0026_campaign_plan_admission"' in source
    assert 'down_revision = "0025_r123_closed_loop"' in source
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == ("0033_bounded_child_replanning")


def test_admission_metadata_is_closed_tenant_owned_and_bounded() -> None:
    names = {
        "campaign_budget_ledgers",
        "campaign_budget_reservations",
        "campaign_budget_events",
        "plan_admission_receipts",
    }
    assert names.issubset(metadata.tables)
    for name in names:
        assert {"id", "tenant_id", "version", "created_at", "updated_at"}.issubset(metadata.tables[name].c.keys())
    assert {
        "campaign_id",
        "envelope_sha256",
        "duration_seconds",
        "requests",
        "rate_per_minute",
        "concurrency",
        "risk_micropoints",
        "cost_microunits",
        "evidence_bytes",
        "data_bytes",
    }.issubset(metadata.tables["campaign_budget_ledgers"].c.keys())
    assert {
        "ledger_id",
        "campaign_id",
        "plan_sha256",
        "request_sha256",
        "idempotency_key",
        "reservation_state",
        "lease_expires_at",
        "effect_started",
    }.issubset(metadata.tables["campaign_budget_reservations"].c.keys())
    assert {"receipt_sha256", "receipt_payload", "outcome", "request_sha256"}.issubset(
        metadata.tables["plan_admission_receipts"].c.keys()
    )


def test_admission_repository_exposes_transaction_neutral_denial() -> None:
    assert callable(getattr(CampaignAdmissionRepository, "deny", None))


def test_admission_metadata_uses_tenant_bound_composite_relationships() -> None:
    expected = {
        "campaigns": {"uq_campaign_tenant_identity"},
        "campaign_budget_ledgers": {
            "uq_campaign_budget_ledger_tenant_identity",
            "fk_campaign_budget_ledger_tenant_campaign",
        },
        "campaign_budget_reservations": {
            "uq_campaign_budget_reservation_tenant_identity",
            "fk_campaign_budget_reservation_tenant_campaign",
            "fk_campaign_budget_reservation_tenant_ledger",
        },
        "campaign_budget_events": {
            "fk_campaign_budget_event_tenant_campaign",
            "fk_campaign_budget_event_tenant_ledger",
            "fk_campaign_budget_event_tenant_reservation",
        },
        "plan_admission_receipts": {
            "fk_plan_admission_receipt_tenant_campaign",
            "fk_plan_admission_receipt_tenant_reservation",
        },
    }
    for table_name, constraint_names in expected.items():
        actual = {constraint.name for constraint in metadata.tables[table_name].constraints}
        assert constraint_names.issubset(actual)

    source = MIGRATION.read_text(encoding="utf-8")
    for constraint_names in expected.values():
        for constraint_name in constraint_names:
            assert constraint_name in source


def test_migration_enforces_rls_immutability_states_and_vector_bounds() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    for name in (
        "campaign_budget_ledgers",
        "campaign_budget_reservations",
        "campaign_budget_events",
        "plan_admission_receipts",
    ):
        assert f"ALTER TABLE {name} ENABLE ROW LEVEL SECURITY" in source
        assert f"ALTER TABLE {name} FORCE ROW LEVEL SECURITY" in source
        assert f"CREATE POLICY {name}_tenant_isolation" in source
    assert "campaign_budget_reservation_state_closed" in source
    assert "campaign_budget_vector_non_negative" in source
    assert "campaign_budget_event_immutable" in source
    assert "plan_admission_receipt_immutable" in source


def test_admission_remains_unregistered_and_has_no_execution_imports() -> None:
    from redagent_platform.campaign_service import admission, admission_repository

    source = (inspect.getsource(admission) + inspect.getsource(admission_repository)).lower()
    for forbidden in (
        "runner_service",
        "subprocess",
        "socket",
        "credential",
        "transport",
        "execute_payload",
    ):
        assert forbidden not in source
    api_source = (ROOT / "redagent_platform" / "api" / "app.py").read_text(encoding="utf-8")
    campaign_api_source = (ROOT / "redagent_platform" / "campaign_service" / "api.py").read_text(encoding="utf-8")
    assert "campaign.plan.admit" not in api_source
    assert "campaign.plan.admit" not in campaign_api_source
