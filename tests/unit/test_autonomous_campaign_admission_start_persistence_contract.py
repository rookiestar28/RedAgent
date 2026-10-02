from __future__ import annotations

from pathlib import Path

from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy import CheckConstraint, ForeignKeyConstraint, UniqueConstraint

from redagent_platform.campaign_service.application_contracts import (
    AutonomousCampaignLifecycle,
    assert_lifecycle_transition,
)
from redagent_platform.persistence.database import DatabaseSettings
from redagent_platform.persistence.models import metadata


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/versions/0031_autonomous_campaign_admission_start.py"


def test_r173_additive_schema_is_current_and_transactionally_bound() -> None:
    scripts = ScriptDirectory.from_config(Config(str(ROOT / "alembic.ini")))
    assert scripts.get_heads() == ["0033_bounded_child_replanning"]
    assert scripts.get_revision("0031_autonomous_admission_start").down_revision == (
        "0030_autonomous_plan_approval"
    )
    assert DatabaseSettings.__dataclass_fields__["expected_revision"].default == (
        "0033_bounded_child_replanning"
    )

    starts = metadata.tables["autonomous_campaign_execution_starts"]
    assert {
        "id",
        "tenant_id",
        "application_id",
        "approved_revision",
        "admitted_revision",
        "preview_id",
        "approval_receipt_id",
        "approval_receipt_sha256",
        "admission_receipt_id",
        "admission_receipt_sha256",
        "reservation_id",
        "execution_run_id",
        "workflow_id",
        "workflow_run_id",
        "idempotency_key",
        "request_sha256",
        "workflow_request_sha256",
        "workflow_input_payload",
        "input_sha256",
        "application_audit_id",
        "application_event_id",
        "signed_authority_sha256",
        "authority_sha256",
        "domain_sha256",
        "plan_sha256",
        "certificate_sha256",
        "reserved_budget_sha256",
        "policy_revision",
        "policy_bundle_sha256",
        "lifecycle_epoch",
        "policy_revocation_epoch",
        "roe_revocation_epoch",
        "kill_switch_epoch",
        "start_state",
        "reason_code",
        "issued_at",
        "expires_at",
    } <= set(starts.c.keys())
    assert _has_unique(starts, {"tenant_id", "id"})
    assert _has_unique(starts, {"tenant_id", "application_id", "approval_receipt_id"})
    assert _has_unique(starts, {"tenant_id", "application_id", "idempotency_key"})
    assert _has_unique(starts, {"tenant_id", "execution_run_id"})
    assert _has_unique(starts, {"tenant_id", "workflow_id"})
    assert _has_fk(
        starts,
        ("tenant_id", "application_id"),
        (
            "autonomous_campaign_applications.tenant_id",
            "autonomous_campaign_applications.id",
        ),
    )
    assert _has_fk(
        starts,
        ("tenant_id", "preview_id"),
        (
            "autonomous_campaign_plan_previews.tenant_id",
            "autonomous_campaign_plan_previews.id",
        ),
    )
    assert _has_fk(
        starts,
        ("tenant_id", "approval_receipt_id"),
        (
            "autonomous_campaign_plan_approval_receipts.tenant_id",
            "autonomous_campaign_plan_approval_receipts.id",
        ),
    )
    assert _has_fk(
        starts,
        ("tenant_id", "admission_receipt_id", "application_id"),
        (
            "plan_admission_receipts.tenant_id",
            "plan_admission_receipts.id",
            "plan_admission_receipts.campaign_id",
        ),
    )
    assert _has_fk(
        starts,
        ("tenant_id", "reservation_id", "application_id"),
        (
            "campaign_budget_reservations.tenant_id",
            "campaign_budget_reservations.id",
            "campaign_budget_reservations.campaign_id",
        ),
    )
    assert _has_fk(
        starts,
        ("tenant_id", "execution_run_id", "application_id"),
        (
            "campaign_execution_runs.tenant_id",
            "campaign_execution_runs.id",
            "campaign_execution_runs.campaign_id",
        ),
    )


def test_r173_migration_protects_tenant_lineage_and_safe_rollback() -> None:
    source = MIGRATION.read_text(encoding="utf-8")
    assert "ALTER TABLE autonomous_campaign_execution_starts ENABLE ROW LEVEL SECURITY" in source
    assert "ALTER TABLE autonomous_campaign_execution_starts FORCE ROW LEVEL SECURITY" in source
    assert "CREATE POLICY autonomous_campaign_execution_starts_tenant_isolation" in source
    assert "autonomous_campaign_execution_start_input_immutable" in source
    assert "autonomous_campaign_admission_start_downgrade_requires_empty_state" in source
    assert "'start_outcome_unknown'" in source
    assert "op.drop_constraint(" in source
    assert "NO FORCE ROW LEVEL SECURITY" in source
    assert "autonomous_campaign.start_bridge.requested.v1" in source
    assert "campaign.dag.start.requested.v1" not in source


def test_r173_admitted_application_can_fail_closed_before_start_confirmation() -> None:
    assert_lifecycle_transition(
        AutonomousCampaignLifecycle.ADMITTED,
        AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
    )


def _has_unique(table, columns: set[str]) -> bool:
    return any(
        isinstance(constraint, UniqueConstraint)
        and {column.name for column in constraint.columns} == columns
        for constraint in table.constraints
    )


def _has_fk(table, local: tuple[str, ...], remote: tuple[str, ...]) -> bool:
    return any(
        isinstance(constraint, ForeignKeyConstraint)
        and tuple(column.name for column in constraint.columns) == local
        and tuple(element.target_fullname for element in constraint.elements) == remote
        for constraint in table.constraints
    )


def _has_check(table, name: str) -> bool:
    return any(
        isinstance(constraint, CheckConstraint) and constraint.name == name
        for constraint in table.constraints
    )
