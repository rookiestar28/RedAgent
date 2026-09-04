from __future__ import annotations

import asyncio
import os
from pathlib import Path
import subprocess
import sys
from uuid import uuid4

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from redagent_platform.persistence.database import load_database_settings


ROOT = Path(__file__).resolve().parents[2]


def test_migration_forward_failure_rollback_downgrade_and_reapply() -> None:
    asyncio.run(_migration_scenario())


async def _migration_scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    database_name = f"r093_{uuid4().hex}"
    test_url = settings.url.set(database=database_name)
    secret_dir = ROOT / ".local" / "redagent" / "test-databases" / database_name
    secret_file = secret_dir / "database-url"
    secret_dir.mkdir(parents=True, exist_ok=False)
    secret_file.write_text(test_url.render_as_string(hide_password=False) + "\n", encoding="utf-8")
    try:
        await _create_database(settings.url.set(database="postgres"), database_name)
        engine = create_async_engine(test_url)
        try:
            async with engine.begin() as connection:
                await connection.execute(text("CREATE TABLE targets (failure_marker integer)"))

            interrupted = _alembic(secret_file, "upgrade", "head")
            assert interrupted.returncode != 0
            assert "password" not in (interrupted.stdout + interrupted.stderr).lower()

            async with engine.begin() as connection:
                tenants = await connection.scalar(text("SELECT to_regclass('public.tenants')"))
                users = await connection.scalar(text("SELECT to_regclass('public.users')"))
                marker = await connection.scalar(text("SELECT to_regclass('public.targets')"))
                assert tenants is None
                assert users is None
                assert marker == "targets"
                await connection.execute(text("DROP TABLE targets"))

            upgraded = _alembic(secret_file, "upgrade", "head")
            assert upgraded.returncode == 0, upgraded.stderr
            current = _alembic(secret_file, "current")
            assert current.returncode == 0
            assert "0029_autonomous_campaign_app (head)" in current.stdout

            async with engine.begin() as connection:
                revision = await connection.scalar(text("SELECT version_num FROM alembic_version"))
                table_count = await connection.scalar(
                    text(
                        "SELECT count(*) FROM information_schema.tables "
                        "WHERE table_schema = 'public' AND table_name IN "
                        "('tenants','users','engagements','targets','roe_versions','approvals',"
                        "'policy_references','campaigns','jobs','workflow_commands','audit_events','outbox_events','idempotency_records',"
                        "'issue_definitions','finding_instances','identity_providers','tenant_memberships',"
                        "'role_assignments','login_transactions','browser_sessions','identity_replay_records',"
                        "'jit_grants','break_glass_reviews','service_identities',"
                        "'evidence_operations','evidence_artifacts','evidence_derivatives',"
                        "'evidence_custody_events','evidence_verifications','secret_references',"
                        "'secret_workload_clients','secret_lease_operations','secret_leases',"
                        "'secret_lease_events','policy_bundle_revisions','policy_bundle_promotions',"
                        "'policy_agent_status','policy_decisions','policy_boundary_receipts','policy_log_receipts',"
                        "'runner_classes','runner_registrations','runner_identities',"
                        "'execution_capability_manifests','artifact_verification_receipts',"
                        "'runner_job_manifests','runner_pull_leases','runner_lifecycle_events',"
                        "'runner_execution_receipts','containment_controls','containment_approvals',"
                        "'containment_job_actions','containment_phase_receipts','containment_residual_risks',"
                        "'containment_incidents','quota_policies','quota_usage','quota_reservations','quota_operations',"
                        "'telemetry_export_operations','telemetry_delivery_attempts','telemetry_dead_letters',"
                        "'security_incidents','incident_timeline_events','incident_actions','slo_definitions',"
                        "'slo_windows','slo_evaluations','alert_instances','alert_notifications',"
                        "'lab_bundles','lab_target_attestations','lab_target_leases','golden_scenario_runs',"
                        "'golden_scenario_steps','golden_finding_expectations','qualification_measurements',"
                        "'lab_backup_restore_receipts','lab_teardown_receipts',"
                        "'zap_profile_revisions','zap_target_attestations','zap_compiled_plans','zap_runs','zap_run_steps',"
                        "'zap_gateway_decisions','zap_normalized_alerts','zap_cancellation_receipts',"
                        "'zap_cleanup_receipts',"
                        "'nuclei_engine_artifacts','nuclei_target_attestations','nuclei_bundle_revisions','nuclei_bundle_files',"
                        "'nuclei_template_revisions','nuclei_bundle_reviews','nuclei_bundle_promotions',"
                        "'nuclei_profile_revisions','nuclei_compiled_plans','nuclei_runs',"
                        "'nuclei_gateway_decisions','nuclei_normalized_results','nuclei_result_rejections',"
                        "'nuclei_cancellation_receipts','nuclei_cleanup_receipts',"
                        "'api_diff_engine_artifacts','api_diff_spec_revisions','api_diff_operation_manifests',"
                        "'api_diff_identity_matrices','api_diff_sequence_grammars','api_diff_reviews',"
                        "'api_diff_promotions','api_diff_profiles','api_diff_target_attestations',"
                        "'api_diff_plans','api_diff_cases','api_diff_runs','api_diff_resource_ledger',"
                        "'api_diff_gateway_decisions','api_diff_observations','api_diff_replay_artifacts',"
                        "'api_diff_cancellation_receipts','api_diff_cleanup_receipts',"
                        "'network_engine_artifacts','network_adapter_declarations','network_profiles',"
                        "'network_topology_attestations','network_target_sets','network_plans',"
                        "'network_plan_tuples','network_runs','network_gateway_decisions',"
                        "'network_observations','network_cancellation_receipts','network_cleanup_receipts',"
                        "'cloud_adapter_artifacts','cloud_provider_profiles','cloud_operation_manifests',"
                        "'cloud_identity_bindings','cloud_control_packs','cloud_offline_artifacts',"
                        "'cloud_collection_plans','cloud_collection_runs','cloud_snapshot_pages',"
                        "'cloud_snapshot_resources','cloud_check_results','cloud_cleanup_receipts',"
                        "'identity_adapter_artifacts','identity_provider_profiles','identity_operation_manifests',"
                        "'identity_tenant_bindings','identity_baseline_artifacts','identity_collection_plans',"
                        "'identity_collection_runs','identity_snapshot_pages','identity_snapshot_resources',"
                        "'identity_baseline_evaluations','identity_exception_annotations','identity_exception_approvals',"
                        "'identity_graph_approvals','identity_graph_nodes','identity_graph_edges','identity_cleanup_receipts',"
                        "'artifact_adapter_artifacts','artifact_pipeline_profiles','artifact_rule_bundles','artifact_database_snapshots',"
                        "'artifact_bindings','artifact_analysis_plans','artifact_analysis_runs','artifact_manifest_entries',"
                        "'artifact_components','artifact_license_observations','artifact_vulnerability_observations','artifact_vex_annotations',"
                        "'artifact_credential_findings','artifact_static_findings','artifact_mobile_observations','artifact_cleanup_receipts',"
                        "'purple_adapter_artifacts','purple_abilities','purple_ability_phases','purple_detection_expectations',"
                        "'purple_lab_bindings','purple_approvals','purple_execution_plans','purple_runs','purple_snapshots',"
                        "'purple_action_receipts','purple_telemetry_events','purple_cleanup_receipts','purple_teardown_receipts',"
                        "'purple_rehearsal_receipts','human_adapter_artifacts','human_campaign_manifests',"
                        "'human_consent_rosters','human_suppression_lists','human_privacy_reviews','human_message_templates',"
                        "'human_campaign_approvals','human_campaign_plans','human_campaign_runs','human_delivery_receipts',"
                        "'human_minimized_events','human_canary_correlations','human_stop_receipts','human_deletion_receipts',"
                        "'human_rehearsal_receipts','human_evidence_records',"
                        "'agent_provider_profiles','agent_projected_tools','agent_runs','agent_steps',"
                        "'agent_proposals','agent_approvals','agent_budget_ledgers','agent_working_memory',"
                        "'agent_reviewed_facts','agent_trace_envelopes','agent_qualification_receipts',"
                        "'mcp_server_registrations','mcp_transport_attestations','mcp_inventory_revisions',"
                        "'mcp_inventory_items','mcp_freeze_events','workbench_campaign_drafts',"
                        "'workbench_trust_items','workbench_disclosures','workbench_reviewer_decisions',"
                        "'workbench_conclusions','workbench_lifecycle_events','mcp_qualification_receipts',"
                        "'finding_import_sessions','finding_import_records','managed_issues','finding_occurrences',"
                        "'finding_evidence_links','finding_operations','finding_comments','finding_risk_acceptances',"
                        "'finding_retests','finding_report_snapshots','finding_report_claims','finding_publications',"
                        "'finding_connector_profiles','finding_connector_deliveries','finding_connector_attempts',"
                        "'finding_connector_callbacks','finding_connector_reconciliations',"
                        "'campaign_strategy_revisions','campaign_effects',"
                        "'campaign_budget_ledgers','campaign_budget_reservations',"
                        "'campaign_budget_events','plan_admission_receipts',"
                        "'campaign_execution_runs','campaign_execution_nodes',"
                        "'campaign_execution_authority_observations',"
                        "'campaign_observation_decisions','trusted_campaign_observations',"
                        "'campaign_replan_proposals','campaign_replan_acceptances',"
                        "'autonomous_campaign_applications',"
                        "'autonomous_campaign_application_events')"
                    )
                )
                assert revision == settings.expected_revision
                assert int(table_count or 0) == 262
                for retired_table in (
                    "r118_campaign_controller_records",
                    "r118_campaign_controller_artifacts",
                ):
                    assert (
                        await connection.scalar(
                            text("SELECT to_regclass(:table_name)"),
                            {"table_name": f"public.{retired_table}"},
                        )
                        is None
                    )

            r158_downgraded = _alembic(secret_file, "downgrade", "0025_r123_closed_loop")
            assert r158_downgraded.returncode == 0, r158_downgraded.stderr
            async with engine.begin() as connection:
                assert await connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                    "0025_r123_closed_loop"
                )
                for r158_table in (
                    "campaign_budget_ledgers",
                    "campaign_budget_reservations",
                    "campaign_budget_events",
                    "plan_admission_receipts",
                ):
                    assert (
                        await connection.scalar(
                            text("SELECT to_regclass(:table_name)"),
                            {"table_name": f"public.{r158_table}"},
                        )
                        is None
                    )

            current_head_reapplied = _alembic(secret_file, "upgrade", "head")
            assert current_head_reapplied.returncode == 0, current_head_reapplied.stderr
            async with engine.begin() as connection:
                assert await connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                    settings.expected_revision
                )
                for r158_table in (
                    "campaign_budget_ledgers",
                    "campaign_budget_reservations",
                    "campaign_budget_events",
                    "plan_admission_receipts",
                ):
                    assert (
                        await connection.scalar(
                            text("SELECT to_regclass(:table_name)"),
                            {"table_name": f"public.{r158_table}"},
                        )
                        == r158_table
                    )
                for r159_table in (
                    "campaign_execution_runs",
                    "campaign_execution_nodes",
                    "campaign_execution_authority_observations",
                ):
                    assert (
                        await connection.scalar(
                            text("SELECT to_regclass(:table_name)"),
                            {"table_name": f"public.{r159_table}"},
                        )
                        == r159_table
                    )

            restored_r118 = _alembic(secret_file, "downgrade", "0023_r118_controller")
            assert restored_r118.returncode == 0, restored_r118.stderr
            async with engine.begin() as connection:
                restored_rls = (
                    await connection.execute(
                        text(
                            "SELECT relname, relrowsecurity, relforcerowsecurity "
                            "FROM pg_class WHERE relname IN "
                            "('r118_campaign_controller_records', "
                            "'r118_campaign_controller_artifacts') ORDER BY relname"
                        )
                    )
                ).all()
                assert restored_rls == [
                    ("r118_campaign_controller_artifacts", True, True),
                    ("r118_campaign_controller_records", True, True),
                ]

            reretired_r118 = _alembic(secret_file, "upgrade", "head")
            assert reretired_r118.returncode == 0, reretired_r118.stderr
            async with engine.begin() as connection:
                for retired_table in (
                    "r118_campaign_controller_records",
                    "r118_campaign_controller_artifacts",
                ):
                    assert (
                        await connection.scalar(
                            text("SELECT to_regclass(:table_name)"),
                            {"table_name": f"public.{retired_table}"},
                        )
                        is None
                    )

            downgraded = _alembic(secret_file, "downgrade", "base")
            assert downgraded.returncode == 0, downgraded.stderr
            async with engine.begin() as connection:
                assert await connection.scalar(text("SELECT to_regclass('public.tenants')")) is None
                assert await connection.scalar(text("SELECT count(*) FROM alembic_version")) == 0

            reapplied = _alembic(secret_file, "upgrade", "head")
            assert reapplied.returncode == 0, reapplied.stderr
            async with engine.begin() as connection:
                assert (
                    await connection.scalar(text("SELECT version_num FROM alembic_version"))
                    == settings.expected_revision
                )
                for statement in (
                        "INSERT INTO tenants (id,name,version,created_at,updated_at) "
                        "VALUES ('migration-retention-tenant','retention',1,now(),now())",
                        "INSERT INTO engagements "
                        "(id,name,owner_user_id,tenant_id,version,created_at,updated_at) VALUES "
                        "('migration-retention-engagement','retention','owner',"
                        "'migration-retention-tenant',1,now(),now())",
                        "INSERT INTO roe_versions "
                        "(id,engagement_id,revision,status,document,tenant_id,version,created_at,updated_at) "
                        "VALUES ('migration-retention-roe','migration-retention-engagement',1,"
                        "'active','{}','migration-retention-tenant',1,now(),now())",
                        "INSERT INTO campaigns "
                        "(id,engagement_id,roe_version_id,name,status,workflow_id,"
                        "orchestration_revision,aggregate_sequence,replan_count,tenant_id,version,"
                        "created_at,updated_at) VALUES ('migration-retention-campaign',"
                        "'migration-retention-engagement','migration-retention-roe','retention',"
                        "'active','migration-retention-workflow',1,0,0,"
                        "'migration-retention-tenant',1,now(),now())",
                        "INSERT INTO campaign_observation_decisions "
                        "(id,campaign_id,candidate_sha256,decision_sha256,outcome,reason_code,"
                        "candidate_payload,decision_payload,decided_at,tenant_id,version,created_at,updated_at) "
                        "VALUES ('migration-retention-decision','migration-retention-campaign',"
                        "repeat('a',64),repeat('b',64),'stale','observation_stale','{}','{}',now(),"
                        "'migration-retention-tenant',1,now(),now())",
                ):
                    await connection.execute(text(statement))

            populated_downgrade = _alembic(
                secret_file,
                "downgrade",
                "0027_campaign_dag_execution",
            )
            assert populated_downgrade.returncode != 0
            assert "observation_replanning_downgrade_requires_empty_lineage" in (
                populated_downgrade.stdout + populated_downgrade.stderr
            )
            async with engine.begin() as connection:
                assert await connection.scalar(text("SELECT version_num FROM alembic_version")) == (
                    settings.expected_revision
                )
                assert await connection.scalar(
                    text(
                        "SELECT count(*) FROM campaign_observation_decisions "
                        "WHERE id = 'migration-retention-decision'"
                    )
                ) == 1
        finally:
            await engine.dispose()
    finally:
        await _drop_database(settings.url.set(database="postgres"), database_name)
        secret_file.unlink(missing_ok=True)
        secret_dir.rmdir()


async def _create_database(admin_url, database_name: str) -> None:
    engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as connection:
            # CRITICAL: the quoted identifier is generated exclusively from a hex UUID.
            await connection.execute(text(f'CREATE DATABASE "{database_name}"'))
    finally:
        await engine.dispose()


async def _drop_database(admin_url, database_name: str) -> None:
    engine = create_async_engine(admin_url, isolation_level="AUTOCOMMIT")
    try:
        async with engine.connect() as connection:
            # CRITICAL: cleanup is restricted to the generated test database identifier.
            await connection.execute(text(f'DROP DATABASE IF EXISTS "{database_name}" WITH (FORCE)'))
    finally:
        await engine.dispose()


def _alembic(secret_file: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    environment = dict(os.environ)
    environment.pop("REDAGENT_DATABASE_URL", None)
    environment["REDAGENT_DATABASE_URL_FILE"] = str(secret_file)
    return subprocess.run(
        [sys.executable, "-m", "alembic", *arguments],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
        timeout=60,
    )
