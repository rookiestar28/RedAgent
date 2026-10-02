from __future__ import annotations

import asyncio
from dataclasses import dataclass, replace
from datetime import timedelta
import importlib.util
from pathlib import Path
from types import ModuleType
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from sqlalchemy import delete, func, insert, select, text, update
from sqlalchemy.exc import DBAPIError

from redagent_platform.campaign_service.admission import AdmissionPolicyAdapter
from redagent_platform.campaign_service.admission_start_contracts import (
    ADMISSION_START_BRIDGE_EVENT_TYPE,
    ADMISSION_START_SCHEMA_VERSION,
    AutonomousCampaignAdmissionContextV1,
    AutonomousCampaignAdmissionStartCommandV1,
    AutonomousCampaignApprovalBundleV1,
)
from redagent_platform.campaign_service.admission_start_service import (
    AutonomousCampaignAdmissionStartService,
)
from redagent_platform.campaign_service.admission_start_store import (
    PostgresAutonomousCampaignAdmissionStartStore,
)
from redagent_platform.campaign_service.application_contracts import (
    AutonomousCampaignLifecycle,
    AutonomousCampaignMode,
)
from redagent_platform.campaign_service.application_repository import (
    PostgresAutonomousCampaignApplicationRepository,
)
from redagent_platform.campaign_service.application_service import (
    AutonomousCampaignApplicationService,
)
from redagent_platform.campaign_service.approval_contracts import (
    PLAN_APPROVE_SCHEMA_VERSION,
    PLAN_STAGE_SCHEMA_VERSION,
    ApproveAutonomousCampaignPlanV1,
    AutonomousCampaignApprovalContextV1,
    StageAutonomousCampaignPlanV1,
)
from redagent_platform.campaign_service.authority_envelope import (
    CampaignApproverRequirementV2,
    SignedCampaignAuthorityEnvelopeV2,
    sign_campaign_authority,
)
from redagent_platform.campaign_service.dag_execution_store import (
    CampaignDagExecutionRepository,
)
from redagent_platform.campaign_service.planning.contracts import CapabilityIdentityV1
from redagent_platform.campaign_service.planning.search import plan_attack_path
from redagent_platform.campaign_service.planning.validation import (
    VALIDATOR_SHA256,
    VALIDATOR_VERSION,
    validate_candidate_plan,
)
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.persistence.models import metadata
from redagent_platform.policy_service.fakes import DeterministicFakePolicyProvider
from tests.integration.test_autonomous_campaign_application_repository import (
    NOW,
    _create_command,
    _database,
    _set_tenant,
)
from tests.integration.test_autonomous_campaign_plan_approval_repository import (
    _ApprovalContextProvider,
)
from tests.integration.test_campaign_plan_admission_repository import (
    _bootstrap as _bootstrap_campaign,
)
from tests.unit.test_campaign_attack_path_planner import search_limits
from tests.unit.test_campaign_authority_envelope import lifecycle, trusted_key
from tests.unit.test_campaign_planning_contracts import (
    authority,
    domain,
    limits,
    operator,
    world,
)
from tests.unit.test_owned_execution_mode import _full_binding


ROOT = Path(__file__).resolve().parents[2]
MIGRATION = ROOT / "migrations/versions/0031_autonomous_campaign_admission_start.py"


@dataclass(frozen=True, slots=True)
class _Prepared:
    engine: object
    sessions: object
    repository: PostgresAutonomousCampaignApplicationRepository
    service: AutonomousCampaignAdmissionStartService
    command: AutonomousCampaignAdmissionStartCommandV1
    context_provider: object
    context: AutonomousCampaignAdmissionContextV1
    trusted_keys: dict[str, object]
    tenant: str
    campaign: str
    approval_context: AutonomousCampaignApprovalContextV1 | None = None


class _AdmissionContextProvider:
    def __init__(self, context: AutonomousCampaignAdmissionContextV1) -> None:
        self._context = context

    async def read_current_admission_context(self, *, tenant_id: str, campaign_id: str):
        if tenant_id != self._context.tenant_id or campaign_id != self._context.campaign_id:
            return None
        return self._context


def test_r173_atomic_concurrent_admission_restart_replay_and_dedicated_outbox() -> None:
    asyncio.run(_atomic_concurrent_scenario())


def test_r173_failure_after_admission_rolls_back_every_bound_row(monkeypatch) -> None:
    asyncio.run(_rollback_scenario(monkeypatch))


def test_r173_populated_downgrade_refuses_under_force_rls_and_restores_forward_state() -> None:
    asyncio.run(_populated_downgrade_guard_scenario())


def test_r173_current_kill_switch_drift_persists_denial_without_start_material() -> None:
    asyncio.run(_kill_switch_drift_scenario())


async def _atomic_concurrent_scenario() -> None:
    prepared = await _prepare_approved_campaign()
    try:
        restarted_service = _admission_service(
            sessions=prepared.sessions,
            repository=prepared.repository,
            context_provider=prepared.context_provider,
            context=prepared.context,
            trusted_keys=prepared.trusted_keys,
        )
        first, replay = await asyncio.gather(
            prepared.service.admit_and_queue(prepared.command),
            restarted_service.admit_and_queue(prepared.command),
        )
        assert sorted((first.replayed, replay.replayed)) == [False, True]
        accepted = first if not first.replayed else replay
        assert accepted.application.lifecycle_state is AutonomousCampaignLifecycle.ADMITTED
        assert accepted.application.aggregate_revision == 5
        assert accepted.start_state.value == "start_pending"

        recovered_bundle = await prepared.repository.read_current_approval_bundle(
            tenant_id=prepared.tenant,
            campaign_id=prepared.campaign,
            approval_receipt_id=prepared.command.approval_receipt_id,
        )
        assert recovered_bundle is not None
        exact_restart = await _admission_service(
            sessions=prepared.sessions,
            repository=PostgresAutonomousCampaignApplicationRepository(prepared.sessions),
            context_provider=prepared.context_provider,
            context=prepared.context,
            trusted_keys=prepared.trusted_keys,
        ).admit_and_queue(prepared.command)
        assert exact_restart.replayed is True
        assert exact_restart.application == accepted.application
        assert exact_restart.admission_receipt == accepted.admission_receipt

        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            assert await _count(session, "campaign_budget_reservations", prepared.tenant) == 1
            assert await _count(session, "plan_admission_receipts", prepared.tenant) == 1
            assert await _count(session, "campaign_execution_runs", prepared.tenant) == 1
            assert await _count(session, "campaign_execution_nodes", prepared.tenant) == 1
            assert await _count(
                session, "autonomous_campaign_execution_starts", prepared.tenant
            ) == 1
            outbox = metadata.tables["outbox_events"]
            r173_events = await session.scalar(
                select(func.count()).select_from(outbox).where(
                    outbox.c.tenant_id == prepared.tenant,
                    outbox.c.event_type == ADMISSION_START_BRIDGE_EVENT_TYPE,
                )
            )
            r159_events = await session.scalar(
                select(func.count()).select_from(outbox).where(
                    outbox.c.tenant_id == prepared.tenant,
                    outbox.c.event_type == "campaign.dag.start.requested.v1",
                )
            )
            assert int(r173_events or 0) == 1
            assert int(r159_events or 0) == 0

            starts = metadata.tables["autonomous_campaign_execution_starts"]
            with pytest.raises(
                DBAPIError,
                match="autonomous_campaign_execution_start_input_immutable",
            ):
                async with session.begin_nested():
                    await session.execute(
                        update(starts)
                        .where(
                            starts.c.tenant_id == prepared.tenant,
                            starts.c.application_id == prepared.campaign,
                        )
                        .values(approval_receipt_sha256="0" * 64)
                    )
            with pytest.raises(
                DBAPIError,
                match="autonomous_campaign_execution_start_input_immutable",
            ):
                async with session.begin_nested():
                    await session.execute(
                        delete(starts).where(
                            starts.c.tenant_id == prepared.tenant,
                            starts.c.application_id == prepared.campaign,
                        )
                    )

    finally:
        await prepared.engine.dispose()


async def _rollback_scenario(monkeypatch) -> None:
    prepared = await _prepare_approved_campaign()

    async def _crash_after_admission(self, material, *, now):
        raise RuntimeError("synthetic_r173_material_crash")

    monkeypatch.setattr(
        CampaignDagExecutionRepository,
        "insert_prepared_material",
        _crash_after_admission,
    )
    try:
        with pytest.raises(RuntimeError, match="synthetic_r173_material_crash"):
            await prepared.service.admit_and_queue(prepared.command)
        application = await prepared.repository.read(
            tenant_id=prepared.tenant,
            campaign_id=prepared.campaign,
        )
        assert application is not None
        assert application.lifecycle_state is AutonomousCampaignLifecycle.APPROVED
        assert application.aggregate_revision == 4
        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            for table_name in (
                "campaign_budget_ledgers",
                "campaign_budget_reservations",
                "campaign_budget_events",
                "plan_admission_receipts",
                "campaign_execution_runs",
                "campaign_execution_nodes",
                "autonomous_campaign_execution_starts",
            ):
                assert await _count(session, table_name, prepared.tenant) == 0
            outbox = metadata.tables["outbox_events"]
            r173_events = await session.scalar(
                select(func.count()).select_from(outbox).where(
                    outbox.c.tenant_id == prepared.tenant,
                    outbox.c.event_type == ADMISSION_START_BRIDGE_EVENT_TYPE,
                )
            )
            assert int(r173_events or 0) == 0
    finally:
        await prepared.engine.dispose()


async def _kill_switch_drift_scenario() -> None:
    prepared = await _prepare_approved_campaign()
    drifted = replace(
        prepared.context,
        authority_lifecycle=replace(
            prepared.context.authority_lifecycle,
            kill_switch_epoch=(
                prepared.context.authority_lifecycle.kill_switch_epoch + 1
            ),
        ),
    )
    provider = _AdmissionContextProvider(drifted)
    service = _admission_service(
        sessions=prepared.sessions,
        repository=prepared.repository,
        context_provider=provider,
        context=drifted,
        trusted_keys=prepared.trusted_keys,
    )
    try:
        denied = await service.admit_and_queue(prepared.command)
        assert denied.admission_receipt.outcome.value == "denied"
        assert denied.admission_receipt.denial_stage == "authority"
        assert denied.admission_receipt.reason_code == (
            "campaign_kill_switch_epoch_mismatch"
        )
        assert denied.application.lifecycle_state is AutonomousCampaignLifecycle.REVOKED
        assert denied.start_state is None
        async with prepared.sessions() as session, session.begin():
            await _set_tenant(session, prepared.tenant)
            assert await _count(session, "plan_admission_receipts", prepared.tenant) == 1
            for table_name in (
                "campaign_budget_reservations",
                "campaign_execution_runs",
                "campaign_execution_nodes",
                "autonomous_campaign_execution_starts",
            ):
                assert await _count(session, table_name, prepared.tenant) == 0
    finally:
        await prepared.engine.dispose()


async def _populated_downgrade_guard_scenario() -> None:
    prepared = await _prepare_approved_campaign()
    role_name = f"r173_owner_{uuid4().hex}"
    migration = _load_migration()
    try:
        await prepared.service.admit_and_queue(prepared.command)
        async with prepared.engine.connect() as connection:
            transaction = await connection.begin()
            try:
                # CRITICAL: this identifier is generated exclusively from a hex UUID.
                await connection.execute(
                    text(
                        f'CREATE ROLE "{role_name}" NOLOGIN NOSUPERUSER NOCREATEDB '
                        "NOCREATEROLE NOINHERIT NOBYPASSRLS"
                    )
                )
                await connection.execute(
                    text(f'GRANT USAGE ON SCHEMA public TO "{role_name}"')
                )
                await connection.execute(
                    text(
                        "ALTER TABLE autonomous_campaign_execution_starts "
                        f'OWNER TO "{role_name}"'
                    )
                )
                await connection.execute(text(f'SET LOCAL ROLE "{role_name}"'))
                await connection.execute(
                    text("SELECT set_config('redagent.tenant_id', '', true)")
                )
                hidden = await connection.scalar(
                    text("SELECT count(*) FROM autonomous_campaign_execution_starts")
                )
                assert int(hidden or 0) == 0
                await connection.execute(
                    text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
                    {"tenant_id": f"other-{prepared.tenant}"[:64]},
                )
                hidden = await connection.scalar(
                    text("SELECT count(*) FROM autonomous_campaign_execution_starts")
                )
                assert int(hidden or 0) == 0
                await connection.execute(
                    text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
                    {"tenant_id": prepared.tenant},
                )
                visible = await connection.scalar(
                    text("SELECT count(*) FROM autonomous_campaign_execution_starts")
                )
                assert int(visible or 0) == 1
                await connection.execute(
                    text("SELECT set_config('redagent.tenant_id', '', true)")
                )

                await connection.run_sync(
                    _assert_populated_downgrade_refused,
                    migration,
                )
                force_enabled = await connection.scalar(
                    text(
                        "SELECT relforcerowsecurity FROM pg_class "
                        "WHERE relname = 'autonomous_campaign_execution_starts'"
                    )
                )
                assert force_enabled is True
                hidden = await connection.scalar(
                    text("SELECT count(*) FROM autonomous_campaign_execution_starts")
                )
                assert int(hidden or 0) == 0
            finally:
                await transaction.rollback()
    finally:
        await prepared.engine.dispose()


def _assert_populated_downgrade_refused(connection, migration: ModuleType) -> None:
    original_get_bind = migration.op.get_bind
    migration.op.get_bind = lambda: connection
    try:
        with pytest.raises(
            RuntimeError,
            match="autonomous_campaign_admission_start_downgrade_requires_empty_state",
        ):
            migration.downgrade()
    finally:
        migration.op.get_bind = original_get_bind


def _load_migration() -> ModuleType:
    spec = importlib.util.spec_from_file_location("r173_migration_0031", MIGRATION)
    if spec is None or spec.loader is None:
        raise AssertionError("r173_migration_loader_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


async def _prepare_approved_campaign(*, mode=AutonomousCampaignMode.PLAN_ONLY, capability_key="zap-controlled-runtime@3", capability_manifest_sha256="1" * 64, now=NOW, validity_seconds=60, policy_revision="policy-a", bounded_manifest_sha256s=None) -> _Prepared:
    NOW = now
    engine, sessions = _database()
    suffix = uuid4().hex
    tenant = f"tenant-r173-{suffix}"[:64]
    actor = f"user-r173-{suffix}"[:64]
    approver = f"approver-r173-{suffix}"[:64]
    campaign = f"campaign-{suffix}"[:64]
    engagement = f"eng-{suffix}"[:64]
    target = f"target-r173-{suffix}"[:64]
    await _bootstrap_campaign(
        sessions,
        tenant=tenant,
        actor=actor,
        campaign=campaign,
        suffix=suffix,
    )
    async with sessions() as session, session.begin():
        await _set_tenant(session, tenant)
        for user_id, subject in (
            (approver, f"subject-approver-r173-{suffix}"[:200]),
        ):
            await session.execute(
                insert(metadata.tables["users"]).values(
                    id=user_id,
                    subject=subject,
                    tenant_id=tenant,
                    version=1,
                    created_at=NOW,
                    updated_at=NOW,
                )
            )
        await session.execute(
            insert(metadata.tables["targets"]).values(
                id=target,
                engagement_id=engagement,
                target_type="url",
                normalized_value=f"http://127.0.0.1:{10000 + int(suffix[-3:], 16) % 50000}",
                tenant_id=tenant,
                version=1,
                created_at=NOW,
                updated_at=NOW,
            )
        )

    repository = PostgresAutonomousCampaignApplicationRepository(sessions)
    create = _create_command(
        tenant=tenant,
        actor=actor,
        engagement=engagement,
        target=target,
        suffix=suffix,
    )
    assert create.campaign_id == campaign
    await repository.create_intent(replace(create, mode=mode))

    binding = closed_execution_registry()[capability_key]
    capability = CapabilityIdentityV1(
        capability_id=binding.capability_id,
        capability_revision=binding.capability_revision,
        adapter_id=binding.adapter_id,
        adapter_version=binding.adapter_version,
        execution_manifest_sha256=capability_manifest_sha256,
        profile_id=binding.profile_id,
        profile_revision=binding.profile_revision,
        profile_sha256=binding.profile_sha256,
        bundle_id=binding.bundle_id,
        bundle_revision=binding.bundle_revision,
        bundle_sha256=binding.bundle_sha256,
    )
    current_operator = replace(operator(), capability=capability)
    if mode is AutonomousCampaignMode.OWNED_LOOPBACK_AUTO:
        current_operator = replace(current_operator, max_duration_seconds=60, max_requests=20,
            max_rate_per_minute=60, max_evidence_bytes=(10 if binding.capability_id == "zap-controlled-runtime" else 2) * 1024 * 1024,
            max_data_bytes=20 * 1024 * 1024)
    current_domain = domain(operators=(current_operator,))
    current_authority = authority(
        envelope_id=f"authority-r173-{suffix}"[:64],
        tenant_id=tenant,
        engagement_id=engagement,
        target_ids=(target,),
        capability_ids=(binding.capability_id,),
        # Fixture authority lifetime and its signed duration bound must agree before
        # construction; each owned operator retains the separate fixed 60-second limit.
        bounds=replace(authority().bounds, max_duration_seconds=max(60, validity_seconds)),
        valid_from=NOW,
        expires_at=NOW + timedelta(seconds=validity_seconds),
        policy_revision=policy_revision,
        required_approvers=(CampaignApproverRequirementV2(approver, "campaign-owner"),),
        nonce=f"nonce-r173-{suffix}"[:100],
    )
    private_key = Ed25519PrivateKey.generate()
    if mode is AutonomousCampaignMode.OWNED_LOOPBACK_AUTO:
        current_authority = replace(current_authority, bounds=replace(current_authority.bounds,
            max_requests=20, max_rate_per_minute=60, max_concurrency=1, max_width=1,
            max_evidence_bytes=current_operator.max_evidence_bytes, max_data_bytes=current_operator.max_data_bytes))
    if mode is AutonomousCampaignMode.BOUNDED_REPLAN:
        from tests.unit.test_child_replan_subset import owned_planning_material
        from redagent_platform.campaign_service.planning.owned_sequential import (
            OWNED_SEQUENTIAL_VALIDATOR_VERSION, OWNED_SEQUENTIAL_VALIDATOR_SHA256,
            plan_owned_sequential_attack_path, validate_owned_sequential_candidate_plan,
        )
        from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1

        if set(bounded_manifest_sha256s or {}) != {"zap-controlled-runtime", "nuclei-trusted-runtime"}:
            raise ValueError("bounded_fixture_exact_manifests_required")
        current_domain, human, initial, _ = owned_planning_material()
        current_domain = replace(current_domain, operators=tuple(replace(op, capability=replace(op.capability,
            execution_manifest_sha256=bounded_manifest_sha256s[op.capability.capability_id])) for op in current_domain.operators))
        current_authority = replace(current_authority, capability_ids=human.capability_ids,
            objective_ids=human.objective_ids, success_condition_ids=human.success_condition_ids, bounds=human.bounds)
    approval_signature = sign_campaign_authority(
        current_authority,
        private_key,
        approver_id=approver,
        approver_role="campaign-owner",
        key_id="key-a",
        approved_at=NOW + timedelta(seconds=1),
        expires_at=NOW + timedelta(seconds=validity_seconds - 10),
    )
    signed = SignedCampaignAuthorityEnvelopeV2(
        authority=current_authority,
        approvals=(approval_signature,),
    )
    planned = (plan_owned_sequential_attack_path(current_domain, current_authority, initial, search_limits())
               if mode is AutonomousCampaignMode.BOUNDED_REPLAN
               else plan_attack_path(current_domain, current_authority, world(), search_limits()))
    assert planned.revision is not None
    validator = (validate_owned_sequential_candidate_plan if mode is AutonomousCampaignMode.BOUNDED_REPLAN else validate_candidate_plan)
    fixture_limits = ValidationLimitsV1(2, 1, 32) if mode is AutonomousCampaignMode.BOUNDED_REPLAN else limits()
    certificate = validator(
        planned.revision.candidate_plan,
        current_domain,
        current_authority,
        limits=fixture_limits,
        validated_at=NOW + timedelta(seconds=2),
    )
    current_lifecycle = lifecycle(
        current_authority,
        observed_at=NOW + timedelta(seconds=1),
        valid_until=NOW + timedelta(seconds=validity_seconds - 5),
    )
    stage = StageAutonomousCampaignPlanV1(
        schema_version=PLAN_STAGE_SCHEMA_VERSION,
        tenant_id=tenant,
        campaign_id=campaign,
        actor_user_id=actor,
        expected_revision=1,
        signed_authority=signed,
        authority_lifecycle=current_lifecycle,
        domain=current_domain,
        revision=planned.revision,
        certificate=certificate,
        idempotency_key=f"stage-r173-{suffix}",
        correlation_id=f"stage-correlation-r173-{suffix}"[:100],
        occurred_at=NOW + timedelta(seconds=3),
    )
    approval_context = AutonomousCampaignApprovalContextV1(
        tenant_id=tenant,
        campaign_id=campaign,
        signed_authority=signed,
        authority_lifecycle=current_lifecycle,
        execution_bindings=(tuple(sorted((_full_binding(op.capability) for op in current_domain.operators), key=lambda item: item.capability_id))
            if mode is AutonomousCampaignMode.BOUNDED_REPLAN else (_full_binding(capability),) if mode is AutonomousCampaignMode.OWNED_LOOPBACK_AUTO else ()),
    )
    current_trusted_key = trusted_key(private_key, approver_id=approver)
    application_service = AutonomousCampaignApplicationService(
        repository,
        mode=mode,
        approval_context_provider=_ApprovalContextProvider(approval_context),
        trusted_approval_keys={"key-a": current_trusted_key},
        validation_limits=fixture_limits,
        trusted_validator_version=OWNED_SEQUENTIAL_VALIDATOR_VERSION if mode is AutonomousCampaignMode.BOUNDED_REPLAN else VALIDATOR_VERSION,
        trusted_validator_sha256=OWNED_SEQUENTIAL_VALIDATOR_SHA256 if mode is AutonomousCampaignMode.BOUNDED_REPLAN else VALIDATOR_SHA256,
    )
    staged = await application_service.stage_plan(stage)
    approved = await application_service.approve_plan(
        ApproveAutonomousCampaignPlanV1(
            schema_version=PLAN_APPROVE_SCHEMA_VERSION,
            tenant_id=tenant,
            campaign_id=campaign,
            preview_id=staged.preview.preview_id,
            preview_sha256=staged.preview.preview_sha256,
            actor_user_id=approver,
            actor_permissions=("campaign:approve", "campaign:read"),
            policy_reference="policy:r173:approval",
            expected_revision=3,
            idempotency_key=f"approve-r173-{suffix}",
            correlation_id=f"approve-correlation-r173-{suffix}"[:100],
            occurred_at=NOW + timedelta(seconds=4),
        )
    )
    bundle = AutonomousCampaignApprovalBundleV1(
        application=approved.application,
        preview=staged.preview,
        approval_receipt=approved.receipt,
    )
    context = AutonomousCampaignAdmissionContextV1(
        tenant_id=tenant,
        campaign_id=campaign,
        signed_authority=signed,
        authority_lifecycle=current_lifecycle,
        domain=current_domain,
        revision=planned.revision,
        certificate=certificate,
    )
    command = AutonomousCampaignAdmissionStartCommandV1(
        schema_version=ADMISSION_START_SCHEMA_VERSION,
        tenant_id=tenant,
        campaign_id=campaign,
        approval_receipt_id=bundle.approval_receipt.receipt_id,
        approval_receipt_sha256=bundle.approval_receipt.receipt_sha256,
        actor_user_id=actor,
        actor_roles=("operator",),
        actor_permissions=("campaign:admit",),
        policy_reference=bundle.approval_receipt.policy_reference,
        expected_revision=4,
        idempotency_key=f"admit-start-r173-{suffix}",
        correlation_id=f"admit-start-correlation-r173-{suffix}"[:100],
        occurred_at=NOW + timedelta(seconds=5),
    )
    context_provider = _AdmissionContextProvider(context)
    trusted_keys = {"key-a": current_trusted_key}
    return _Prepared(
        engine=engine,
        sessions=sessions,
        repository=repository,
        service=_admission_service(
            sessions=sessions,
            repository=repository,
            context_provider=context_provider,
            context=context,
            trusted_keys=trusted_keys,
            owned_sequential=mode is AutonomousCampaignMode.BOUNDED_REPLAN,
        ),
        command=command,
        context_provider=context_provider,
        context=context,
        trusted_keys=trusted_keys,
        tenant=tenant,
        campaign=campaign,
        approval_context=approval_context,
    )


def _admission_service(
    *, sessions, repository, context_provider, context, trusted_keys, policy_provider=None, lease_seconds=60,
    owned_sequential=False, child_lineage_verifier=None,
):
    def _store_factory(command, bundle, current_context):
        return PostgresAutonomousCampaignAdmissionStartStore(
            sessions,
            command=command,
            bundle=bundle,
            context=current_context,
            child_lineage_verifier=child_lineage_verifier,
        )

    from redagent_platform.campaign_service.planning.contracts import ValidationLimitsV1
    from redagent_platform.campaign_service.planning.owned_sequential import OWNED_SEQUENTIAL_VALIDATOR_VERSION, OWNED_SEQUENTIAL_VALIDATOR_SHA256
    return AutonomousCampaignAdmissionStartService(
        source=repository,
        context_provider=context_provider,
        store_factory=_store_factory,
        policy=AdmissionPolicyAdapter(
            policy_provider or DeterministicFakePolicyProvider(
                revision=context.signed_authority.authority.policy_revision
            ),
            required_revision=context.signed_authority.authority.policy_revision,
            trusted_bundle_sha256=context.signed_authority.authority.policy_bundle_sha256,
        ),
        trusted_keys=trusted_keys,
        validation_limits=ValidationLimitsV1(2, 1, 32) if owned_sequential else limits(),
        trusted_validator_version=OWNED_SEQUENTIAL_VALIDATOR_VERSION if owned_sequential else VALIDATOR_VERSION,
        trusted_validator_sha256=OWNED_SEQUENTIAL_VALIDATOR_SHA256 if owned_sequential else VALIDATOR_SHA256,
        lease_seconds=lease_seconds,
    )
async def _count(session, table_name: str, tenant: str) -> int:
    table = metadata.tables[table_name]
    value = await session.scalar(
        select(func.count()).select_from(table).where(table.c.tenant_id == tenant)
    )
    return int(value or 0)
