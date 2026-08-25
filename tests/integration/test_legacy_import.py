from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
from pathlib import Path
from uuid import uuid4

import pytest
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

from redagent_platform.control_plane import ControlPlaneRecordType, JsonlControlPlaneStore
from redagent_platform.persistence.database import load_database_settings
from redagent_platform.persistence.legacy_import import LegacyImportError, LegacyJsonlImporter, load_legacy_import_bundle
from redagent_platform.persistence.models import metadata


ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 7, 10, 8, 30, tzinfo=timezone.utc)


def test_legacy_jsonl_import_is_atomic_idempotent_audited_and_source_immutable() -> None:
    asyncio.run(_legacy_import_scenario())


async def _legacy_import_scenario() -> None:
    settings = load_database_settings(ROOT, env=os.environ)
    suffix = uuid4().hex
    tenant_id = f"tenant-legacy-{suffix}"
    user_id = f"user-legacy-{suffix}"
    engagement_id = f"eng-legacy-{suffix}"
    target_id = f"target-legacy-{suffix}"
    roe_id = f"roe-legacy-{suffix}"
    approval_id = f"approval-legacy-{suffix}"
    source_dir = ROOT / ".local" / "redagent" / "test-imports" / suffix
    source_dir.mkdir(parents=True, exist_ok=False)
    source = source_dir / "control-plane.jsonl"
    store = JsonlControlPlaneStore(source)
    store.append(
        ControlPlaneRecordType.ENGAGEMENT,
        engagement_id,
        {
            "engagement_id": engagement_id,
            "organization_id": tenant_id,
            "name": "Legacy lifecycle",
            "owner_user_id": user_id,
            "created_at": NOW.isoformat(),
        },
    )
    store.append(
        ControlPlaneRecordType.TARGET,
        target_id,
        {
            "target_id": target_id,
            "organization_id": tenant_id,
            "engagement_id": engagement_id,
            "owner_label": "Synthetic owner",
            "target_type": "hostname",
            "value": "legacy.example.invalid",
            "environment": "lab",
            "data_sensitivity": "public",
            "authorization_status": "approved",
            "allowed_modes": ["passive"],
            "registered_at": NOW.isoformat(),
            "registered_by_user_id": user_id,
        },
    )
    store.append(
        ControlPlaneRecordType.ROE_VERSION,
        roe_id,
        {
            "roe_version_id": roe_id,
            "engagement_id": engagement_id,
            "organization_id": tenant_id,
            "version": 1,
            "status": "approved",
            "allowed_targets": [{"type": "hostname", "value": "legacy.example.invalid"}],
            "forbidden_targets": [],
            "allowed_modes": ["passive"],
            "window_start": NOW.isoformat(),
            "window_end": "2026-07-11T08:30:00+00:00",
            "max_interactions": 10,
            "max_rate_per_second": 1.0,
            "emergency_contact_method": "synthetic@example.invalid",
            "created_by_user_id": user_id,
            "created_at": NOW.isoformat(),
            "approved_by_user_id": user_id,
            "approved_at": NOW.isoformat(),
            "superseded_by_version_id": None,
            "status_reason": None,
        },
    )
    store.append(
        ControlPlaneRecordType.APPROVAL,
        approval_id,
        {
            "approval_id": approval_id,
            "roe_version_id": roe_id,
            "approved_by_user_id": user_id,
            "approved_at": NOW.isoformat(),
            "approval_label": "Legacy approved",
        },
    )
    store.append(
        ControlPlaneRecordType.POLICY_DECISION,
        f"decision-{suffix}",
        {
            "decision_id": f"decision-{suffix}",
            "roe_version_id": roe_id,
            "organization_id": tenant_id,
            "engagement_id": engagement_id,
            "outcome": "allow",
            "reason": "legacy synthetic",
            "decided_at": NOW.isoformat(),
            "expires_at": "2026-07-10T09:30:00+00:00",
            "target": {"type": "hostname", "value": "legacy.example.invalid"},
            "mode": "passive",
            "projected_interactions": 1,
            "operator_user_id": user_id,
        },
    )
    before = source.read_bytes()
    bundle = load_legacy_import_bundle(ROOT, source)
    engine = create_async_engine(settings.url)
    sessions = async_sessionmaker(engine, expire_on_commit=False)
    try:
        async with sessions() as session, session.begin():
            importer = LegacyJsonlImporter(
                session,
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id=f"corr-legacy-{suffix}",
            )
            first = await importer.import_bundle(bundle, idempotency_key=f"legacy-{suffix}", occurred_at=NOW)
        async with sessions() as session, session.begin():
            importer = LegacyJsonlImporter(
                session,
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id=f"corr-legacy-replay-{suffix}",
            )
            replay = await importer.import_bundle(bundle, idempotency_key=f"legacy-{suffix}", occurred_at=NOW)
        assert first.replayed is False
        assert replay.replayed is True
        assert replay.resource == first.resource
        assert source.read_bytes() == before

        async with sessions() as session, session.begin():
            for table_name, expected in (
                ("engagements", 1),
                ("targets", 1),
                ("roe_versions", 1),
                ("approvals", 1),
                ("policy_references", 1),
                ("idempotency_records", 1),
                ("outbox_events", 1),
            ):
                table = metadata.tables[table_name]
                count = await session.scalar(
                    select(func.count()).select_from(table).where(table.c.tenant_id == tenant_id)
                )
                assert int(count or 0) == expected, table_name
            audits = metadata.tables["audit_events"]
            audit_actions = set(
                (await session.scalars(select(audits.c.action).where(audits.c.tenant_id == tenant_id))).all()
            )
            assert "legacy.policy_decision" in audit_actions
            assert "legacy-jsonl:import" in audit_actions

        source.write_bytes(before + b"\n")
        async with sessions() as session, session.begin():
            importer = LegacyJsonlImporter(
                session,
                tenant_id=tenant_id,
                actor_user_id=user_id,
                correlation_id=f"corr-legacy-changed-{suffix}",
            )
            with pytest.raises(LegacyImportError, match="legacy_source_changed"):
                await importer.import_bundle(bundle, idempotency_key=f"changed-{suffix}", occurred_at=NOW)
    finally:
        await engine.dispose()
        source.unlink(missing_ok=True)
        source_dir.rmdir()
