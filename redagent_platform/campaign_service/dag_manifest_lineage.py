"""Execution-lineage adapter for shared manifest-v2 issuance."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import and_, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.campaign_service.service import (
    EffectDispatchCommand,
    ManifestLineageContext,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.persistence.repository import ControlPlaneRepository


class PostgresDagManifestLineageOwner:
    """Rebind one claimed shared effect to a job without strategy lineage."""

    async def prepare(
        self,
        session: AsyncSession,
        command: EffectDispatchCommand,
        *,
        actor_user_id: str,
        stable: str,
        now: datetime,
    ) -> ManifestLineageContext:
        del stable
        # CRITICAL: use the RLS tenant key and set_config for bound PostgreSQL parameters.
        # SET LOCAL cannot bind a value; app.current_tenant also leaves tenant isolation unset.
        await session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
            {"tenant_id": command.tenant_id},
        )
        effects = metadata.tables["campaign_effects"]
        runs = metadata.tables["campaign_execution_runs"]
        campaigns = metadata.tables["campaigns"]
        row = (
            await session.execute(
                select(
                    effects.c.campaign_id,
                    effects.c.execution_run_id,
                    effects.c.node_id,
                    campaigns.c.engagement_id,
                    campaigns.c.roe_version_id,
                )
                .select_from(
                    effects.join(
                        runs,
                        and_(
                            runs.c.tenant_id == effects.c.tenant_id,
                            runs.c.id == effects.c.execution_run_id,
                            runs.c.campaign_id == effects.c.campaign_id,
                        ),
                    ).join(
                        campaigns,
                        and_(
                            campaigns.c.tenant_id == runs.c.tenant_id,
                            campaigns.c.id == runs.c.campaign_id,
                        ),
                    )
                )
                .where(
                    effects.c.tenant_id == command.tenant_id,
                    effects.c.effect_id == command.effect_id,
                    effects.c.strategy_revision_id.is_(None),
                    effects.c.execution_run_id.is_not(None),
                    effects.c.effect_state == "claimed",
                    effects.c.claim_owner == command.claim_owner,
                    effects.c.claim_expires_at > now,
                    effects.c.envelope_sha256 == command.envelope_sha256,
                    runs.c.run_state.in_(("running", "reconciliation_required")),
                    runs.c.stop_requested.is_(False),
                )
            )
        ).mappings().one_or_none()
        if row is None:
            raise RuntimeError("dag_manifest_effect_context_mismatch")
        job = await ControlPlaneRepository(
            session,
            tenant_id=command.tenant_id,
            actor_user_id=actor_user_id,
            correlation_id=f"dag-manifest-job-{command.effect_id[-12:]}",
        ).create_campaign_execution_runner_job(
            campaign_id=str(row["campaign_id"]),
            execution_run_id=str(row["execution_run_id"]),
            node_id=str(row["node_id"]),
            effect_id=command.effect_id,
            claim_owner=command.claim_owner,
            capability_id=command.binding.capability_id,
            envelope_sha256=command.envelope_sha256,
            occurred_at=now,
        )
        return ManifestLineageContext(
            campaign_id=str(row["campaign_id"]),
            engagement_id=str(row["engagement_id"]),
            roe_id=str(row["roe_version_id"]),
            job_id=str(job.resource["job_id"]),
            manifest_namespace="dag-v1",
        )
