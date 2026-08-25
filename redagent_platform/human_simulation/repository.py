"""PostgreSQL-authoritative compat_112 consent, campaign, run, and minimized evidence state."""

from __future__ import annotations

from datetime import datetime, timedelta
import hashlib
import json
from uuid import uuid4

from sqlalchemy import insert, select, text, update
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.human_simulation.catalog import certified_campaign
from redagent_platform.human_simulation.compiler import CompiledCampaignPlan
from redagent_platform.human_simulation.contracts import CampaignApproval, CampaignAuthorization, campaign_sha256
from redagent_platform.persistence.models import metadata


class HumanSimulationRepositoryConflict(RuntimeError):
    """Stable compat_112 persistence or delivery denial."""


class HumanSimulationRepository:
    def __init__(self, session: AsyncSession, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session; self.tenant_id = _id(tenant_id); self.actor_user_id = _id(actor_user_id); self.correlation_id = _id(correlation_id)

    async def certify_foundation(self, *, occurred_at: datetime) -> dict[str, object]:
        _aware(occurred_at); await self._context(); await self._lock("human-foundation")
        campaign = certified_campaign(); digest = campaign_sha256(campaign); adapter_sha = _digest("redagent-owned-message-sink/1.0.0")
        adapter = await self._immutable("human_adapter_artifacts", {"adapter_id": "redagent-owned-message-sink", "adapter_sha256": adapter_sha},
            {"adapter_id": "redagent-owned-message-sink", "adapter_sha256": adapter_sha, "owned": True,
             "external_delivery_allowed": False, "adapter_state": "certified-sink-only"}, occurred_at, "adapter")
        for external in ("gophish", "canarytokens", "openaev", "mailpit"):
            external_sha = _digest(external)
            await self._immutable("human_adapter_artifacts", {"adapter_id": external, "adapter_sha256": external_sha},
                {"adapter_id": external, "adapter_sha256": external_sha, "owned": False,
                 "external_delivery_allowed": False, "adapter_state": "disabled-reference-only"}, occurred_at, "adapter")
        manifest = await self._immutable("human_campaign_manifests", {"campaign_id": campaign.campaign_id, "campaign_sha256": digest},
            {"campaign_id": campaign.campaign_id, "campaign_sha256": digest, "purpose": campaign.purpose,
             "jurisdiction_review_id": campaign.jurisdiction_review_id, "privacy_review_id": campaign.privacy_review_id,
             "roster_sha256": campaign.roster_sha256, "suppression_sha256": campaign.suppression_sha256,
             "template_sha256": campaign.template_sha256, "sink_id": campaign.sink_id, "canary_id": campaign.canary_id,
             "max_deliveries": 1, "rate_per_minute": 1, "retention_seconds": 300, "human_delivery": False,
             "external_delivery": False, "manifest_state": "certified-synthetic-sink"}, occurred_at, "campaign")
        roster = await self._immutable("human_consent_rosters", {"roster_id": "roster-r112-synthetic", "roster_sha256": campaign.roster_sha256},
            {"campaign_record_id": manifest["id"], "roster_id": "roster-r112-synthetic", "roster_sha256": campaign.roster_sha256,
             "recipient_count": 1, "synthetic_only": True, "consent_state": "approved-synthetic",
             "expires_at": occurred_at + timedelta(days=1)}, occurred_at, "roster")
        suppression = await self._immutable("human_suppression_lists", {"suppression_id": "suppression-r112-deny-real", "suppression_sha256": campaign.suppression_sha256},
            {"campaign_record_id": manifest["id"], "suppression_id": "suppression-r112-deny-real",
             "suppression_sha256": campaign.suppression_sha256, "deny_real_recipients": True,
             "suppression_state": "active-deny-real"}, occurred_at, "suppression")
        privacy = await self._immutable("human_privacy_reviews", {"review_id": campaign.privacy_review_id},
            {"campaign_record_id": manifest["id"], "review_id": campaign.privacy_review_id, "purpose": campaign.purpose,
             "jurisdiction": "local-synthetic", "minimized_categories": ["synthetic_accepted", "empty", "rejected_real_or_unknown", "canary_triggered", "reported"],
             "retention_seconds": 300, "deletion_required": True, "reviewed_by": "privacy-reviewer-r112",
             "review_state": "approved-synthetic-only"}, occurred_at, "privacy")
        template = await self._immutable("human_message_templates", {"template_id": "template-r112-owned", "template_sha256": campaign.template_sha256},
            {"campaign_record_id": manifest["id"], "template_id": "template-r112-owned", "template_sha256": campaign.template_sha256,
             "rendered_sha256": _digest([campaign.sender, campaign.recipient, campaign.subject, campaign.body]),
             "external_link_count": 0, "attachment_count": 0, "tracking_count": 0,
             "template_state": "rendered-owned-synthetic"}, occurred_at, "template")
        await self._audit("human.foundation.certified", campaign.campaign_id,
            {"campaign_sha256": digest, "human_delivery": False, "external_delivery": False, "raw_submission_retention": False}, occurred_at)
        return {"adapter": adapter, "campaign": manifest, "roster": roster, "suppression": suppression, "privacy": privacy, "template": template}

    async def store_approval(self, *, approval: CampaignApproval, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"human-approval:{_id(approval.approval_id)}")
        campaign = await self._find("human_campaign_manifests", {"campaign_id": approval.campaign_id, "campaign_sha256": approval.campaign_sha256})
        roster = await self._find("human_consent_rosters", {"campaign_record_id": campaign["id"]}) if campaign else None
        suppression = await self._find("human_suppression_lists", {"campaign_record_id": campaign["id"]}) if campaign else None
        privacy = await self._find("human_privacy_reviews", {"campaign_record_id": campaign["id"]}) if campaign else None
        if campaign is None or roster is None or suppression is None or privacy is None or not roster["synthetic_only"] or not suppression["deny_real_recipients"] or not privacy["deletion_required"]:
            raise HumanSimulationRepositoryConflict("human_exact_consent_privacy_foundation_required")
        return await self._immutable("human_campaign_approvals", {"approval_id": approval.approval_id},
            {"approval_id": approval.approval_id, "campaign_record_id": campaign["id"], "campaign_sha256": approval.campaign_sha256,
             "rendered_sha256": approval.rendered_sha256, "test_delivery_sha256": approval.test_delivery_sha256,
             "requester_id": approval.requester_id, "preview_reviewer_id": approval.preview_reviewer_id,
             "send_approver_id": approval.send_approver_id, "approval_state": "send-approved-exact",
             "approved_at": approval.approved_at, "expires_at": approval.expires_at}, occurred_at, "approval")

    async def store_plan(self, *, plan_id: str, compiled: CompiledCampaignPlan, approval: CampaignApproval,
                         authorization: CampaignAuthorization, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"human-plan:{_id(plan_id)}")
        campaign = await self._find("human_campaign_manifests", {"campaign_id": compiled.campaign_id, "campaign_sha256": compiled.campaign_sha256})
        approved = await self._find("human_campaign_approvals", {"approval_id": approval.approval_id})
        if campaign is None or approved is None or approved["campaign_sha256"] != compiled.campaign_sha256 or approved["rendered_sha256"] != compiled.rendered_sha256 or approved["test_delivery_sha256"] != compiled.test_delivery_sha256:
            raise HumanSimulationRepositoryConflict("human_exact_approval_required")
        return await self._immutable("human_campaign_plans", {"plan_id": plan_id},
            {"plan_id": plan_id, "campaign_record_id": campaign["id"], "approval_record_id": approved["id"],
             "policy_decision_id": authorization.policy_decision_id, "roe_revision": authorization.roe_revision,
             "reservation_id": authorization.reservation_id, "delivery_lease_id": authorization.delivery_lease_id,
             "stop_switch_id": authorization.stop_switch_id, "quota_id": authorization.quota_id,
             "plan_sha256": compiled.plan_sha256, "plan_state": "compiled-synthetic-sink",
             "expires_at": authorization.expires_at}, occurred_at, "plan")

    async def create_run(self, *, run_id: str, plan_id: str, job_id: str, runner_id: str, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"human-run:{_id(run_id)}"); existing = await self._find("human_campaign_runs", {"run_id": run_id})
        if existing:
            return existing
        plan = await self._find("human_campaign_plans", {"plan_id": plan_id})
        if plan is None or plan["expires_at"] <= occurred_at:
            raise HumanSimulationRepositoryConflict("human_active_plan_required")
        row = self._owned("run", occurred_at) | {"run_id": run_id, "plan_record_id": plan["id"], "job_id": _id(job_id),
            "runner_id": _id(runner_id), "run_state": "delivery_pending", "new_delivery_blocked": False,
            "human_delivery_count": 0, "external_delivery_count": 0, "deletion_verified": False, "failure_code": None}
        await self.session.execute(insert(metadata.tables["human_campaign_runs"]).values(**row))
        await self._audit("human.run.accepted", run_id, {"plan_id": plan_id, "synthetic_sink_only": True}, occurred_at); return row

    async def request_stop(self, *, run_id: str, expected_version: int, occurred_at: datetime) -> dict[str, object]:
        await self._context(); await self._lock(f"human-run:{_id(run_id)}"); row = await self._find("human_campaign_runs", {"run_id": run_id})
        if row is None:
            raise HumanSimulationRepositoryConflict("human_run_not_found")
        if row["version"] != expected_version:
            raise HumanSimulationRepositoryConflict("human_run_version_conflict")
        values = {"run_state": "stop_requested", "new_delivery_blocked": True, "version": int(row["version"]) + 1, "updated_at": occurred_at}
        await self.session.execute(update(metadata.tables["human_campaign_runs"]).where(metadata.tables["human_campaign_runs"].c.id == row["id"]).values(**values))
        await self._audit("human.run.stop_requested", run_id, {"block_delivery_first": True, "revoke_lease_first": True, "recall_claimed": False}, occurred_at)
        return row | values

    async def dashboard(self) -> dict[str, list[dict[str, object]]]:
        await self._context(); result: dict[str, list[dict[str, object]]] = {}
        for key, name in (("campaigns", "human_campaign_manifests"), ("rosters", "human_consent_rosters"),
                          ("suppressions", "human_suppression_lists"), ("privacy_reviews", "human_privacy_reviews"),
                          ("templates", "human_message_templates"), ("approvals", "human_campaign_approvals"),
                          ("plans", "human_campaign_plans"), ("runs", "human_campaign_runs"),
                          ("deliveries", "human_delivery_receipts"), ("events", "human_minimized_events"),
                          ("canaries", "human_canary_correlations"), ("stops", "human_stop_receipts"),
                          ("deletions", "human_deletion_receipts"), ("rehearsals", "human_rehearsal_receipts")):
            table = metadata.tables[name]
            rows = (await self.session.execute(select(table).where(table.c.tenant_id == self.tenant_id).order_by(table.c.created_at.desc()).limit(100))).mappings().all()
            result[key] = [dict(item) for item in rows]
        capabilities = metadata.tables["execution_capability_manifests"]
        capability_rows = (await self.session.execute(select(capabilities).where(
            capabilities.c.tenant_id == self.tenant_id,
            capabilities.c.capability_id == "human-simulation-sink",
            capabilities.c.capability_status == "certified",
        ))).mappings().all()
        registrations = metadata.tables["runner_registrations"]
        runner_rows = (await self.session.execute(select(registrations).where(
            registrations.c.tenant_id == self.tenant_id,
        ).order_by(registrations.c.last_seen_at.desc()).limit(100))).mappings().all()
        jobs = metadata.tables["jobs"]
        job_rows = (await self.session.execute(select(jobs).where(
            jobs.c.tenant_id == self.tenant_id,
        ).order_by(jobs.c.created_at.desc()).limit(100))).mappings().all()
        reservations = metadata.tables["quota_reservations"]
        reservation_rows = (await self.session.execute(select(reservations).where(
            reservations.c.tenant_id == self.tenant_id,
            reservations.c.reservation_state.in_(("reserved", "partially_consumed")),
        ).order_by(reservations.c.created_at.desc()).limit(100))).mappings().all()
        compatible = {
            (f"{row['adapter_id']}:{row['adapter_version']}", str(row["image_digest"]))
            for row in capability_rows
        }
        # CRITICAL: option visibility is read-only; compile/run handlers retain exact authorization authority.
        result["approval_options"] = [row for row in result["approvals"] if row["approval_state"] == "send-approved-exact"]
        result["runner_options"] = [dict(row) for row in runner_rows if any(
            adapter in row["adapter_allowlist"] and image in row["image_allowlist"]
            for adapter, image in compatible
        )]
        result["job_options"] = [dict(row) for row in job_rows if (
            isinstance(row["request"], dict) and row["request"].get("capability") == "human-simulation-sink"
        )]
        result["reservation_options"] = [dict(row) for row in reservation_rows]
        return result

    async def _immutable(self, table_name: str, where: dict[str, object], values: dict[str, object], occurred_at: datetime, prefix: str) -> dict[str, object]:
        existing = await self._find(table_name, where)
        if existing:
            if any(existing[name] != value for name, value in values.items()):
                raise HumanSimulationRepositoryConflict(f"human_{prefix}_immutable")
            return existing
        row = self._owned(prefix, occurred_at) | values; await self.session.execute(insert(metadata.tables[table_name]).values(**row)); return row

    async def _find(self, table_name: str, where: dict[str, object]) -> dict[str, object] | None:
        table = metadata.tables[table_name]; clauses = [table.c.tenant_id == self.tenant_id] + [getattr(table.c, key) == value for key, value in where.items()]
        row = (await self.session.execute(select(table).where(*clauses))).mappings().one_or_none(); return dict(row) if row else None

    def _owned(self, prefix: str, occurred_at: datetime) -> dict[str, object]:
        return {"id": f"human-{prefix}-{uuid4().hex}", "tenant_id": self.tenant_id, "version": 1,
                "created_at": occurred_at, "updated_at": occurred_at}

    async def _context(self) -> None:
        await self.session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": self.tenant_id})

    async def _lock(self, scope: str) -> None:
        await self.session.execute(text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"), {"scope": f"{self.tenant_id}:{scope}"})

    async def _audit(self, event: str, subject: str, details: dict[str, object], occurred_at: datetime) -> None:
        owned = {"tenant_id": self.tenant_id, "version": 1, "created_at": occurred_at, "updated_at": occurred_at}
        await self.session.execute(insert(metadata.tables["audit_events"]).values(id=f"audit-{uuid4().hex}", actor_user_id=self.actor_user_id,
            action=event, subject_type="human_simulation", subject_id=subject[:64], correlation_id=self.correlation_id, details=details, **owned))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(id=f"outbox-{uuid4().hex}", event_type=event,
            aggregate_id=subject[:64], payload=details, published=False, **owned))


def _id(value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not all(char.isalnum() or char in "._:-" for char in value):
        raise HumanSimulationRepositoryConflict("human_identifier_invalid")
    return value


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise HumanSimulationRepositoryConflict("human_time_invalid")


def _digest(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()).hexdigest()
