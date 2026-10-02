"""Current relational lifecycle projection for one admitted DAG authority."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from sqlalchemy import func, or_, select, text
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from redagent_platform.campaign_service.authority_envelope import (
    CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION,
    CAMPAIGN_AUTHORITY_MAX_LIFECYCLE_OBSERVATION_SECONDS,
    CampaignAuthorityLifecycleState,
    CampaignAuthorityLifecycleV2,
)
from redagent_platform.persistence.models import metadata


class PostgresDagLifecycleOwner:
    """Rebuild lifecycle from current canonical rows; observations remain evidence only."""

    def __init__(self, sessions: async_sessionmaker[AsyncSession]) -> None:
        self._sessions = sessions

    async def read_current_lifecycle(
        self, *, tenant_id: str, authority_sha256: str, now: datetime
    ) -> CampaignAuthorityLifecycleV2 | None:
        _required("dag_lifecycle_tenant", tenant_id, 64)
        _digest("dag_lifecycle_authority", authority_sha256)
        # CRITICAL: use the gate's application clock for observation and expiry;
        # database clock skew otherwise makes a freshly read lifecycle look future-dated.
        _aware(now)
        async with self._sessions() as session, session.begin():
            await session.execute(
                text("SELECT set_config('redagent.tenant_id', :tenant_id, true)"),
                {"tenant_id": tenant_id},
            )
            runs = metadata.tables["campaign_execution_runs"]
            receipts = metadata.tables["plan_admission_receipts"]
            reservations = metadata.tables["campaign_budget_reservations"]
            rows = (
                await session.execute(
                    select(
                        runs,
                        receipts.c.receipt_payload,
                        reservations.c.lease_expires_at,
                        reservations.c.reservation_state,
                    )
                    .join(
                        receipts,
                        (receipts.c.tenant_id == runs.c.tenant_id)
                        & (receipts.c.id == runs.c.admission_receipt_id),
                    )
                    .join(
                        reservations,
                        (reservations.c.tenant_id == runs.c.tenant_id)
                        & (reservations.c.id == runs.c.reservation_id),
                    )
                    .where(
                        runs.c.tenant_id == tenant_id,
                        runs.c.authority_sha256 == authority_sha256,
                        runs.c.run_state.in_(
                            ("start_pending", "running", "stopping", "reconciliation_required")
                        ),
                    )
                    .limit(2)
                    .with_for_update()
                )
            ).mappings().all()
            if len(rows) != 1:
                return None
            run = rows[0]
            receipt_expires_at = _payload_time(run["receipt_payload"], "expires_at")
            valid_until = min(
                receipt_expires_at,
                run["lease_expires_at"],
                now
                + timedelta(
                    seconds=CAMPAIGN_AUTHORITY_MAX_LIFECYCLE_OBSERVATION_SECONDS
                ),
            )
            controls = metadata.tables["containment_controls"]
            nodes = metadata.tables["campaign_execution_nodes"]
            capabilities = select(nodes.c.capability_id).where(
                nodes.c.tenant_id == tenant_id,
                nodes.c.execution_run_id == run["id"],
            )
            stop_count = await session.scalar(
                select(func.count())
                .select_from(controls)
                .where(
                    controls.c.tenant_id == tenant_id,
                    controls.c.control_state.in_(("pending_approval", "active")),
                    or_(
                        controls.c.scope_kind == "global",
                        (controls.c.scope_kind == "tenant")
                        & (controls.c.scope_id == tenant_id),
                        (controls.c.scope_kind == "campaign")
                        & (controls.c.scope_id == run["campaign_id"]),
                        (controls.c.scope_kind == "capability")
                        & controls.c.scope_id.in_(capabilities),
                    ),
                )
            )
            if stop_count:
                return _inactive(
                    run,
                    now=now,
                    state=CampaignAuthorityLifecycleState.REVOKED,
                    reason_code="kill_switch_active",
                    kill_switch_epoch=int(run["kill_switch_epoch"]) + 1,
                )
            if (
                run["reservation_state"] not in {"reserved", "held"}
                or valid_until <= now
            ):
                return _inactive(
                    run,
                    now=now,
                    state=CampaignAuthorityLifecycleState.EXPIRED,
                    reason_code="authority_expired",
                    kill_switch_epoch=int(run["kill_switch_epoch"]),
                )
            return CampaignAuthorityLifecycleV2(
                schema_version=CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION,
                authority_sha256=authority_sha256,
                tenant_id=tenant_id,
                engagement_id=_engagement_id(run),
                state=CampaignAuthorityLifecycleState.ACTIVE,
                lifecycle_epoch=int(run["lifecycle_epoch"]),
                policy_revocation_epoch=int(run["policy_revocation_epoch"]),
                roe_revocation_epoch=int(run["roe_revocation_epoch"]),
                kill_switch_epoch=int(run["kill_switch_epoch"]),
                observed_at=now,
                valid_until=valid_until,
                revoked_at=None,
                reason_code=None,
            )


def _inactive(
    run: Any,
    *,
    now: datetime,
    state: CampaignAuthorityLifecycleState,
    reason_code: str,
    kill_switch_epoch: int,
) -> CampaignAuthorityLifecycleV2:
    return CampaignAuthorityLifecycleV2(
        schema_version=CAMPAIGN_AUTHORITY_LIFECYCLE_SCHEMA_VERSION,
        authority_sha256=str(run["authority_sha256"]),
        tenant_id=str(run["tenant_id"]),
        engagement_id=_engagement_id(run),
        state=state,
        lifecycle_epoch=int(run["lifecycle_epoch"]),
        policy_revocation_epoch=int(run["policy_revocation_epoch"]),
        roe_revocation_epoch=int(run["roe_revocation_epoch"]),
        kill_switch_epoch=kill_switch_epoch,
        observed_at=now,
        valid_until=now + timedelta(seconds=1),
        revoked_at=now,
        reason_code=reason_code,
    )


def _engagement_id(run: Any) -> str:
    payload = run["input_payload"]
    receipt = payload.get("admission_receipt") if isinstance(payload, dict) else None
    value = receipt.get("engagement_id") if isinstance(receipt, dict) else None
    return _required("dag_lifecycle_engagement", value, 64)


def _payload_time(payload: object, name: str) -> datetime:
    value = payload.get(name) if isinstance(payload, dict) else None
    if not isinstance(value, str):
        raise ValueError("dag_lifecycle_receipt_invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("dag_lifecycle_receipt_invalid") from exc
    _aware(parsed)
    return parsed


def _required(name: str, value: object, maximum: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > maximum
    ):
        raise ValueError(f"{name}_invalid")
    return value


def _digest(name: str, value: object) -> str:
    normalized = _required(name, value, 64)
    if len(normalized) != 64 or any(
        character not in "0123456789abcdef" for character in normalized
    ):
        raise ValueError(f"{name}_invalid")
    return normalized


def _aware(value: datetime) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("dag_lifecycle_time_invalid")
