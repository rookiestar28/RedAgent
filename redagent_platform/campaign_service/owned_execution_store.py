"""PostgreSQL application ownership at the admitted DAG execution boundary."""

from datetime import datetime
from dataclasses import asdict
import hashlib
from typing import Any

from sqlalchemy import insert, select
from sqlalchemy.ext.asyncio import AsyncSession

from redagent_platform.campaign_service.application_contracts import (
    is_owned_execution_mode,
    ApplicationBindingConflict,
    AutonomousCampaignLifecycle,
)
from redagent_platform.campaign_service.application_repository import (
    _state_from_row,
    _verified_preview_from_payload,
    _verified_receipt_from_payload,
)
from redagent_platform.campaign_service.admission_start_store import _transition_application
from redagent_platform.campaign_service.dag_execution_contracts import (
    DAG_EXECUTION_SCHEMA_VERSION,
    DagWorkflowInputV1,
    dag_workflow_request_sha256,
)
from redagent_platform.campaign_service.owned_execution import (
    OwnedExecutionDenied,
    owned_execution_attention,
    validate_owned_execution_input,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from redagent_platform.persistence.models import metadata
from redagent_platform.campaign_service.child_lineage import (
    ChildLineageConflict, ChildLineageVerifier, require_current_child_lineage,
)
from redagent_platform.campaign_service.operator_scope import assert_operator_scope_current


async def assert_owned_execution_current(
    session: AsyncSession, run: Any, *, now: datetime, enabled: bool,
    child_lineage_verifier: ChildLineageVerifier | None = None,
) -> None:
    """Legacy unlinked DAGs retain their gate; application DAGs require exact auto approval."""
    applications = metadata.tables["autonomous_campaign_applications"]
    row = (await session.execute(select(applications).where(
        applications.c.tenant_id == run["tenant_id"],
        applications.c.id == run["campaign_id"],
    ).with_for_update())).mappings().one_or_none()
    if row is None:
        return
    current = _state_from_row(row)
    try:
        await assert_operator_scope_current(session, tenant_id=run["tenant_id"], campaign_id=run["campaign_id"])
    except ApplicationBindingConflict as exc:
        raise OwnedExecutionDenied(str(exc)) from exc
    if not enabled or not is_owned_execution_mode(current.mode):
        raise OwnedExecutionDenied("owned_execution_mode_denied")
    if current.lifecycle_state not in {AutonomousCampaignLifecycle.EXECUTION_QUEUED, AutonomousCampaignLifecycle.RUNNING, AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED}:
        raise OwnedExecutionDenied("owned_execution_lifecycle_denied")
    starts = metadata.tables["autonomous_campaign_execution_starts"]
    start = (await session.execute(select(starts).where(
        starts.c.tenant_id == run["tenant_id"],
        starts.c.application_id == current.campaign_id,
        starts.c.execution_run_id == run["id"],
        starts.c.start_state == "execution_queued",
    ))).mappings().one_or_none()
    if start is None or start["workflow_run_id"] is None or now >= start["expires_at"]:
        raise OwnedExecutionDenied("owned_execution_start_not_current")
    approvals = metadata.tables["autonomous_campaign_plan_approval_receipts"]
    approval_row = (await session.execute(select(approvals).where(
        approvals.c.tenant_id == run["tenant_id"], approvals.c.id == start["approval_receipt_id"],
        approvals.c.application_id == current.campaign_id,
    ))).mappings().one_or_none()
    if approval_row is None:
        raise OwnedExecutionDenied("owned_execution_approval_missing")
    approval = _verified_receipt_from_payload(approval_row["receipt_payload"], str(approval_row["receipt_sha256"]))
    previews = metadata.tables["autonomous_campaign_plan_previews"]
    preview_row = (await session.execute(select(previews).where(
        previews.c.tenant_id == run["tenant_id"], previews.c.id == approval.preview_id,
        previews.c.application_id == current.campaign_id,
    ))).mappings().one_or_none()
    if preview_row is None:
        raise OwnedExecutionDenied("owned_execution_preview_missing")
    preview = _verified_preview_from_payload(preview_row["preview_payload"], str(preview_row["preview_sha256"]))
    if (
        preview.execution_mode is not current.mode
        or preview.preview_sha256 != approval.preview_sha256
        or approval.decision.value != "approved"
        or approval.receipt_sha256 != start["approval_receipt_sha256"]
        or now >= min(approval.expires_at, preview.expires_at)
        or preview.target_id != current.target_id
        or preview.application_intent_sha256 != current.intent_sha256
        or preview.source_binding_sha256 != current.source_binding_sha256
    ):
        raise OwnedExecutionDenied("owned_execution_approval_binding_mismatch")
    for key in ("input_sha256", "authority_sha256", "domain_sha256", "plan_sha256", "certificate_sha256", "admission_receipt_sha256", "reserved_budget_sha256"):
        if run[key] != start[key]:
            raise OwnedExecutionDenied("owned_execution_run_binding_mismatch")
    payload = run["input_payload"]
    if not isinstance(payload, dict) or canonical_planning_sha256(payload) != run["input_sha256"]:
        raise OwnedExecutionDenied("owned_execution_input_digest_mismatch")
    validate_owned_execution_input(payload)
    if canonical_planning_sha256(payload.get("execution_bindings")) != canonical_planning_sha256(preview.execution_bindings):
        raise OwnedExecutionDenied("owned_execution_semantics_binding_mismatch")
    if any(node["target_id"] != current.target_id for node in payload["revision"]["candidate_plan"]["nodes"]):
        raise OwnedExecutionDenied("owned_execution_target_binding_mismatch")
    if int(run["max_transitions"]) > 32:
        raise OwnedExecutionDenied("owned_execution_transition_bound_exceeded")
    try:
        await require_current_child_lineage(preview=preview, tenant_id=current.tenant_id, campaign_id=current.campaign_id,
            now=now, verifier=child_lineage_verifier, session=session)
    except (ChildLineageConflict, ValueError) as exc:
        raise OwnedExecutionDenied("owned_execution_child_lineage_not_current") from exc


async def emit_owned_execution_start(session: AsyncSession, run: Any, *, now: datetime) -> None:
    """Called only inside the exact admission-bridge acknowledgement transaction."""
    payload = run["input_payload"]
    validate_owned_execution_input(payload)
    request = DagWorkflowInputV1(
        schema_version=DAG_EXECUTION_SCHEMA_VERSION,
        tenant_id=str(run["tenant_id"]), execution_run_id=str(run["id"]),
        input_sha256=str(run["input_sha256"]), plan_sha256=str(run["plan_sha256"]),
        max_activity_attempts=2, max_transitions=int(run["max_transitions"]),
    )
    if request.max_transitions > 32 or dag_workflow_request_sha256(request) != run["request_sha256"]:
        raise OwnedExecutionDenied("owned_execution_workflow_binding_mismatch")
    stable = hashlib.sha256(str(run["id"]).encode()).hexdigest()[:32]
    await session.execute(insert(metadata.tables["outbox_events"]).values(
        id=f"outbox-dag-{stable}", tenant_id=run["tenant_id"],
        event_type="campaign.dag.start.requested.v1", aggregate_id=run["id"],
        payload=asdict(request), published=False, schema_revision=2,
        aggregate_type="campaign_execution", aggregate_sequence=1, available_at=now,
        claim_owner=None, claim_expires_at=None, attempt_count=0, last_error=None,
        delivered_at=None, delivery_state="pending", reconciliation_state="none",
        dead_lettered_at=None, version=1, created_at=now, updated_at=now,
    ))


async def project_owned_execution(
    session: AsyncSession, run: Any, *, now: datetime, actor_user_id: str
) -> None:
    applications = metadata.tables["autonomous_campaign_applications"]
    row = (await session.execute(select(applications).where(
        applications.c.tenant_id == run["tenant_id"], applications.c.id == run["campaign_id"],
    ).with_for_update())).mappings().one_or_none()
    if row is None:
        return
    current = _state_from_row(row)
    if not is_owned_execution_mode(current.mode):
        return
    target = {
        "running": AutonomousCampaignLifecycle.RUNNING,
        "completed": AutonomousCampaignLifecycle.EVIDENCE_PENDING,
        "reconciliation_required": AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED,
        "contained": AutonomousCampaignLifecycle.FAILED_CONTAINED,
        "failed_before_io": AutonomousCampaignLifecycle.FAILED_CONTAINED,
        "failed": AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
        "manual_review_required": AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
    }.get(str(run["run_state"]))
    reason = run["terminal_reason"]
    if reason is None:
        effects = metadata.tables["campaign_effects"]
        failures = (await session.execute(select(effects.c.failure_code).where(
            effects.c.tenant_id == run["tenant_id"], effects.c.execution_run_id == run["id"],
            effects.c.failure_code.is_not(None),
        ).order_by(effects.c.outbox_sequence.desc()))).scalars().all()
        reason = next((value for value in failures if owned_execution_attention(value) is not None), None)
    attention = owned_execution_attention(reason)
    if attention is not None and target is not AutonomousCampaignLifecycle.FAILED_CONTAINED:
        target = attention
    if target is None or target is current.lifecycle_state or current.lifecycle_state is AutonomousCampaignLifecycle.REVOKED:
        return
    # CRITICAL: execution completion is only evidence-pending, never verified success.
    await _transition_application(
        session, current=current, target=target,
        operation="autonomous_campaign.execution.project.v1",
        event_type="autonomous_campaign.execution_state.v1", actor_user_id=actor_user_id,
        correlation_id=f"owned-execution-{str(run['id'])[-24:]}",
        request_sha256=str(run["request_sha256"]), policy_reference="owned-execution-current",
        event_payload={"execution_run_id": str(run["id"]), "run_state": str(run["run_state"]), "reason_code": run["terminal_reason"]},
        occurred_at=now,
        attention_reason=(str(reason or "owned_execution_attention")[:100] if target in {
            AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED, AutonomousCampaignLifecycle.MANUAL_REVIEW_REQUIRED,
            AutonomousCampaignLifecycle.CLEANUP_INCOMPLETE, AutonomousCampaignLifecycle.EVIDENCE_INCOMPLETE,
        } else None),
    )
