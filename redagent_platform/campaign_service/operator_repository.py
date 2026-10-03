"""Native operator snapshot and recovery ownership; no execution authority is minted here."""

from __future__ import annotations

from dataclasses import replace
from datetime import datetime
import hashlib
from typing import Any, Mapping

from sqlalchemy import select, text, update

from redagent_platform.campaign_service.application_contracts import (
    ApplicationBindingConflict, ApplicationNotFound, ApplicationPlanInvalid,
    ApplicationRevisionConflict, ApplicationTransitionConflict, AutonomousCampaignMutationResultV1,
)
from redagent_platform.campaign_service.application_repository import (
    PostgresAutonomousCampaignApplicationRepository,
    _read_row, _state_from_row, _verified_preview_from_payload, _verified_receipt_from_payload,
    _lock_idempotency, _read_idempotency_payload, _record_lifecycle_event,
    _record_idempotency, _result_payload, _result_from_payload, _verify_replay_lineage,
)
from redagent_platform.campaign_service.approval_api import _preview_payload
from redagent_platform.campaign_service.operations import (
    _read_source, _capability_label, project_campaign_operations, CampaignOperationsProjectionInvalid,
)
from redagent_platform.campaign_service.planning.contracts import canonical_planning_sha256
from redagent_platform.campaign_service.repository import (
    campaign_core_principal_is_active, _effect_receipt_contract,
)
from redagent_platform.persistence.models import metadata
from redagent_platform.campaign_service.operator_contracts import (
    AutonomousCampaignOperatorRecoveryV1, AutonomousCampaignOperatorStopCommitV1,
)
from redagent_platform.campaign_service.operator_evidence import native_operator_result_sha256, verify_operator_bundle
from redagent_platform.campaign_service.operator_scope import read_operator_scope, assert_operator_scope_current
from redagent_platform.evidence_service.service import _stored_from_artifact
from redagent_platform.campaign_service.child_admission import verify_child_transition_settlement


_STOP_OPERATION = "autonomous_campaign.operator.stop.v1"
_STOP_EVENT = "autonomous_campaign.operator.stop_requested.v1"
_NONTERMINAL_RUNS = {"start_pending", "running", "stopping", "reconciliation_required"}


class PostgresAutonomousCampaignOperatorOwner:
    def __init__(self, sessions, *, bundle_source=None, evidence_backend=None) -> None:
        if bundle_source is not None and (not callable(getattr(bundle_source, "read_current_bundle", None))
            or not callable(getattr(evidence_backend, "verify_exact", None))):
            raise ValueError("operator_bundle_owner_configuration_incomplete")
        self._sessions = sessions
        self._bundle_source, self._evidence_backend = bundle_source, evidence_backend

    async def request_revoke(self, command: AutonomousCampaignOperatorRecoveryV1) -> AutonomousCampaignMutationResultV1:
        if not isinstance(command, AutonomousCampaignOperatorRecoveryV1) or command.action != "revoke":
            raise ValueError("operator_revoke_command_invalid")
        # Reuse the canonical graph and audit/replay transaction; disabled creation does not grant
        # another lifecycle edge or require a fresh effect authority for this safety action.
        return await PostgresAutonomousCampaignApplicationRepository(self._sessions).revoke_intent(
            command.revoke_command(), operator_request=True,
        )

    async def request_stop(self, command: AutonomousCampaignOperatorRecoveryV1) -> AutonomousCampaignOperatorStopCommitV1:
        if not isinstance(command, AutonomousCampaignOperatorRecoveryV1) or command.action != "stop":
            raise ValueError("operator_stop_command_invalid")
        async with self._sessions() as session, session.begin():
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": command.tenant_id})
            await _current_principal(session, tenant_id=command.tenant_id, principal_id=command.actor_user_id,
                                     now=command.occurred_at, lock=True)
            await _lock_idempotency(session, tenant_id=command.tenant_id, operation=_STOP_OPERATION, idempotency_key=command.idempotency_key)
            replay = await _read_idempotency_payload(session, tenant_id=command.tenant_id, operation=_STOP_OPERATION,
                                                    idempotency_key=command.idempotency_key, request_sha256=command.request_sha256)
            if replay is not None:
                mutation = _result_from_payload(replay["mutation"], replayed=True)
                if mutation.application.tenant_id != command.tenant_id or mutation.application.campaign_id != command.campaign_id or mutation.application.aggregate_revision != command.expected_revision + 1:
                    raise ApplicationBindingConflict("operator_stop_replay_binding_invalid")
                commit = AutonomousCampaignOperatorStopCommitV1(
                    mutation, replay["execution_run_id"], replay["workflow_id"], replay["workflow_run_id"], replay["signal_id"],
                )
                await _verify_replay_lineage(
                    session, state=mutation.application, operation=_STOP_OPERATION, request_sha256=command.request_sha256,
                    actor_user_id=command.actor_user_id, audit_id=mutation.audit_id, event_id=mutation.event_id,
                    event_type=_STOP_EVENT, previous_states=(mutation.application.lifecycle_state,),
                    event_payload=_stop_event_payload(command, commit), policy_reference=None,
                )
                run = await _exact(session, "campaign_execution_runs", command.tenant_id, commit.execution_run_id)
                # IMPORTANT: a stop committed before Temporal starts has no run ID yet. The later
                # native assignment is progress, not a changed stop; replay never sends a new signal.
                if run is None or run["campaign_id"] != command.campaign_id or run["stop_requested"] is not True or run["workflow_id"] != commit.workflow_id or (
                    commit.workflow_run_id is not None and run["workflow_run_id"] != commit.workflow_run_id
                ):
                    raise ApplicationBindingConflict("operator_stop_replay_owner_invalid")
                return commit
            runs = metadata.tables["campaign_execution_runs"]
            starts = metadata.tables["autonomous_campaign_execution_starts"]
            run = (await session.execute(select(runs).join(starts, (
                (starts.c.tenant_id == runs.c.tenant_id) & (starts.c.execution_run_id == runs.c.id)
                & (starts.c.application_id == runs.c.campaign_id)
            )).where(runs.c.tenant_id == command.tenant_id, runs.c.campaign_id == command.campaign_id)
                .order_by(starts.c.created_at.desc(), starts.c.id.desc()).limit(1)
                .with_for_update(of=runs))).mappings().one_or_none()
            if run is None:
                raise ApplicationTransitionConflict("operator_run_unavailable")
            # CRITICAL: lock the exact run before the application, matching pre-I/O and child intake.
            # Reversing this order can deadlock stop against a runner authorization transaction.
            applications = metadata.tables["autonomous_campaign_applications"]
            row = (await session.execute(select(applications).where(
                applications.c.tenant_id == command.tenant_id, applications.c.id == command.campaign_id,
            ).with_for_update())).mappings().one_or_none()
            if row is None:
                raise ApplicationNotFound("autonomous_campaign_not_found")
            current = _state_from_row(row)
            if current.aggregate_revision != command.expected_revision:
                raise ApplicationRevisionConflict("application_revision_conflict")
            if run["run_state"] not in _NONTERMINAL_RUNS:
                raise ApplicationTransitionConflict("operator_run_terminal")
            preview = await _application_latest(session, "autonomous_campaign_plan_previews", command.tenant_id, command.campaign_id)
            start = None if preview is None else await _application_latest(
                session, "autonomous_campaign_execution_starts", command.tenant_id, command.campaign_id, preview_id=preview["id"],
            )
            if start is None or start["execution_run_id"] != run["id"]:
                raise ApplicationTransitionConflict("operator_current_run_unavailable")
            successor = replace(current, aggregate_revision=current.aggregate_revision + 1, updated_at=command.occurred_at)
            signal_id = "operator-stop-" + command.request_sha256[:48]
            await session.execute(update(runs).where(runs.c.tenant_id == command.tenant_id, runs.c.id == run["id"])
                                  .values(stop_requested=True, version=runs.c.version + 1, updated_at=command.occurred_at))
            await session.execute(update(applications).where(
                applications.c.tenant_id == command.tenant_id, applications.c.id == command.campaign_id,
            ).values(aggregate_revision=successor.aggregate_revision, version=applications.c.version + 1, updated_at=command.occurred_at))
            event_payload = {"reason_sha256": command.reason_sha256, "execution_run_id": str(run["id"]), "signal_id": signal_id}
            audit_id, event_id = await _record_lifecycle_event(
                session, state=successor, operation=_STOP_OPERATION, correlation_id=command.correlation_id,
                actor_user_id=command.actor_user_id, request_sha256=command.request_sha256, event_type=_STOP_EVENT,
                previous_state=current.lifecycle_state, event_payload=event_payload, occurred_at=command.occurred_at,
            )
            commit = AutonomousCampaignOperatorStopCommitV1(
                AutonomousCampaignMutationResultV1(successor, audit_id, event_id, False),
                str(run["id"]), str(run["workflow_id"]), run["workflow_run_id"], signal_id,
            )
            await _record_idempotency(
                session, tenant_id=command.tenant_id, operation=_STOP_OPERATION, idempotency_key=command.idempotency_key,
                request_sha256=command.request_sha256, response_status=202, occurred_at=command.occurred_at,
                response_body={"mutation": _result_payload(commit.mutation), "execution_run_id": commit.execution_run_id,
                               "workflow_id": commit.workflow_id, "workflow_run_id": commit.workflow_run_id, "signal_id": signal_id},
            )
            return commit

    async def read_status(
        self, *, tenant_id: str, campaign_id: str, principal_id: str, now: datetime,
    ) -> dict[str, Any]:
        async with self._sessions() as session, session.begin():
            # CRITICAL: application, current preview/start, effects and imports share one snapshot.
            # Separate reads can accidentally attach the parent's result to a fresh child preview.
            await session.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
            await session.execute(text("SELECT set_config('redagent.tenant_id', :tenant, true)"), {"tenant": tenant_id})
            await _current_principal(session, tenant_id=tenant_id, principal_id=principal_id, now=now)
            row = await _read_row(session, tenant_id=tenant_id, campaign_id=campaign_id)
            if row is None:
                raise ApplicationNotFound("autonomous_campaign_not_found")
            state = _state_from_row(row)
            scope = await read_operator_scope(session, tenant_id=tenant_id, campaign_id=campaign_id)
            native = await _read_source(session, tenant_id=tenant_id, campaign_id=campaign_id)
            if native.campaign["engagement_id"] != state.engagement_id or native.campaign["intent_sha256"] != state.intent_sha256:
                raise ApplicationBindingConflict("operator_native_application_mismatch")
            target = await _exact(session, "targets", tenant_id, state.target_id)
            if target is None or target["engagement_id"] != state.engagement_id:
                raise ApplicationBindingConflict("operator_target_owner_missing")
            preview_row = await _application_latest(session, "autonomous_campaign_plan_previews", tenant_id, campaign_id)
            preview = None if preview_row is None else _verified_preview_from_payload(
                preview_row["preview_payload"], str(preview_row["preview_sha256"]),
            )
            if preview is not None and (
                preview.tenant_id != tenant_id or preview.campaign_id != campaign_id
                or preview.preview_id != preview_row["id"]
                or preview.application_revision != int(preview_row["application_revision"])
                or preview.application_revision > state.aggregate_revision
                or preview.application_intent_sha256 != state.intent_sha256
                or preview.source_binding_sha256 != state.source_binding_sha256
                or preview.target_id != state.target_id or preview.execution_mode is not state.mode
            ):
                raise ApplicationPlanInvalid("operator_preview_binding_invalid")
            approval_row = None if preview is None else await _application_latest(
                session, "autonomous_campaign_plan_approval_receipts", tenant_id, campaign_id,
                preview_id=preview.preview_id,
            )
            approval = None if approval_row is None else _verified_receipt_from_payload(
                approval_row["receipt_payload"], str(approval_row["receipt_sha256"]),
            )
            if approval is not None and (
                approval.preview_sha256 != preview.preview_sha256 or approval.preview_id != preview.preview_id
                or approval.tenant_id != tenant_id or approval.campaign_id != campaign_id
                or approval.application_revision != preview.application_revision + 1
                or approval.application_revision > state.aggregate_revision
                or int(approval_row["application_revision"]) != approval.application_revision
                or approval.receipt_id != approval_row["id"]
            ):
                raise ApplicationPlanInvalid("operator_approval_binding_invalid")
            start = None if preview is None else await _application_latest(
                session, "autonomous_campaign_execution_starts", tenant_id, campaign_id,
                preview_id=preview.preview_id,
            )
            if start is not None:
                if approval is None or start["approval_receipt_id"] != approval.receipt_id or start["approval_receipt_sha256"] != approval.receipt_sha256:
                    raise ApplicationPlanInvalid("operator_start_approval_invalid")
                run = await _exact(session, "campaign_execution_runs", tenant_id, str(start["execution_run_id"]))
                admission = await _exact(session, "plan_admission_receipts", tenant_id, str(start["admission_receipt_id"]))
                reservation = await _exact(session, "campaign_budget_reservations", tenant_id, str(start["reservation_id"]))
                if run is None or admission is None or reservation is None or any(
                    item["campaign_id"] != campaign_id for item in (run, admission, reservation)
                ) or run["reservation_id"] != reservation["id"] or run["admission_receipt_id"] != admission["id"]:
                    raise ApplicationPlanInvalid("operator_start_native_owners_missing")
                nodes_table = metadata.tables["campaign_execution_nodes"]
                nodes = tuple(dict(item) for item in (await session.execute(select(nodes_table).where(
                    nodes_table.c.tenant_id == tenant_id, nodes_table.c.execution_run_id == run["id"],
                    nodes_table.c.campaign_id == campaign_id,
                ).order_by(nodes_table.c.node_order).limit(101))).mappings().all())
                if len(nodes) > 100:
                    raise ApplicationPlanInvalid("operator_nodes_unbounded")
                effects = tuple(item for item in native.effects if item["execution_run_id"] == run["id"])
                native = replace(native, admission=admission, execution=run, nodes=nodes, effects=effects)
            else:
                # IMPORTANT: a child awaiting its own approval/admission cannot inherit parent success.
                native = replace(native, admission=None, execution=None, nodes=(), effects=())
            results = tuple([await _effect_result_owners(session, tenant_id, item) for item in native.effects])
            child = await _application_latest(session, "autonomous_campaign_child_replans", tenant_id, campaign_id)
            child_summary = None
            if child is not None:
                if canonical_planning_sha256(child["lineage_payload"]) != child["lineage_sha256"]:
                    raise ApplicationPlanInvalid("operator_child_lineage_invalid")
                child_summary = {
                    "replan_sequence": int(child["replan_sequence"]),
                    "parent_execution_run_id": str(child["parent_execution_run_id"]),
                    "lineage_sha256": str(child["lineage_sha256"]),
                    "preview_id": str(child["preview_id"]),
                }
                if start is not None and preview.child_lineage_sha256 is not None:
                    settlement = await _exact(session, "campaign_child_capacity_settlements", tenant_id, str(child["settlement_id"]))
                    parent = await _exact(session, "campaign_execution_runs", tenant_id, str(child["parent_execution_run_id"]))
                    if settlement is None or parent is None:
                        raise ApplicationPlanInvalid("operator_child_settlement_owner_missing")
                    native = replace(native, reservations=_settled_operator_reservations(native,
                        run=native.execution, preview=preview, child=child, settlement=settlement, parent_run=parent, now=now))
            operations = project_campaign_operations(native, now=now)
            if preview is not None and start is None:
                # CRITICAL: pre-admission canonical plans live in the preview owner, not a legacy
                # run payload. Show its validation without implying current execution authority.
                operations["preparation_state"] = state.lifecycle_state.value.lower()
                operations["authority"] = {
                    "state": "requires_current_verification", "signed_authority_sha256": preview.signed_authority_sha256,
                    "authority_sha256": preview.authority_sha256, "expires_at": preview.expires_at.isoformat(),
                    **{field: getattr(preview, field) for field in (
                        "lifecycle_epoch", "policy_revocation_epoch", "roe_revocation_epoch", "kill_switch_epoch")},
                }
                operations["validation"] = {"result": preview.validation_result.value, "reason": None, "counterexample_codes": []}
                operations["plan"] = {
                    "revision_label": f"Preview revision {preview.application_revision}",
                    "parent_revision_present": preview.child_lineage_sha256 is not None,
                    "nodes": [{"label": f"Step {action.order + 1}", "capability": _capability_label(action.capability_id),
                               "state": "planned", "order": action.order} for action in preview.actions],
                    "edges": [],
                }
            result = project_operator_result(native.effects, results, run_state=None if native.execution is None else str(native.execution["run_state"]), now=now)
            if (self._bundle_source is not None and preview is not None and native.execution is not None
                and native.execution["run_state"] in {"completed", "contained"}
                and result["evidence_state"] == "retained_pending_verification"):
                try:
                    reference = await self._bundle_source.read_current_bundle(tenant_id=tenant_id,
                        campaign_id=campaign_id, execution_run_id=str(native.execution["id"]),
                        preview_sha256=preview.preview_sha256, now=now)
                    if reference is not None:
                        if not all(self._evidence_backend.verify_exact(_stored_from_artifact(dict(item["artifact"]))).ok for item in results):
                            raise ValueError("operator_retained_object_verification_failed")
                        verify_operator_bundle(reference, tenant_id=tenant_id, campaign_id=campaign_id,
                            signed_authority_sha256=preview.signed_authority_sha256,
                            native_result_sha256=native_operator_result_sha256(execution_run_id=str(native.execution["id"]),
                                preview_sha256=preview.preview_sha256, effects=native.effects, owners=results), now=now)
                        result["evidence_state"] = "verified"
                        result["export_state"] = "unavailable_export_not_configured"
                except (ValueError, TypeError, KeyError, OSError):
                    # A lost/tampered bundle must not remove authorized stop/revoke/status recovery.
                    result["evidence_state"] = "verification_failed"
            # The existing legacy projection counts receipt identifiers. The operator journey requires
            # the exact retained native owners below before displaying complete cleanup.
            operations["evidence"]["cleanup_state"] = result["cleanup_state"]
            attention = []
            if scope is not None:
                try:
                    await assert_operator_scope_current(session, tenant_id=tenant_id, campaign_id=campaign_id, lock=False)
                except ApplicationBindingConflict:
                    attention.append("operator_native_source_changed")
            preview_expired = preview is not None and now >= preview.expires_at
            if preview_expired:
                attention.append("preview_expired")
            if state.attention_reason is not None:
                attention.append(state.attention_reason)
            if native.execution is not None:
                run_state = str(native.execution["run_state"])
                if bool(native.execution["stop_requested"]) and run_state in {"start_pending", "running", "stopping", "reconciliation_required"}:
                    attention.append("stop_requested")
                if run_state in {"reconciliation_required", "manual_review_required", "failed"}:
                    attention.append(run_state)
                if run_state in {"completed", "contained"}:
                    if result["evidence_state"] != "verified":
                        attention.append("evidence_pending")
                    if result["cleanup_state"] == "incomplete":
                        attention.append("cleanup_incomplete")
            return {
                "campaign_id": campaign_id, "mode": state.mode.value,
                "target_label": (f'{scope["target_type"]}: {scope["target_value"]}' if scope is not None
                                 else f'{target["target_type"]}: {target["normalized_value"]}'),
                "objective_label": None if scope is None else scope["objective_label"],
                "lifecycle_state": state.lifecycle_state.value, "aggregate_revision": state.aggregate_revision,
                "etag": f'"autonomous-{campaign_id}:{state.aggregate_revision}"',
                "roe_version_id": str(native.campaign["roe_version_id"]),
                "preview": None if preview is None else _preview_payload(preview),
                "preview_etag": None if preview is None else preview.etag,
                "approval_etag": None if approval is None else f'"r173-{state.aggregate_revision}-{approval.receipt_sha256}"',
                "preview_expired": preview_expired,
                "approval": None if approval is None else {
                    "receipt_id": approval.receipt_id, "receipt_sha256": approval.receipt_sha256,
                    "decision": approval.decision.value, "reason_code": approval.reason_code,
                    "application_revision": approval.application_revision, "expires_at": approval.expires_at.isoformat(),
                    "expired": now >= approval.expires_at,
                },
                "start": None if start is None else {
                    "execution_run_id": str(start["execution_run_id"]),
                    "admission_receipt_id": str(start["admission_receipt_id"]),
                    "reservation_id": str(start["reservation_id"]), "state": str(start["start_state"]),
                    "reason_code": start["reason_code"],
                },
                "operations": operations, "result": result, "child": child_summary,
                "attention": sorted(set(attention)),
            }


async def _current_principal(session, *, tenant_id, principal_id, now, lock=False):
    if not await campaign_core_principal_is_active(
        session, tenant_id=tenant_id, principal_id=principal_id, now=now, lock=lock,
    ):
        raise ApplicationBindingConflict("operator_principal_inactive")


def _settled_operator_reservations(source, *, run, preview, child, settlement, parent_run, now):
    verified = verify_child_transition_settlement(run=run, preview=preview, child=child,
        settlement=settlement, parent_run=parent_run, now=now)
    parent = tuple(item for item in source.reservations if item["id"] == verified.parent_reservation_id)
    if len(parent) != 1 or parent[0]["reservation_state"] not in {"reserved", "held", "consumed"}:
        raise CampaignOperationsProjectionInvalid("operator_settled_parent_charge_missing")
    # CRITICAL: native child settlement reopens only parent peak occupancy after cooldown.
    # Summing that historical peak again hides the child; refunding cumulative work multiplies authority.
    return tuple({**item, "rate_per_minute": 0, "concurrency": 0} if item["id"] == verified.parent_reservation_id
                 else dict(item) for item in source.reservations)


def _stop_event_payload(command, commit):
    return {"reason_sha256": command.reason_sha256, "execution_run_id": commit.execution_run_id, "signal_id": commit.signal_id}


async def _application_latest(session, table_name, tenant_id, campaign_id, *, preview_id=None):
    table = metadata.tables[table_name]
    query = select(table).where(table.c.tenant_id == tenant_id, table.c.application_id == campaign_id)
    if preview_id is not None:
        query = query.where(table.c.preview_id == preview_id)
    order = table.c.application_revision if "application_revision" in table.c else table.c.created_at
    row = (await session.execute(query.order_by(order.desc(), table.c.id.desc()).limit(1))).mappings().one_or_none()
    return None if row is None else dict(row)


async def _exact(session, table_name, tenant_id, identity):
    table = metadata.tables[table_name]
    row = (await session.execute(select(table).where(table.c.tenant_id == tenant_id, table.c.id == identity))).mappings().one_or_none()
    return None if row is None else dict(row)


async def _effect_result_owners(session, tenant_id, effect):
    stable = hashlib.sha256(f"{tenant_id}\0{effect['effect_id']}".encode()).hexdigest()[:24]
    receipts = metadata.tables["runner_execution_receipts"]
    imports = metadata.tables["finding_import_sessions"]
    receipt = (await session.execute(select(receipts).where(
        receipts.c.tenant_id == tenant_id, receipts.c.execution_id == f"execution-r123-{stable}",
    ))).mappings().one_or_none()
    imported = (await session.execute(select(imports).where(
        imports.c.tenant_id == tenant_id, imports.c.import_id == f"import-r123-{stable}",
        imports.c.run_id == f"execution-r123-{stable}",
    ))).mappings().one_or_none()
    return {
        "effect_id": effect["effect_id"], "receipt": None if receipt is None else dict(receipt),
        "artifact": await _exact(session, "evidence_artifacts", tenant_id, f"evidence-r123-{stable}"),
        "import": None if imported is None else dict(imported),
    }


def project_operator_result(effects: tuple[Mapping[str, Any], ...], owners: tuple[Mapping[str, Any], ...], *, run_state: str | None, now: datetime | None = None) -> dict[str, Any]:
    if len(effects) > 100 or len(owners) > 100:
        raise CampaignOperationsProjectionInvalid("operator_result_unbounded")
    indexed = {item["effect_id"]: item for item in owners}
    if len(indexed) != len(owners):
        raise CampaignOperationsProjectionInvalid("operator_result_ambiguous")
    verified, cleaned = 0, 0
    for effect in effects:
        owned = indexed.get(effect.get("effect_id"))
        if owned is None or owned.get("receipt") is None:
            continue
        receipt, artifact, imported = owned["receipt"], owned["artifact"], owned["import"]
        try:
            effect_receipt = _effect_receipt_contract(effect["effect_receipt_payload"])
        except (ValueError, TypeError, KeyError):
            continue
        if (
            effect.get("effect_state") != "confirmed"
            or effect_receipt.receipt_sha256 != effect.get("effect_receipt_sha256")
            or effect_receipt.effect_id != effect.get("effect_id")
            or effect_receipt.effect_intent_sha256 != effect.get("effect_intent_sha256")
            or effect_receipt.envelope_sha256 != effect.get("envelope_sha256")
            or effect_receipt.external_receipt_id != receipt["execution_id"]
            or effect.get("external_receipt_id") != receipt["execution_id"]
            or effect_receipt.cleanup_receipt_id != effect.get("cleanup_receipt_id")
            or not effect_receipt.output_complete or effect_receipt.external_contact_count != 0
            or effect_receipt.failure_code is not None
            or receipt["outcome"] != "succeeded" or receipt["cleanup_completed"] is not True
            or receipt["residual_risk"] is not None
        ):
            continue
        # CRITICAL: cleanup and retained evidence are separate owners. Expired/lost evidence or
        # incomplete imports deny evidence verification without erasing a valid cleanup receipt.
        cleaned += 1
        if artifact is None or imported is None:
            continue
        if (
            effect_receipt.evidence_ids != (artifact["id"],)
            or receipt["evidence_artifact_id"] != artifact["id"]
            or receipt["evidence_sha256"] != artifact["content_sha256"]
            or artifact["artifact_class"] not in {"report_safe", "export_safe"}
            or artifact["redaction_state"] != artifact["artifact_class"]
            or artifact["quarantine_reason"] is not None or artifact["finalized_at"] is None
            or (now is not None and (artifact.get("retain_until") is None
                or (not artifact.get("legal_hold") and artifact["retain_until"] <= now)))
            or imported["run_id"] != receipt["execution_id"]
            or imported["import_state"] != "accepted" or imported["coverage_state"] != "complete"
        ):
            continue
        verified += 1
    # CRITICAL: native completed/imported/cleaned results never substitute for a retained bundle
    # checked against an independently configured trust anchor. Readback grants no export authority.
    return {
        "effect_count": len(effects), "verified_effect_count": verified,
        "cleanup_state": "complete" if effects and cleaned == len(effects) else "incomplete" if effects else "not_started",
        "evidence_state": "retained_pending_verification" if effects and verified == len(effects) else "pending" if effects or run_state in {"completed", "contained"} else "not_started",
        "export_state": "unavailable_without_verified_bundle",
    }
