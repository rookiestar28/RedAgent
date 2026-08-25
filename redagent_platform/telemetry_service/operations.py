"""Durable incident, SLO, and alert operations over PostgreSQL truth."""

from __future__ import annotations

from datetime import datetime
import hashlib
import json
from uuid import uuid4

from sqlalchemy import func, insert, select, text, update

from redagent_platform.persistence.models import metadata
from redagent_platform.telemetry_service.incidents import (
    IncidentAction, IncidentSnapshot, IncidentState, apply_incident_action,
)
from redagent_platform.telemetry_service.slo import (
    SloEvaluationState, SloObjective, evaluate_ratio_window,
)


class ObservabilityRepositoryConflict(RuntimeError):
    """Stable incident/SLO persistence conflict."""


class _Repository:
    def __init__(self, session, *, tenant_id: str, actor_user_id: str, correlation_id: str) -> None:
        self.session = session
        self.tenant_id = _identifier("tenant_id", tenant_id, 64)
        self.actor_user_id = _identifier("actor_user_id", actor_user_id, 64)
        self.correlation_id = _identifier("correlation_id", correlation_id, 100)

    async def _context(self) -> None:
        await self.session.execute(
            text("SELECT set_config('redagent.tenant_id', :tenant, true)"),
            {"tenant": self.tenant_id},
        )

    async def _lock(self, scope: str) -> None:
        await self.session.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:scope, 0))"),
            {"scope": f"{self.tenant_id}:{scope}"},
        )

    async def _audit_outbox(
        self, event_type: str, subject_type: str, subject_id: str,
        details: dict[str, object], occurred_at: datetime,
    ) -> None:
        await self.session.execute(insert(metadata.tables["audit_events"]).values(
            id=f"audit-{uuid4().hex}", tenant_id=self.tenant_id,
            actor_user_id=self.actor_user_id, action=event_type,
            subject_type=subject_type, subject_id=subject_id[:64],
            correlation_id=self.correlation_id, details=details,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        await self.session.execute(insert(metadata.tables["outbox_events"]).values(
            id=f"outbox-{uuid4().hex}", tenant_id=self.tenant_id,
            event_type=event_type, aggregate_id=subject_id[:64], payload=details,
            published=False, version=1, created_at=occurred_at, updated_at=occurred_at,
        ))


class IncidentRepository(_Repository):
    async def open_incident(
        self, *, incident_id: str, source_kind: str, source_id: str,
        severity: str, reason_code: str, occurred_at: datetime,
    ) -> dict[str, object]:
        incident = _identifier("incident_id", incident_id, 64)
        source = _identifier("source_id", source_id, 64)
        if source_kind not in {"alert", "containment", "telemetry"}:
            raise ObservabilityRepositoryConflict("incident_source_kind_invalid")
        if severity not in {"low", "medium", "high", "critical"}:
            raise ObservabilityRepositoryConflict("incident_severity_invalid")
        reason = _code("reason_code", reason_code)
        _aware(occurred_at)
        await self._context()
        await self._lock(f"incident:{incident}")
        table = metadata.tables["security_incidents"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.incident_id == incident,
        ))).mappings().one_or_none()
        identity = (source_kind, source, severity, reason)
        if existing is not None:
            if tuple(existing[key] for key in (
                "source_kind", "source_id", "severity", "reason_code",
            )) != identity:
                raise ObservabilityRepositoryConflict("incident_open_replay_mismatch")
            return dict(existing)
        row = {
            "id": f"security-incident-{uuid4().hex}", "tenant_id": self.tenant_id,
            "incident_id": incident, "source_kind": source_kind, "source_id": source,
            "severity": severity, "incident_state": IncidentState.OPEN.value,
            "reason_code": reason, "opened_by_user_id": self.actor_user_id,
            "assigned_to_user_id": None, "acknowledged_by_user_id": None,
            "contained_by_user_id": None, "recovered_by_user_id": None,
            "reviewed_by_user_id": None, "evidence_preserved": False,
            "containment_verified": False, "opened_at": occurred_at, "closed_at": None,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(table).values(**row))
        await self._timeline(row, f"incident-open-{uuid4().hex}", "opened", reason, occurred_at)
        await self._audit_outbox(
            "incident.opened", "incident", incident,
            {"source_kind": source_kind, "source_id": source, "severity": severity,
             "reason_code": reason}, occurred_at,
        )
        return row

    async def apply_action(
        self, *, incident_id: str, action_id: str, action: IncidentAction,
        expected_version: int, occurred_at: datetime, assignee_id: str | None = None,
    ) -> dict[str, object]:
        incident = _identifier("incident_id", incident_id, 64)
        action_key = _identifier("action_id", action_id, 64)
        if not isinstance(action, IncidentAction):
            raise ObservabilityRepositoryConflict("incident_action_invalid")
        if assignee_id is not None:
            assignee_id = _identifier("assignee_id", assignee_id, 64)
        _aware(occurred_at)
        request_hash = _hash({
            "incident_id": incident, "action": action.value,
            "expected_version": expected_version, "assignee_id": assignee_id,
        })
        await self._context()
        await self._lock(f"incident:{incident}")
        actions = metadata.tables["incident_actions"]
        existing_action = (await self.session.execute(select(actions).where(
            actions.c.tenant_id == self.tenant_id, actions.c.action_id == action_key,
        ))).mappings().one_or_none()
        if existing_action is not None and existing_action["request_hash"] != request_hash:
            raise ObservabilityRepositoryConflict("incident_action_replay_mismatch")
        table = metadata.tables["security_incidents"]
        row = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id, table.c.incident_id == incident,
        ).with_for_update())).mappings().one_or_none()
        if row is None:
            raise ObservabilityRepositoryConflict("incident_not_found")
        if existing_action is not None:
            return dict(row)
        snapshot = _snapshot(row)
        try:
            result = apply_incident_action(
                snapshot, action=action, actor_id=self.actor_user_id,
                expected_version=expected_version, occurred_at=occurred_at,
                assignee_id=assignee_id,
            )
        except ValueError as exc:
            raise ObservabilityRepositoryConflict(str(exc)) from exc
        values = {
            "incident_state": result.state.value,
            "assigned_to_user_id": result.assigned_to,
            "acknowledged_by_user_id": result.acknowledged_by,
            "contained_by_user_id": result.contained_by,
            "recovered_by_user_id": result.recovered_by,
            "reviewed_by_user_id": result.reviewed_by,
            "evidence_preserved": result.evidence_preserved,
            "containment_verified": result.containment_verified,
            "closed_at": occurred_at if result.state is IncidentState.CLOSED else row["closed_at"],
            "version": result.version, "updated_at": occurred_at,
        }
        await self.session.execute(update(table).where(table.c.id == row["id"]).values(**values))
        await self.session.execute(insert(actions).values(
            id=f"incident-action-{uuid4().hex}", tenant_id=self.tenant_id,
            incident_record_id=row["id"], action_id=action_key, action=action.value,
            actor_user_id=self.actor_user_id, request_hash=request_hash,
            expected_version=expected_version, result_version=result.version,
            occurred_at=occurred_at, version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        await self._timeline(
            row, f"incident-event-{action_key}", action.value,
            f"incident_{action.value}", occurred_at,
        )
        await self._audit_outbox(
            f"incident.{action.value}", "incident", incident,
            {"action_id": action_key, "expected_version": expected_version,
             "result_version": result.version}, occurred_at,
        )
        return {**dict(row), **values}

    async def list_incidents(
        self, *, limit: int = 100, offset: int = 0,
    ) -> list[dict[str, object]]:
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 501:
            raise ObservabilityRepositoryConflict("incident_list_limit_invalid")
        if not isinstance(offset, int) or isinstance(offset, bool) or not 0 <= offset <= 100000:
            raise ObservabilityRepositoryConflict("incident_list_offset_invalid")
        await self._context()
        table = metadata.tables["security_incidents"]
        rows = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id,
        ).order_by(table.c.opened_at.desc(), table.c.incident_id).limit(limit).offset(offset))).mappings().all()
        return [dict(row) for row in rows]

    async def timeline(self, *, incident_id: str) -> list[dict[str, object]]:
        incident = _identifier("incident_id", incident_id, 64)
        await self._context()
        incidents = metadata.tables["security_incidents"]
        row_id = await self.session.scalar(select(incidents.c.id).where(
            incidents.c.tenant_id == self.tenant_id, incidents.c.incident_id == incident,
        ))
        if row_id is None:
            raise ObservabilityRepositoryConflict("incident_not_found")
        timeline = metadata.tables["incident_timeline_events"]
        rows = (await self.session.execute(select(timeline).where(
            timeline.c.tenant_id == self.tenant_id,
            timeline.c.incident_record_id == row_id,
        ).order_by(timeline.c.occurred_at, timeline.c.id))).mappings().all()
        return [dict(row) for row in rows]

    async def _timeline(
        self, incident: dict[str, object], event_id: str, event_type: str,
        reason_code: str, occurred_at: datetime,
    ) -> None:
        await self.session.execute(insert(metadata.tables["incident_timeline_events"]).values(
            id=f"incident-timeline-{uuid4().hex}", tenant_id=self.tenant_id,
            incident_record_id=incident["id"], event_id=event_id[:64],
            event_type=event_type, actor_user_id=self.actor_user_id,
            reason_code=reason_code, occurred_at=occurred_at,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))


class SloRepository(_Repository):
    async def register_objective(
        self, objective: SloObjective, *, revision: int, metric_name: str,
        occurred_at: datetime,
    ) -> dict[str, object]:
        if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
            raise ObservabilityRepositoryConflict("slo_revision_invalid")
        metric = _identifier("metric_name", metric_name, 64)
        _aware(occurred_at)
        await self._context()
        await self._lock(f"slo:{objective.objective_id}:{revision}")
        table = metadata.tables["slo_definitions"]
        existing = (await self.session.execute(select(table).where(
            table.c.tenant_id == self.tenant_id,
            table.c.objective_id == objective.objective_id,
            table.c.objective_revision == revision,
        ))).mappings().one_or_none()
        row = {
            "tenant_id": self.tenant_id, "objective_id": objective.objective_id,
            "objective_revision": revision, "metric_name": metric,
            "comparison": "min" if objective.target_basis_points is not None else objective.comparison.value,
            "target_basis_points": objective.target_basis_points,
            "threshold_millionths": objective.threshold_millionths,
            "window_seconds": objective.window_seconds,
            "minimum_samples": objective.minimum_samples,
            "definition_state": "active",
        }
        if existing is not None:
            if any(existing[key] != value for key, value in row.items() if key != "tenant_id"):
                raise ObservabilityRepositoryConflict("slo_definition_revision_immutable")
            return dict(existing)
        row.update({
            "id": f"slo-definition-{uuid4().hex}", "version": 1,
            "created_at": occurred_at, "updated_at": occurred_at,
        })
        await self.session.execute(insert(table).values(**row))
        await self._audit_outbox(
            "slo.objective.registered", "slo", objective.objective_id,
            {"revision": revision, "metric_name": metric}, occurred_at,
        )
        return row

    async def evaluate_ratio_window(
        self, *, definition_id: str, window_start: datetime, window_end: datetime,
        total: int, bad: int, missing: int, source_hash: str, occurred_at: datetime,
    ) -> dict[str, object]:
        definition_key = _identifier("definition_id", definition_id, 64)
        if not _sha256(source_hash):
            raise ObservabilityRepositoryConflict("slo_source_hash_invalid")
        _aware(window_start); _aware(window_end); _aware(occurred_at)
        if window_end <= window_start:
            raise ObservabilityRepositoryConflict("slo_window_invalid")
        await self._context()
        await self._lock(f"slo-window:{definition_key}:{window_start.isoformat()}:{window_end.isoformat()}")
        definitions = metadata.tables["slo_definitions"]
        definition = (await self.session.execute(select(definitions).where(
            definitions.c.tenant_id == self.tenant_id, definitions.c.id == definition_key,
            definitions.c.definition_state == "active",
        ))).mappings().one_or_none()
        if definition is None or definition["target_basis_points"] is None:
            raise ObservabilityRepositoryConflict("slo_ratio_definition_required")
        objective = SloObjective(
            objective_id=str(definition["objective_id"]),
            target_basis_points=int(definition["target_basis_points"]),
            window_seconds=int(definition["window_seconds"]),
        )
        try:
            evaluation = evaluate_ratio_window(objective, total=total, bad=bad, missing=missing)
        except ValueError as exc:
            raise ObservabilityRepositoryConflict(str(exc)) from exc
        windows = metadata.tables["slo_windows"]
        existing_window = (await self.session.execute(select(windows).where(
            windows.c.tenant_id == self.tenant_id, windows.c.definition_id == definition_key,
            windows.c.window_start == window_start, windows.c.window_end == window_end,
        ))).mappings().one_or_none()
        if existing_window is not None:
            if tuple(existing_window[key] for key in (
                "total_count", "bad_count", "missing_count", "source_hash",
            )) != (total, bad, missing, source_hash):
                raise ObservabilityRepositoryConflict("slo_window_replay_mismatch")
            existing_evaluation = (await self.session.execute(select(
                metadata.tables["slo_evaluations"]
            ).where(
                metadata.tables["slo_evaluations"].c.tenant_id == self.tenant_id,
                metadata.tables["slo_evaluations"].c.window_id == existing_window["id"],
            ))).mappings().one()
            return dict(existing_evaluation)
        window_id = f"slo-window-{uuid4().hex}"
        await self.session.execute(insert(windows).values(
            id=window_id, tenant_id=self.tenant_id, definition_id=definition_key,
            window_start=window_start, window_end=window_end,
            total_count=total, bad_count=bad, missing_count=missing, source_hash=source_hash,
            version=1, created_at=occurred_at, updated_at=occurred_at,
        ))
        observed = None if total == 0 or missing else (total - bad) * 1_000_000 // total
        consumed = evaluation.error_budget_consumed
        result = {
            "id": f"slo-evaluation-{uuid4().hex}", "tenant_id": self.tenant_id,
            "window_id": window_id, "evaluation_state": evaluation.state.value,
            "observed_millionths": observed,
            "burn_numerator": consumed.numerator if consumed is not None else None,
            "burn_denominator": consumed.denominator if consumed is not None else None,
            "reason_code": f"slo_{evaluation.state.value}", "evaluated_at": occurred_at,
            "version": 1, "created_at": occurred_at, "updated_at": occurred_at,
        }
        await self.session.execute(insert(metadata.tables["slo_evaluations"]).values(**result))
        if evaluation.state is SloEvaluationState.BREACHING:
            await self._open_alert(definition, result, window_start, window_end, occurred_at)
        await self._audit_outbox(
            "slo.window.evaluated", "slo", str(definition["objective_id"]),
            {"state": evaluation.state.value, "window_id": window_id}, occurred_at,
        )
        return result

    async def dashboard(self) -> dict[str, object]:
        await self._context()
        evaluations = metadata.tables["slo_evaluations"]
        alerts = metadata.tables["alert_instances"]
        state_rows = (await self.session.execute(select(
            evaluations.c.evaluation_state, func.count(),
        ).where(evaluations.c.tenant_id == self.tenant_id).group_by(
            evaluations.c.evaluation_state
        ))).all()
        open_alerts = await self.session.scalar(select(func.count()).select_from(alerts).where(
            alerts.c.tenant_id == self.tenant_id, alerts.c.alert_state == "firing",
        ))
        exports = metadata.tables["telemetry_export_operations"]
        incidents = metadata.tables["security_incidents"]
        dead = metadata.tables["telemetry_dead_letters"]
        export_rows = (await self.session.execute(select(
            exports.c.export_state, func.count(),
        ).where(exports.c.tenant_id == self.tenant_id).group_by(exports.c.export_state))).all()
        incident_rows = (await self.session.execute(select(
            incidents.c.incident_state, func.count(),
        ).where(incidents.c.tenant_id == self.tenant_id).group_by(incidents.c.incident_state))).all()
        unreplayed = await self.session.scalar(select(func.count()).select_from(dead).where(
            dead.c.tenant_id == self.tenant_id, dead.c.replayed_at.is_(None),
        ))
        return {
            "slo_state_counts": {str(state): int(count) for state, count in state_rows},
            "export_state_counts": {str(state): int(count) for state, count in export_rows},
            "incident_state_counts": {str(state): int(count) for state, count in incident_rows},
            "open_alerts": int(open_alerts or 0),
            "unreplayed_dead_letters": int(unreplayed or 0),
        }

    async def _open_alert(
        self, definition, evaluation: dict[str, object], start: datetime,
        end: datetime, occurred_at: datetime,
    ) -> None:
        alerts = metadata.tables["alert_instances"]
        rule_id = f"slo-burn-{definition['objective_id']}"[:64]
        fingerprint = _hash({
            "rule_id": rule_id, "window_start": start.isoformat(), "window_end": end.isoformat(),
        })
        existing = await self.session.scalar(select(alerts.c.id).where(
            alerts.c.tenant_id == self.tenant_id, alerts.c.rule_id == rule_id,
            alerts.c.fingerprint == fingerprint,
        ))
        if existing is None:
            await self.session.execute(insert(alerts).values(
                id=f"alert-{uuid4().hex}", tenant_id=self.tenant_id,
                rule_id=rule_id, fingerprint=fingerprint, alert_state="firing",
                severity="high", evaluation_id=evaluation["id"], incident_record_id=None,
                first_seen_at=occurred_at, last_seen_at=occurred_at,
                version=1, created_at=occurred_at, updated_at=occurred_at,
            ))


def _snapshot(row) -> IncidentSnapshot:
    return IncidentSnapshot(
        incident_id=str(row["incident_id"]), tenant_id=str(row["tenant_id"]),
        severity=str(row["severity"]), state=IncidentState(str(row["incident_state"])),
        opened_by=str(row["opened_by_user_id"]), assigned_to=row["assigned_to_user_id"],
        acknowledged_by=row["acknowledged_by_user_id"], contained_by=row["contained_by_user_id"],
        recovered_by=row["recovered_by_user_id"], reviewed_by=row["reviewed_by_user_id"],
        evidence_preserved=bool(row["evidence_preserved"]),
        containment_verified=bool(row["containment_verified"]), version=int(row["version"]),
    )


def _hash(value: dict[str, object]) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _identifier(field: str, value: object, maximum: int) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or not all(
        char.isalnum() or char in "._:-" for char in value
    ):
        raise ObservabilityRepositoryConflict(f"{field}_invalid")
    return value


def _code(field: str, value: object) -> str:
    if not isinstance(value, str) or not 1 <= len(value) <= 100 or not all(
        char.islower() or char.isdigit() or char == "_" for char in value
    ):
        raise ObservabilityRepositoryConflict(f"{field}_invalid")
    return value


def _aware(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ObservabilityRepositoryConflict("observability_time_invalid")


def _sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and all(char in "0123456789abcdef" for char in value)
