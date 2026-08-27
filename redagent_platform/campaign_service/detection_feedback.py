"""Typed detection observations and pure deterministic correlation/adaptation inputs."""

from __future__ import annotations

from dataclasses import InitVar, dataclass
from datetime import datetime, timedelta
from enum import Enum
import json
import math
from pathlib import Path
import re
from typing import Any

from redagent_platform.campaign_service.contracts import (
    Confidence,
    DetectionCorrelationDispositionV1,
    DetectionDisposition,
    DetectionObservationV1,
    DetectionPromotionKind,
    DetectionSeverity,
    TypedReferenceV1,
    TelemetrySource,
    _validated_detection_correlation,
    _validated_detection_observation,
    _validated_detection_promotion,
    canonical_sha256,
)


_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_TECHNIQUE = re.compile(r"^T\d{4}(?:\.\d{3})?$")
_MATRIX_VALIDATION_TOKEN = object()
_MATRIX_FIELDS = frozenset(
    {
        "schema_version",
        "matrix_id",
        "revision",
        "attack_version",
        "authoring_source",
        "approved_by",
        "approval_ref",
        "entries",
    }
)
_ENTRY_FIELDS = frozenset(
    {
        "attack_technique_id",
        "capability_id",
        "expected_detectability",
        "last_confirmed_status",
    }
)


def detection_campaign_schema_pair_is_valid(context_schema: str, decision_schema: str) -> bool:
    """Accept only the explicit detection-bearing campaign-start schema pair."""
    return (
        context_schema,
        decision_schema,
    ) == (
        "redagent.detection-decision-context/v2",
        "redagent.detection-strategy-receipt/v2",
    )


class DetectionCoverageAuthoringSource(str, Enum):
    HUMAN = "human"
    PIPELINE = "pipeline"


class ExpectedDetectability(str, Enum):
    EXPECTED = "expected"
    NOT_EXPECTED = "not_expected"
    UNKNOWN = "unknown"


class LastConfirmedDetectionStatus(str, Enum):
    DETECTED = "detected"
    NOT_DETECTED = "not_detected"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionCoverageEntryV1:
    attack_technique_id: str
    capability_id: str
    expected_detectability: ExpectedDetectability
    last_confirmed_status: LastConfirmedDetectionStatus

    def __post_init__(self) -> None:
        if not _TECHNIQUE.fullmatch(self.attack_technique_id):
            raise ValueError("detection_matrix_technique_invalid")
        _identifier("detection_matrix_capability", self.capability_id)
        if not isinstance(self.expected_detectability, ExpectedDetectability) or not isinstance(
            self.last_confirmed_status, LastConfirmedDetectionStatus
        ):
            raise ValueError("detection_matrix_status_invalid")


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionCoverageMatrixV1:
    schema_version: str
    matrix_id: str
    revision: int
    attack_version: str
    authoring_source: DetectionCoverageAuthoringSource
    approved_by: str
    approval_ref: str
    entries: tuple[DetectionCoverageEntryV1, ...]
    matrix_sha256: str
    _validation_token: InitVar[object] = None

    def __post_init__(self, _validation_token: object) -> None:
        # CRITICAL: the strategy accepts only the strict repo-owned loader's reviewed matrix.
        if _validation_token is not _MATRIX_VALIDATION_TOKEN:
            raise ValueError("detection_matrix_loader_required")
        if self.schema_version != "redagent.detection-coverage-matrix/v1":
            raise ValueError("detection_matrix_schema_invalid")
        for name, value in (
            ("detection_matrix_id", self.matrix_id),
            ("detection_matrix_attack_version", self.attack_version),
            ("detection_matrix_approved_by", self.approved_by),
            ("detection_matrix_approval_ref", self.approval_ref),
        ):
            _identifier(name, value)
        if isinstance(self.revision, bool) or not isinstance(self.revision, int) or self.revision < 1:
            raise ValueError("detection_matrix_revision_invalid")
        if not isinstance(self.authoring_source, DetectionCoverageAuthoringSource):
            raise ValueError("detection_matrix_authoring_source_invalid")
        canonical_entries = tuple(
            sorted(
                set(self.entries),
                key=lambda item: (item.attack_technique_id, item.capability_id),
            )
        )
        if not self.entries or canonical_entries != self.entries:
            raise ValueError("detection_matrix_entries_not_canonical")
        keys = tuple((item.attack_technique_id, item.capability_id) for item in self.entries)
        if len(set(keys)) != len(keys):
            raise ValueError("detection_matrix_entry_duplicate")
        _sha256("detection_matrix_sha256", self.matrix_sha256)
        if self.matrix_sha256 != canonical_sha256(self.canonical_body()):
            raise ValueError("detection_matrix_digest_mismatch")

    def canonical_body(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "matrix_id": self.matrix_id,
            "revision": self.revision,
            "attack_version": self.attack_version,
            "authoring_source": self.authoring_source,
            "approved_by": self.approved_by,
            "approval_ref": self.approval_ref,
            "entries": self.entries,
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class DetectionAdaptationRequestV1:
    schema_version: str
    correlation_key: str
    attack_technique_id: str
    max_age_seconds: int
    coverage_matrix: DetectionCoverageMatrixV1

    def __post_init__(self) -> None:
        if self.schema_version != "redagent.detection-adaptation-request/v1":
            raise ValueError("detection_adaptation_schema_invalid")
        _identifier("detection_adaptation_correlation_key", self.correlation_key)
        if not _TECHNIQUE.fullmatch(self.attack_technique_id):
            raise ValueError("detection_adaptation_technique_invalid")
        if (
            isinstance(self.max_age_seconds, bool)
            or not isinstance(self.max_age_seconds, int)
            or not 1 <= self.max_age_seconds <= 3600
        ):
            raise ValueError("detection_adaptation_timespan_invalid")
        if not isinstance(self.coverage_matrix, DetectionCoverageMatrixV1):
            raise ValueError("detection_adaptation_matrix_invalid")


def ingest_detection_observation(
    *,
    observation_id: str,
    tenant_id: str,
    engagement_id: str,
    correlation_key: str,
    capability_id: str,
    source: TelemetrySource,
    source_system: str,
    attack_technique_id: str,
    attack_version: str,
    confidence: Confidence,
    severity: DetectionSeverity,
    evidence_ref: TypedReferenceV1,
    observed_at: datetime,
    ingested_at: datetime,
    expires_at: datetime,
    ocsf_class_uid: int | None = None,
    ocsf_category_uid: int | None = None,
) -> DetectionObservationV1:
    """Parse a bounded signal into an unconfirmed fact; no raw alert field exists."""
    return _validated_detection_observation(
        schema_version="redagent.detection-observation/v1",
        observation_id=observation_id,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        correlation_key=correlation_key,
        capability_id=capability_id,
        source=source,
        source_system=source_system,
        attack_technique_id=attack_technique_id,
        attack_version=attack_version,
        confidence=confidence,
        severity=severity,
        disposition=DetectionDisposition.UNCONFIRMED,
        promotion=None,
        evidence_ref=evidence_ref,
        observed_at=observed_at,
        ingested_at=ingested_at,
        expires_at=expires_at,
        ocsf_class_uid=ocsf_class_uid,
        ocsf_category_uid=ocsf_category_uid,
    )


def promote_detection_observation_by_human(
    *,
    observation: DetectionObservationV1,
    review_ref: TypedReferenceV1,
    reviewed_at: datetime,
) -> DetectionObservationV1:
    if review_ref.kind != "human-review":
        raise ValueError("detection_review_reference_invalid")
    if observation.disposition is not DetectionDisposition.UNCONFIRMED:
        raise ValueError("detection_observation_already_disposed")
    if not observation.ingested_at <= reviewed_at < observation.expires_at:
        raise ValueError("detection_review_time_invalid")
    promotion = _validated_detection_promotion(
        kind=DetectionPromotionKind.HUMAN_REVIEW,
        proof_ref=review_ref,
        promoted_at=reviewed_at,
    )
    values = _observation_values(observation)
    values.update(disposition=DetectionDisposition.CONFIRMED, promotion=promotion)
    return _validated_detection_observation(**values)


def promote_detection_observation_by_correlation(
    *,
    observation: DetectionObservationV1,
    correlation: DetectionCorrelationDispositionV1,
    receipt_ref: TypedReferenceV1,
) -> DetectionObservationV1:
    if receipt_ref.kind != "correlation-receipt" or receipt_ref.sha256 != correlation.correlation_sha256:
        raise ValueError("detection_correlation_reference_invalid")
    if not correlation.correlated or observation.disposition is not DetectionDisposition.UNCONFIRMED:
        raise ValueError("detection_correlation_promotion_denied")
    if (
        observation.tenant_id != correlation.tenant_id
        or observation.engagement_id != correlation.engagement_id
        or
        observation.correlation_key != correlation.correlation_key
        or observation.attack_technique_id != correlation.attack_technique_id
    ):
        raise ValueError("detection_correlation_scope_mismatch")
    binding = (observation.observation_id, canonical_sha256(observation))
    if binding not in correlation.input_observation_bindings:
        raise ValueError("detection_correlation_input_not_bound")
    if (
        observation.confidence is Confidence.LOW
        or observation.ingested_at > correlation.evaluated_at
        or not observation.observed_at <= correlation.evaluated_at < observation.expires_at
        or correlation.evaluated_at - observation.observed_at
        > timedelta(seconds=correlation.max_age_seconds)
    ):
        raise ValueError("detection_correlation_promotion_denied")
    promotion = _validated_detection_promotion(
        kind=DetectionPromotionKind.DETERMINISTIC_CORRELATION,
        proof_ref=receipt_ref,
        promoted_at=correlation.evaluated_at,
    )
    values = _observation_values(observation)
    values.update(disposition=DetectionDisposition.CONFIRMED, promotion=promotion)
    return _validated_detection_observation(**values)


def correlate_detection_observations(
    *,
    observations: tuple[DetectionObservationV1, ...],
    tenant_id: str,
    engagement_id: str,
    correlation_key: str,
    attack_technique_id: str,
    now: datetime,
    max_age_seconds: int,
) -> DetectionCorrelationDispositionV1:
    _identifier("detection_correlation_tenant", tenant_id)
    _identifier("detection_correlation_engagement", engagement_id)
    _identifier("detection_correlation_key", correlation_key)
    if not _TECHNIQUE.fullmatch(attack_technique_id):
        raise ValueError("detection_correlation_technique_invalid")
    _aware("detection_correlation_now", now)
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or not 1 <= max_age_seconds <= 3600:
        raise ValueError("detection_correlation_timespan_invalid")
    qualified: list[str] = []
    excluded: list[tuple[str, str]] = []
    input_bindings = tuple(
        sorted((item.observation_id, canonical_sha256(item)) for item in observations)
    )
    if len({item[0] for item in input_bindings}) != len(input_bindings):
        raise ValueError("detection_correlation_input_identity_conflict")
    for observation in sorted(observations, key=lambda item: item.observation_id):
        reason: str | None = None
        if observation.tenant_id != tenant_id or observation.engagement_id != engagement_id:
            reason = "scope_mismatch"
        elif observation.correlation_key != correlation_key:
            reason = "correlation_key_mismatch"
        elif observation.attack_technique_id != attack_technique_id:
            reason = "technique_mismatch"
        elif observation.disposition is not DetectionDisposition.CONFIRMED:
            reason = "unconfirmed"
        elif observation.confidence is Confidence.LOW:
            reason = "confidence_below_medium"
        elif observation.ingested_at > now or (
            observation.promotion is not None and observation.promotion.promoted_at > now
        ):
            reason = "future_evidence"
        elif not observation.observed_at <= now < observation.expires_at:
            reason = "not_current"
        elif now - observation.observed_at > timedelta(seconds=max_age_seconds):
            reason = "outside_timespan"
        if reason is None:
            qualified.append(observation.observation_id)
        else:
            excluded.append((observation.observation_id, reason))
    values: dict[str, object] = {
        "schema_version": "redagent.detection-correlation/v1",
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "correlation_key": correlation_key,
        "attack_technique_id": attack_technique_id,
        "input_observation_bindings": input_bindings,
        "correlated": bool(qualified),
        "qualified_observation_ids": tuple(qualified),
        "excluded": tuple(sorted(excluded)),
        "evaluated_at": now,
        "max_age_seconds": max_age_seconds,
    }
    return _validated_detection_correlation(
        **values,
        correlation_sha256=canonical_sha256(values),
    )


def build_detection_correlation_opa_input(
    *,
    observations: tuple[DetectionObservationV1, ...],
    tenant_id: str,
    engagement_id: str,
    correlation_key: str,
    attack_technique_id: str,
    now: datetime,
    max_age_seconds: int,
) -> dict[str, object]:
    """Build the sole typed Python-to-Rego differential-conformance input."""
    # Reuse the Python evaluator's complete validation before serializing any policy input.
    correlate_detection_observations(
        observations=observations,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        correlation_key=correlation_key,
        attack_technique_id=attack_technique_id,
        now=now,
        max_age_seconds=max_age_seconds,
    )
    return {
        "tenant_id": tenant_id,
        "engagement_id": engagement_id,
        "correlation_key": correlation_key,
        "attack_technique_id": attack_technique_id,
        "max_age_seconds": max_age_seconds,
        "observations": [
            {
                "observation_id": item.observation_id,
                "tenant_id": item.tenant_id,
                "engagement_id": item.engagement_id,
                "correlation_key": item.correlation_key,
                "attack_technique_id": item.attack_technique_id,
                "disposition": item.disposition.value,
                "confidence": item.confidence.value,
                # IMPORTANT: ceiling is fail-closed at the inclusive max-age boundary.
                "age_seconds": math.ceil((now - item.observed_at).total_seconds()),
                "current": item.observed_at <= now < item.expires_at,
                "future_evidence": item.ingested_at > now
                or (item.promotion is not None and item.promotion.promoted_at > now),
            }
            for item in sorted(observations, key=lambda value: value.observation_id)
        ],
    }


def evaluate_detection_adaptation(
    *,
    request: DetectionAdaptationRequestV1,
    observations: tuple[DetectionObservationV1, ...],
    capability_ids: frozenset[str],
    tenant_id: str,
    engagement_id: str,
    now: datetime,
) -> tuple[DetectionCorrelationDispositionV1, frozenset[str]]:
    entries = tuple(
        item
        for item in request.coverage_matrix.entries
        if item.attack_technique_id == request.attack_technique_id
    )
    if not entries:
        raise ValueError("detection_matrix_technique_missing")
    matrix_capabilities = frozenset(item.capability_id for item in entries)
    if matrix_capabilities != capability_ids:
        raise ValueError("detection_matrix_capability_set_mismatch")
    observed_versions = {
        item.attack_version
        for item in observations
        if item.attack_technique_id == request.attack_technique_id
    }
    if observed_versions - {request.coverage_matrix.attack_version}:
        raise ValueError("detection_matrix_attack_version_mismatch")
    disposition = correlate_detection_observations(
        observations=observations,
        tenant_id=tenant_id,
        engagement_id=engagement_id,
        correlation_key=request.correlation_key,
        attack_technique_id=request.attack_technique_id,
        now=now,
        max_age_seconds=request.max_age_seconds,
    )
    qualified = frozenset(disposition.qualified_observation_ids)
    flagged = frozenset(
        item.capability_id
        for item in observations
        if item.observation_id in qualified
    )
    if not flagged <= capability_ids:
        raise ValueError("detection_observation_capability_outside_set")
    return disposition, flagged


def validate_detection_snapshot_inputs(
    *,
    current: tuple[DetectionObservationV1, ...],
    prior: tuple[DetectionObservationV1, ...],
    tenant_id: str,
    engagement_id: str,
    capability_ids: frozenset[str],
    snapshot_at: datetime,
) -> tuple[DetectionObservationV1, ...]:
    indexed: dict[str, DetectionObservationV1] = {}
    for observation in (*prior, *current):
        if not isinstance(observation, DetectionObservationV1):
            raise ValueError("detection_snapshot_observation_invalid")
        if observation.tenant_id != tenant_id or observation.engagement_id != engagement_id:
            raise ValueError("detection_snapshot_scope_mismatch")
        if observation.capability_id not in capability_ids:
            raise ValueError("detection_snapshot_capability_mismatch")
        if observation.ingested_at > snapshot_at or observation.expires_at <= snapshot_at:
            raise ValueError("detection_snapshot_observation_not_current")
        if observation.promotion is not None and observation.promotion.promoted_at > snapshot_at:
            raise ValueError("detection_snapshot_promotion_from_future")
        existing = indexed.get(observation.observation_id)
        if existing is not None and existing != observation:
            raise ValueError("detection_snapshot_identity_conflict")
        indexed[observation.observation_id] = observation
    return tuple(indexed[key] for key in sorted(indexed))


def load_detection_coverage_matrix(path: Path) -> DetectionCoverageMatrixV1:
    expected = Path(__file__).resolve().parents[2] / "config" / "detection-coverage-matrix.json"
    try:
        if path.absolute() != expected.absolute() or path.is_symlink():
            raise ValueError("unexpected matrix path")
        if not path.is_file() or path.stat().st_size > 64 * 1024:
            raise ValueError("invalid matrix file")
        payload = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_closed_json_object,
            parse_constant=lambda _value: (_ for _ in ()).throw(ValueError("invalid constant")),
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise ValueError("detection_matrix_document_invalid") from exc
    if not isinstance(payload, dict) or set(payload) != _MATRIX_FIELDS:
        raise ValueError("detection_matrix_document_invalid")
    raw_entries = payload["entries"]
    if not isinstance(raw_entries, list):
        raise ValueError("detection_matrix_document_invalid")
    entries: list[DetectionCoverageEntryV1] = []
    try:
        for raw in raw_entries:
            if not isinstance(raw, dict) or set(raw) != _ENTRY_FIELDS:
                raise ValueError("detection_matrix_document_invalid")
            entries.append(
                DetectionCoverageEntryV1(
                    attack_technique_id=raw["attack_technique_id"],
                    capability_id=raw["capability_id"],
                    expected_detectability=ExpectedDetectability(raw["expected_detectability"]),
                    last_confirmed_status=LastConfirmedDetectionStatus(
                        raw["last_confirmed_status"]
                    ),
                )
            )
        values: dict[str, Any] = {
            "schema_version": payload["schema_version"],
            "matrix_id": payload["matrix_id"],
            "revision": payload["revision"],
            "attack_version": payload["attack_version"],
            "authoring_source": DetectionCoverageAuthoringSource(payload["authoring_source"]),
            "approved_by": payload["approved_by"],
            "approval_ref": payload["approval_ref"],
            "entries": tuple(entries),
        }
        return DetectionCoverageMatrixV1(
            **values,
            matrix_sha256=canonical_sha256(values),
            _validation_token=_MATRIX_VALIDATION_TOKEN,
        )
    except (TypeError, ValueError) as exc:
        raise ValueError("detection_matrix_document_invalid") from exc


def _observation_values(observation: DetectionObservationV1) -> dict[str, object]:
    return {
        field: getattr(observation, field)
        for field in observation.__dataclass_fields__
        if field != "_validation_token"
    }


def _closed_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate key")
        value[key] = item
    return value


def _identifier(name: str, value: object) -> None:
    if not isinstance(value, str) or not _ID.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _sha256(name: str, value: object) -> None:
    if not isinstance(value, str) or not _SHA.fullmatch(value):
        raise ValueError(f"{name}_invalid")


def _aware(name: str, value: object) -> None:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise ValueError(f"{name}_invalid")
