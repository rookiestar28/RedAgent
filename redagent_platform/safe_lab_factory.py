"""Safe lab target factory and synthetic evidence corpus contracts.

The factory builds metadata, synthetic data, and proof records only. It never
starts lab services, sends network traffic, executes scanners, or runs adapters.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum

from redagent_platform import adapter_certification, lab_harness
from redagent_platform.domain import PolicyDecisionOutcome, TestMode
from redagent_platform.evidence_chain import AuditAction, EvidenceChain
from redagent_platform.target_inventory import DataSensitivity, EnvironmentType, InventoryTarget


class LabTestCategory(str, Enum):
    PASSIVE_WEB = "passive_web"
    API = "api"
    ZAP = "zap"
    NUCLEI = "nuclei"
    REDACTION = "redaction"
    REPORTING = "reporting"
    KILL_SWITCH = "kill_switch"
    ADAPTER_VALIDATION = "adapter_validation"


class SyntheticRecordKind(str, Enum):
    USER_ALIAS = "user_alias"
    ORDER_REFERENCE = "order_reference"
    HEADER_VALUE = "header_value"
    CANARY = "canary"


@dataclass(frozen=True, kw_only=True)
class SafeLabTargetRequest:
    factory_id: str
    lab_request: lab_harness.LabTargetRequest
    allowed_categories: tuple[LabTestCategory, ...]
    disposable: bool
    non_production_attested: bool
    requested_by_user_id: str


@dataclass(frozen=True, kw_only=True)
class SafeLabTarget:
    factory_id: str
    registration: lab_harness.LabTargetRegistration
    allowed_categories: tuple[LabTestCategory, ...]
    disposable: bool
    non_production: bool
    requested_by_user_id: str


@dataclass(frozen=True, kw_only=True)
class SyntheticRecord:
    record_id: str
    kind: SyntheticRecordKind
    value: str
    classification: str


@dataclass(frozen=True, kw_only=True)
class SyntheticDataset:
    dataset_id: str
    generated_at: datetime
    records: tuple[SyntheticRecord, ...]
    canary_values: tuple[str, ...]
    forbidden_real_data_classes: tuple[str, ...]
    dataset_hash: str


@dataclass(frozen=True, kw_only=True)
class GoldenEvidenceExpectation:
    expectation_id: str
    expected_finding_ids: tuple[str, ...]
    redaction_expectations: tuple[str, ...]
    cleanup_expectations: tuple[str, ...]
    report_snapshot_hash: str
    synthetic_dataset_hash: str


@dataclass(frozen=True, kw_only=True)
class GoldenEvidenceCorpus:
    corpus_id: str
    lab_target_id: str
    expectations: tuple[GoldenEvidenceExpectation, ...]
    corpus_hash: str


@dataclass(frozen=True, kw_only=True)
class TeardownProof:
    proof_id: str
    lab_target_id: str
    teardown_at: datetime
    completed_step_orders: tuple[int, ...]
    artifact_ids: tuple[str, ...]
    disposable_removed: bool
    audit_event_hash: str


@dataclass(frozen=True, kw_only=True)
class AdapterLabValidation:
    outcome: PolicyDecisionOutcome
    reason: str
    adapter_id: str
    version: str
    lab_target_id: str

    @property
    def allowed(self) -> bool:
        return self.outcome is PolicyDecisionOutcome.ALLOW


FORBIDDEN_REAL_DATA_CLASSES: tuple[str, ...] = (
    "real_personal_data",
    "customer_data",
    "regulated_data",
    "credential_material",
    "production_data",
)


def register_safe_lab_target(
    request: SafeLabTargetRequest,
    approval: lab_harness.SandboxApproval,
) -> SafeLabTarget:
    _validate_safe_lab_request(request)
    registration = lab_harness.register_lab_target(request.lab_request, approval)
    assert_non_production_lab_target(registration.inventory_target)
    return SafeLabTarget(
        factory_id=request.factory_id.strip(),
        registration=registration,
        allowed_categories=request.allowed_categories,
        disposable=True,
        non_production=True,
        requested_by_user_id=request.requested_by_user_id.strip(),
    )


def assert_non_production_lab_target(target: InventoryTarget) -> None:
    if target.environment is EnvironmentType.PRODUCTION:
        raise ValueError("production_target_forbidden")
    if target.environment is not EnvironmentType.LAB:
        raise ValueError("lab_environment_required")
    if target.data_sensitivity is not DataSensitivity.PUBLIC:
        raise ValueError("lab_target_must_use_public_synthetic_data")


def build_synthetic_dataset(
    *,
    dataset_id: str,
    generated_at: datetime,
    canary_seed: str,
) -> SyntheticDataset:
    _require_non_empty("dataset_id", dataset_id)
    _require_non_empty("canary_seed", canary_seed)
    _require_timezone(generated_at)
    canaries = (
        f"canary-{_short_hash(canary_seed)}-alpha",
        f"canary-{_short_hash(canary_seed + ':beta')}-beta",
    )
    records = (
        SyntheticRecord(
            record_id=f"{dataset_id}:user-alias",
            kind=SyntheticRecordKind.USER_ALIAS,
            value=f"synthetic-user-{_short_hash(dataset_id)}@example.invalid",
            classification="synthetic_public",
        ),
        SyntheticRecord(
            record_id=f"{dataset_id}:order-reference",
            kind=SyntheticRecordKind.ORDER_REFERENCE,
            value=f"LAB-ORDER-{_short_hash(dataset_id + ':order').upper()}",
            classification="synthetic_public",
        ),
        SyntheticRecord(
            record_id=f"{dataset_id}:header-value",
            kind=SyntheticRecordKind.HEADER_VALUE,
            value=f"x-redagent-lab-{_short_hash(dataset_id + ':header')}",
            classification="synthetic_public",
        ),
        SyntheticRecord(
            record_id=f"{dataset_id}:canary",
            kind=SyntheticRecordKind.CANARY,
            value=canaries[0],
            classification="synthetic_canary",
        ),
    )
    _assert_synthetic_only(records, canaries)
    dataset_hash = _canonical_sha256(
        {
            "dataset_id": dataset_id.strip(),
            "generated_at": generated_at.isoformat(),
            "records": tuple(record.__dict__ for record in records),
            "canary_values": canaries,
            "forbidden_real_data_classes": FORBIDDEN_REAL_DATA_CLASSES,
        }
    )
    return SyntheticDataset(
        dataset_id=dataset_id.strip(),
        generated_at=generated_at,
        records=records,
        canary_values=canaries,
        forbidden_real_data_classes=FORBIDDEN_REAL_DATA_CLASSES,
        dataset_hash=dataset_hash,
    )


def build_golden_evidence_corpus(
    *,
    corpus_id: str,
    target: SafeLabTarget,
    dataset: SyntheticDataset,
    expected_finding_ids: tuple[str, ...],
    redaction_expectations: tuple[str, ...],
    cleanup_expectations: tuple[str, ...],
    report_snapshot_markdown: str,
) -> GoldenEvidenceCorpus:
    _require_non_empty("corpus_id", corpus_id)
    _validate_expectation_inputs(expected_finding_ids, redaction_expectations, cleanup_expectations, report_snapshot_markdown)
    expectation = GoldenEvidenceExpectation(
        expectation_id=f"{corpus_id}:expectation",
        expected_finding_ids=tuple(expected_finding_ids),
        redaction_expectations=tuple(redaction_expectations),
        cleanup_expectations=tuple(cleanup_expectations),
        report_snapshot_hash=_stable_text_hash(report_snapshot_markdown),
        synthetic_dataset_hash=dataset.dataset_hash,
    )
    corpus_hash = _canonical_sha256(
        {
            "corpus_id": corpus_id.strip(),
            "lab_target_id": target.registration.target_id,
            "expectations": (expectation.__dict__,),
        }
    )
    return GoldenEvidenceCorpus(
        corpus_id=corpus_id.strip(),
        lab_target_id=target.registration.target_id,
        expectations=(expectation,),
        corpus_hash=corpus_hash,
    )


def verify_golden_evidence_corpus(corpus: GoldenEvidenceCorpus) -> None:
    _require_non_empty("corpus_id", corpus.corpus_id)
    _require_non_empty("lab_target_id", corpus.lab_target_id)
    if not corpus.expectations:
        raise ValueError("golden_expectations_required")
    for expectation in corpus.expectations:
        _validate_expectation_inputs(
            expectation.expected_finding_ids,
            expectation.redaction_expectations,
            expectation.cleanup_expectations,
            expectation.report_snapshot_hash,
        )
        _require_non_empty("synthetic_dataset_hash", expectation.synthetic_dataset_hash)
    expected_hash = _canonical_sha256(
        {
            "corpus_id": corpus.corpus_id,
            "lab_target_id": corpus.lab_target_id,
            "expectations": tuple(expectation.__dict__ for expectation in corpus.expectations),
        }
    )
    if expected_hash != corpus.corpus_hash:
        raise ValueError("golden_corpus_hash_mismatch")


def record_teardown_proof(
    *,
    proof_id: str,
    target: SafeLabTarget,
    completed_step_orders: tuple[int, ...],
    artifact_ids: tuple[str, ...],
    disposable_removed: bool,
    teardown_at: datetime,
    actor_user_id: str,
    audit_event_id: str,
    audit_chain: EvidenceChain,
) -> tuple[EvidenceChain, TeardownProof]:
    _require_non_empty("proof_id", proof_id)
    _require_non_empty("actor_user_id", actor_user_id)
    _require_non_empty("audit_event_id", audit_event_id)
    _require_timezone(teardown_at)
    if not target.disposable or not disposable_removed:
        raise ValueError("disposable_teardown_required")
    expected_steps = tuple(step.order for step in target.registration.teardown_procedure.steps)
    if tuple(sorted(completed_step_orders)) != expected_steps:
        raise ValueError("teardown_steps_incomplete")
    if not artifact_ids:
        raise ValueError("teardown_artifacts_required")
    next_chain = audit_chain.append_audit_event(
        event_id=audit_event_id,
        organization_id=target.registration.inventory_target.organization_id,
        actor_user_id=actor_user_id,
        action=AuditAction.TEST_DEFINITION_CHANGE,
        subject_type="safe_lab_teardown",
        subject_id=target.registration.target_id,
        occurred_at=teardown_at,
        details={
            "proof_id": proof_id,
            "completed_step_orders": completed_step_orders,
            "artifact_count": len(artifact_ids),
            "disposable_removed": disposable_removed,
        },
    )
    return next_chain, TeardownProof(
        proof_id=proof_id.strip(),
        lab_target_id=target.registration.target_id,
        teardown_at=teardown_at,
        completed_step_orders=tuple(completed_step_orders),
        artifact_ids=tuple(artifact_ids),
        disposable_removed=True,
        audit_event_hash=next_chain.audit_events[-1].event_hash,
    )


def validate_adapter_for_lab_target(
    *,
    adapter_registry: adapter_certification.AdapterCertificationRegistry,
    target: SafeLabTarget,
    adapter_id: str,
    version: str,
    mode: TestMode,
) -> AdapterLabValidation:
    if LabTestCategory.ADAPTER_VALIDATION not in target.allowed_categories:
        return _adapter_denied(adapter_id, version, target, "adapter_validation_category_required")
    assert_non_production_lab_target(target.registration.inventory_target)
    decision = adapter_registry.authorize_use(
        adapter_id=adapter_id,
        version=version,
        surface=adapter_certification.AdapterUseSurface.RUNNER_JOB,
        mode=mode,
    )
    if not decision.allowed:
        return _adapter_denied(adapter_id, version, target, decision.reason)
    return AdapterLabValidation(
        outcome=PolicyDecisionOutcome.ALLOW,
        reason="certified_adapter_allowed_for_lab_target",
        adapter_id=adapter_id,
        version=version,
        lab_target_id=target.registration.target_id,
    )


def _adapter_denied(
    adapter_id: str,
    version: str,
    target: SafeLabTarget,
    reason: str,
) -> AdapterLabValidation:
    return AdapterLabValidation(
        outcome=PolicyDecisionOutcome.DENY,
        reason=reason,
        adapter_id=adapter_id,
        version=version,
        lab_target_id=target.registration.target_id,
    )


def _validate_safe_lab_request(request: SafeLabTargetRequest) -> None:
    _require_non_empty("factory_id", request.factory_id)
    _require_non_empty("requested_by_user_id", request.requested_by_user_id)
    if not request.allowed_categories:
        raise ValueError("lab_test_categories_required")
    if not request.disposable:
        raise ValueError("lab_target_must_be_disposable")
    if not request.non_production_attested:
        raise ValueError("non_production_attestation_required")


def _validate_expectation_inputs(
    expected_finding_ids: tuple[str, ...],
    redaction_expectations: tuple[str, ...],
    cleanup_expectations: tuple[str, ...],
    report_snapshot: str,
) -> None:
    if not expected_finding_ids:
        raise ValueError("expected_findings_required")
    if not redaction_expectations:
        raise ValueError("redaction_expectations_required")
    if not cleanup_expectations:
        raise ValueError("cleanup_expectations_required")
    _require_non_empty("report_snapshot", report_snapshot)
    for finding_id in expected_finding_ids:
        _require_non_empty("expected_finding_id", finding_id)


def _assert_synthetic_only(records: tuple[SyntheticRecord, ...], canary_values: tuple[str, ...]) -> None:
    for record in records:
        _require_non_empty("synthetic_record_id", record.record_id)
        _require_non_empty("synthetic_value", record.value)
        if not record.classification.startswith("synthetic_"):
            raise ValueError("synthetic_record_classification_required")
        lowered = record.value.lower()
        for forbidden in ("prod", "production", "customer", "regulated", "real-person", "auth-material"):
            if forbidden in lowered:
                raise ValueError("real_data_marker_forbidden")
    if not canary_values or any(not value.startswith("canary-") for value in canary_values):
        raise ValueError("synthetic_canaries_required")


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:10]


def _stable_text_hash(value: str) -> str:
    return hashlib.sha256(value.strip().encode("utf-8")).hexdigest()


def _canonical_sha256(payload: dict[str, object]) -> str:
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _require_timezone(value: datetime) -> None:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timezone_required")


def _require_non_empty(field_name: str, value: str) -> None:
    if not value or not value.strip():
        raise ValueError(f"missing_{field_name}")
