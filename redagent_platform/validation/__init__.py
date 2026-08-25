"""Deterministic, fail-closed repository validation contracts for R118."""

from redagent_platform.validation.classifier import (
    ChangeRequest,
    GateDecision,
    classify_change,
    decision_evidence_payload,
)
from redagent_platform.validation.config import PathMappingConfig, PathRule, load_path_mapping
from redagent_platform.validation.receipt import (
    ReceiptVerificationError,
    build_verification_receipt,
    current_configuration_digests,
    verify_verification_receipt,
)
from redagent_platform.validation.stages import (
    Stage,
    StageRegistry,
    StageResult,
    StageRunner,
    STAGE_REGISTRY_REVISION,
    ValidationConfigError,
    build_default_registry,
    load_stage_registry,
)
__all__ = [
    "ChangeRequest",
    "GateDecision",
    "PathMappingConfig",
    "PathRule",
    "ReceiptVerificationError",
    "Stage",
    "StageRegistry",
    "StageResult",
    "StageRunner",
    "STAGE_REGISTRY_REVISION",
    "ValidationConfigError",
    "build_default_registry",
    "build_verification_receipt",
    "current_configuration_digests",
    "classify_change",
    "decision_evidence_payload",
    "load_path_mapping",
    "load_stage_registry",
    "verify_verification_receipt",
]
