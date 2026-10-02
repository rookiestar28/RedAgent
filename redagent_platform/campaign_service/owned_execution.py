"""Closed limits for the explicitly approved owned-loopback execution slice."""

from collections.abc import Mapping

from redagent_platform.campaign_service.application_contracts import AutonomousCampaignLifecycle


class OwnedExecutionDenied(RuntimeError):
    """Current application authority cannot permit a new owned effect."""


def owned_execution_attention(reason: object) -> AutonomousCampaignLifecycle | None:
    if not isinstance(reason, str):
        return None
    if reason in {"campaign_stop_active_cleanup_required", "cleanup_receipt_missing", "cleanup_failed"}:
        return AutonomousCampaignLifecycle.CLEANUP_INCOMPLETE
    if reason in {"evidence_output_incomplete", "evidence_persistence_failed"}:
        return AutonomousCampaignLifecycle.EVIDENCE_INCOMPLETE
    if reason == "adapter_receipt_commit_unknown":
        return AutonomousCampaignLifecycle.RECONCILIATION_REQUIRED
    return None


def validate_owned_execution_input(payload: Mapping[str, object]) -> None:
    revision = payload.get("revision")
    domain = payload.get("domain")
    if not isinstance(revision, dict) or not isinstance(domain, dict):
        raise OwnedExecutionDenied("owned_execution_input_invalid")
    plan = revision.get("candidate_plan")
    nodes = plan.get("nodes") if isinstance(plan, dict) else None
    operators = domain.get("operators")
    if not isinstance(nodes, list) or not 1 <= len(nodes) <= 2 or not isinstance(operators, list):
        raise OwnedExecutionDenied("owned_execution_width_invalid")
    indexed = {op.get("operator_id"): op for op in operators if isinstance(op, dict)}
    for node in nodes:
        if not isinstance(node, dict) or node.get("environment") != "synthetic_loopback":
            raise OwnedExecutionDenied("owned_execution_target_class_denied")
        operator = indexed.get(node.get("operator_id"))
        if not isinstance(operator, dict):
            raise OwnedExecutionDenied("owned_execution_operator_missing")
        capability = operator.get("capability")
        if not isinstance(capability, dict) or (
            capability.get("capability_id") not in {"zap-controlled-runtime", "nuclei-trusted-runtime"}
            or capability.get("capability_revision") != 2
        ):
            raise OwnedExecutionDenied("owned_execution_capability_denied")
        # CRITICAL: a larger signed budget cannot broaden this certified sequential slice.
        for key, maximum in (
            ("max_duration_seconds", 60),
            ("max_rate_per_minute", 60),
            ("concurrency_weight", 1),
            ("max_retries", 1),
        ):
            value = operator.get(key)
            if type(value) is not int or not 0 <= value <= maximum:
                raise OwnedExecutionDenied("owned_execution_bound_exceeded")
        evidence_limit = (10 if capability["capability_id"] == "zap-controlled-runtime" else 2) * 1024 * 1024
        # CRITICAL: these transports run one fixed profile. A smaller declaration is not
        # enforceable runtime authority; deny it instead of under-reserving its effects.
        for key, minimum in (("max_requests", 20), ("max_duration_seconds", 60),
                             ("max_rate_per_minute", 60), ("max_evidence_bytes", evidence_limit),
                             ("max_data_bytes", 20 * 1024 * 1024)):
            value = operator.get(key)
            if type(value) is not int or value < minimum:
                raise OwnedExecutionDenied("owned_execution_profile_budget_insufficient")
