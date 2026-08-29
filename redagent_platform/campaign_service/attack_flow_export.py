"""Sanitized one-way Attack Flow projection for verified campaign evidence."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import uuid

from redagent_platform.campaign_service.planner_evidence import (
    CampaignEvidenceVerificationOutcome,
    CampaignEvidenceVerificationResultV1,
    LineageArtifactKind,
    campaign_context_sha256,
)
from redagent_platform.identity.authorization import authorize_permission
from redagent_platform.evidence_chain import EvidenceAccessPolicy
from redagent_platform.redaction import RedactionArtifactClass, assert_no_sensitive_output


ATTACK_FLOW_EXPORT_PERMISSION = "campaign:evidence-export"
ATTACK_FLOW_SPEC_VERSION = "2.1"
ATTACK_FLOW_EXTENSION_VERSION = "3.2.0"
_STIX_NAMESPACE = uuid.UUID("7bf30ee0-d8af-4a4f-bace-304699357f3e")
_SEMANTIC_LOSS = (
    "authorization_approver_identities_omitted",
    "evidence_content_and_internal_identifiers_omitted",
    "policy_inputs_and_credential_references_omitted",
    "runtime_commands_payloads_and_raw_targets_omitted",
)


@dataclass(frozen=True, slots=True, kw_only=True)
class AttackFlowExportRequestV1:
    tenant_id: str
    campaign_id: str
    roles: tuple[str, ...]
    exported_at: datetime

    def __post_init__(self) -> None:
        for name, value in (("tenant_id", self.tenant_id), ("campaign_id", self.campaign_id)):
            if not isinstance(value, str) or not value or len(value) > 256:
                raise ValueError(f"attack_flow_{name}_invalid")
        if (
            not isinstance(self.roles, tuple)
            or not self.roles
            or len(self.roles) > 16
            or len(set(self.roles)) != len(self.roles)
            or tuple(sorted(self.roles)) != self.roles
            or any(not isinstance(role, str) or not role or len(role) > 64 for role in self.roles)
        ):
            raise ValueError("attack_flow_roles_invalid")
        if self.exported_at.tzinfo is None or self.exported_at.utcoffset() is None:
            raise ValueError("attack_flow_export_time_invalid")


def export_verified_campaign_attack_flow(
    verified: CampaignEvidenceVerificationResultV1,
    *,
    request: AttackFlowExportRequestV1,
) -> dict[str, object]:
    """Project verified digests only; there is deliberately no inverse/import operation."""

    if not isinstance(verified, CampaignEvidenceVerificationResultV1) or not isinstance(
        request, AttackFlowExportRequestV1
    ):
        raise ValueError("attack_flow_export_input_invalid")
    if verified.outcome is not CampaignEvidenceVerificationOutcome.VERIFIED:
        raise PermissionError("attack_flow_verified_complete_bundle_required")
    if (
        verified.tenant_sha256 != campaign_context_sha256(request.tenant_id)
        or verified.campaign_sha256 != campaign_context_sha256(request.campaign_id)
    ):
        # CRITICAL: authenticated tenant/campaign context must match the independently verified bundle.
        raise PermissionError("attack_flow_context_binding_denied")
    if not authorize_permission(
        roles=request.roles,
        permission=ATTACK_FLOW_EXPORT_PERMISSION,
        now=request.exported_at,
        object_id=None,
    ):
        raise PermissionError("attack_flow_export_permission_denied")
    access_policies = {item.access_policy for item in verified.artifacts}
    if (
        EvidenceAccessPolicy.SECURITY_LEADS_ONLY in access_policies
        and "tenant_admin" not in request.roles
    ):
        raise PermissionError("attack_flow_security_lead_access_required")
    if EvidenceAccessPolicy.REVIEWERS_ONLY in access_policies and not {
        "reviewer",
        "tenant_admin",
    }.intersection(request.roles):
        raise PermissionError("attack_flow_reviewer_access_required")

    timestamp = request.exported_at.isoformat().replace("+00:00", "Z")
    flow_id = _stix_id("attack-flow", verified.manifest_sha256)
    action_artifacts = tuple(
        item
        for item in verified.artifacts
        if item.kind
        not in {
            LineageArtifactKind.AUTHORIZATION,
            LineageArtifactKind.AUTHORITY_LIFECYCLE,
            LineageArtifactKind.TERMINAL_DISPOSITION,
        }
    )
    action_ids = tuple(
        _stix_id("attack-action", f"{verified.manifest_sha256}:{item.artifact_sha256}")
        for item in action_artifacts
    )
    flow: dict[str, object] = {
        "type": "attack-flow",
        "spec_version": ATTACK_FLOW_SPEC_VERSION,
        "id": flow_id,
        "created": timestamp,
        "modified": timestamp,
        "name": "Verified campaign evidence flow",
        "description": "Sanitized non-executable projection of a verified retained evidence lineage.",
        "scope": "incident",
        "start_refs": list(action_ids[:1]),
        "extensions": {
            "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4": {
                "extension_type": "new-sdo",
                "version": ATTACK_FLOW_EXTENSION_VERSION,
            }
        },
    }
    actions = []
    for index, (artifact, action_id) in enumerate(zip(action_artifacts, action_ids, strict=True)):
        next_refs = list(action_ids[index + 1 : index + 2])
        actions.append(
            {
                "type": "attack-action",
                "spec_version": ATTACK_FLOW_SPEC_VERSION,
                "id": action_id,
                "created": timestamp,
                "modified": timestamp,
                "name": _safe_stage_name(artifact.kind),
                "effect_refs": next_refs,
                "x_redagent_sequence": artifact.sequence,
                "x_redagent_state": artifact.state.value,
                "x_redagent_source_sha256": artifact.artifact_sha256,
            }
        )
    export: dict[str, object] = {
        "type": "bundle",
        "id": _stix_id("bundle", verified.manifest_sha256),
        "objects": [flow, *actions],
        "x_redagent_source_manifest_sha256": verified.manifest_sha256,
        "x_redagent_semantic_loss": list(_SEMANTIC_LOSS),
        "x_redagent_non_executable": True,
    }
    # CRITICAL: redaction is a pre-export gate; never repair or redact an already emitted object.
    encoded = json.dumps(export, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    assert_no_sensitive_output(encoded, RedactionArtifactClass.JSON_SARIF)
    return export


def _stix_id(object_type: str, material: str) -> str:
    digest = hashlib.sha256(material.encode("ascii")).hexdigest()
    return f"{object_type}--{uuid.uuid5(_STIX_NAMESPACE, digest)}"


def _safe_stage_name(kind: LineageArtifactKind) -> str:
    return {
        LineageArtifactKind.PLANNING_DOMAIN: "Planning domain evaluated",
        LineageArtifactKind.TRUSTED_CONTEXT: "Trusted context evaluated",
        LineageArtifactKind.PLAN_REVISION: "Plan revision selected",
        LineageArtifactKind.PLANNER_RECEIPT: "Planner receipt recorded",
        LineageArtifactKind.VALIDATION_CERTIFICATE: "Independent validation recorded",
        LineageArtifactKind.SUBSET_PROOF: "Authority subset proven",
        LineageArtifactKind.ADMISSION_POLICY: "Admission policy evaluated",
        LineageArtifactKind.ADMISSION_RECEIPT: "Plan admission recorded",
        LineageArtifactKind.BUDGET_RESERVATION: "Campaign budget reserved",
        LineageArtifactKind.NODE_INTENT: "Node intent admitted",
        LineageArtifactKind.EFFECT_POLICY_DECISION: "Effect policy evaluated",
        LineageArtifactKind.CREDENTIAL_LEASE: "Credential lease referenced",
        LineageArtifactKind.RUNNER_RESULT: "Runner result recorded",
        LineageArtifactKind.EVIDENCE: "Evidence recorded",
        LineageArtifactKind.TRUSTED_OBSERVATION: "Trusted observation evaluated",
        LineageArtifactKind.REPLAN: "Bounded replan evaluated",
        LineageArtifactKind.CLEANUP: "Cleanup recorded",
        LineageArtifactKind.CONTAINMENT: "Containment recorded",
        LineageArtifactKind.BUDGET_RECONCILIATION: "Campaign budget reconciled",
    }[kind]
