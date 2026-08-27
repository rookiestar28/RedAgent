from __future__ import annotations

from fastapi import FastAPI
from typing import (
    Any,
    Callable,
    Mapping,
)


LEGACY_COMPONENT_NAMES: Mapping[str, str] = {
    "CampaignEffectStatusData": "R123CampaignEffectStatusData",
    "CampaignStatusData": "R123CampaignStatusData",
    "CampaignStatusResponse": "R123CampaignStatusResponse",
    "CampaignQualificationData": "R123QualificationData",
    "CampaignQualificationRequest": "R123QualificationRequest",
    "CampaignQualificationResponse": "R123QualificationResponse",
    "CampaignReadinessStatusData": "R123StatusData",
    "CampaignReadinessStatusResponse": "R123StatusResponse",
    "CampaignCoreAttentionData": "R124AttentionData",
    "CampaignCoreAttentionPageResponse": "R124AttentionPageResponse",
    "CampaignCoreAuthorityData": "R124AuthorityData",
    "CampaignCoreAggregateData": "R124CampaignAggregateData",
    "CampaignCoreAggregateResponse": "R124CampaignAggregateResponse",
    "CampaignCoreInspectorData": "R124CampaignInspectorData",
    "CampaignCoreInspectorResponse": "R124CampaignInspectorResponse",
    "CampaignCoreMutationData": "R124CampaignMutationData",
    "CampaignCoreMutationResponse": "R124CampaignMutationResponse",
    "CampaignCoreStartRequest": "R124CampaignStartRequest",
    "CampaignCoreSummaryData": "R124CampaignSummaryData",
    "CampaignCoreSummaryPageResponse": "R124CampaignSummaryPageResponse",
    "CampaignCoreCandidateData": "R124CandidateData",
    "CampaignCoreContextData": "R124ContextData",
    "CampaignCoreDecisionData": "R124DecisionData",
    "CampaignCoreEffectData": "R124EffectData",
    "CampaignCoreEngagementOptionPageResponse": "R124EngagementOptionPageResponse",
    "CampaignCoreFindingData": "R124FindingData",
    "CampaignCoreOptionData": "R124OptionData",
    "CampaignCorePageData": "R124PageData",
    "CampaignCorePlanData": "R124PlanData",
    "CampaignCoreRecoveryData": "R124RecoveryData",
    "CampaignCoreRecoveryRequest": "R124RecoveryRequest",
    "CampaignCoreRetestData": "R124RetestData",
    "CampaignCoreRiskProfileOptionPageResponse": "R124RiskProfileOptionPageResponse",
    "CampaignCoreTargetOptionPageResponse": "R124TargetOptionPageResponse",
}


LEGACY_OPERATION_SUMMARIES: Mapping[str, tuple[str, str]] = {
    "list_r124_attention": ("List Campaign Core Attention", "List R124 Attention"),
    "list_r124_campaigns": ("List Campaign Core Campaigns", "List R124 Campaigns"),
    "start_r124_campaign": ("Start Campaign Core Campaign", "Start R124 Campaign"),
    "get_r124_campaign": ("Get Campaign Core Campaign", "Get R124 Campaign"),
    "inspect_r124_campaign": ("Inspect Campaign Core Campaign", "Inspect R124 Campaign"),
    "revoke_r124_campaign": ("Revoke Campaign Core Campaign", "Revoke R124 Campaign"),
    "stop_r124_campaign": ("Stop Campaign Core Campaign", "Stop R124 Campaign"),
    "list_r124_engagement_options": ("List Campaign Core Engagement Options", "List R124 Engagement Options"),
    "list_r124_risk_profile_options": (
        "List Campaign Core Risk Profile Options",
        "List R124 Risk Profile Options",
    ),
    "list_r124_target_options": ("List Campaign Core Target Options", "List R124 Target Options"),
}


class OpenApiCompatibilityError(RuntimeError):
    """Raised when the expected component rename boundary has drifted."""


def _rewrite_openapi_refs(value: Any) -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "$ref" and isinstance(child, str):
                prefix = "#/components/schemas/"
                component = child.removeprefix(prefix)
                if child.startswith(prefix) and component in LEGACY_COMPONENT_NAMES:
                    value[key] = prefix + LEGACY_COMPONENT_NAMES[component]
            else:
                _rewrite_openapi_refs(child)
    elif isinstance(value, list):
        for child in value:
            _rewrite_openapi_refs(child)


def _apply_legacy_component_names(schema: dict[str, Any]) -> dict[str, Any]:
    paths = schema.get("paths")
    if not isinstance(paths, dict):
        raise OpenApiCompatibilityError("OpenAPI paths are unavailable")
    operation_ids: set[str] = set()
    for path_item in paths.values():
        if not isinstance(path_item, dict):
            continue
        for operation in path_item.values():
            if not isinstance(operation, dict):
                continue
            operation_id = operation.get("operationId")
            if not isinstance(operation_id, str) or operation_id not in LEGACY_OPERATION_SUMMARIES:
                continue
            current_summary, legacy_summary = LEGACY_OPERATION_SUMMARIES[operation_id]
            if operation.get("summary") not in {current_summary, legacy_summary}:
                raise OpenApiCompatibilityError(f"OpenAPI operation summary drifted: {operation_id}")
            operation["summary"] = legacy_summary
            operation_ids.add(operation_id)
    if operation_ids != set(LEGACY_OPERATION_SUMMARIES):
        raise OpenApiCompatibilityError("OpenAPI operation compatibility set drifted")
    components = schema.get("components")
    if not isinstance(components, dict):
        raise OpenApiCompatibilityError("OpenAPI components are unavailable")
    schemas = components.get("schemas")
    if not isinstance(schemas, dict):
        raise OpenApiCompatibilityError("OpenAPI schemas are unavailable")
    new_present = {name for name in LEGACY_COMPONENT_NAMES if name in schemas}
    legacy_present = {name for name in LEGACY_COMPONENT_NAMES.values() if name in schemas}
    if not new_present and legacy_present == set(LEGACY_COMPONENT_NAMES.values()):
        return schema
    if new_present != set(LEGACY_COMPONENT_NAMES) or legacy_present:
        raise OpenApiCompatibilityError("OpenAPI component rename set drifted")
    remapped: dict[str, Any] = {}
    for name, value in schemas.items():
        legacy_name = LEGACY_COMPONENT_NAMES.get(name, name)
        if legacy_name in remapped:
            raise OpenApiCompatibilityError(f"duplicate OpenAPI component after compatibility mapping: {legacy_name}")
        if name in LEGACY_COMPONENT_NAMES:
            if not isinstance(value, dict) or value.get("title") != name:
                raise OpenApiCompatibilityError(f"OpenAPI component title drifted before mapping: {name}")
            value["title"] = legacy_name
        remapped[legacy_name] = value
    components["schemas"] = remapped
    _rewrite_openapi_refs(schema)
    return schema


def install_legacy_component_name_compatibility(app: FastAPI) -> None:
    original_openapi: Callable[[], dict[str, Any]] = app.openapi

    def compatible_openapi() -> dict[str, Any]:
        schema = original_openapi()
        compatible = _apply_legacy_component_names(schema)
        app.openapi_schema = compatible
        return compatible

    # IMPORTANT: this map is the public-contract pin for compat_135 model renames; keep it fail closed.
    setattr(app, "openapi", compatible_openapi)
