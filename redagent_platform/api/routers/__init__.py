"""Ordered control-plane API domain registrars."""

from redagent_platform.api.routers.foundation import (
    register_foundation_routes,
)

from redagent_platform.api.routers.access import (
    register_access_context_routes,
    register_access_management_routes,
)

from redagent_platform.api.routers.policy import (
    register_policy_routes,
)

from redagent_platform.api.routers.jobs import (
    register_job_list_routes,
    register_job_mutation_routes,
)

from redagent_platform.api.routers.runners import (
    register_runner_routes,
)

from redagent_platform.api.routers.containment import (
    register_containment_routes,
    register_quota_routes,
)

from redagent_platform.api.routers.observability import (
    register_observability_dashboard_routes,
    register_observability_incident_routes,
)

from redagent_platform.api.routers.lab import (
    register_lab_routes,
)

from redagent_platform.api.routers.zap import (
    register_zap_routes,
)

from redagent_platform.api.routers.api_differential import (
    register_api_differential_routes,
)

from redagent_platform.api.routers.network import (
    register_network_routes,
)

from redagent_platform.api.routers.cloud import (
    register_cloud_routes,
)

from redagent_platform.api.routers.identity_saas import (
    register_identity_saas_routes,
)

from redagent_platform.api.routers.artifact import (
    register_artifact_routes,
)

from redagent_platform.api.routers.purple import (
    register_purple_routes,
)

from redagent_platform.api.routers.human_simulation import (
    register_human_simulation_routes,
)

from redagent_platform.api.routers.agent import (
    register_agent_tool_routes,
    register_agent_runtime_routes,
)

from redagent_platform.api.routers.workbench import (
    register_workbench_routes,
)

from redagent_platform.api.routers.finding_operations import (
    register_finding_operations_routes,
)

from redagent_platform.api.routers.nuclei import (
    register_nuclei_routes,
)

from redagent_platform.api.routers.campaigns import (
    register_campaign_routes,
)

from redagent_platform.api.routers.evidence import (
    register_evidence_routes,
)

from redagent_platform.api.routers.findings import (
    register_finding_routes,
)

from redagent_platform.api.routers.secrets import (
    register_secret_routes,
)

__all__ = (
    "register_foundation_routes",
    "register_access_context_routes",
    "register_access_management_routes",
    "register_policy_routes",
    "register_job_list_routes",
    "register_job_mutation_routes",
    "register_runner_routes",
    "register_containment_routes",
    "register_quota_routes",
    "register_observability_dashboard_routes",
    "register_observability_incident_routes",
    "register_lab_routes",
    "register_zap_routes",
    "register_api_differential_routes",
    "register_network_routes",
    "register_cloud_routes",
    "register_identity_saas_routes",
    "register_artifact_routes",
    "register_purple_routes",
    "register_human_simulation_routes",
    "register_agent_tool_routes",
    "register_agent_runtime_routes",
    "register_workbench_routes",
    "register_finding_operations_routes",
    "register_nuclei_routes",
    "register_campaign_routes",
    "register_evidence_routes",
    "register_finding_routes",
    "register_secret_routes",
)
