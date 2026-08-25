import type { ComponentType } from "react";


export type RouteGroup =
  | "command-center"
  | "campaigns"
  | "assets-assessments"
  | "findings-evidence"
  | "approvals-governance"
  | "platform";

export type RouteFeatureState = "enabled" | "conditional" | "development";
export type RouteVisibility = "production" | "development";
export type ApplicationRouteId =
  | "overview" | "engagements" | "campaigns" | "campaign-attention" | "campaign-new"
  | "jobs" | "agent-kernel" | "workbench" | "zap" | "nuclei" | "api-differential"
  | "network-assessment" | "cloud-posture" | "identity-posture" | "artifact-posture"
  | "purple-lab" | "human-simulation" | "evidence" | "finding-operations" | "access"
  | "policy" | "credential-leases" | "activity" | "runners" | "observability"
  | "safe-lab";

export type RouteAvailability = {
  readonly campaignCreateEnabled: boolean;
};

export type RoutePageModule = {
  default: ComponentType;
};

export type ApplicationRoute = {
  readonly id: ApplicationRouteId;
  readonly path: string;
  readonly title: string;
  readonly navigationLabel: string;
  readonly group: RouteGroup | null;
  readonly breadcrumb: readonly string[];
  readonly featureState: RouteFeatureState;
  readonly visibility: RouteVisibility;
  readonly requiredPermission: string | null;
  readonly load: () => Promise<RoutePageModule>;
};

export const ROUTE_GROUP_LABELS: Readonly<Record<RouteGroup, string>> = {
  "command-center": "Command Center",
  campaigns: "Campaigns",
  "assets-assessments": "Assets & Assessments",
  "findings-evidence": "Findings & Evidence",
  "approvals-governance": "Approvals & Governance",
  platform: "Platform",
};

type RouteAdapterName = keyof typeof import("./RoutePage");

const ROUTE_ADAPTERS: Readonly<Record<ApplicationRouteId, RouteAdapterName>> = {
  overview: "OverviewRoute",
  engagements: "EngagementsRoute",
  campaigns: "CampaignsRoute",
  "campaign-attention": "CampaignAttentionRoute",
  "campaign-new": "CampaignNewRoute",
  jobs: "JobsRoute",
  "agent-kernel": "AgentKernelRoute",
  workbench: "WorkbenchRoute",
  zap: "ZapRoute",
  nuclei: "NucleiRoute",
  "api-differential": "ApiDifferentialRoute",
  "network-assessment": "NetworkAssessmentRoute",
  "cloud-posture": "CloudPostureRoute",
  "identity-posture": "IdentityPostureRoute",
  "artifact-posture": "ArtifactPostureRoute",
  "purple-lab": "PurpleLabRoute",
  "human-simulation": "HumanSimulationRoute",
  evidence: "EvidenceRoute",
  "finding-operations": "FindingOperationsRoute",
  access: "AccessRoute",
  policy: "PolicyRoute",
  "credential-leases": "SecretsRoute",
  activity: "ActivityRoute",
  runners: "RunnersRoute",
  observability: "ObservabilityRoute",
  "safe-lab": "LabRoute",
};

function route(
  id: ApplicationRouteId,
  path: string,
  title: string,
  navigationLabel: string,
  group: RouteGroup | null,
  requiredPermission: string | null,
  featureState: RouteFeatureState = "enabled",
  visibility: RouteVisibility = "production",
): ApplicationRoute {
  const adapter = ROUTE_ADAPTERS[id];
  if (adapter === undefined) throw new Error(`route adapter missing: ${id}`);
  return {
    id,
    path,
    title,
    navigationLabel,
    group,
    breadcrumb: group === null ? [title] : [ROUTE_GROUP_LABELS[group], title],
    featureState,
    visibility,
    requiredPermission,
    load: async () => {
      const module = await import("./RoutePage");
      return { default: module[adapter] };
    },
  };
}

export const APPLICATION_ROUTES: readonly ApplicationRoute[] = [
  route("overview", "/", "Overview", "Overview", "command-center", null),
  route("engagements", "/engagements", "Engagements", "Engagements", "campaigns", "engagement:read"),
  route("campaigns", "/campaigns", "Campaigns", "Campaigns", "campaigns", "campaign:read"),
  route("campaign-attention", "/campaigns/attention", "Campaign attention", "Campaign attention", "campaigns", "campaign:read"),
  route("campaign-new", "/campaigns/new", "New campaign", "New campaign", "campaigns", "campaign:read", "conditional"),
  route("jobs", "/jobs", "Jobs", "Jobs", "campaigns", "job:read"),
  route("agent-kernel", "/agent", "Agent kernel", "Agent kernel", "campaigns", "agent:read"),
  route("workbench", "/workbench", "Campaign workbench", "Campaign workbench", "campaigns", "workbench:read"),
  route("zap", "/zap", "ZAP runtime", "ZAP runtime", "assets-assessments", "zap:read"),
  route("nuclei", "/nuclei", "Nuclei runtime", "Nuclei runtime", "assets-assessments", "nuclei:read"),
  route("api-differential", "/api-differential", "API authorization", "API authorization", "assets-assessments", "api-differential:read"),
  route("network-assessment", "/network-assessment", "Network assessment", "Network assessment", "assets-assessments", "network:read"),
  route("cloud-posture", "/cloud-posture", "Cloud posture", "Cloud posture", "assets-assessments", "cloud:read"),
  route("identity-posture", "/identity-posture", "Identity posture", "Identity posture", "assets-assessments", "identity-saas:read"),
  route("artifact-posture", "/artifact-posture", "Artifact posture", "Artifact posture", "assets-assessments", "artifact:read"),
  route("purple-lab", "/purple-lab", "Purple lab", "Purple lab", "assets-assessments", "purple:read"),
  route("human-simulation", "/human-simulation", "Human simulation", "Human simulation", "assets-assessments", "human-simulation:read"),
  route("evidence", "/evidence", "Evidence", "Evidence", "findings-evidence", "evidence:read"),
  route("finding-operations", "/finding-operations", "Findings and remediation", "Findings and remediation", "findings-evidence", "finding:read"),
  route("access", "/access", "Access", "Access", "approvals-governance", "jit:read"),
  route("policy", "/policy", "Policy", "Policy", "approvals-governance", "policy:read"),
  route("credential-leases", "/secrets", "Credential leases", "Credential leases", "approvals-governance", "secret:read"),
  route("activity", "/activity", "Activity", "Activity", "approvals-governance", "audit:read"),
  route("runners", "/runners", "Runners", "Runners", "platform", "runner:read"),
  route("observability", "/observability", "Observability", "Observability", "platform", "observability:read"),
  route("safe-lab", "/lab", "Safe lab", "Safe lab", "platform", "lab:read"),
] as const;

export function validateRouteRegistry(routes: readonly ApplicationRoute[]): string[] {
  const issues: string[] = [];
  const ids = new Set<string>();
  const paths = new Set<string>();
  for (const item of routes) {
    if (ids.has(item.id)) issues.push(`duplicate route id: ${item.id}`);
    if (paths.has(item.path)) issues.push(`duplicate route path: ${item.path}`);
    ids.add(item.id);
    paths.add(item.path);
    if (!item.title.trim()) issues.push(`${item.path} title is required`);
    if (item.breadcrumb.length === 0) issues.push(`${item.path} breadcrumb is required`);
    if (item.visibility === "production" && item.group === null) {
      issues.push(`${item.path} production group is required`);
    }
    if (!isLiteralPath(item.path)) issues.push(`${item.path} is not a safe literal path`);
  }
  return issues;
}

export function isSafeApplicationPath(candidate: string): boolean {
  return isLiteralPath(candidate) && APPLICATION_ROUTES.some(({ path }) => path === candidate);
}

export function routeForPath(path: string): ApplicationRoute | null {
  if (!isSafeApplicationPath(path)) return null;
  return APPLICATION_ROUTES.find((routeDefinition) => routeDefinition.path === path) ?? null;
}

export function commandRoutesForPermissions(
  routes: readonly ApplicationRoute[],
  permissions: readonly string[],
  query: string,
  limit: number,
  availability: RouteAvailability = { campaignCreateEnabled: true },
): ApplicationRoute[] {
  const normalizedQuery = query.trim().toLocaleLowerCase();
  const boundedLimit = Math.max(0, Math.min(50, Math.trunc(limit)));
  return orientationRoutesForPermissions(routes, permissions, availability).filter((item) => {
    if (!normalizedQuery) return true;
    return `${item.title} ${item.navigationLabel} ${item.breadcrumb.join(" ")}`
      .toLocaleLowerCase()
      .includes(normalizedQuery);
  }).slice(0, boundedLimit);
}

export function orientationRoutesForPermissions(
  routes: readonly ApplicationRoute[],
  permissions: readonly string[],
  availability: RouteAvailability = { campaignCreateEnabled: true },
): ApplicationRoute[] {
  const wildcard = permissions.includes("*");
  return routes.filter((item) => {
    if (item.visibility !== "production") return false;
    if (item.id === "campaign-new" && !availability.campaignCreateEnabled) return false;
    return wildcard || item.requiredPermission === null || permissions.includes(item.requiredPermission);
  });
}

function isLiteralPath(candidate: string): boolean {
  return candidate === "/" || (
    candidate.startsWith("/")
    && !candidate.startsWith("//")
    && !candidate.includes("\\")
    && !candidate.includes("?")
    && !candidate.includes("#")
    && !candidate.split("/").some((segment) => segment === "." || segment === "..")
    && /^\/[A-Za-z0-9/_-]+$/.test(candidate)
  );
}
