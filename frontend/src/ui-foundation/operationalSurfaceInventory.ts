import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";

export const OPERATIONAL_SURFACE_INVENTORY_VERSION = UI_FOUNDATION_CONTRACT_VERSION;

export type OperationalSurface = {
  readonly id: string;
  readonly path: string;
  readonly currentLabel: string;
  readonly group:
    | "command-center"
    | "campaigns"
    | "assets-assessments"
    | "findings-evidence"
    | "approvals-governance"
    | "platform"
    | null;
  readonly disposition: "migrate" | "redirect" | "merge" | "development-only";
  readonly visibility: "production" | "development";
  readonly targetRegion: "primary-navigation" | "development-diagnostics";
  readonly futureDestination: string;
  readonly pageModule: string;
  readonly actions: readonly string[];
  readonly apiDependencies: readonly string[];
  readonly formInputs: readonly string[];
  readonly requiredStates: readonly string[];
  readonly responsiveBehavior: readonly string[];
  readonly parityTests: readonly string[];
  readonly coverage: "dedicated" | "shared" | "gap";
  readonly gapOwner: "compat_127" | "compat_128" | null;
};

const BASE_STATES = ["loading", "ready", "empty", "error", "denied"] as const;
const RESPONSIVE_BEHAVIOR = [
  "desktop-sidebar",
  "tablet-rail",
  "mobile-modal-drawer",
  "no-page-horizontal-overflow",
] as const;

type SurfaceInput = Omit<
  OperationalSurface,
  "requiredStates" | "responsiveBehavior" | "gapOwner"
> & {
  readonly requiredStates?: readonly string[];
  readonly responsiveBehavior?: readonly string[];
  readonly gapOwner?: OperationalSurface["gapOwner"];
};

function surface(input: SurfaceInput): OperationalSurface {
  return {
    ...input,
    requiredStates: [...BASE_STATES, ...(input.requiredStates ?? [])],
    responsiveBehavior: input.responsiveBehavior ?? RESPONSIVE_BEHAVIOR,
    gapOwner: input.gapOwner ?? null,
  };
}

export const OPERATIONAL_SURFACE_INVENTORY: readonly OperationalSurface[] = [
  surface({
    id: "overview",
    path: "/",
    currentLabel: "Overview",
    group: "command-center",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/",
    pageModule: "App.Overview",
    actions: ["view-authority-state", "open-engagement-management"],
    apiDependencies: ["getContext", "listEngagements"],
    formInputs: [],
    requiredStates: ["attention-required", "safety-context-unavailable"],
    parityTests: ["frontend/src/App.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "shared",
  }),
  surface({
    id: "engagements",
    path: "/engagements",
    currentLabel: "Engagements",
    group: "campaigns",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/engagements",
    pageModule: "features/residual/command/EngagementsPage",
    actions: ["create-engagement", "select-engagement", "create-target", "create-roe-version", "approve-roe-version"],
    apiDependencies: ["approveRoeVersion", "createEngagement", "createRoeVersion", "createTarget", "listEngagementsPage", "listRoeVersions", "listTargets"],
    formInputs: ["name", "normalized_value", "objective", "request_budget", "target_type"],
    requiredStates: ["roe-awaiting-approval", "roe-approved", "target-needs-review"],
    parityTests: ["frontend/src/App.workflows.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "shared",
  }),
  surface({
    id: "jobs",
    path: "/jobs",
    currentLabel: "Jobs",
    group: "campaigns",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/jobs",
    pageModule: "features/residual/command/JobsPage",
    actions: ["create-job", "approve-job", "pause-job", "resume-job", "retry-job", "cancel-job", "emergency-stop", "request-containment", "approve-containment", "recover-containment"],
    apiDependencies: ["approveContainmentControl", "commandJob", "createJob", "emergencyStopJob", "getJobContainment", "getQuotaStatus", "listContainmentControls", "listEngagementsPage", "listJobsPage", "listRoeVersions", "recoverContainmentControl", "requestContainmentControl"],
    formInputs: ["capability", "reason", "scope_kind"],
    requiredStates: ["awaiting-approval", "running", "paused", "failed", "cancelled", "stop-requested", "containment-incomplete", "cleanup-incomplete", "quota-denied"],
    parityTests: ["frontend/src/JobsPage.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "agent-kernel",
    path: "/agent",
    currentLabel: "Agent kernel",
    group: "campaigns",
    disposition: "merge",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/campaigns/:campaignId/agent",
    pageModule: "features/residual/supervision/AgentKernelPage.AgentKernelPage",
    actions: ["review-proposal", "approve-proposal", "cancel-agent-run", "inspect-certified-tools"],
    apiDependencies: ["approveAgentProposal", "cancelAgentRun", "getAgentDashboard", "listAgentTools"],
    formInputs: [],
    requiredStates: ["awaiting-approval", "approved", "cancel-requested", "budget-denied", "tool-ineligible"],
    parityTests: ["frontend/src/App.agent-kernel.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "campaign-workbench",
    path: "/workbench",
    currentLabel: "Campaign workbench",
    group: "campaigns",
    disposition: "merge",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/campaigns/:campaignId/workbench",
    pageModule: "features/residual/supervision/WorkbenchPage.WorkbenchPage",
    actions: ["create-draft", "review-draft", "create-successor", "freeze-mcp-server"],
    apiDependencies: ["createWorkbenchDraft", "createWorkbenchSuccessor", "freezeMcpServer", "getWorkbenchDashboard", "reviewWorkbenchDraft"],
    formInputs: [],
    requiredStates: ["draft", "awaiting-review", "approved", "superseded", "server-frozen"],
    parityTests: ["frontend/src/App.workbench.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "zap-runtime",
    path: "/zap",
    currentLabel: "ZAP runtime",
    group: "assets-assessments",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/zap",
    pageModule: "features/residual/assessment/ZapPage.ZapPage",
    actions: ["compile-plan", "queue-run", "cancel-and-contain", "refresh"],
    apiDependencies: ["cancelZapRun", "compileZapPlan", "createZapRun", "getZapDashboard", "listJobsPage", "listPolicyDecisionsPage", "listSecretReferencesPage", "listZapProfiles"],
    formInputs: ["credential_binding", "job_binding", "plan_binding", "policy_binding", "profile_binding", "runner_binding", "target_binding"],
    requiredStates: ["compiled", "queued", "running", "cancel-requested", "cleanup-incomplete", "containment-denied", "quota-denied"],
    parityTests: ["frontend/src/App.zap.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "nuclei-runtime",
    path: "/nuclei",
    currentLabel: "Nuclei runtime",
    group: "assets-assessments",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/nuclei",
    pageModule: "features/residual/assessment/NucleiPage.NucleiPage",
    actions: ["compile-plan", "queue-run", "cancel-and-contain", "review-findings", "refresh"],
    apiDependencies: ["cancelNucleiRun", "compileNucleiPlan", "createNucleiRun", "getNucleiDashboard", "listNucleiProfiles", "listPolicyDecisionsPage"],
    formInputs: ["job_binding", "plan_binding", "policy_binding", "profile_binding", "runner_binding", "target_binding"],
    requiredStates: ["compiled", "queued", "running", "cancel-requested", "cleanup-incomplete", "containment-denied", "quota-denied"],
    parityTests: ["frontend/src/App.nuclei.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "api-differential",
    path: "/api-differential",
    currentLabel: "API authorization",
    group: "assets-assessments",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/api-differential",
    pageModule: "features/residual/assessment/ApiDifferentialPage.ApiDifferentialPage",
    actions: ["compile-plan", "queue-run", "cancel-and-contain", "review-observations", "review-replay", "refresh"],
    apiDependencies: ["cancelApiDifferentialRun", "compileApiDifferentialPlan", "createApiDifferentialRun", "getApiDifferentialDashboard", "listApiDifferentialProfiles", "listPolicyDecisionsPage"],
    formInputs: ["job_binding", "plan_binding", "policy_binding", "profile_binding", "runner_binding", "seed", "target_binding"],
    requiredStates: ["compiled", "queued", "running", "cancel-requested", "cleanup-incomplete", "containment-denied", "quota-denied"],
    parityTests: ["frontend/src/App.api-differential.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "network-assessment",
    path: "/network-assessment",
    currentLabel: "Network assessment",
    group: "assets-assessments",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/network-assessment",
    pageModule: "features/residual/assessment/NetworkAssessmentPage.NetworkAssessmentPage",
    actions: ["compile-plan", "queue-run", "block-gateway-and-cancel", "review-observations", "refresh"],
    apiDependencies: ["cancelNetworkRun", "compileNetworkPlan", "createNetworkRun", "getNetworkDashboard", "listNetworkProfiles", "listPolicyDecisionsPage"],
    formInputs: ["job_binding", "plan_binding", "policy_binding", "profile_binding", "reservation_binding", "runner_binding", "target_binding"],
    requiredStates: ["compiled", "queued", "running", "cancel-requested", "cleanup-failed", "uncertain-observation"],
    parityTests: ["frontend/src/App.network-assessment.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "cloud-posture",
    path: "/cloud-posture",
    currentLabel: "Cloud posture",
    group: "assets-assessments",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/cloud-posture",
    pageModule: "features/residual/assessment/CloudPosturePage.CloudPosturePage",
    actions: ["compile-plan", "queue-run", "revoke-lease-and-cancel", "review-posture-results", "refresh"],
    apiDependencies: ["cancelCloudRun", "compileCloudPlan", "createCloudRun", "getCloudDashboard", "listCloudProfiles", "listPolicyDecisionsPage"],
    formInputs: ["identity_binding", "job_binding", "lease_binding", "plan_binding", "policy_binding", "profile_binding", "reservation_binding", "runner_binding"],
    requiredStates: ["compiled", "queued", "running", "partial", "cancel-requested", "lease-revoked", "cleanup-incomplete"],
    parityTests: ["frontend/src/App.cloud-posture.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "identity-posture",
    path: "/identity-posture",
    currentLabel: "Identity posture",
    group: "assets-assessments",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/identity-posture",
    pageModule: "features/residual/assessment/IdentityPosturePage.IdentityPosturePage",
    actions: ["compile-plan", "queue-run", "revoke-lease-and-cancel", "review-identity-results", "refresh"],
    apiDependencies: ["cancelIdentitySaasRun", "compileIdentitySaasPlan", "createIdentitySaasRun", "getIdentitySaasDashboard", "listIdentitySaasProfiles", "listPolicyDecisionsPage"],
    formInputs: ["job_binding", "lease_binding", "plan_binding", "policy_binding", "profile_binding", "reservation_binding", "runner_binding", "tenant_binding"],
    requiredStates: ["compiled", "queued", "running", "partial", "cancel-requested", "lease-revoked", "cleanup-incomplete"],
    parityTests: ["frontend/src/App.identity-posture.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "artifact-posture",
    path: "/artifact-posture",
    currentLabel: "Artifact posture",
    group: "assets-assessments",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/artifact-posture",
    pageModule: "features/residual/assessment/ArtifactPosturePage.ArtifactPosturePage",
    actions: ["compile-plan", "queue-run", "cancel-and-clean", "review-artifact-results", "refresh"],
    apiDependencies: ["cancelArtifactRun", "compileArtifactPlan", "createArtifactRun", "getArtifactDashboard", "listArtifactProfiles", "listPolicyDecisionsPage"],
    formInputs: ["artifact_binding", "job_binding", "plan_binding", "policy_binding", "profile_binding", "reservation_binding", "runner_binding"],
    requiredStates: ["compiled", "queued", "running", "partial", "cancel-requested", "cleanup-incomplete"],
    parityTests: ["frontend/src/App.artifact-posture.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "purple-lab",
    path: "/purple-lab",
    currentLabel: "Purple lab",
    group: "assets-assessments",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/purple-lab",
    pageModule: "features/residual/assessment/PurpleLabPage.PurpleLabPage",
    actions: ["compile-plan", "queue-run", "kill-run", "review-detections", "verify-teardown", "refresh"],
    apiDependencies: ["compilePurplePlan", "createPurpleRun", "getPurpleDashboard", "killPurpleRun", "listPolicyDecisionsPage", "listPurpleAbilities"],
    formInputs: ["ability_binding", "approval_binding", "job_binding", "lab_binding", "plan_binding", "policy_binding", "reservation_binding", "runner_binding"],
    requiredStates: ["awaiting-approval", "queued", "running", "kill-requested", "dispatch-blocked", "cleanup-incomplete", "teardown-incomplete"],
    parityTests: ["frontend/src/App.purple-lab.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "human-simulation",
    path: "/human-simulation",
    currentLabel: "Human simulation",
    group: "assets-assessments",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/human-simulation",
    pageModule: "features/residual/assessment/HumanSimulationPage.HumanSimulationPage",
    actions: ["compile-sink-plan", "queue-sink-rehearsal", "block-delivery-and-stop", "verify-deletion", "refresh"],
    apiDependencies: ["compileHumanSimulationPlan", "createHumanSimulationRun", "getHumanSimulationDashboard", "listHumanSimulationCampaigns", "listPolicyDecisionsPage", "stopHumanSimulationRun"],
    formInputs: ["approval_binding", "campaign_binding", "job_binding", "plan_binding", "policy_binding", "reservation_binding", "runner_binding"],
    requiredStates: ["awaiting-approval", "queued", "running", "stop-requested", "delivery-blocked", "deletion-pending", "deleted"],
    parityTests: ["frontend/src/App.human-simulation.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "evidence",
    path: "/evidence",
    currentLabel: "Evidence",
    group: "findings-evidence",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/evidence",
    pageModule: "features/residual/trust/EvidencePage",
    actions: ["register-synthetic-evidence", "select-evidence", "verify-evidence", "derive-evidence", "place-legal-hold"],
    apiDependencies: ["deriveEvidence", "getEvidence", "listEvidencePage", "listJobsPage", "placeEvidenceLegalHold", "registerSyntheticEvidence", "selectEvidence", "verifyEvidence"],
    formInputs: ["artifact_class", "fixture_kind", "job_binding", "selection_purpose"],
    requiredStates: ["verification-failed", "verification-passed", "legal-hold", "retention-active", "evidence-outage"],
    parityTests: ["frontend/src/App.evidence.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "finding-operations",
    path: "/finding-operations",
    currentLabel: "Findings and remediation",
    group: "findings-evidence",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/finding-operations",
    pageModule: "features/residual/trust/FindingOperationsPage",
    actions: ["import-synthetic-fixture", "review-issue", "create-report", "publish-report", "queue-delivery", "refresh"],
    apiDependencies: ["createFindingReport", "getFindingOperationsDashboard", "importFindingFixture", "listEvidencePage", "publishFindingReport", "queueFindingDelivery", "reviewFindingIssue"],
    formInputs: ["evidence_binding", "query"],
    requiredStates: ["open", "under-review", "remediation-pending", "retest-pending", "delivery-failed", "published"],
    parityTests: ["frontend/src/App.finding-operations.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "access",
    path: "/access",
    currentLabel: "Access",
    group: "approvals-governance",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/access",
    pageModule: "features/residual/command/AccessPage",
    actions: ["request-jit", "review-jit", "approve-jit", "revoke-jit"],
    apiDependencies: ["approveJitGrant", "listEngagementsPage", "listJitGrantsPage", "requestJitGrant", "reviewJitGrant", "revokeJitGrant"],
    formInputs: ["permission", "reason", "scope_id"],
    requiredStates: ["pending-approval", "active", "expired", "revoked", "separation-of-duties-denied"],
    parityTests: ["frontend/src/App.workflows.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "shared",
  }),
  surface({
    id: "policy",
    path: "/policy",
    currentLabel: "Policy",
    group: "approvals-governance",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/policy",
    pageModule: "features/residual/command/PolicyPage",
    actions: ["simulate-policy", "promote-policy", "rollback-policy", "review-decisions"],
    apiDependencies: ["getPolicyStatus", "listPolicyBundlesPage", "listPolicyDecisionsPage", "promotePolicy", "rollbackPolicy", "simulatePolicy"],
    formInputs: ["fixture", "reason", "revision"],
    requiredStates: ["simulation-denied", "promotion-pending", "promoted", "rollback-required", "policy-unavailable"],
    parityTests: ["frontend/src/App.policy.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "credential-leases",
    path: "/secrets",
    currentLabel: "Credential leases",
    group: "approvals-governance",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/secrets",
    pageModule: "features/residual/trust/SecretsPage",
    actions: ["issue-synthetic-lease", "revoke-lease", "review-reference"],
    apiDependencies: ["issueSyntheticSecretLease", "listJobsPage", "listSecretLeasesPage", "listSecretReferencesPage", "revokeSecretLease"],
    formInputs: ["job_binding", "ttl_seconds"],
    requiredStates: ["active", "expired", "revoked", "lease-denied", "secret-unavailable"],
    parityTests: ["frontend/src/App.secrets.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "activity",
    path: "/activity",
    currentLabel: "Activity",
    group: "approvals-governance",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/activity",
    pageModule: "features/residual/trust/ActivityPage",
    actions: ["review-audit-activity"],
    apiDependencies: ["listActivityPage"],
    formInputs: [],
    requiredStates: ["audit-unavailable", "redacted"],
    parityTests: ["frontend/src/App.activity.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "runners",
    path: "/runners",
    currentLabel: "Runners",
    group: "platform",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/runners",
    pageModule: "features/residual/trust/RunnersPage",
    actions: ["review-runner-status", "review-registrations", "review-executions", "review-manifests"],
    apiDependencies: ["getRunnerStatus", "listRunnerExecutionsPage", "listRunnerManifestsPage", "listRunnerRegistrationsPage"],
    formInputs: [],
    requiredStates: ["ready", "unhealthy", "registration-denied", "execution-failed", "cleanup-incomplete"],
    parityTests: ["frontend/src/App.runners.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "observability",
    path: "/observability",
    currentLabel: "Observability",
    group: "platform",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/observability",
    pageModule: "features/residual/trust/ObservabilityPage",
    actions: ["lookup-correlation", "review-incidents", "apply-incident-action", "review-timeline", "review-runbooks", "refresh"],
    apiDependencies: ["applyIncidentAction", "getIncidentTimeline", "getObservabilityDashboard", "listIncidentRunbooks", "listIncidentsPage", "lookupCorrelationPage"],
    formInputs: ["correlation_id"],
    requiredStates: ["incident-open", "acknowledged", "evidence-preserved", "contained", "recovered", "closed"],
    parityTests: ["frontend/src/App.observability.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
  surface({
    id: "safe-lab",
    path: "/lab",
    currentLabel: "Safe lab",
    group: "platform",
    disposition: "migrate",
    visibility: "production",
    targetRegion: "primary-navigation",
    futureDestination: "/lab",
    pageModule: "features/residual/trust/LabPage",
    actions: ["review-lab-bundle", "review-scenarios", "review-measurements", "open-emergency-stop-controls", "refresh"],
    apiDependencies: ["getLabDashboard"],
    formInputs: [],
    requiredStates: ["bundle-missing", "scenario-failed", "measurement-missing", "qualification-ready"],
    parityTests: ["frontend/src/App.lab.test.tsx", "tests/e2e/operational-console.spec.js"],
    coverage: "dedicated",
  }),
];

export function validateOperationalSurfaceInventory(
  inventory: readonly OperationalSurface[],
): string[] {
  const issues: string[] = [];
  const paths = new Set<string>();
  const ids = new Set<string>();

  for (const item of inventory) {
    if (paths.has(item.path)) issues.push(`duplicate path: ${item.path}`);
    if (ids.has(item.id)) issues.push(`duplicate id: ${item.id}`);
    paths.add(item.path);
    ids.add(item.id);

    if (item.actions.length === 0) issues.push(`${item.path} actions must not be empty`);
    if (item.requiredStates.length === 0) issues.push(`${item.path} requiredStates must not be empty`);
    if (item.responsiveBehavior.length === 0) issues.push(`${item.path} responsiveBehavior must not be empty`);
    if (item.parityTests.length === 0) issues.push(`${item.path} parityTests must not be empty`);

    for (const state of BASE_STATES) {
      if (!item.requiredStates.includes(state)) issues.push(`${item.path} requiredStates missing ${state}`);
    }

    if (item.visibility === "production") {
      if (item.group === null) issues.push(`${item.path} production group must not be null`);
      if (item.targetRegion !== "primary-navigation") {
        issues.push(`${item.path} production targetRegion must be primary-navigation`);
      }
      if (item.apiDependencies.length === 0) {
        issues.push(`${item.path} apiDependencies must not be empty`);
      }
    }

    if (item.coverage === "gap" && item.gapOwner === null) {
      issues.push(`${item.path} coverage gap must have an owner`);
    }
  }

  return issues;
}
