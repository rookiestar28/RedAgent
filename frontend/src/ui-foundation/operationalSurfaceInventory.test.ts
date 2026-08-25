import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import {
  OPERATIONAL_SURFACE_INVENTORY,
  OPERATIONAL_SURFACE_INVENTORY_VERSION,
  validateOperationalSurfaceInventory,
} from "./operationalSurfaceInventory";
import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";
import { APPLICATION_ROUTES } from "../shell/routeRegistry";

const EXPECTED_CURRENT_PATHS = [
  "/",
  "/access",
  "/activity",
  "/agent",
  "/api-differential",
  "/artifact-posture",
  "/cloud-posture",
  "/engagements",
  "/evidence",
  "/finding-operations",
  "/human-simulation",
  "/identity-posture",
  "/jobs",
  "/lab",
  "/network-assessment",
  "/nuclei",
  "/observability",
  "/policy",
  "/purple-lab",
  "/runners",
  "/secrets",
  "/workbench",
  "/zap",
] as const;

describe("compat_126 operational surface inventory", () => {
  it("uses the shared versioned UI foundation contract", () => {
    expect(OPERATIONAL_SURFACE_INVENTORY_VERSION).toBe(UI_FOUNDATION_CONTRACT_VERSION);
  });

  it("maps the exact 23 production entry routes once", () => {
    expect(OPERATIONAL_SURFACE_INVENTORY.map(({ path }) => path).sort()).toEqual(
      [...EXPECTED_CURRENT_PATHS],
    );
  });

  it("stays bound to the current typed route registry", () => {
    const currentPaths = APPLICATION_ROUTES.map(({ path }) => path).sort();

    const r124CampaignPaths = currentPaths.filter((path) => path.startsWith("/campaigns"));
    expect(r124CampaignPaths).toEqual(["/campaigns", "/campaigns/attention", "/campaigns/new"]);
    expect(currentPaths.filter((path) => !path.startsWith("/campaigns")))
      .toEqual([...EXPECTED_CURRENT_PATHS]);
  });

  it("keeps every operational page outside the deleted page monolith", () => {
    expect(existsSync(resolve(process.cwd(), "frontend/src/OperationalPages.tsx"))).toBe(false);
    expect(OPERATIONAL_SURFACE_INVENTORY.every(({ pageModule }) => !pageModule.startsWith("OperationalPages.")))
      .toBe(true);
  });

  it("replaces the no-op overview control with bounded engagement navigation", () => {
    const appSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    const overviewBlock = appSource.match(/function Overview\([\s\S]*?\n}\n/)?.[0] ?? "";
    expect(overviewBlock).not.toContain('<button type="button">Create engagement</button>');
    expect(overviewBlock).toContain('<RouteLink className="button-link"');
    expect(overviewBlock).toContain('path="/engagements"');
    expect(overviewBlock).not.toContain("client.createEngagement");

    const overview = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "overview");
    expect(overview?.actions).toEqual(["view-authority-state", "open-engagement-management"]);
    expect(overview?.apiDependencies).not.toContain("createEngagement");
  });

  it("binds Access to authoritative focused-module JIT governance", () => {
    const access = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "access");
    expect(access).toMatchObject({
      pageModule: "features/residual/command/AccessPage",
      actions: ["request-jit", "review-jit", "approve-jit", "revoke-jit"],
      apiDependencies: [
        "approveJitGrant",
        "listEngagementsPage",
        "listJitGrantsPage",
        "requestJitGrant",
        "reviewJitGrant",
        "revokeJitGrant",
      ],
      formInputs: ["permission", "reason", "scope_id"],
      requiredStates: [
        "loading",
        "ready",
        "empty",
        "error",
        "denied",
        "pending-approval",
        "active",
        "expired",
        "revoked",
        "separation-of-duties-denied",
      ],
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { AccessPage } from "../features/residual/command/AccessPage";');
    expect(routeSource).toContain("return <AccessPage client={client} context={context} />;");
  });

  it("binds Policy to authoritative focused-module lifecycle governance", () => {
    const policy = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "policy");
    expect(policy).toMatchObject({
      pageModule: "features/residual/command/PolicyPage",
      actions: ["simulate-policy", "promote-policy", "rollback-policy", "review-decisions"],
      apiDependencies: [
        "getPolicyStatus",
        "listPolicyBundlesPage",
        "listPolicyDecisionsPage",
        "promotePolicy",
        "rollbackPolicy",
        "simulatePolicy",
      ],
      formInputs: ["fixture", "reason", "revision"],
      requiredStates: [
        "loading",
        "ready",
        "empty",
        "error",
        "denied",
        "simulation-denied",
        "promotion-pending",
        "promoted",
        "rollback-required",
        "policy-unavailable",
      ],
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { PolicyPage } from "../features/residual/command/PolicyPage";');
    expect(routeSource).toContain("return <PolicyPage client={client} context={context} />;");
  });

  it("binds Activity to the focused redacted audit projection", () => {
    const activity = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "activity");
    expect(activity).toMatchObject({
      pageModule: "features/residual/trust/ActivityPage",
      actions: ["review-audit-activity"],
      apiDependencies: ["listActivityPage"],
      formInputs: [],
      requiredStates: ["loading", "ready", "empty", "error", "denied", "audit-unavailable", "redacted"],
      coverage: "dedicated",
    });
    expect(activity?.gapOwner).toBeNull();
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { ActivityPage } from "../features/residual/trust/ActivityPage";');
    expect(routeSource).toContain("return <ActivityPage client={client} context={context} />;");
  });

  it("binds Runners to focused metadata-only platform inventory", () => {
    const runners = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "runners");
    expect(runners).toMatchObject({
      pageModule: "features/residual/trust/RunnersPage",
      actions: ["review-runner-status", "review-registrations", "review-executions", "review-manifests"],
      apiDependencies: [
        "getRunnerStatus",
        "listRunnerExecutionsPage",
        "listRunnerManifestsPage",
        "listRunnerRegistrationsPage",
      ],
      formInputs: [],
      requiredStates: [
        "loading", "ready", "empty", "error", "denied", "ready", "unhealthy",
        "registration-denied", "execution-failed", "cleanup-incomplete",
      ],
      coverage: "dedicated",
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { RunnersPage } from "../features/residual/trust/RunnersPage";');
    expect(routeSource).toContain("return <RunnersPage client={client} context={context} />;");
  });

  it("binds Safe Lab to focused read-only qualification evidence", () => {
    const lab = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "safe-lab");
    expect(lab).toMatchObject({
      pageModule: "features/residual/trust/LabPage",
      actions: ["review-lab-bundle", "review-scenarios", "review-measurements", "open-emergency-stop-controls", "refresh"],
      apiDependencies: ["getLabDashboard"],
      formInputs: [],
      requiredStates: [
        "loading", "ready", "empty", "error", "denied", "bundle-missing",
        "scenario-failed", "measurement-missing", "qualification-ready",
      ],
      coverage: "dedicated",
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { LabPage } from "../features/residual/trust/LabPage";');
    expect(routeSource).toContain("return <LabPage client={client} context={context} />;");
  });

  it("binds Observability to focused incident and correlation governance", () => {
    const observability = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "observability");
    expect(observability).toMatchObject({
      pageModule: "features/residual/trust/ObservabilityPage",
      actions: ["lookup-correlation", "review-incidents", "apply-incident-action", "review-timeline", "review-runbooks", "refresh"],
      apiDependencies: [
        "applyIncidentAction", "getIncidentTimeline", "getObservabilityDashboard",
        "listIncidentRunbooks", "listIncidentsPage", "lookupCorrelationPage",
      ],
      formInputs: ["correlation_id"],
      requiredStates: [
        "loading", "ready", "empty", "error", "denied", "incident-open",
        "acknowledged", "evidence-preserved", "contained", "recovered", "closed",
      ],
      coverage: "dedicated",
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { ObservabilityPage } from "../features/residual/trust/ObservabilityPage";');
    expect(routeSource).toContain("return <ObservabilityPage client={client} context={context} />;");
  });

  it("binds Evidence to focused custody workflows without transcribed identifiers", () => {
    const evidence = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "evidence");
    expect(evidence).toMatchObject({
      pageModule: "features/residual/trust/EvidencePage",
      actions: ["register-synthetic-evidence", "select-evidence", "verify-evidence", "derive-evidence", "place-legal-hold"],
      apiDependencies: [
        "deriveEvidence", "getEvidence", "listEvidencePage", "listJobsPage",
        "placeEvidenceLegalHold", "registerSyntheticEvidence", "selectEvidence", "verifyEvidence",
      ],
      formInputs: ["artifact_class", "fixture_kind", "job_binding", "selection_purpose"],
      requiredStates: [
        "loading", "ready", "empty", "error", "denied", "verification-failed",
        "verification-passed", "legal-hold", "retention-active", "evidence-outage",
      ],
      coverage: "dedicated",
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { EvidencePage } from "../features/residual/trust/EvidencePage";');
    expect(routeSource).toContain("return <EvidencePage client={client} context={context} />;");
  });

  it("binds Finding Operations to focused fixture-only reviewed workflows", () => {
    const findings = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "finding-operations");
    expect(findings).toMatchObject({
      pageModule: "features/residual/trust/FindingOperationsPage",
      actions: ["import-synthetic-fixture", "review-issue", "create-report", "publish-report", "queue-delivery", "refresh"],
      apiDependencies: [
        "createFindingReport", "getFindingOperationsDashboard", "importFindingFixture",
        "listEvidencePage", "publishFindingReport", "queueFindingDelivery", "reviewFindingIssue",
      ],
      formInputs: ["evidence_binding", "query"],
      requiredStates: [
        "loading", "ready", "empty", "error", "denied", "open", "under-review",
        "remediation-pending", "retest-pending", "delivery-failed", "published",
      ],
      coverage: "dedicated",
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { FindingOperationsPage } from "../features/residual/trust/FindingOperationsPage";');
    expect(routeSource).toContain("return <FindingOperationsPage client={client} context={context} />;");
  });

  it("binds Credential Leases to focused metadata-only synthetic governance", () => {
    const secrets = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "credential-leases");
    expect(secrets).toMatchObject({
      pageModule: "features/residual/trust/SecretsPage",
      actions: ["issue-synthetic-lease", "revoke-lease", "review-reference"],
      apiDependencies: [
        "issueSyntheticSecretLease", "listJobsPage", "listSecretLeasesPage",
        "listSecretReferencesPage", "revokeSecretLease",
      ],
      formInputs: ["job_binding", "ttl_seconds"],
      requiredStates: [
        "loading", "ready", "empty", "error", "denied", "active", "expired",
        "revoked", "lease-denied", "secret-unavailable",
      ],
      coverage: "dedicated",
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { SecretsPage } from "../features/residual/trust/SecretsPage";');
    expect(routeSource).toContain("return <SecretsPage client={client} context={context} />;");
  });

  it("binds ZAP runtime to focused server-owned execution choices", () => {
    const zap = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "zap-runtime");
    expect(zap).toMatchObject({
      pageModule: "features/residual/assessment/ZapPage.ZapPage",
      actions: ["compile-plan", "queue-run", "cancel-and-contain", "refresh"],
      apiDependencies: [
        "cancelZapRun", "compileZapPlan", "createZapRun", "getZapDashboard",
        "listJobsPage", "listPolicyDecisionsPage", "listSecretReferencesPage", "listZapProfiles",
      ],
      formInputs: [
        "credential_binding", "job_binding", "plan_binding", "policy_binding",
        "profile_binding", "runner_binding", "target_binding",
      ],
      coverage: "dedicated",
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { ZapPage } from "../features/residual/assessment/ZapPage";');
    expect(routeSource).toContain("return <ZapPage client={client} context={context} />;");
  });

  it("binds Nuclei runtime to focused signed-bundle execution choices", () => {
    const nuclei = OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "nuclei-runtime");
    expect(nuclei).toMatchObject({
      pageModule: "features/residual/assessment/NucleiPage.NucleiPage",
      actions: ["compile-plan", "queue-run", "cancel-and-contain", "review-findings", "refresh"],
      apiDependencies: [
        "cancelNucleiRun", "compileNucleiPlan", "createNucleiRun", "getNucleiDashboard",
        "listNucleiProfiles", "listPolicyDecisionsPage",
      ],
      formInputs: ["job_binding", "plan_binding", "policy_binding", "profile_binding", "runner_binding", "target_binding"],
      coverage: "dedicated",
    });
    const routeSource = readFileSync(resolve(process.cwd(), "frontend/src/shell/RoutePage.tsx"), "utf8");
    expect(routeSource).toContain('import { NucleiPage } from "../features/residual/assessment/NucleiPage";');
    expect(routeSource).toContain("return <NucleiPage client={client} context={context} />;");
  });

  it("binds every source-visible Refresh control and previously omitted form inputs", () => {
    // compat_128 C5 completion: the old page monolith and all adapter-owned refresh controls are absent.
    expect(existsSync(resolve(process.cwd(), "frontend/src/OperationalPages.tsx"))).toBe(false);

    expect(OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "campaign-workbench")?.formInputs).toEqual([]);
    expect(OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "campaign-workbench")?.pageModule)
      .toBe("features/residual/supervision/WorkbenchPage.WorkbenchPage");
    expect(OPERATIONAL_SURFACE_INVENTORY.find(({ id }) => id === "finding-operations")?.formInputs).toEqual([
      "evidence_binding",
      "query",
    ]);
  });

  it("places every production destination in grouped primary navigation rather than the header", () => {
    const productionRoutes = OPERATIONAL_SURFACE_INVENTORY.filter(
      ({ visibility }) => visibility === "production",
    );

    expect(productionRoutes).toHaveLength(23);
    expect(productionRoutes.every(({ targetRegion }) => targetRegion === "primary-navigation")).toBe(true);
    expect(new Set(productionRoutes.map(({ group }) => group))).toEqual(new Set([
      "command-center",
      "campaigns",
      "assets-assessments",
      "findings-evidence",
      "approvals-governance",
      "platform",
    ]));
  });

  it("removes lifecycle diagnostics from the operational inventory", () => {
    expect(OPERATIONAL_SURFACE_INVENTORY.some(({ path }) => path === "/states")).toBe(false);
  });

  it("records action, API, state, responsive, and parity dispositions for every route", () => {
    for (const surface of OPERATIONAL_SURFACE_INVENTORY) {
      expect(surface.actions.length, `${surface.path} actions`).toBeGreaterThan(0);
      expect(surface.requiredStates, `${surface.path} states`).toEqual(expect.arrayContaining([
        "loading",
        "ready",
        "empty",
        "error",
        "denied",
      ]));
      expect(surface.responsiveBehavior.length, `${surface.path} responsive behavior`).toBeGreaterThan(0);
      expect(surface.parityTests.length, `${surface.path} parity tests`).toBeGreaterThan(0);
      if (surface.visibility === "production") {
        expect(surface.apiDependencies.length, `${surface.path} API dependencies`).toBeGreaterThan(0);
      }
    }
  });

  it("does not retain obsolete compat_127 test-gap ownership", () => {
    expect(OPERATIONAL_SURFACE_INVENTORY.filter(({ gapOwner }) => gapOwner === "compat_127")).toEqual([]);
  });

  it("rejects duplicate paths and incomplete production dispositions", () => {
    const first = OPERATIONAL_SURFACE_INVENTORY[0];
    expect(first).toBeDefined();
    if (!first) return;

    const issues = validateOperationalSurfaceInventory([
      ...OPERATIONAL_SURFACE_INVENTORY,
      { ...first, apiDependencies: [], requiredStates: [] },
    ]);

    expect(issues).toEqual(expect.arrayContaining([
      expect.stringContaining("duplicate path"),
      expect.stringContaining("apiDependencies"),
      expect.stringContaining("requiredStates"),
    ]));
  });
});
