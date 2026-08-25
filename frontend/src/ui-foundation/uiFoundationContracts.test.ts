import { describe, expect, it } from "vitest";

import {
  API_GAP_LEDGER,
  INTERACTION_CONTRACTS,
  PERFORMANCE_BUDGETS,
  REPRESENTATIVE_TASK_PROTOCOL,
  SHELL_SPECIFICATION,
  UI_FOUNDATION_BUDGET_MANIFEST_VERSION,
  UI_FOUNDATION_CONTRACTS_VERSION,
  validateUiFoundationContracts,
} from "./uiFoundationContracts";
import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";

describe("compat_126 shell and interaction contracts", () => {
  it("uses the shared versioned UI foundation contract", () => {
    expect(UI_FOUNDATION_CONTRACTS_VERSION).toBe(UI_FOUNDATION_CONTRACT_VERSION);
    expect(UI_FOUNDATION_BUDGET_MANIFEST_VERSION).toBe(UI_FOUNDATION_CONTRACT_VERSION);
  });

  it("defines four distinct shell regions with no module navigation in the header", () => {
    expect(SHELL_SPECIFICATION.regions.map(({ id }) => id)).toEqual([
      "primary-navigation",
      "global-context-header",
      "primary-workspace",
      "context-inspector",
    ]);
    expect(SHELL_SPECIFICATION.primaryNavigation.orientation).toBe("vertical");
    expect(SHELL_SPECIFICATION.globalContextHeader.allowedContents).not.toContain("module-navigation");
    expect(SHELL_SPECIFICATION.prohibitedPatterns).toEqual(expect.arrayContaining([
      "horizontal-feature-strip",
      "wrapped-header-navigation",
      "scrolling-header-navigation",
      "overflow-header-navigation",
    ]));
  });

  it("documents semantics, keyboard, focus, state, responsive, and motion behavior for every interaction", () => {
    expect(INTERACTION_CONTRACTS.map(({ id }) => id)).toEqual([
      "primary-navigation",
      "mobile-navigation-drawer",
      "command-search",
      "context-inspector",
      "persistent-stop-revoke",
      "destructive-confirmation",
      "read-only-data-table",
      "status-feedback",
      "route-transition",
    ]);
    for (const contract of INTERACTION_CONTRACTS) {
      expect(contract.semanticPattern.length, `${contract.id} semantic`).toBeGreaterThan(0);
      expect(contract.keyboard.length, `${contract.id} keyboard`).toBeGreaterThan(0);
      expect(contract.focus.entry.length, `${contract.id} focus entry`).toBeGreaterThan(0);
      expect(contract.focus.exit.length, `${contract.id} focus exit`).toBeGreaterThan(0);
      expect(contract.focus.restore.length, `${contract.id} focus restore`).toBeGreaterThan(0);
      expect(contract.states, `${contract.id} states`).toEqual(expect.arrayContaining([
        "loading",
        "empty",
        "error",
        "denied",
        "stale",
      ]));
      expect(contract.responsive.length, `${contract.id} responsive`).toBeGreaterThan(0);
      expect(contract.reducedMotion.length, `${contract.id} motion`).toBeGreaterThan(0);
      expect(contract.accessibleName.length, `${contract.id} accessible name`).toBeGreaterThan(0);
      expect(contract.announcement.length, `${contract.id} announcement`).toBeGreaterThan(0);
      expect(contract.forcedColors.length, `${contract.id} forced colors`).toBeGreaterThan(0);
    }

    const stop = INTERACTION_CONTRACTS.find(({ id }) => id === "persistent-stop-revoke")!;
    expect(stop.states).toEqual(expect.arrayContaining(["unauthorized", "submitting", "containment-pending"]));
    expect(stop.responsive.join(" ")).toContain("route transition");
  });

  it("assigns every API gap to an exact roadmap owner and security/test disposition", () => {
    expect(API_GAP_LEDGER.map(({ id, owner }) => [id, owner])).toEqual([
      ["operator-shell-context", "compat_127"],
      ["routeable-resource-context", "compat_127"],
      ["operator-attention-queue", "compat_124"],
      ["automation-resource-options", "compat_124"],
      ["legacy-resource-resolvers", "compat_128"],
      ["bounded-pagination", "compat_128"],
      ["canonical-target-taxonomy", "compat_120"],
      ["direct-agent-path-execution", "compat_123"],
    ]);
    for (const gap of API_GAP_LEDGER) {
      expect(gap.schemaDisposition.length, `${gap.id} schema`).toBeGreaterThan(0);
      expect(gap.authorization.length, `${gap.id} authorization`).toBeGreaterThan(0);
      expect(gap.rls.length, `${gap.id} RLS`).toBeGreaterThan(0);
      expect(gap.pagination.length, `${gap.id} pagination`).toBeGreaterThan(0);
      expect(gap.states.length, `${gap.id} states`).toBeGreaterThan(0);
      expect(gap.auditEvents.length, `${gap.id} audit`).toBeGreaterThan(0);
      expect(gap.generatedClientImpact.length, `${gap.id} client`).toBeGreaterThan(0);
      expect(gap.acceptanceTests.length, `${gap.id} tests`).toBeGreaterThan(0);
    }
  });

  it("freezes the six-role task protocol and objective safety thresholds", () => {
    expect(REPRESENTATIVE_TASK_PROTOCOL.roles).toHaveLength(6);
    expect(REPRESENTATIVE_TASK_PROTOCOL.roles.filter(({ role }) => role === "red-team-operator")).toHaveLength(2);
    expect(REPRESENTATIVE_TASK_PROTOCOL.tasks.map(({ id }) => id)).toEqual([
      "recognize-scope-authority",
      "find-pending-approval",
      "understand-rejected-tool-path",
      "compare-safe-alternatives",
      "stop-active-work",
      "verify-cleanup-evidence",
      "find-remediation-retest",
    ]);
    expect(REPRESENTATIVE_TASK_PROTOCOL.thresholds).toEqual({
      safetyCriticalSuccessRate: 1,
      overallUnassistedSuccessRate: 0.9,
      nonSafetyUnassistedSuccessRate: 0.9,
      unsafeInterpretations: 0,
      medianTopLevelActivations: 2,
      medianDestinationActivations: 3,
    });
  });

  it("freezes source-backed and measured performance budgets", () => {
    expect(PERFORMANCE_BUDGETS).toMatchObject({
      lcpP75Milliseconds: 2500,
      inpP75Milliseconds: 200,
      clsP75: 0.1,
      localShellReadyP95Milliseconds: 1000,
      localFeedbackP95Milliseconds: 100,
      longTaskMaximumMilliseconds: 50,
      initialJavaScriptGzipBytes: 122880,
      initialCssGzipBytes: 12288,
      initialCombinedGzipBytes: 138240,
      largeData: {
        totalRecords: 1000,
        renderedPageSize: 100,
        readyP95Milliseconds: 250,
        maximumWorkspaceDomElements: 1500,
      },
      commandSearch: {
        optionCount: 1000,
        resultLimit: 50,
        readyP95Milliseconds: 100,
      },
    });
  });

  it("rejects header navigation, incomplete interaction contracts, and ownerless API gaps", () => {
    const invalid = {
      shell: structuredClone(SHELL_SPECIFICATION),
      interactions: structuredClone(INTERACTION_CONTRACTS),
      apiGaps: structuredClone(API_GAP_LEDGER),
      protocol: structuredClone(REPRESENTATIVE_TASK_PROTOCOL),
      performance: structuredClone(PERFORMANCE_BUDGETS),
    };
    invalid.shell.globalContextHeader.allowedContents.push("module-navigation");
    invalid.interactions[0]!.keyboard = [];
    invalid.interactions[0]!.accessibleName = "";
    invalid.apiGaps[0]!.owner = "";

    expect(validateUiFoundationContracts(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("header"),
      expect.stringContaining("keyboard"),
      expect.stringContaining("accessibleName"),
      expect.stringContaining("owner"),
    ]));
  });

  it("rejects deleted critical contract families, incomplete role mix, and missing privacy requirements", () => {
    const invalid = {
      shell: structuredClone(SHELL_SPECIFICATION),
      interactions: structuredClone(INTERACTION_CONTRACTS).filter(({ id }) => id !== "persistent-stop-revoke"),
      apiGaps: structuredClone(API_GAP_LEDGER),
      protocol: structuredClone(REPRESENTATIVE_TASK_PROTOCOL),
      performance: structuredClone(PERFORMANCE_BUDGETS),
    };
    invalid.protocol.roles = invalid.protocol.roles.filter(({ role }) => role !== "keyboard-accessibility-evaluator");
    invalid.protocol.privacy = [];

    expect(validateUiFoundationContracts(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("missing interaction persistent-stop-revoke"),
      expect.stringContaining("keyboard-accessibility-evaluator"),
      expect.stringContaining("privacy"),
    ]));
  });

  it("rejects incomplete shell/API-gap families and any relaxed performance budget", () => {
    const invalid = {
      shell: structuredClone(SHELL_SPECIFICATION),
      interactions: structuredClone(INTERACTION_CONTRACTS),
      apiGaps: structuredClone(API_GAP_LEDGER),
      protocol: structuredClone(REPRESENTATIVE_TASK_PROTOCOL),
      performance: structuredClone(PERFORMANCE_BUDGETS),
    };
    invalid.shell.regions.pop();
    invalid.shell.primaryNavigation.groups.pop();
    invalid.apiGaps = [];
    invalid.performance.lcpP75Milliseconds += 1;
    invalid.performance.clsP75 += 0.01;
    invalid.performance.initialJavaScriptGzipBytes += 1;
    invalid.performance.largeData.maximumWorkspaceDomElements += 1;

    expect(validateUiFoundationContracts(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("shell regions"),
      expect.stringContaining("shell specification"),
      expect.stringContaining("navigation groups"),
      expect.stringContaining("missing API gap"),
      expect.stringContaining("performance budgets"),
    ]));
  });

  it("rejects semantic or responsive drift inside otherwise present shell families", () => {
    const invalid = {
      shell: structuredClone(SHELL_SPECIFICATION),
      interactions: structuredClone(INTERACTION_CONTRACTS),
      apiGaps: structuredClone(API_GAP_LEDGER),
      protocol: structuredClone(REPRESENTATIVE_TASK_PROTOCOL),
      performance: structuredClone(PERFORMANCE_BUDGETS),
    };
    invalid.shell.regions[0]!.landmark = "header";
    invalid.shell.primaryNavigation.mobile = "horizontal overflow fallback";

    expect(validateUiFoundationContracts(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("shell specification"),
    ]));
  });

  it("rejects duplicate and unexpected API-gap identifiers", () => {
    const invalid = {
      shell: structuredClone(SHELL_SPECIFICATION),
      interactions: structuredClone(INTERACTION_CONTRACTS),
      apiGaps: structuredClone(API_GAP_LEDGER),
      protocol: structuredClone(REPRESENTATIVE_TASK_PROTOCOL),
      performance: structuredClone(PERFORMANCE_BUDGETS),
    };
    const first = invalid.apiGaps[0]!;
    invalid.apiGaps.push({ ...first }, { ...first, id: "unreviewed-gap" });

    expect(validateUiFoundationContracts(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining(`duplicate API gap ${first.id}`),
      expect.stringContaining("unexpected API gap unreviewed-gap"),
    ]));
  });

  it("rejects semantic drift inside otherwise complete API-gap fields", () => {
    const invalid = {
      shell: structuredClone(SHELL_SPECIFICATION),
      interactions: structuredClone(INTERACTION_CONTRACTS),
      apiGaps: structuredClone(API_GAP_LEDGER),
      protocol: structuredClone(REPRESENTATIVE_TASK_PROTOCOL),
      performance: structuredClone(PERFORMANCE_BUDGETS),
    };
    invalid.apiGaps[0]!.authorization = "Any non-empty client-provided context is accepted";
    invalid.apiGaps[0]!.rls = "Not required";
    invalid.apiGaps[0]!.acceptanceTests = ["field is present"];

    expect(validateUiFoundationContracts(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("API-gap ledger must exactly match"),
    ]));
  });

  it("rejects a reduced task protocol or non-finite navigation thresholds", () => {
    const invalid = {
      shell: structuredClone(SHELL_SPECIFICATION),
      interactions: structuredClone(INTERACTION_CONTRACTS),
      apiGaps: structuredClone(API_GAP_LEDGER),
      protocol: structuredClone(REPRESENTATIVE_TASK_PROTOCOL),
      performance: structuredClone(PERFORMANCE_BUDGETS),
    };
    invalid.protocol.tasks = invalid.protocol.tasks.slice(0, 1);
    invalid.protocol.thresholds.medianTopLevelActivations = Number.NaN;
    invalid.protocol.thresholds.medianDestinationActivations = 99;

    expect(validateUiFoundationContracts(invalid)).toEqual(expect.arrayContaining([
      expect.stringContaining("representative protocol must exactly match"),
    ]));
  });
});
