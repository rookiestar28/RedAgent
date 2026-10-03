import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ConsoleApiError, type CampaignOperations, type AutonomousCampaignPreview,
  type AutonomousCampaignStatus } from "../../lib/apiClient";

import {
  CampaignAttentionFeature,
  CampaignCoreFeature,
  CampaignStatusFeature,
  type CampaignCoreClient,
  type CampaignReadClient,
} from "./CampaignCoreFeature";


function client(): CampaignCoreClient {
  return {
    getAutonomousCampaignAvailability: vi.fn().mockResolvedValue({ canonical_configured: false,
      create_available: false, preparation_available: false, status_available: false, stop_available: false,
      revoke_available: false, mode: "disabled", legacy_available: true, reason: "operator_owner_not_configured" }),
    createAutonomousCampaignIntent: vi.fn(), getAutonomousCampaignStatus: vi.fn(),
    prepareAutonomousCampaignPlan: vi.fn(), decideAutonomousCampaignPlan: vi.fn(),
    admitAutonomousCampaign: vi.fn(), prepareAutonomousCampaignChild: vi.fn(), recoverAutonomousCampaign: vi.fn(),
    listCampaignCoreEngagementOptions: vi.fn().mockResolvedValue({
      data: [
        { binding: "opaque-eng-a", label: "Loopback alpha", revision: "1", freshness: "current", eligible: true },
        { binding: "opaque-eng-b", label: "Loopback beta", revision: "2", freshness: "current", eligible: true },
      ],
      page: { limit: 50, next_cursor: null },
    }),
    listCampaignCoreTargetOptions: vi.fn().mockResolvedValue({
      data: [
        { binding: "opaque-target-a", label: "HTTP fixture A", revision: "3", freshness: "current", eligible: true },
        { binding: "opaque-target-b", label: "HTTP fixture B", revision: "4", freshness: "current", eligible: true },
      ],
      page: { limit: 50, next_cursor: null },
    }),
    listCampaignCoreRiskOptions: vi.fn().mockResolvedValue({
      data: [{ binding: "opaque-risk", label: "Tier 1 passive", revision: "1", freshness: "current", eligible: true }],
      page: { limit: 50, next_cursor: null },
    }),
    startCampaignCore: vi.fn().mockResolvedValue({
      campaign_id: "campaign-server-generated",
      status: "dispatch_pending",
      aggregate_sequence: 1,
      etag: '"campaign-server-generated:1"',
      replayed: false,
    }),
    getCampaignCoreCampaign: vi.fn().mockResolvedValue({
      campaign_id: "campaign-server-generated",
      label: "Assess HTTP security posture",
      status: "workflow_started",
      aggregate_sequence: 2,
      etag: '"campaign-server-generated:2"',
      authority: { state: "current_at_last_resolution", attention_reason: null },
      decision: { outcome: "select", candidates: [], rejected: [] },
      plan: { primary: { capability_id: "zap-controlled-runtime" }, successor: null, depth: 1 },
      effects: [],
      findings: [],
      recovery: { stop_visible: true, revoke_visible: true, cleanup_required: false, guidance: "Stop remains available." },
    }),
    recoverCampaignCore: vi.fn(),
  };
}


describe("compat_124 portable campaign core", () => {
  it("starts the standing Tier-1 flow in five deliberate activations with no raw-ID input", async () => {
    const api = client();
    const activations: string[] = [];
    const user = userEvent.setup();
    render(<CampaignCoreFeature client={api} onActivation={(event) => activations.push(event)} />);

    await user.selectOptions(await screen.findByLabelText("Authorized engagement"), "opaque-eng-b");
    await user.selectOptions(await screen.findByLabelText("Authorized target"), "opaque-target-b");
    await user.selectOptions(screen.getByLabelText("Objective"), "Assess HTTP security posture");
    await user.selectOptions(await screen.findByLabelText("Risk profile"), "opaque-risk");
    await user.click(screen.getByRole("button", { name: "Start authorized campaign" }));

    await waitFor(() => expect(api.startCampaignCore).toHaveBeenCalledWith(
      {
        engagement_binding: "opaque-eng-b",
        target_binding: "opaque-target-b",
        objective: "Assess HTTP security posture",
        risk_profile: "opaque-risk",
      },
      expect.any(String),
    ));
    expect(activations).toEqual(["engagement", "target", "objective", "risk", "start"]);
    expect(screen.queryByLabelText(/\b(?:campaign|target|engagement|job|runner|workflow) id\b/i)).toBeNull();
    expect(await screen.findByText("Stop remains available.")).toBeVisible();
    expect(screen.getByRole("button", { name: "Request containment" })).toBeVisible();
  });

  it("shows denied/unavailable reasons and never enables an ineligible option", async () => {
    const api = client();
    vi.mocked(api.listCampaignCoreEngagementOptions).mockResolvedValue({
      data: [{
        binding: "opaque-denied",
        label: "Expired engagement",
        revision: "8",
        freshness: "stale",
        eligible: false,
        unavailable_reason: "roe_expired",
      }],
      page: { limit: 50, next_cursor: null },
    });
    render(<CampaignCoreFeature client={api} />);

    expect(await screen.findByText(/roe expired/i)).toBeVisible();
    expect(screen.getByRole("button", { name: "Start authorized campaign" })).toBeDisabled();
    expect(screen.getByText(/refresh current authority/i)).toBeVisible();
  });

  it("offers the repository snapshot objective without raw repository or receipt input", async () => {
    const api = client();
    vi.mocked(api.listCampaignCoreTargetOptions).mockResolvedValue({
      data: [{
        binding: "opaque-artifact-binding",
        label: "Repository snapshot: canonical data-only binding",
        revision: "1:11",
        freshness: "current",
        eligible: true,
      }],
      page: { limit: 50, next_cursor: null },
    });
    const user = userEvent.setup();
    render(<CampaignCoreFeature client={api} />);

    await user.selectOptions(await screen.findByLabelText("Authorized engagement"), "opaque-eng-a");
    await user.selectOptions(await screen.findByLabelText("Authorized target"), "opaque-artifact-binding");
    await user.selectOptions(screen.getByLabelText("Objective"), "Assess repository snapshot posture");
    await user.selectOptions(await screen.findByLabelText("Risk profile"), "opaque-risk");
    await user.click(screen.getByRole("button", { name: "Start authorized campaign" }));

    await waitFor(() => expect(api.startCampaignCore).toHaveBeenCalledWith(
      expect.objectContaining({
        target_binding: "opaque-artifact-binding",
        objective: "Assess repository snapshot posture",
      }),
      expect.any(String),
    ));
    expect(screen.queryByLabelText(/repository|artifact receipt|path|url/i)).toBeNull();
  });

  it("presents bounded status truth without displaying the transport campaign identifier", async () => {
    const user = userEvent.setup();
    const readClient: CampaignReadClient = {
      ...client(),
      listCampaignCoreCampaigns: vi.fn().mockResolvedValue({
        data: [{
          campaign_id: "campaign-internal-hidden",
          label: "Owned loopback posture",
          status: "workflow_started",
          authority_state: "current_at_last_resolution",
          attention_reason: null,
          aggregate_sequence: 2,
        }],
        page: { limit: 50, next_cursor: null },
      }),
      getCampaignCoreCampaign: vi.fn().mockResolvedValue(campaignTruth()),
      getCampaignOperations: vi.fn().mockResolvedValue(campaignOperations()),
      listCampaignCoreAttention: vi.fn(),
      recoverCampaignCore: vi.fn().mockResolvedValue({
        campaign_id: "campaign-internal-hidden",
        status: "contained",
        aggregate_sequence: 3,
        etag: '"campaign-internal-hidden:3"',
        replayed: false,
      }),
    };

    render(<CampaignStatusFeature client={readClient} />);
    await user.click(await screen.findByRole("button", { name: "View current status" }));

    expect(await screen.findByRole("complementary", { name: "Selected campaign truth" })).toBeVisible();
    expect(screen.getByText("Primary web posture assessment")).toBeVisible();
    expect(screen.getByRole("button", { name: "Request containment" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Request containment" }));
    expect(screen.getByRole("dialog", { name: "Confirm containment request" })).toBeVisible();
    expect(screen.getByText(/does not claim that active effects are already contained/i)).toBeVisible();
    const confirm = screen.getByRole("button", { name: "Confirm containment request" });
    expect(confirm).toHaveFocus();
    await user.click(confirm);
    await waitFor(() => expect(readClient.recoverCampaignCore).toHaveBeenCalledWith(
      "stop",
      "campaign-internal-hidden",
      '"campaign-internal-hidden:2"',
      expect.stringContaining("persistent status"),
    ));
    await waitFor(() => expect(screen.getByRole("button", { name: "Request containment" })).toHaveFocus());
    expect(screen.queryByText("campaign-internal-hidden")).toBeNull();
  });

  it("renders the bounded autonomous operations workspace without raw identifiers or false export authority", async () => {
    const user = userEvent.setup();
    const getCampaignOperations = vi.fn().mockResolvedValue(campaignOperations());
    const readClient = {
      ...client(),
      listCampaignCoreCampaigns: vi.fn().mockResolvedValue({
        data: [{
          campaign_id: "campaign-internal-hidden",
          label: "Owned loopback posture",
          status: "workflow_started",
          authority_state: "current_at_last_resolution",
          attention_reason: null,
          aggregate_sequence: 2,
        }],
        page: { limit: 50, next_cursor: null },
      }),
      getCampaignCoreCampaign: vi.fn().mockResolvedValue(campaignTruth()),
      getCampaignOperations,
      listCampaignCoreAttention: vi.fn(),
      recoverCampaignCore: vi.fn(),
    } as unknown as CampaignReadClient;

    render(<CampaignStatusFeature client={readClient} />);
    await user.click(await screen.findByRole("button", { name: "View current status" }));

    expect(await screen.findByRole("heading", { name: "Autonomous campaign operations" })).toBeVisible();
    expect(getCampaignOperations).toHaveBeenCalledWith("campaign-internal-hidden");
    expect(screen.getAllByText("Admitted")).toHaveLength(2);
    expect(screen.getByText("Valid")).toBeVisible();
    await user.click(screen.getByText("Exact authority binding"));
    expect(screen.getByText("a".repeat(64))).toBeVisible();
    expect(screen.getByText("c".repeat(64))).toBeVisible();
    expect(screen.getByText("Step 1")).toBeVisible();
    expect(screen.getByText("HTTP posture")).toBeVisible();
    expect(screen.getByText(/75 of 100 requests remaining/i)).toBeVisible();
    expect(screen.getByText(/1 invalidated · 1 retained · 1 substitution/i)).toBeVisible();
    expect(screen.getByText(/verified retained bundle is not available/i)).toBeVisible();
    expect(screen.getByRole("button", { name: "Request containment" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Revoke future authority" })).toBeVisible();
    expect(screen.queryByRole("button", { name: /export/i })).toBeNull();
    expect(document.body).not.toHaveTextContent(/campaign-internal-hidden|node-internal|target-internal|operator-internal/i);
  });

  it("never retains a higher operations version from a different selected campaign", async () => {
    const user = userEvent.setup();
    const firstOperations = campaignOperations();
    firstOperations.aggregate_version = 99;
    firstOperations.plan.nodes[0]!.capability = "First campaign capability";
    const secondOperations = campaignOperations();
    secondOperations.aggregate_version = 2;
    secondOperations.plan.nodes[0]!.capability = "Second campaign capability";
    const readClient = {
      ...client(),
      listCampaignCoreCampaigns: vi.fn().mockResolvedValue({
        data: [
          {
            campaign_id: "campaign-first-hidden", label: "First campaign", status: "workflow_started",
            authority_state: "current_at_last_resolution", attention_reason: null, aggregate_sequence: 99,
          },
          {
            campaign_id: "campaign-second-hidden", label: "Second campaign", status: "workflow_started",
            authority_state: "current_at_last_resolution", attention_reason: null, aggregate_sequence: 2,
          },
        ],
        page: { limit: 50, next_cursor: null },
      }),
      getCampaignCoreCampaign: vi.fn().mockImplementation((campaignId: string) => Promise.resolve({
        ...campaignTruth(),
        campaign_id: campaignId,
        label: campaignId === "campaign-first-hidden" ? "First campaign truth" : "Second campaign truth",
      })),
      getCampaignOperations: vi.fn().mockImplementation((campaignId: string) => Promise.resolve(
        campaignId === "campaign-first-hidden" ? firstOperations : secondOperations
      )),
      listCampaignCoreAttention: vi.fn(),
      recoverCampaignCore: vi.fn(),
    } as unknown as CampaignReadClient;

    render(<CampaignStatusFeature client={readClient} />);
    const viewButtons = await screen.findAllByRole("button", { name: "View current status" });
    await user.click(viewButtons[0]!);
    expect(await screen.findByText("First campaign capability")).toBeVisible();
    await user.click(viewButtons[1]!);

    expect(await screen.findByText("Second campaign truth")).toBeVisible();
    expect(await screen.findByText("Second campaign capability")).toBeVisible();
    expect(screen.queryByText("First campaign capability")).toBeNull();
  });

  it("renders bounded validator counterexamples for denied preparation", async () => {
    const user = userEvent.setup();
    const operations = campaignOperations();
    operations.preparation_state = "denied";
    operations.validation = {
      result: "invalid",
      reason: null,
      counterexample_codes: ["scope-expansion-denied"],
    };
    operations.authority.state = "revoked";
    operations.authority.kill_switch_epoch = 1;
    const readClient = {
      ...client(),
      listCampaignCoreCampaigns: vi.fn().mockResolvedValue({
        data: [{
          campaign_id: "campaign-internal-hidden",
          label: "Owned loopback posture",
          status: "dispatch_pending",
          authority_state: "current_at_last_resolution",
          attention_reason: null,
          aggregate_sequence: 2,
        }],
        page: { limit: 50, next_cursor: null },
      }),
      getCampaignCoreCampaign: vi.fn().mockResolvedValue(campaignTruth()),
      getCampaignOperations: vi.fn().mockResolvedValue(operations),
      listCampaignCoreAttention: vi.fn(),
      recoverCampaignCore: vi.fn(),
    } as unknown as CampaignReadClient;

    render(<CampaignStatusFeature client={readClient} />);
    await user.click(await screen.findByRole("button", { name: "View current status" }));

    expect(await screen.findByText("Scope expansion denied")).toBeVisible();
    expect(screen.getByRole("button", { name: "Request containment" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Revoke future authority" })).toBeNull();
  });

  it("shows governed recovery guidance for bounded attention categories", async () => {
    const readClient: CampaignReadClient = {
      ...client(),
      listCampaignCoreCampaigns: vi.fn(),
      getCampaignCoreCampaign: vi.fn(),
      getCampaignOperations: vi.fn(),
      listCampaignCoreAttention: vi.fn().mockResolvedValue({
        data: [{
          binding: "opaque-attention-binding",
          campaign_label: "Owned loopback posture",
          category: "reconciliation",
          reason: "effect_requires_reconciliation",
          next_safe_action: "Inspect the bounded receipt; automatic redispatch remains blocked.",
          occurred_at: "2026-08-24T12:00:00Z",
        }],
        page: { limit: 50, next_cursor: null },
      }),
      recoverCampaignCore: vi.fn(),
    };

    render(<CampaignAttentionFeature client={readClient} />);

    expect(await screen.findByText(/effect requires reconciliation/i)).toBeVisible();
    expect(screen.getByText(/automatic redispatch remains blocked/i)).toBeVisible();
    expect(screen.queryByText("opaque-attention-binding")).toBeNull();
  });

  it("hides normal creation under rollback while preserving recovery directions", () => {
    const api = client();

    render(<CampaignCoreFeature client={api} createEnabled={false} />);

    expect(screen.getByRole("heading", { name: "Campaign creation is disabled" })).toBeVisible();
    expect(screen.getByText(/emergency stop, revoke, evidence, and audit recovery remain available/i)).toBeVisible();
    expect(screen.queryByRole("button", { name: "Start authorized campaign" })).toBeNull();
    expect(api.listCampaignCoreEngagementOptions).not.toHaveBeenCalled();
  });

  it("preserves the transport key across a safe retry of the same intent", async () => {
    const api = client();
    const user = userEvent.setup();
    vi.mocked(api.startCampaignCore)
      .mockRejectedValueOnce(new Error("temporary transport failure"))
      .mockResolvedValueOnce({
        campaign_id: "campaign-server-generated",
        status: "dispatch_pending",
        aggregate_sequence: 1,
        etag: '"campaign-server-generated:1"',
        replayed: true,
      });
    render(<CampaignCoreFeature client={api} />);

    await user.selectOptions(await screen.findByLabelText("Authorized engagement"), "opaque-eng-a");
    await user.selectOptions(await screen.findByLabelText("Authorized target"), "opaque-target-a");
    await user.selectOptions(screen.getByLabelText("Objective"), "Assess HTTP security posture");
    await user.selectOptions(await screen.findByLabelText("Risk profile"), "opaque-risk");
    await user.click(screen.getByRole("button", { name: "Start authorized campaign" }));
    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "Start authorized campaign" }));

    await waitFor(() => expect(api.startCampaignCore).toHaveBeenCalledTimes(2));
    const firstKey = vi.mocked(api.startCampaignCore).mock.calls.at(0)?.[1];
    const secondKey = vi.mocked(api.startCampaignCore).mock.calls.at(1)?.[1];
    expect(firstKey).toBeTruthy();
    expect(secondKey).toBe(firstKey);
  });

  it("keeps emergency recovery available when start commits but aggregate refresh fails", async () => {
    const api = client();
    const user = userEvent.setup();
    vi.mocked(api.getCampaignCoreCampaign).mockRejectedValue(new Error("projection unavailable"));
    render(<CampaignCoreFeature client={api} />);

    await user.selectOptions(await screen.findByLabelText("Authorized engagement"), "opaque-eng-a");
    await user.selectOptions(await screen.findByLabelText("Authorized target"), "opaque-target-a");
    await user.selectOptions(screen.getByLabelText("Objective"), "Assess HTTP security posture");
    await user.selectOptions(await screen.findByLabelText("Risk profile"), "opaque-risk");
    await user.click(screen.getByRole("button", { name: "Start authorized campaign" }));

    expect(await screen.findByText(/campaign start was accepted/i)).toBeVisible();
    expect(screen.getByRole("button", { name: "Request containment" })).toBeVisible();
    expect(screen.queryByText("campaign-server-generated")).toBeNull();
  });
});

function campaignTruth() {
  return {
    campaign_id: "campaign-internal-hidden",
    label: "Owned loopback posture",
    status: "workflow_started",
    aggregate_sequence: 2,
    etag: '"campaign-internal-hidden:2"',
    authority: { state: "current_at_last_resolution", attention_reason: null },
    context: {
      schema: "redagent.r119-context/v1",
      coverage: "Canonical authority and two-capability snapshot",
      freshness: "Resolved at campaign start; mutations recheck authority",
    },
    decision: {
      outcome: "planned",
      reason: "primary_selected",
      candidates: [],
    },
    plan: {
      primary: "Primary web posture assessment",
      successor: null,
      successor_condition: null,
      depth: 1,
      risk: "Tier 1 passive, owned-loopback only",
      cost: "At most 2 operations in 300 seconds",
      evidence: "1 reviewed evidence schema expected",
      cleanup: "cleanup_receipt_required",
      approval: "standing Tier 1 authority",
    },
    effects: [],
    findings: [],
    recovery: {
      stop_visible: true,
      revoke_visible: true,
      cleanup_required: false,
      guidance: "Stop remains available.",
    },
  };
}


function campaignOperations(): CampaignOperations {
  return {
    schema_version: "redagent.campaign-operations/v1",
    aggregate_version: 7,
    etag: '"campaign-internal-hidden:7"',
    preparation_state: "executing",
    authority: {
      state: "admitted",
      signed_authority_sha256: "a".repeat(64),
      authority_sha256: "b".repeat(64),
      lifecycle_epoch: 4,
      policy_revocation_epoch: 2,
      roe_revocation_epoch: 1,
      kill_switch_epoch: 0,
      expires_at: "2026-08-29T13:00:00Z",
    },
    plan: {
      revision_label: "Current revision",
      parent_revision_present: false,
      nodes: [{ label: "Step 1", capability: "HTTP posture", state: "running", order: 0 }],
      edges: [],
    },
    validation: { result: "valid", reason: null, counterexample_codes: [] },
    admission: { outcome: "admitted", reason: "admitted", receipt_sha256: "c".repeat(64) },
    budget: {
      state: "available",
      dimensions: {
        requests: { authorized: 100, committed: 25, residual: 75, unit: "requests" },
      },
    },
    execution: {
      state: "running",
      transition_count: 3,
      max_transitions: 20,
      stop_requested: false,
      terminal_reason: null,
      frontier: { running: 1 },
    },
    observations: [{
      fact: "Http header present",
      producer_kind: "dag_runner_result",
      observation_sha256: "d".repeat(64),
      provenance_sha256: "e".repeat(64),
      freshness: "current",
    }],
    revisions: [{
      label: "Revision 1",
      state: "proposed",
      proposal_sha256: "f".repeat(64),
      invalidated_count: 1,
      retained_count: 1,
      substitution_count: 1,
    }],
    audit: [{
      action: "campaign.dag.start.requested",
      occurred_at: "2026-08-29T12:00:00Z",
      correlation_id: "safe-correlation",
      details_sha256: "1".repeat(64),
    }],
    evidence: {
      effect_count: 1,
      evidence_count: 1,
      cleanup_state: "complete",
      terminal_receipt_present: false,
      export_state: "unavailable_without_verified_bundle",
    },
  };
}

function normalClient(mode: AutonomousCampaignStatus["mode"] = "owned_loopback_auto"): CampaignCoreClient {
  const api = client();
  vi.mocked(api.getAutonomousCampaignAvailability).mockResolvedValue({ canonical_configured: true,
    create_available: true, preparation_available: true, status_available: true, stop_available: true,
    revoke_available: true, mode, legacy_available: true, reason: "ready" });
  vi.mocked(api.createAutonomousCampaignIntent).mockResolvedValue({ campaign_id: "server-native-campaign",
    mode, lifecycle_state: "INTENT_CREATED", aggregate_revision: 1,
    etag: '"server-intent-token"', replayed: false });
  vi.mocked(api.prepareAutonomousCampaignPlan).mockResolvedValue(normalPreview(mode));
  vi.mocked(api.getAutonomousCampaignStatus).mockResolvedValueOnce(normalStatus("INTENT_CREATED", 1, mode))
    .mockResolvedValue(normalStatus("AWAITING_APPROVAL", 3, mode));
  return api;
}

function normalPreview(mode: AutonomousCampaignStatus["mode"] = "owned_loopback_auto"): AutonomousCampaignPreview {
  const budget = { schema_version: "redagent.campaign-budget-vector/v1" as const, duration_seconds: 120,
    requests: 20, rate_per_minute: 20, concurrency: 1, risk_micropoints: 10, cost_microunits: 20,
    evidence_bytes: 4096, data_bytes: 4096 };
  return { schema_version: "redagent.autonomous-campaign-plan-preview/v1", preview_id: "preview-native",
    preview_sha256: "a".repeat(64), tenant_id: "tenant-native", campaign_id: "server-native-campaign",
    engagement_id: "engagement-native", application_revision: 3, application_intent_sha256: "b".repeat(64),
    source_binding_sha256: "c".repeat(64), signed_authority_sha256: "d".repeat(64), authority_sha256: "e".repeat(64),
    domain_sha256: "f".repeat(64), plan_revision_id: "plan-native", plan_revision_sha256: "1".repeat(64),
    plan_sha256: "2".repeat(64), objective_id: "objective-native", objective_sha256: "3".repeat(64),
    target_id: "target-native", capability_ids: ["zap-controlled-runtime"], capability_set_sha256: "4".repeat(64),
    effect_classes: ["owned_http_passive"], actions: [{ node_id: "node-native", order: 0,
      operator_id: "operator-native", target_id: "target-native", capability_id: "zap-controlled-runtime",
      capability_revision: 3, effect_class: "owned_http_passive", executable: true, max_duration_seconds: 120,
      max_requests: 20, max_rate_per_minute: 20, concurrency_weight: 1, max_retries: 0, max_risk_micropoints: 10,
      max_cost_microunits: 20, max_evidence_bytes: 4096, max_data_bytes: 4096, cleanup_mode: "receipt_required" }],
    authorized_budget: budget, plan_budget: budget, certificate_sha256: "5".repeat(64), validator_version: "validator-v1",
    validator_sha256: "6".repeat(64), validation_result: "valid", policy_revision: "policy-native",
    policy_bundle_sha256: "7".repeat(64), lifecycle_epoch: 0, policy_revocation_epoch: 0,
    roe_revocation_epoch: 0, kill_switch_epoch: 0, required_approvers: [{ principal_id: "approver-native", role_id: "operator" }],
    issued_at: "2026-10-03T04:00:00Z", expires_at: "2026-10-03T04:02:00Z", execution_mode: mode,
    execution_bindings: [], child_lineage_sha256: null };
}

function normalStatus(lifecycle = "AWAITING_APPROVAL", revision = 3,
  mode: AutonomousCampaignStatus["mode"] = "owned_loopback_auto"): AutonomousCampaignStatus {
  const operations = campaignOperations();
  operations.execution = { ...operations.execution, state: "unavailable", stop_requested: false, frontier: {} };
  operations.admission = { outcome: "unavailable", reason: "not_admitted", receipt_sha256: null };
  operations.evidence = { ...operations.evidence, cleanup_state: "not_started", effect_count: 0, evidence_count: 0 };
  return { campaign_id: "server-native-campaign", mode, lifecycle_state: lifecycle,
    target_label: "HTTP fixture A",
    aggregate_revision: revision, etag: `"server-current-${revision}"`, roe_version_id: "server-native-roe",
    preview: lifecycle === "INTENT_CREATED" ? null : normalPreview(mode),
    preview_etag: lifecycle === "INTENT_CREATED" ? null : '"server-preview-token"', preview_expired: false,
    approval_etag: '"server-approval-token"', approval: lifecycle === "APPROVED" ? {
      receipt_id: "approval-native", receipt_sha256: "8".repeat(64), decision: "approved", reason_code: "approved",
      application_revision: 4, expires_at: "2026-10-03T04:02:00Z", expired: false } : null,
    start: null, operations, result: { effect_count: 0, verified_effect_count: 0,
      cleanup_state: "not_started", evidence_state: "not_started", export_state: "unavailable_without_verified_bundle" },
    child: null, attention: [] };
}

async function prepareNormal(api: CampaignCoreClient) {
  const user = userEvent.setup();
  render(<CampaignCoreFeature client={api} />);
  await user.selectOptions(await screen.findByLabelText("Authorized engagement"), "opaque-eng-a");
  await user.selectOptions(await screen.findByLabelText("Authorized target"), "opaque-target-a");
  await user.selectOptions(screen.getByLabelText("Objective"), "Assess HTTP security posture");
  await user.selectOptions(await screen.findByLabelText("Risk profile"), "opaque-risk");
  await user.click(screen.getByRole("button", { name: "Prepare plan" }));
  await screen.findByRole("heading", { name: "Immutable plan" });
  return user;
}

describe("normal staged Campaign Core journey", () => {
  it.each(["policy_denied", "authority_revoked", "budget_exhausted", "unknown_capability",
    "kill_switch_active", "manual_review_required", "reconciliation_required", "operator_native_source_changed"])
  ("blocks new gates for server attention %s while preserving recovery", async (reason) => {
    const api = normalClient();
    const user = await prepareNormal(api);
    const blocked = normalStatus("APPROVED", 4);
    blocked.attention = [reason];
    blocked.operations.execution.state = "running";
    vi.mocked(api.getAutonomousCampaignStatus).mockResolvedValue(blocked);
    await user.click(screen.getByRole("button", { name: "Refresh current status" }));
    expect(screen.queryByRole("button", { name: "Admit and start" })).toBeNull();
    expect(screen.getByRole("button", { name: "Request containment" })).toBeEnabled();
    expect(screen.getByRole("button", { name: "Revoke future authority" })).toBeEnabled();
    expect(screen.getByLabelText("Campaign attention")).toHaveTextContent(reason.replaceAll("_", " "));
    blocked.lifecycle_state = "AWAITING_APPROVAL";
    blocked.approval = null;
    await user.click(screen.getByRole("button", { name: "Refresh current status" }));
    expect(screen.queryByRole("button", { name: "Approve plan" })).toBeNull();
    expect(api.decideAutonomousCampaignPlan).not.toHaveBeenCalled();
    expect(api.admitAutonomousCampaign).not.toHaveBeenCalled();
  });

  it("isolates confirmation from background controls and shows objective and both total budgets", async () => {
    const api = normalClient();
    const awaiting = normalStatus();
    awaiting.objective_label = "Assess HTTP security posture";
    awaiting.preview = { ...normalPreview(), authorized_budget: { ...normalPreview().authorized_budget, requests: 100 } };
    vi.mocked(api.getAutonomousCampaignStatus).mockReset()
      .mockResolvedValueOnce(normalStatus("INTENT_CREATED", 1)).mockResolvedValue(awaiting);
    const user = await prepareNormal(api);
    const refresh = screen.getByRole("button", { name: "Refresh current status" });
    await user.click(screen.getByRole("button", { name: "Approve plan" }));
    const dialog = screen.getByRole("dialog", { name: "Confirm plan approval" });
    expect(refresh.closest("[inert]")).not.toBeNull();
    expect(dialog.closest("[inert]")).toBeNull();
    expect(within(dialog).getByText("Assess HTTP security posture")).toBeVisible();
    expect(within(dialog).getByLabelText("Authorized campaign bounds")).toHaveTextContent("100");
    expect(within(dialog).getByLabelText("Plan total bounds")).toBeVisible();
    await user.keyboard("{Escape}");
    expect(refresh.closest("[inert]")).toBeNull();
    expect(api.decideAutonomousCampaignPlan).not.toHaveBeenCalled();
  });

  it("prepares exactly one child with fresh human approval and no inherited parent admission", async () => {
    const api = normalClient("bounded_replan");
    const user = await prepareNormal(api);
    const terminal = normalStatus("EVIDENCE_PENDING", 7, "bounded_replan");
    terminal.operations.execution.state = "contained";
    terminal.result.evidence_state = "pending";
    vi.mocked(api.getAutonomousCampaignStatus).mockResolvedValue(terminal);
    await user.click(screen.getByRole("button", { name: "Refresh current status" }));
    await user.click(await screen.findByRole("button", { name: "Prepare child plan" }));
    expect(api.prepareAutonomousCampaignChild).not.toHaveBeenCalled();
    const child = normalStatus("AWAITING_APPROVAL", 9, "bounded_replan");
    child.preview = { ...normalPreview("bounded_replan"), preview_id: "child-preview", application_revision: 9,
      child_lineage_sha256: "9".repeat(64), actions: [{ ...normalPreview().actions[0]!, capability_id: "nuclei-trusted-runtime" }] };
    child.preview_etag = '"server-child-preview-token"';
    child.approval = null;
    child.approval_etag = null;
    child.child = { replan_sequence: 1, parent_execution_run_id: "parent-run-native",
      lineage_sha256: "9".repeat(64), preview_id: "child-preview" };
    vi.mocked(api.getAutonomousCampaignStatus).mockResolvedValue(child);
    await user.click(screen.getByRole("button", { name: "Confirm child plan preparation" }));
    await waitFor(() => expect(api.prepareAutonomousCampaignChild).toHaveBeenCalledWith("server-native-campaign", 7,
      "server-native-roe", expect.any(String)));
    expect(await screen.findByRole("button", { name: "Approve plan" })).toBeVisible();
    expect(screen.queryByRole("button", { name: "Admit and start" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Prepare child plan" })).toBeNull();
    expect(api.decideAutonomousCampaignPlan).not.toHaveBeenCalled();
    expect(api.admitAutonomousCampaign).not.toHaveBeenCalled();
    expect(screen.getByText(/parent receipts do not transfer/i)).toBeVisible();
  });

  it("records an explicit PLAN_ONLY denial without any admission or execution", async () => {
    const api = normalClient("plan_only");
    const user = await prepareNormal(api);
    await user.click(screen.getByRole("button", { name: "Deny plan" }));
    expect(api.decideAutonomousCampaignPlan).not.toHaveBeenCalled();
    vi.mocked(api.getAutonomousCampaignStatus).mockResolvedValue(normalStatus("DENIED", 4, "plan_only"));
    await user.click(screen.getByRole("button", { name: "Confirm plan denial" }));
    await waitFor(() => expect(api.decideAutonomousCampaignPlan).toHaveBeenCalledWith("deny", "server-native-campaign",
      { preview_id: "preview-native", preview_sha256: "a".repeat(64) }, '"server-preview-token"', expect.any(String)));
    expect(api.admitAutonomousCampaign).not.toHaveBeenCalled();
    expect(api.startCampaignCore).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Admit and start" })).toBeNull();
  });

  it("reuses the exact preparation key after uncertain transport without falling back to legacy", async () => {
    const api = normalClient();
    vi.mocked(api.prepareAutonomousCampaignPlan).mockRejectedValueOnce(new Error("lost stage acknowledgement"))
      .mockResolvedValue(normalPreview());
    const user = userEvent.setup();
    render(<CampaignCoreFeature client={api} />);
    await user.selectOptions(await screen.findByLabelText("Authorized engagement"), "opaque-eng-a");
    await user.selectOptions(await screen.findByLabelText("Authorized target"), "opaque-target-a");
    await user.selectOptions(screen.getByLabelText("Objective"), "Assess HTTP security posture");
    await user.selectOptions(await screen.findByLabelText("Risk profile"), "opaque-risk");
    await user.click(screen.getByRole("button", { name: "Prepare plan" }));
    await screen.findByRole("alert");
    await user.click(screen.getByRole("button", { name: "Prepare plan" }));
    await screen.findByRole("heading", { name: "Immutable plan" });
    const attempts = vi.mocked(api.prepareAutonomousCampaignPlan).mock.calls;
    expect(attempts).toHaveLength(2);
    expect(attempts[0]?.[3]).toBe(attempts[1]?.[3]);
    expect(api.startCampaignCore).not.toHaveBeenCalled();
    expect(api.createAutonomousCampaignIntent).toHaveBeenCalledTimes(1);
  });

  it("resumes a server-listed canonical campaign with creation disabled and never reads legacy detail", async () => {
    const api = normalClient();
    const current = normalStatus("RUNNING", 6);
    current.operations.execution.state = "running";
    vi.mocked(api.getAutonomousCampaignStatus).mockReset().mockResolvedValue(current);
    vi.mocked(api.getAutonomousCampaignAvailability).mockResolvedValue({ canonical_configured: true,
      create_available: false, preparation_available: false, status_available: true, stop_available: true,
      revoke_available: true, mode: "disabled", legacy_available: false, reason: "operator_creation_unavailable" });
    const read: CampaignReadClient = { ...api, listCampaignCoreCampaigns: vi.fn().mockResolvedValue({
      data: [{ campaign_id: current.campaign_id, label: "Owned fixture campaign", status: "RUNNING",
        authority_state: "requires_current_verification", attention_reason: null, aggregate_sequence: 6, operator_kind: "canonical" }],
      page: { limit: 50, next_cursor: null } }), getCampaignOperations: vi.fn(), listCampaignCoreAttention: vi.fn() };
    const user = userEvent.setup();
    render(<CampaignStatusFeature client={read} />);
    await user.click(await screen.findByRole("button", { name: "View current status" }));
    expect(await screen.findByRole("heading", { name: "Immutable plan" })).toBeVisible();
    expect(api.getCampaignCoreCampaign).not.toHaveBeenCalled();
    expect(read.getCampaignOperations).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Request containment" })).toBeEnabled();
    expect(screen.queryByRole("button", { name: "Prepare plan" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Admit and start" })).toBeNull();
  });

  it("keeps canonical status failure visible without adopting legacy results", async () => {
    const api = normalClient();
    vi.mocked(api.getAutonomousCampaignStatus).mockReset().mockRejectedValue(new Error("owner missing"));
    const read: CampaignReadClient = { ...api, listCampaignCoreCampaigns: vi.fn().mockResolvedValue({
      data: [{ campaign_id: "server-native-campaign", label: "Owned fixture campaign", status: "RUNNING",
        authority_state: "requires_current_verification", attention_reason: null, aggregate_sequence: 6, operator_kind: "canonical" }],
      page: { limit: 50, next_cursor: null } }), getCampaignOperations: vi.fn(), listCampaignCoreAttention: vi.fn() };
    const user = userEvent.setup();
    render(<CampaignStatusFeature client={read} />);
    await user.click(await screen.findByRole("button", { name: "View current status" }));
    expect(await screen.findByRole("alert")).toBeVisible();
    expect(api.getCampaignCoreCampaign).not.toHaveBeenCalled();
    expect(screen.queryByRole("button", { name: "Request containment" })).toBeNull();
  });

  it("prepares, previews and separately confirms exact approval and admission without legacy start", async () => {
    const api = normalClient();
    const user = await prepareNormal(api);
    expect(api.startCampaignCore).not.toHaveBeenCalled();
    expect(api.decideAutonomousCampaignPlan).not.toHaveBeenCalled();
    expect(api.admitAutonomousCampaign).not.toHaveBeenCalled();
    expect(screen.getByText("validator-v1")).toBeVisible();
    expect(screen.getByText(/120 seconds/)).toBeVisible();
    expect(screen.getAllByText(/receipt required/i).length).toBeGreaterThan(0);
    await user.click(screen.getByRole("button", { name: "Approve plan" }));
    expect(screen.getByRole("dialog", { name: "Confirm plan approval" })).toBeVisible();
    expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus();
    expect(api.decideAutonomousCampaignPlan).not.toHaveBeenCalled();
    vi.mocked(api.getAutonomousCampaignStatus).mockResolvedValue(normalStatus("APPROVED", 4));
    await user.click(screen.getByRole("button", { name: "Confirm plan approval" }));
    await waitFor(() => expect(api.decideAutonomousCampaignPlan).toHaveBeenCalledWith("approve",
      "server-native-campaign", { preview_id: "preview-native", preview_sha256: "a".repeat(64) },
      '"server-preview-token"', expect.any(String)));
    await user.click(await screen.findByRole("button", { name: "Admit and start" }));
    expect(api.admitAutonomousCampaign).not.toHaveBeenCalled();
    vi.mocked(api.getAutonomousCampaignStatus).mockResolvedValue(normalStatus("EXECUTION_QUEUED", 6));
    await user.click(screen.getByRole("button", { name: "Confirm admission and start" }));
    await waitFor(() => expect(api.admitAutonomousCampaign).toHaveBeenCalledWith("server-native-campaign",
      { approval_receipt_id: "approval-native", approval_receipt_sha256: "8".repeat(64) },
      '"server-approval-token"', expect.any(String)));
    expect(vi.mocked(api.decideAutonomousCampaignPlan).mock.calls[0]?.[4])
      .not.toBe(vi.mocked(api.admitAutonomousCampaign).mock.calls[0]?.[3]);
    expect(screen.getByRole("button", { name: "Export evidence" })).toBeDisabled();
    expect(screen.queryByLabelText(/campaign id|target id|mode|proof|url/i)).toBeNull();
  });

  it("fails closed on unavailable canonical authority and never falls back to legacy", async () => {
    const api = normalClient();
    vi.mocked(api.getAutonomousCampaignAvailability).mockRejectedValue(new Error("owner unavailable"));
    render(<CampaignCoreFeature client={api} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/unavailable/i);
    expect(screen.queryByRole("button", { name: "Start authorized campaign" })).toBeNull();
    expect(api.listCampaignCoreEngagementOptions).not.toHaveBeenCalled();
    expect(api.startCampaignCore).not.toHaveBeenCalled();
  });

  it("refreshes a 409 approval and requires a new human confirmation", async () => {
    const api = normalClient();
    const user = await prepareNormal(api);
    vi.mocked(api.decideAutonomousCampaignPlan).mockRejectedValue(new ConsoleApiError(
      "application_revision_conflict", "Refresh before confirming again.", 409, null));
    const changed = normalStatus("AWAITING_APPROVAL", 5);
    changed.preview = { ...normalPreview(), preview_id: "preview-new", application_revision: 5 };
    changed.preview_etag = '"server-new-preview-token"';
    vi.mocked(api.getAutonomousCampaignStatus).mockResolvedValue(changed);
    await user.click(screen.getByRole("button", { name: "Approve plan" }));
    await user.click(screen.getByRole("button", { name: "Confirm plan approval" }));
    await screen.findByRole("alert");
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(api.decideAutonomousCampaignPlan).toHaveBeenCalledTimes(1);
    expect(api.admitAutonomousCampaign).not.toHaveBeenCalled();
    expect(screen.getByText(/review the refreshed state and confirm again/i)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Approve plan" }));
    expect(api.decideAutonomousCampaignPlan).toHaveBeenCalledTimes(1);
  });

  it("keeps stop acknowledgement, incomplete cleanup and export unavailability distinct with keyboard recovery", async () => {
    const api = normalClient();
    const user = await prepareNormal(api);
    const running = normalStatus("RUNNING", 6);
    running.operations.execution.state = "running";
    vi.mocked(api.getAutonomousCampaignStatus).mockResolvedValue(running);
    await user.click(screen.getByRole("button", { name: "Refresh current status" }));
    const trigger = await screen.findByRole("button", { name: "Request containment" });
    await user.click(trigger);
    await user.keyboard("{Escape}");
    expect(api.recoverAutonomousCampaign).not.toHaveBeenCalled();
    await waitFor(() => expect(trigger).toHaveFocus());
    await user.click(trigger);
    await user.click(screen.getByRole("button", { name: "Confirm containment request" }));
    await waitFor(() => expect(api.recoverAutonomousCampaign).toHaveBeenCalledWith("stop", "server-native-campaign",
      6, '"server-current-6"', expect.stringContaining("containment"), expect.any(String)));
    expect(screen.getByText(/a stop request does not prove containment or cleanup/i)).toBeVisible();
    expect(screen.getByRole("button", { name: "Export evidence" })).toBeDisabled();
  });

  it("does not offer approval for an expired preview or execution in PLAN_ONLY", async () => {
    const api = normalClient();
    const expired = normalStatus();
    expired.preview_expired = true;
    expired.mode = "plan_only";
    vi.mocked(api.getAutonomousCampaignStatus).mockReset().mockResolvedValueOnce(normalStatus("INTENT_CREATED", 1))
      .mockResolvedValue(expired);
    await prepareNormal(api);
    expect(screen.queryByRole("button", { name: "Approve plan" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Admit and start" })).toBeNull();
    expect(screen.getByText(/preview has expired/i)).toBeVisible();
  });
});
