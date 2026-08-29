import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { CampaignOperations } from "../../lib/apiClient";

import {
  CampaignAttentionFeature,
  CampaignCoreFeature,
  CampaignStatusFeature,
  type CampaignCoreClient,
  type CampaignReadClient,
} from "./CampaignCoreFeature";


function client(): CampaignCoreClient {
  return {
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
