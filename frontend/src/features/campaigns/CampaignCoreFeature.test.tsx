import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

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
    expect(screen.getByRole("button", { name: "Stop & revoke" })).toBeVisible();
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
    expect(screen.getByRole("button", { name: "Stop & revoke" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Stop & revoke" }));
    await waitFor(() => expect(readClient.recoverCampaignCore).toHaveBeenCalledWith(
      "stop",
      "campaign-internal-hidden",
      '"campaign-internal-hidden:2"',
      expect.stringContaining("persistent status"),
    ));
    expect(screen.queryByText("campaign-internal-hidden")).toBeNull();
  });

  it("shows governed recovery guidance for bounded attention categories", async () => {
    const readClient: CampaignReadClient = {
      listCampaignCoreCampaigns: vi.fn(),
      getCampaignCoreCampaign: vi.fn(),
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
    expect(screen.getByRole("button", { name: "Stop & revoke" })).toBeVisible();
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
