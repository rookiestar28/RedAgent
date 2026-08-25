import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";


describe("policy console", () => {
  it("renders convergence and decision metadata and runs only a fixed fixture", async () => {
    window.history.replaceState({}, "", "/policy");
    let simulationCount = 0;
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      const path = url.pathname;
      if (path === "/api/v1/context") return Promise.resolve(json({ data: {
        subject: "operator-1", tenant_id: "tenant-1",
        permissions: ["engagement:read", "policy:read", "policy:simulate", "policy:promote", "policy:rollback"], roles: ["operator"],
      }}));
      if (path === "/api/v1/engagements") return Promise.resolve(json({ data: [], page: page(0) }));
      if (path === "/api/v1/policy/status") return Promise.resolve(json({ data: {
        required_revision: "r099-v1", previous_revision: "r099-v0", promotion_state: "promoted",
        required_agents: ["api-pdp"], acknowledged_agents: ["api-pdp"], converged: true,
      }}));
      if (path === "/api/v1/policy/bundles" && url.searchParams.get("offset") === "1") {
        return Promise.resolve(json({ data: [{
          revision: "r099-draft", artifact_sha256: "d".repeat(64), artifact_size: 1024,
          author_user_id: "operator-1", reviewer_user_id: "reviewer-1", rego_version: 1,
          coverage_basis_points: 9000, signing_key_id: "key-1", status: "draft",
          created_at: "2026-07-10T12:00:00Z", version: 1,
        }], page: page(1, 1, null) }));
      }
      if (path === "/api/v1/policy/bundles") return Promise.resolve(json({ data: [{
        revision: "r099-v2", artifact_sha256: "c".repeat(64), artifact_size: 2048,
        author_user_id: "author-1", reviewer_user_id: "reviewer-1", rego_version: 1,
        coverage_basis_points: 10000, signing_key_id: "key-1", status: "accepted",
        created_at: "2026-07-10T13:00:00Z", version: 3,
      }], page: page(1, 0, 1) }));
      if (path === "/api/v1/policy/decisions" && url.searchParams.get("offset") === "1") {
        return Promise.resolve(json({ data: [{
          decision_id: "decision-2", bundle_revision: "r099-v1", input_hash: "e".repeat(64),
          boundary: "workflow", action: "job.command", subject_id: "operator-2", resource_type: "job",
          resource_id: "job-2", allowed: false, reason_code: "policy_denied",
          obligations: ["audit"], issued_at: "2026-07-10T14:01:00Z",
          valid_until: "2026-07-10T14:01:30Z", correlation_id: "correlation-2",
        }], page: page(1, 1, null) }));
      }
      if (path === "/api/v1/policy/decisions") return Promise.resolve(json({ data: [{
        decision_id: "decision-1", bundle_revision: "r099-v1", input_hash: "a".repeat(64),
        boundary: "api", action: "job:create", subject_id: "operator-1", resource_type: "job",
        resource_id: "job-1", allowed: true, reason_code: "boundary_authorized",
        obligations: ["audit"], issued_at: "2026-07-10T14:00:00Z",
        valid_until: "2026-07-10T14:00:30Z", correlation_id: "correlation-1",
      }], page: page(1, 0, 1) }));
      if (path === "/api/v1/policy/simulations" && request.method === "POST") {
        simulationCount += 1;
        return Promise.resolve(simulationCount === 1
          ? json({ data: {
            fixture: "api-job-create", decision_id: "decision-sim", receipt_id: "receipt-sim",
            bundle_revision: "r099-v1", input_hash: "b".repeat(64), obligations: ["audit"],
          }})
          : json({ error: { code: "policy_denied", message: "Fixed fixture denied", correlation_id: "correlation-policy-denied" } }, 403));
      }
      if (path === "/api/v1/policy/promotions" && request.method === "POST") return Promise.resolve(json({
        data: { revision: "r099-v2", previous_revision: "r099-v1", state: "promoted",
          required_agents: ["api", "workflow", "evidence", "secret", "runner"],
          acknowledged_agents: ["api", "workflow", "evidence", "secret", "runner"],
          promoted_at: "2026-07-10T15:00:00Z", version: 1 }, meta: { replayed: false },
      }));
      if (path === "/api/v1/policy/rollbacks" && request.method === "POST") return Promise.resolve(json({
        data: { revision: "r099-v2", previous_revision: "r099-v1", state: "rollback_promoted",
          required_agents: ["api", "workflow", "evidence", "secret", "runner"],
          acknowledged_agents: ["api", "workflow", "evidence", "secret", "runner"],
          promoted_at: "2026-07-10T15:01:00Z", version: 1 }, meta: { replayed: false },
      }));
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    expect((await screen.findAllByText("r099-v1"))[0]).toBeVisible();
    expect(screen.getByText("job:create")).toBeVisible();
    expect(screen.getByText("Converged")).toBeVisible();
    expect(screen.queryByLabelText(/rego/i)).not.toBeInTheDocument();
    expect(screen.queryAllByLabelText("Expected version")).toHaveLength(0);
    await user.click(screen.getByRole("button", { name: "Run fixed fixture" }));
    expect(await screen.findByText(/receipt receipt-sim/i)).toBeVisible();

    const promoteForm = screen.getByRole("form", { name: "Promote policy revision" });
    await user.selectOptions(within(promoteForm).getByLabelText("Accepted revision"), "r099-v2");
    await user.type(within(promoteForm).getByLabelText("Reason"), "Promote fully reviewed policy");
    await user.click(within(promoteForm).getByRole("button", { name: "Promote after convergence" }));
    expect(await screen.findByText(/^Promoted: r099-v2/)).toBeVisible();
    const promotion = findMutation(fetchMock, "/api/v1/policy/promotions");
    expect(await readRequestRecord(promotion)).toMatchObject({
      revision: "r099-v2",
      expected_version: 3,
      reason: "Promote fully reviewed policy",
    });

    const rollbackForm = screen.getByRole("form", { name: "Rollback policy revision" });
    await user.selectOptions(within(rollbackForm).getByLabelText("Accepted revision"), "r099-v2");
    await user.type(within(rollbackForm).getByLabelText("Reason"), "Rollback after reviewed incident");
    await user.click(within(rollbackForm).getByRole("button", { name: "Rollback after convergence" }));
    expect(await screen.findByText(/^Rollback Promoted: r099-v2/)).toBeVisible();
    expect(await readRequestRecord(findMutation(fetchMock, "/api/v1/policy/rollbacks"))).toMatchObject({
      revision: "r099-v2",
      expected_version: 3,
      reason: "Rollback after reviewed incident",
    });

    await user.selectOptions(screen.getByLabelText("Fixture"), "secret-lease");
    await user.click(screen.getByRole("button", { name: "Run fixed fixture" }));
    expect(await screen.findByText("Simulation denied")).toBeVisible();
    expect(screen.getByText(/correlation-policy-denied/)).toBeVisible();

    await user.click(screen.getByRole("button", { name: "Next decisions" }));
    expect(await screen.findByText("job.command")).toBeVisible();
    expect(screen.getByText("Denied")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Next bundles" }));
    expect(await screen.findByText("r099-draft")).toBeVisible();
    expect(screen.getByText("Unavailable: author cannot promote the same bundle.")).toBeVisible();
  });

  it("shows rollback-required policy truth without enabling unavailable bundles", async () => {
    window.history.replaceState({}, "", "/policy");
    vi.stubGlobal("fetch", policyReadFetch({
      required_revision: "r099-v2", previous_revision: "r099-v1", promotion_state: "rollback_required",
      required_agents: ["api", "workflow"], acknowledged_agents: ["api"], converged: false,
    }));

    render(<App />);

    expect(await screen.findByText("Rollback required")).toBeVisible();
    expect(screen.getByText("Not converged")).toBeVisible();
    expect(screen.getByRole("button", { name: "Promote after convergence" })).toBeDisabled();
  });

  it("renders policy-unavailable failure with correlation and retry", async () => {
    window.history.replaceState({}, "", "/policy");
    let statusReads = 0;
    const user = userEvent.setup();
    const fetchMock = policyReadFetch(null, () => { statusReads += 1; return statusReads === 1; });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);

    expect(await screen.findByRole("alert", { name: "Policy unavailable" })).toBeVisible();
    expect(screen.getByText("Correlation: correlation-policy-unavailable")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Retry route data" }));
    expect(await screen.findByText("No policy decisions recorded")).toBeVisible();
    expect(statusReads).toBe(2);
  });
});


function page(returned: number, offset = 0, nextOffset: number | null = null) {
  return { limit: 50, offset, returned, next_offset: nextOffset };
}
function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}

function findMutation(fetchMock: ReturnType<typeof vi.fn<typeof fetch>>, path: string): Request | undefined {
  return fetchMock.mock.calls
    .map(([input, init]) => input instanceof Request ? input : new Request(input, init))
    .find((request) => request.method === "POST" && new URL(request.url).pathname === path);
}

async function readRequestRecord(request: Request | undefined): Promise<Record<string, unknown>> {
  if (!request) throw new Error("Expected mutation request");
  const value = JSON.parse(await request.clone().text()) as unknown;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("Expected JSON object");
  return value as Record<string, unknown>;
}

function policyReadFetch(
  status: object | null,
  unavailable?: () => boolean,
): ReturnType<typeof vi.fn<typeof fetch>> {
  const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return Promise.resolve(json({ data: {
      subject: "operator-1", tenant_id: "tenant-1",
      permissions: ["engagement:read", "policy:read", "policy:promote", "policy:rollback"], roles: ["operator"],
    } }));
    if (path === "/api/v1/policy/status") {
      if (unavailable?.()) return Promise.resolve(json({ error: {
        code: "policy_unavailable", message: "Policy enforcement unavailable",
        correlation_id: "correlation-policy-unavailable",
      } }, 503));
      return Promise.resolve(json({ data: status ?? {
        required_revision: "r099-v1", previous_revision: null, promotion_state: "unregistered",
        required_agents: [], acknowledged_agents: [], converged: false,
      } }));
    }
    if (path === "/api/v1/policy/decisions" || path === "/api/v1/policy/bundles") {
      return Promise.resolve(json({ data: [], page: page(0) }));
    }
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  });
  return fetchMock;
}
