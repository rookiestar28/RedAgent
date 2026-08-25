import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";

beforeEach(() => { window.history.replaceState({}, "", "/artifact-posture"); });
afterEach(() => { vi.unstubAllGlobals(); });

test("renders pinned zero-execution artifact truth and fully redacted findings", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-1", tenant_id: "tenant-r110", roles: ["operator"], permissions: ["job:read", "job:create", "job:stop", "audit:read"]}});
    if (path === "/api/v1/engagements") return json({data: [], page: {limit: 50, offset: 0, total: 0}});
    if (path === "/api/v1/artifact-posture/profiles") return json({data: [profile()]});
    if (path === "/api/v1/artifact-posture/dashboard") return json({data: {profiles: [profile()], plans: [], runs: [{run_id: "run-r110", plan_id: "plan-r110", job_id: "job-r110", runner_id: "runner-r110", run_state: "succeeded", complete: false, partial_reasons: ["component-identity-incomplete"], result_sha256: "a".repeat(64), untrusted_execution_count: 0, version: 2}], components: [{component_id: "component-r110"}], vulnerabilities: [{advisory_id: "R110-ADVISORY-1"}], credential_findings: [{fingerprint: "b".repeat(64), redacted_fragment: "[REDACTED]"}], static_findings: [{rule_id: "ci-dangerous-checkout"}], mobile: [{control_id: "mobile-debuggable"}], cleanups: [{receipt_id: "cleanup-r110"}]}});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); render(<App />);
  expect(await screen.findByRole("heading", {name: "Repository, CI, and mobile posture"})).toBeInTheDocument();
  expect(screen.getByText(/repo-owned canonical data fixtures/i)).toBeInTheDocument();
  expect(await screen.findByText(/repository_snapshot · zero execution/i)).toBeInTheDocument();
  expect(screen.getByText(/component-identity-incomplete/)).toBeInTheDocument();
  expect(screen.getByText("Untrusted executions")).toBeInTheDocument();
  expect(screen.getByText(/1 fully redacted credential findings/i)).toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryByLabelText(/repository url|archive path|content|token|command|scanner|rule|mobile binary/i)).not.toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryAllByLabelText(/^Plan ID$|Artifact binding \/ lease ID|Policy decision ID|Policy revision|Approved ROE version ID|Quota reservation ID/i)).toHaveLength(0);
  expect(within(screen.getByRole("main")).queryAllByLabelText(/^Run ID$|Compiled plan ID|^Job ID$|^Runner ID$/i)).toHaveLength(0);
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});

test("fails closed locally when artifact posture read authority is absent", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {
      subject: "operator-1", tenant_id: "tenant-r110", roles: ["operator"], permissions: [],
    }});
    return json({error: {code: "unexpected_request", message: "Unexpected request"}});
  });
  vi.stubGlobal("fetch", fetchMock);

  render(<App />);
  expect(await screen.findByRole("alert", {name: "Route access denied"})).toBeVisible();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("derives canonical zero-execution compile and queue bindings", async () => {
  const payloads: Array<Record<string, unknown>> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(input, init);
    const path = new URL(request.url).pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-1", tenant_id: "tenant-r110", roles: ["operator"], permissions: ["job:read", "audit:read", "job:create", "policy:read"]}});
    if (path === "/api/v1/artifact-posture/profiles") return json({data: [profile()]});
    if (path === "/api/v1/policy/decisions") return json({data: [policyDecision()], page: page(1)});
    if (path === "/api/v1/artifact-posture/dashboard") return json({data: {
      profiles: [profile()], plans: [], runs: [], components: [], vulnerabilities: [], credential_findings: [], static_findings: [], mobile: [], cleanups: [],
      binding_options: [{binding_id: "binding-r110", artifact_kind: "repository_snapshot", declared_files: 1, declared_bytes: 128, binding_state: "active-canonical-fixture", expires_at: "2099-01-01T00:00:00Z"}],
      runner_options: [{runner_id: "runner-r110", environment: "local-conformance", network_plane: "none", required_policy_revision: "r099-v1", registration_state: "active", expires_at: "2099-01-01T00:00:00Z"}],
      job_options: [{job_id: "job-r110", engagement_id: "engagement-r110", roe_version_id: "roe-r110", status: "approved", current_gate: "runner_dispatch", dispatch_blocked: false, stop_requested: false}],
      reservation_options: [{reservation_id: "reservation-r110", reserved_amount: 8, consumed_amount: 0, released_amount: 0, remaining_amount: 8, reservation_state: "reserved", expires_at: "2099-01-01T00:00:00Z"}],
    }});
    if (path === "/api/v1/artifact-posture/plans" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>; payloads.push(body);
      return json({data: {plan_id: body.plan_id, profile_id: body.profile_id, artifact_binding_id: body.artifact_binding_id, policy_decision_id: body.policy_decision_id, reservation_id: body.reservation_id, artifact_lease_id: body.artifact_lease_id, plan_sha256: "a".repeat(64), plan_state: "compiled-canonical-fixture", expires_at: "2099-01-01T00:00:00Z", version: 1}}, 201);
    }
    if (path === "/api/v1/artifact-posture/runs" && request.method === "POST") {
      const body = await request.json() as Record<string, unknown>; payloads.push(body);
      return json({data: {...body, run_state: "dispatch_pending", complete: false, partial_reasons: [], result_sha256: null, untrusted_execution_count: 0, version: 1}}, 202);
    }
    return json({error: {code: "not_found", message: "Not found"}}, 404);
  });
  vi.stubGlobal("fetch", fetchMock); const user = userEvent.setup(); render(<App />);
  await user.selectOptions(await screen.findByRole("combobox", {name: "Certified profile"}), "r110-repository-snapshot-v1");
  const jobs = screen.getAllByRole("combobox", {name: "Authorized artifact job"});
  await user.selectOptions(jobs[0]!, "job-r110");
  await user.selectOptions(screen.getByRole("combobox", {name: "Current policy decision"}), "decision-r110");
  await user.selectOptions(screen.getByRole("combobox", {name: "Canonical artifact binding"}), "binding-r110");
  await user.selectOptions(screen.getByRole("combobox", {name: "Active quota reservation"}), "reservation-r110");
  await user.click(screen.getByRole("button", {name: "Compile zero-execution plan"}));
  expect(await screen.findByText(/Compiled zero-execution assessment/)).toBeVisible();
  expect(payloads[0]?.plan_id).toMatch(/^artifact-plan-[0-9a-f-]+$/);
  expect(payloads[0]).toMatchObject({profile_id: "r110-repository-snapshot-v1", artifact_binding_id: "binding-r110", artifact_lease_id: "binding-r110", policy_decision_id: "decision-r110", policy_revision: "r099-v1", roe_version_id: "roe-r110", reservation_id: "reservation-r110", confirmation: "--confirm-r110-canonical-fixture"});
  const planId = String(payloads[0]?.plan_id);
  await user.selectOptions(screen.getByRole("combobox", {name: "Compiled plan"}), planId);
  await user.selectOptions(jobs[1]!, "job-r110");
  await user.selectOptions(screen.getByRole("combobox", {name: "Compatible data-only runner"}), "runner-r110");
  await user.click(screen.getByRole("button", {name: "Queue local analysis"}));
  expect(await screen.findByText(/Queued .* selected artifact posture job/)).toBeVisible();
  expect(payloads[1]?.run_id).toMatch(/^artifact-run-[0-9a-f-]+$/);
  expect(payloads[1]).toMatchObject({plan_id: planId, job_id: "job-r110", runner_id: "runner-r110", confirmation: "--confirm-r110-canonical-fixture"});
});

test("projects a correlated artifact outage and retries without inferring findings", async () => {
  let attempts = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "operator-1", tenant_id: "tenant-r110", roles: ["operator"], permissions: ["job:read", "audit:read"]}});
    if (path === "/api/v1/artifact-posture/profiles") return json({data: [profile()]});
    if (path === "/api/v1/artifact-posture/dashboard" && attempts++ === 0) return json({error: {code: "artifact_posture_unavailable", message: "Artifact posture runtime unavailable", correlation_id: "corr-artifact"}}, 503);
    if (path === "/api/v1/artifact-posture/dashboard") return json({data: {profiles: [profile()], plans: [], runs: [], components: [], vulnerabilities: [], credential_findings: [], static_findings: [], mobile: [], cleanups: [], binding_options: [], runner_options: [], job_options: [], reservation_options: []}});
    return json({error: {code: "not_found", message: "Not found"}}, 404);
  });
  vi.stubGlobal("fetch", fetchMock); const user = userEvent.setup(); render(<App />);
  expect(await screen.findByRole("alert", {name: "Artifact posture runtime unavailable"})).toBeVisible();
  expect(screen.getByText("Correlation: corr-artifact")).toBeVisible();
  await user.click(screen.getByRole("button", {name: "Retry route data"}));
  expect(await screen.findByText("No artifact posture runs recorded")).toBeVisible();
  expect(attempts).toBe(2);
});

function profile() { return {profile_id: "r110-repository-snapshot-v1", artifact_kind: "repository_snapshot", stages: ["manifest_validate", "sbom", "license", "credential_pattern", "structural", "ci_workflow"], max_files: 64, max_bytes: 262144, max_depth: 8, max_expansion_ratio: 20, profile_state: "certified-local-lab", zero_execution: true, production_qualified: false}; }
function policyDecision() { return {decision_id: "decision-r110", bundle_revision: "r099-v1", input_hash: "a".repeat(64), boundary: "api", action: "artifact.plan.compile", subject_id: "operator-1", resource_type: "artifact_profile", resource_id: "r110-repository-snapshot-v1", allowed: true, reason_code: "r110_profile_approved", obligations: ["canonical_fixture_only"], issued_at: "2026-08-25T00:00:00Z", valid_until: "2099-01-01T00:00:00Z", correlation_id: "corr-policy"}; }
function page(total: number) { return {limit: 50, offset: 0, total, has_more: false}; }
function json(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), {status, headers: {"content-type": "application/json"}})); }
