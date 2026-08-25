import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, expect, test, vi } from "vitest";

import { App } from "./App";

beforeEach(() => { window.history.replaceState({}, "", "/finding-operations"); });
afterEach(() => { vi.unstubAllGlobals(); });

test("shows reviewed issues occurrence lineage publication truth and network-free delivery without unsafe inputs", async () => {
  const now = "2026-07-12T14:00:00Z";
  const issue = {issue_id: "issue-r115", issue_fingerprint: "a".repeat(64), title: "Missing HSTS",
    severity: "medium", confidence: "confirmed", disposition: "confirmed", disposition_revision: 2,
    owner_id: "reviewer-r115", sla_due_at: "2026-07-20T00:00:00Z", first_seen_at: now,
    last_seen_at: now, issue_state: "active", version: 2};
  const occurrence = {occurrence_id: "occurrence-r115", issue_id: issue.issue_id, tool_id: "r115-fixture",
    tool_version: "1.0.0", rule_id: "fixture-missing-hsts", rule_version: "r115-closed-v1",
    database_version: "fixture-db-1", coverage_state: "complete", occurrence_state: "observed",
    evidence_id: "evidence-r115", evidence_sha256: "d".repeat(64), redaction_state: "report_safe",
    observed_at: now, version: 1};
  const report = {report_id: "report-r115", audience: "technical", reviewed_snapshot_sha256: "b".repeat(64),
    policy_revision: "r099-v1", roe_version_id: "roe-r115-reviewed", coverage_state: "complete",
    report_sha256: "c".repeat(64), generation_profile: "deterministic-json-v1", report_state: "publishable",
    generated_by: "generator-r115", generated_at: now, version: 1};
  const publication = {publication_id: "publication-r115", report_id: report.report_id,
    report_sha256: report.report_sha256, reviewer_id: "generator-r115", publisher_id: "publisher-r115",
    publication_state: "published", published_at: now, version: 1};
  const delivery = {delivery_id: "delivery-r115", profile_id: "fixture-ticket-v1", report_id: report.report_id,
    snapshot_sha256: report.report_sha256, delivery_state: "queued", attempt_count: 0,
    network_contact_count: 0, next_attempt_at: now, version: 1};
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "reviewer-r115", tenant_id: "tenant-r115",
      roles: ["reviewer"], permissions: ["engagement:read", "finding:read", "finding:review", "report:create"]}});
    if (path === "/api/v1/engagements") return json({data: [], page: {limit: 50, offset: 0, total: 0}});
    if (path === "/api/v1/finding-operations/dashboard") return json({data: {
      issues: [issue], occurrences: [occurrence], reports: [report], publications: [publication], deliveries: [delivery]}});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); render(<App />);
  expect(await screen.findByRole("heading", {name: "Finding and remediation operations"})).toBeInTheDocument();
  expect(await screen.findByText(/confirmed · revision 2/i)).toBeInTheDocument();
  expect(screen.getByText(/fixture-missing-hsts · complete · observed/i)).toBeInTheDocument();
  expect(screen.getByText(/publishable · deterministic-json-v1/i)).toBeInTheDocument();
  expect(screen.getByText(/queued · 0 attempts · 0 network contacts/i)).toBeInTheDocument();
  expect(screen.getByText(/needs review/i)).toBeInTheDocument();
  expect(screen.getByText(/SLA breaches/i)).toBeInTheDocument();
  expect(screen.getByText(/exception expiry/i)).toBeInTheDocument();
  expect(screen.getByText(/publication blocked/i)).toBeInTheDocument();
  expect(screen.getByLabelText("Search findings")).toBeInTheDocument();
  expect(screen.queryByLabelText(/Import ID|Stored run ID|Source record ID|Resource ID|Approved evidence ID|Approved evidence SHA-256/i)).not.toBeInTheDocument();
  expect(within(screen.getByRole("main")).queryByLabelText(/raw evidence|payload|url|command|args|environment|header|token|credential|prompt|reasoning|scanner flags/i)).not.toBeInTheDocument();
  await waitFor(() => expect(fetchMock).toHaveBeenCalled());
});

test("fails closed locally without finding read authority", async () => {
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "reviewer-r115", tenant_id: "tenant-r115",
      roles: ["reviewer"], permissions: []}});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock); render(<App />);

  expect(await screen.findByRole("alert", {name: "Route access denied"})).toBeInTheDocument();
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

test("imports only a selected report-safe evidence row with generated fixture bindings", async () => {
  const payloads: Array<Record<string, unknown>> = [];
  const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const request = input instanceof Request ? input : new Request(String(input), init);
    const path = new URL(request.url, "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "reviewer-r115", tenant_id: "tenant-r115",
      roles: ["reviewer"], permissions: ["finding:read", "finding:ingest", "evidence:read"]}});
    if (path === "/api/v1/finding-operations/dashboard") return json({data: {
      issues: [], occurrences: [], reports: [], publications: [], deliveries: []}});
    if (path === "/api/v1/evidence/artifacts") return json({data: [{
      artifact_id: "evidence-report-safe", artifact_class: "report_safe", quarantine_reason: null,
      content_sha256: "d".repeat(64), retain_until: "2026-09-25T00:00:00Z",
    }], page: {limit: 50, offset: 0, returned: 1, next_offset: null}});
    if (path === "/api/v1/finding-operations/imports" && request.method === "POST") {
      payloads.push(await request.json() as Record<string, unknown>);
      return json({data: {import_id: payloads[0]?.import_id, issue_count: 1, occurrence_count: 1}});
    }
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  const user = userEvent.setup(); render(<App />);

  await user.selectOptions(await screen.findByRole("combobox", {name: "Approved report-safe evidence"}), "evidence-report-safe");
  await user.click(screen.getByRole("button", {name: "Import fixture result"}));
  expect(await screen.findByText("Accepted normalized fixture result imported from approved report-safe evidence.")).toBeInTheDocument();
  expect(payloads[0]).toMatchObject({
    evidence_id: "evidence-report-safe", evidence_sha256: "d".repeat(64), coverage_state: "complete",
    baseline_run_id: null, confirmation: "--confirm-r115-fixture-import",
  });
  for (const field of ["import_id", "run_id", "source_record_id", "resource_id"] as const) {
    expect(payloads[0]?.[field]).toMatch(/^fixture-(import|run|source|resource)-[0-9a-f-]+$/);
  }
});

test("projects a correlated finding-operations outage and retries", async () => {
  let attempts = 0;
  const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
    const path = new URL(input instanceof Request ? input.url : String(input), "http://localhost").pathname;
    if (path === "/api/v1/context") return json({data: {subject: "reviewer-r115", tenant_id: "tenant-r115",
      roles: ["reviewer"], permissions: ["finding:read"]}});
    if (path === "/api/v1/finding-operations/dashboard" && attempts++ === 0) return json({error: {
      code: "finding_operations_unavailable", message: "Finding operations unavailable", correlation_id: "corr-findings",
    }}, 503);
    if (path === "/api/v1/finding-operations/dashboard") return json({data: {
      issues: [], occurrences: [], reports: [], publications: [], deliveries: []}});
    throw new Error(`unexpected path ${path}`);
  });
  vi.stubGlobal("fetch", fetchMock);
  const user = userEvent.setup(); render(<App />);

  expect(await screen.findByRole("alert", {name: "Finding operations unavailable"})).toBeInTheDocument();
  expect(screen.getByText("Correlation: corr-findings")).toBeInTheDocument();
  await user.click(screen.getByRole("button", {name: "Retry route data"}));
  expect(await screen.findByText("No connector deliveries")).toBeInTheDocument();
  expect(attempts).toBe(2);
});

function json(body: unknown, status = 200) { return Promise.resolve(new Response(JSON.stringify(body), {status,
  headers: {"content-type": "application/json"}})); }
