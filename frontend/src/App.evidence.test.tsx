import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";


describe("persistent evidence console", () => {
  it("shows immutable metadata and verifies an exact version without rendering bytes", async () => {
    window.history.replaceState({}, "", "/evidence");
    const artifact = evidenceArtifact();
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/context") return Promise.resolve(json({ data: {
        subject: "operator-1", tenant_id: "tenant-1",
        permissions: ["engagement:read", "evidence:read", "evidence:verify", "evidence:derive", "evidence:retention-admin"],
        roles: ["operator"],
      }}));
      if (url.pathname === "/api/v1/engagements") return Promise.resolve(json({ data: [], page: { limit: 50, offset: 0, returned: 0 } }));
      if (url.pathname === "/api/v1/evidence/artifacts" && request.method === "GET") {
        const offset = Number(url.searchParams.get("offset") ?? "0");
        return Promise.resolve(json(offset === 0
          ? { data: [artifact], page: { limit: 50, offset: 0, returned: 1, next_offset: 50 } }
          : { data: [{ ...artifact, artifact_id: "artifact-2", object_version_id: "version-2" }], page: { limit: 50, offset, returned: 1, next_offset: null } }));
      }
      if (url.pathname === `/api/v1/evidence/artifacts/${artifact.artifact_id}` && request.method === "GET") {
        return Promise.resolve(json({ data: {
          ...artifact, source_artifact_id: null, transform_name: null, transform_version: null,
          transform_config_hash: null, custody_event_count: 4, verification_count: 1,
          last_verified: true, last_verified_at: "2026-07-10T20:00:00Z",
        }}));
      }
      if (url.pathname.endsWith("/verify") && request.method === "POST") {
        return Promise.resolve(json({ data: {
          artifact_id: artifact.artifact_id, object_version_id: artifact.object_version_id,
          verified: true, reason: "verified",
        }}));
      }
      if (url.pathname.endsWith("/selection") && request.method === "GET") {
        return Promise.resolve(json({ data: artifact }));
      }
      if (url.pathname.endsWith("/derive") && request.method === "POST") {
        return Promise.resolve(json({ data: { ...artifact, artifact_id: "derived-artifact", artifact_class: "report_safe" } }));
      }
      if (url.pathname.endsWith("/legal-hold") && request.method === "POST") {
        return Promise.resolve(json({ data: { ...artifact, legal_hold: true, version: 2 } }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    await user.click(await screen.findByRole("button", { name: new RegExp(artifact.artifact_id) }));
    expect(await screen.findByText(artifact.content_sha256)).toBeVisible();
    expect(screen.getByText(artifact.object_version_id)).toBeVisible();
    expect(screen.getByText("4 events · 1 checks · Passing")).toBeVisible();
    expect(screen.queryByText("raw-secret-evidence-bytes")).not.toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "Verify exact version" }));
    expect(await screen.findByText(`Exact version ${artifact.object_version_id} verified.`)).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Select approved evidence" }));
    expect(await screen.findByText("Approved review evidence selected.")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Create derivative" }));
    expect(await screen.findByText("Immutable report_safe derivative created.")).toBeVisible();
    vi.spyOn(window, "confirm").mockReturnValue(true);
    await user.click(screen.getByRole("button", { name: "Place legal hold" }));
    expect(await screen.findByText(`Legal hold placed on exact object version ${artifact.object_version_id}.`)).toBeVisible();

    await user.click(screen.getByRole("button", { name: "Next evidence" }));
    expect(await screen.findByRole("button", { name: /artifact-2/ })).toBeVisible();
  });

  it("uses authorized resource choices instead of transcribed artifact and job identifiers", async () => {
    window.history.replaceState({}, "", "/evidence");
    const registeredPayloads: Array<Record<string, unknown>> = [];
    const fetchMock = vi.fn<typeof fetch>().mockImplementation(async (input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/context") return json({ data: {
        subject: "operator-1", tenant_id: "tenant-1",
        permissions: ["evidence:read", "evidence:write", "evidence:derive", "job:read"], roles: ["operator"],
      }});
      if (url.pathname === "/api/v1/evidence/artifacts") return json({ data: [], page: { limit: 50, offset: 0, returned: 0, next_offset: null } });
      if (url.pathname === "/api/v1/jobs") {
        const offset = Number(url.searchParams.get("offset") ?? "0");
        return json(offset === 0
          ? { data: [job()], page: { limit: 50, offset: 0, returned: 1, next_offset: 50 } }
          : { data: [job("job-2")], page: { limit: 50, offset, returned: 1, next_offset: null } });
      }
      if (url.pathname === "/api/v1/evidence/synthetic" && request.method === "POST") {
        const registeredPayload = await request.json() as Record<string, unknown>;
        registeredPayloads.push(registeredPayload);
        return json({ data: { ...evidenceArtifact(), artifact_id: registeredPayload.artifact_id } }, 201);
      }
      return json({ error: { code: "not_found", message: "Not found" } }, 404);
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    const picker = await screen.findByRole("combobox", { name: "Authorized job" });
    expect(picker).toBeVisible();
    expect(screen.queryByRole("textbox", { name: "Artifact ID" })).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Job ID" })).not.toBeInTheDocument();
    expect(screen.queryByRole("textbox", { name: "Derivative artifact ID" })).not.toBeInTheDocument();
    await user.selectOptions(picker, "job-1");
    await user.click(screen.getByRole("button", { name: "Register fixture" }));
    expect(await screen.findByText(/Synthetic evidence evidence-/)).toBeVisible();
    expect(registeredPayloads[0]).toMatchObject({
      engagement_id: "engagement-1", job_id: "job-1", fixture_kind: "sanitized-log", retention_days: 30,
    });
    expect(registeredPayloads[0]?.artifact_id).toMatch(/^evidence-[0-9a-f-]+$/);
    await user.click(screen.getByRole("button", { name: "Next jobs" }));
    expect(await screen.findByRole("option", { name: /job-2/ })).toBeInTheDocument();
  });

  it("fails closed locally when evidence read permission is absent", async () => {
    window.history.replaceState({}, "", "/evidence");
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/context") return Promise.resolve(json({ data: {
        subject: "operator-1", tenant_id: "tenant-1", permissions: [], roles: ["operator"],
      }}));
      return Promise.resolve(json({ error: { code: "unexpected_request", message: "Unexpected request" } }, 500));
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<App />);
    expect(await screen.findByRole("alert", { name: "Route access denied" })).toBeVisible();
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("projects an evidence outage with correlation and retries without inferring custody state", async () => {
    window.history.replaceState({}, "", "/evidence");
    let attempts = 0;
    const fetchMock = vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      const url = new URL(request.url);
      if (url.pathname === "/api/v1/context") return Promise.resolve(json({ data: {
        subject: "operator-1", tenant_id: "tenant-1", permissions: ["evidence:read"], roles: ["operator"],
      }}));
      if (url.pathname === "/api/v1/evidence/artifacts" && attempts++ === 0) {
        return Promise.resolve(json({ error: {
          code: "evidence_unavailable", message: "Evidence store unavailable", correlation_id: "corr-evidence",
        } }, 503));
      }
      if (url.pathname === "/api/v1/evidence/artifacts") {
        return Promise.resolve(json({ data: [], page: { limit: 50, offset: 0, returned: 0, next_offset: null } }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();

    render(<App />);
    expect(await screen.findByRole("alert", { name: "Evidence unavailable" })).toBeVisible();
    expect(screen.getByText("Correlation: corr-evidence")).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Retry route data" }));
    expect(await screen.findByText("No persistent evidence yet")).toBeVisible();
    expect(attempts).toBe(2);
  });
});


function evidenceArtifact() {
  return {
    artifact_id: "artifact-1", tenant_id: "tenant-1", engagement_id: "engagement-1", job_id: "job-1",
    producer_id: "operator-1", object_key: "tenants/tenant-1/immutable/key", object_version_id: "version-1",
    content_sha256: "a".repeat(64), provider_checksum: "provider-checksum", size_bytes: 42,
    content_type: "text/plain", artifact_class: "redacted", classification: "confidential",
    redaction_state: "redacted", retention_mode: "GOVERNANCE", retain_until: "2026-08-10T00:00:00Z",
    legal_hold: false, kms_reference: "kms:local:fixture", attestation_hash: "b".repeat(64),
    policy_reference: "policy:compat_097:1", quarantine_reason: null, version: 1,
  } as const;
}


function job(jobId = "job-1") {
  return {
    job_id: jobId, campaign_id: null, engagement_id: "engagement-1", tenant_id: "tenant-1",
    created_by_user_id: "operator-1", current_gate: "authorized", dispatch_blocked: false,
    failure_code: null, orchestration_revision: 1, orchestration_state: "accepted",
    policy_reference: "policy:1", request: {}, retry_count: 0, roe_version_id: "roe-1",
    status: "succeeded", stop_requested: false, version: 1, workflow_id: "workflow-1",
    workflow_run_id: "workflow-run-1",
  };
}


function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });
}
