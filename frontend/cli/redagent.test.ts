import { describe, expect, it } from "vitest";

import {
  CliUsageError,
  exitCode,
  loadConfiguration,
  parseArguments,
  recoverableCampaigns,
} from "./redagent";

describe("RedAgent CLI contract", () => {
  it("offers stop and revoke only for active campaign states", () => {
    const campaigns = recoverableCampaigns([
      { status: "dispatch_pending", label: "Pending" },
      { status: "workflow_started", label: "Running" },
      { status: "completed", label: "Completed" },
      { status: "contained", label: "Contained" },
    ]);

    expect(campaigns.map(({ label }) => label)).toEqual(["Pending", "Running"]);
  });

  it("supports bounded observability and confirmed incident commands", () => {
    expect(parseArguments(["observability", "status"])).toEqual({ kind: "observability-status" });
    expect(parseArguments(["lab", "status"])).toEqual({ kind: "lab-status" });
    expect(parseArguments(["zap", "profiles"])).toEqual({ kind: "zap-profiles" });
    expect(parseArguments(["zap", "status"])).toEqual({ kind: "zap-status" });
    expect(parseArguments(["nuclei", "profiles"])).toEqual({ kind: "nuclei-profiles" });
    expect(parseArguments(["nuclei", "status"])).toEqual({ kind: "nuclei-status" });
    expect(parseArguments(["api-differential", "profiles"])).toEqual({ kind: "api-differential-profiles" });
    expect(parseArguments(["api-differential", "status"])).toEqual({ kind: "api-differential-status" });
    expect(parseArguments(["network", "profiles"])).toEqual({ kind: "network-profiles" });
    expect(parseArguments(["network", "status"])).toEqual({ kind: "network-status" });
    expect(parseArguments(["cloud", "profiles"])).toEqual({ kind: "cloud-profiles" });
    expect(parseArguments(["cloud", "status"])).toEqual({ kind: "cloud-status" });
    expect(parseArguments(["identity", "profiles"])).toEqual({ kind: "identity-profiles" });
    expect(parseArguments(["identity", "status"])).toEqual({ kind: "identity-status" });
    expect(parseArguments(["artifact", "profiles"])).toEqual({ kind: "artifact-profiles" });
    expect(parseArguments(["artifact", "status"])).toEqual({ kind: "artifact-status" });
    expect(parseArguments(["purple", "abilities"])).toEqual({ kind: "purple-abilities" });
    expect(parseArguments(["purple", "status"])).toEqual({ kind: "purple-status" });
    expect(parseArguments(["human-simulation", "campaigns"])).toEqual({ kind: "human-campaigns" });
    expect(parseArguments(["human-simulation", "status"])).toEqual({ kind: "human-status" });
    expect(parseArguments(["agent", "tools"])).toEqual({ kind: "agent-tools" });
    expect(parseArguments(["agent", "status"])).toEqual({ kind: "agent-status" });
    expect(parseArguments(["workbench", "status"])).toEqual({ kind: "workbench-status" });
    expect(parseArguments(["findings", "status"])).toEqual({ kind: "findings-status" });
    expect(() => parseArguments(["findings", "deliver", "--url", "https://example.invalid"]))
      .toThrow("unsupported_command");
    expect(() => parseArguments(["workbench", "connect", "--url", "https://example.invalid"]))
      .toThrow("unsupported_command");
    expect(() => parseArguments(["workbench", "stdio", "--command", "node server.js"]))
      .toThrow("unsupported_command");
    expect(() => parseArguments(["agent", "run", "--prompt", "scan everything"]))
      .toThrow("unsupported_command");
    expect(() => parseArguments(["agent", "run", "--command", "whoami"]))
      .toThrow("unsupported_command");
    expect(() => parseArguments(["nuclei", "run", "--template", "custom.yaml"])).toThrow("unsupported_command");
    expect(() => parseArguments(["api-differential", "run", "--url", "https://example.invalid"])).toThrow("unsupported_command");
    expect(() => parseArguments(["network", "run", "--cidr", "10.0.0.0/8"])).toThrow("unsupported_command");
    expect(() => parseArguments(["cloud", "run", "--endpoint", "https://example.invalid"])).toThrow("unsupported_command");
    expect(() => parseArguments(["identity", "collect", "--token", "opaque"])).toThrow("secret_or_policy_flags_forbidden");
    expect(() => parseArguments(["artifact", "scan", "--repository-url", "https://example.invalid"])).toThrow("unsupported_command");
    expect(() => parseArguments(["purple", "run", "--command", "touch marker"])).toThrow("unsupported_command");
    expect(() => parseArguments(["purple", "run", "--target", "example.invalid"])).toThrow("unsupported_command");
    expect(() => parseArguments(["human-simulation", "send", "--recipient", "person@example.com"])).toThrow("unsupported_command");
    expect(() => parseArguments(["human-simulation", "send", "--body", "click"])).toThrow("unsupported_command");
    expect(() => parseArguments(["lab", "qualify", "--target", "example.com"]))
      .toThrow("unsupported_command");
    expect(parseArguments(["observability", "correlation", "corr-1"])).toEqual({
      kind: "observability-correlation", correlationId: "corr-1",
    });
    expect(parseArguments(["incidents", "timeline", "incident-1"])).toEqual({
      kind: "incidents-timeline", incidentId: "incident-1",
    });
    expect(() => parseArguments([
      "incidents", "action", "incident-1", "assign", "--version", "1",
      "--assignee", "responder-1", "--confirm",
    ])).toThrow("legacy_mutation_disabled_until_r128");
    expect(() => parseArguments([
      "incidents", "action", "incident-1", "close", "--version", "3",
    ])).toThrow("legacy_mutation_disabled_until_r128");
  });

  it("supports bounded dry-run input and rejects secret-bearing flags", () => {
    expect(() => parseArguments(["engagements", "create", "--input", "request.json", "--dry-run"]))
      .toThrow("legacy_mutation_disabled_until_r128");
    expect(() => parseArguments(["context", "--token", "value"]))
      .toThrow("secret_or_policy_flags_forbidden");
  });

  it("permits HTTPS or loopback HTTP and never sources identity from arguments", () => {
    expect(loadConfiguration({
      REDAGENT_API_URL: "http://127.0.0.1:8000",
      REDAGENT_SERVICE_TENANT: "tenant-1",
      REDAGENT_SERVICE_CLIENT: "client-1",
      REDAGENT_SERVICE_SECRET: "synthetic-fixture-value", // pragma: allowlist secret
    }).apiUrl).toBe("http://127.0.0.1:8000/");
    expect(() => loadConfiguration({
      REDAGENT_API_URL: "http://api.example.test",
      REDAGENT_SERVICE_TENANT: "tenant-1",
      REDAGENT_SERVICE_CLIENT: "client-1",
      REDAGENT_SERVICE_SECRET: "synthetic-fixture-value", // pragma: allowlist secret
    })).toThrow("insecure_api_url_forbidden");
  });

  it("uses deterministic usage exit codes", () => {
    expect(exitCode(new CliUsageError("bad input"))).toBe(2);
    expect(exitCode(new Error("unavailable"))).toBe(5);
  });

  it("supports bounded job list, get, start dry-run, command, and emergency-stop forms", () => {
    expect(parseArguments(["jobs", "list"])).toEqual({ kind: "jobs-list" });
    expect(parseArguments(["jobs", "get", "job-1", "--roe", "roe-1"]))
      .toEqual({ kind: "jobs-get", jobId: "job-1", roeVersionId: "roe-1" });
    expect(parseArguments(["jobs", "containment", "job-1"]))
      .toEqual({ kind: "jobs-containment", jobId: "job-1" });
    expect(() => parseArguments(["jobs", "start", "--input", "job.json", "--dry-run"]))
      .toThrow("legacy_mutation_disabled_until_r128");
    expect(() => parseArguments(["jobs", "command", "job-1", "approve", "--roe", "roe-1", "--revision", "2", "--reason", "Independent approval"]))
      .toThrow("legacy_mutation_disabled_until_r128");
    expect(parseArguments(["jobs", "stop"])).toEqual({ kind: "jobs-stop" });
    expect(() => parseArguments(["jobs", "stop", "job-1", "--roe", "roe-1", "--reason", "Emergency operator stop"]))
      .toThrow("raw_id_arguments_forbidden");
  });

  it("supports typed containment hierarchy, approval, recovery, and quota status", () => {
    const hash = "a".repeat(64);
    expect(parseArguments(["containment", "list"])).toEqual({ kind: "containment-list" });
    expect(parseArguments(["containment", "get", "control-1"])).toEqual({ kind: "containment-get", controlId: "control-1" });
    expect(() => parseArguments(["containment", "request", "campaign", "campaign-1", "--reason", "Stop affected campaign now", "--confirm"]))
      .toThrow("legacy_mutation_disabled_until_r128");
    expect(() => parseArguments(["containment", "request", "global", "*", "--reason", "Stop all authorized execution", "--confirm"]))
      .toThrow("legacy_mutation_disabled_until_r128");
    expect(parseArguments(["containment", "approve"])).toEqual({ kind: "containment-approve" });
    expect(parseArguments(["containment", "recover"])).toEqual({ kind: "containment-recover" });
    expect(() => parseArguments(["containment", "approve", "control-1", "--hash", hash, "--version", "1"]))
      .toThrow("raw_id_arguments_forbidden");
    expect(parseArguments(["quotas", "status"])).toEqual({ kind: "quotas-status" });
    expect(() => parseArguments(["containment", "request", "global", "tenant-1", "--reason", "Invalid global scope request", "--confirm"]))
      .toThrow("legacy_mutation_disabled_until_r128");
  });

  it("supports metadata-only runner readiness and lineage without execution inputs", () => {
    expect(parseArguments(["runners", "status"])).toEqual({ kind: "runners-status" });
    expect(parseArguments(["runners", "registrations"])).toEqual({ kind: "runners-registrations" });
    expect(parseArguments(["runners", "manifests"])).toEqual({ kind: "runners-manifests" });
    expect(parseArguments(["runners", "executions"])).toEqual({ kind: "runners-executions" });
    expect(() => parseArguments(["runners", "execute", "--command", "whoami"]))
      .toThrow("unsupported_command");
  });

  it("supports bounded evidence metadata, verification, derivation, hold, and synthetic dry-run forms", () => {
    expect(parseArguments(["evidence", "list"])).toEqual({ kind: "evidence-list" });
    expect(parseArguments(["evidence", "get", "artifact-1"])).toEqual({ kind: "evidence-get", artifactId: "artifact-1" });
    expect(parseArguments(["evidence", "verify", "artifact-1"])).toEqual({ kind: "evidence-verify", artifactId: "artifact-1" });
    expect(() => parseArguments(["evidence", "derive", "artifact-1", "--artifact", "artifact-report-1", "--class", "report_safe"]))
      .toThrow("legacy_mutation_disabled_until_r128");
    expect(parseArguments(["evidence", "hold"])).toEqual({ kind: "evidence-hold" });
    expect(() => parseArguments(["evidence", "hold", "artifact-1", "--version", "2"]))
      .toThrow("raw_id_arguments_forbidden");
    expect(parseArguments(["evidence", "synthetic", "--input", "synthetic.json", "--dry-run"])).toEqual({
      kind: "evidence-synthetic-dry-run", input: "synthetic.json",
    });
    expect(() => parseArguments(["evidence", "synthetic", "--input", "synthetic.json"]))
      .toThrow("unsupported_command");
  });

  it("supports metadata-only exact lease list and revoke without credential inputs", () => {
    expect(parseArguments(["leases", "list"])).toEqual({ kind: "leases-list" });
    expect(parseArguments(["leases", "revoke"])).toEqual({ kind: "leases-revoke" });
    expect(() => parseArguments(["leases", "revoke", "lease-1", "--version", "2"]))
      .toThrow("raw_id_arguments_forbidden");
    expect(() => parseArguments(["leases", "revoke", "lease-1", "--token", "value"]))
      .toThrow("secret_or_policy_flags_forbidden");
  });

  it("supports metadata-only policy lifecycle commands and rejects policy injection", () => {
    expect(parseArguments(["policy", "status"])).toEqual({ kind: "policy-status" });
    expect(parseArguments(["policy", "simulate", "evidence-write"]))
      .toEqual({ kind: "policy-simulate", fixture: "evidence-write" });
    expect(() => parseArguments(["policy", "promote", "r099-v1", "--version", "1", "--reason", "Reviewed converged promotion"]))
      .toThrow("legacy_mutation_disabled_until_r128");
    expect(() => parseArguments(["policy", "status", "--rego", "package injected"]))
      .toThrow("secret_or_policy_flags_forbidden");
    expect(() => parseArguments(["policy", "simulate", "arbitrary-input"]))
      .toThrow("invalid_policy_fixture");
  });
});
