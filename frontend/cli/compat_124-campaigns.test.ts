import { describe, expect, it } from "vitest";

import { parseArguments } from "./redagent";

describe("compat_124 zero-raw-ID CLI boundary", () => {
  it("starts campaign and recovery selection without resource arguments", () => {
    expect(parseArguments(["campaigns", "start"])).toEqual({ kind: "campaigns-start" });
    expect(parseArguments(["campaigns", "stop"])).toEqual({ kind: "campaigns-stop" });
    expect(parseArguments(["campaigns", "revoke"])).toEqual({ kind: "campaigns-revoke" });
  });

  it("rejects raw campaign IDs and the inventoried non-core mutation fallbacks", () => {
    expect(() => parseArguments(["campaigns", "start", "campaign-raw-id"]))
      .toThrow("raw_id_arguments_forbidden");
    expect(() => parseArguments(["engagements", "create", "--input", "request.json", "--dry-run"]))
      .toThrow("legacy_mutation_disabled_until_r128");
    expect(() => parseArguments(["jobs", "start", "--input", "job.json", "--dry-run"]))
      .toThrow("legacy_mutation_disabled_until_r128");
    expect(() => parseArguments([
      "incidents", "action", "incident-1", "close", "--version", "3", "--confirm",
    ])).toThrow("legacy_mutation_disabled_until_r128");
    expect(() => parseArguments([
      "policy", "rollback", "revision-1", "--version", "2", "--reason", "Reviewed rollback",
    ])).toThrow("legacy_mutation_disabled_until_r128");
  });

  it("preserves explicit safety recovery commands", () => {
    expect(parseArguments(["jobs", "stop"])).toEqual({ kind: "jobs-stop" });
    expect(parseArguments(["containment", "approve"])).toEqual({ kind: "containment-approve" });
    expect(parseArguments(["containment", "recover"])).toEqual({ kind: "containment-recover" });
    expect(parseArguments(["evidence", "hold"])).toEqual({ kind: "evidence-hold" });
    expect(parseArguments(["leases", "revoke"])).toEqual({ kind: "leases-revoke" });
    expect(() => parseArguments([
      "jobs", "stop", "job-1", "--roe", "roe-1", "--reason", "Emergency operator stop",
    ])).toThrow("raw_id_arguments_forbidden");
    expect(() => parseArguments(["leases", "revoke", "lease-1", "--version", "2"]))
      .toThrow("raw_id_arguments_forbidden");
  });
});
