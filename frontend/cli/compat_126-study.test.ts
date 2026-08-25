import { readFileSync } from "node:fs";
import { resolve } from "node:path";

import { describe, expect, it } from "vitest";

import { runR126StudyCli } from "./compat_126-study";

describe("retired compat_126 representative study CLI boundary", () => {
  it.each([
    { args: [] },
    { args: ["--template", "a".repeat(40)] },
    { args: [".local/validation/stale-study.json"] },
  ])("rejects the retired full-study lane without reading or emitting evidence: $args", async ({ args }) => {
    await expect(runR126StudyCli(args)).rejects.toThrow(
      "r126_study_lane_retired_use_r124_or_r128_partition",
    );
  });

  it("keeps the compatibility entry point free of file-I/O and full-study evaluation imports", () => {
    const source = readFileSync(resolve(process.cwd(), "frontend/cli/compat_126-study.ts"), "utf8");
    expect(source).not.toContain('from "node:fs');
    expect(source).not.toContain("buildRepresentativeStudyTemplate");
    expect(source).not.toContain("evaluateRepresentativeTaskStudy");
    expect(source).not.toContain("REPRESENTATIVE_TASK_PROTOCOL");
  });
});
