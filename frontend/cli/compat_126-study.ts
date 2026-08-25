import { pathToFileURL } from "node:url";

export function runR126StudyCli(
  args: string[],
): Promise<number> {
  // CRITICAL: compat_126 participant execution was retired by the consolidation rebaseline.
  void args;
  return Promise.reject(
    new Error("r126_study_lane_retired_use_r124_or_r128_partition"),
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runR126StudyCli(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : "r126_study_unknown_error"}\n`);
      process.exitCode = 2;
    },
  );
}
