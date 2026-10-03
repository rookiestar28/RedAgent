import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { promisify } from "node:util";
import { describe, expect, it, vi } from "vitest";

import {
  buildR124RepresentativeStudyTemplate,
  evaluateR124RepresentativeStudyValue,
  assertR124StudyWorkspaceStatus,
  parseWorkspaceGitHead,
  readWorkspaceGitHead,
  resolveR124StudyEvidencePath,
  runR124StudyCli,
} from "./compat_124-study";

const SOURCE_REVISION = "a".repeat(40);
const execFileAsync = promisify(execFile);

async function createStudyTestRepository(): Promise<string> {
  const workspaceRoot = resolve(".");
  const temporaryRoot = resolve(workspaceRoot, ".tmp");
  await mkdir(temporaryRoot, { recursive: true });
  const repository = await mkdtemp(join(temporaryRoot, "r124-study-git-"));
  await execFileAsync("git", ["init", "--quiet"], { cwd: repository, windowsHide: true });
  await writeFile(join(repository, "tracked.txt"), "baseline\n", "utf8");
  await execFileAsync("git", ["add", "tracked.txt"], { cwd: repository, windowsHide: true });
  await execFileAsync("git", [
    "-c", "user.name=compat_124 Test", "-c", "user.email=compat_124@example.invalid",
    "commit", "--quiet", "-m", "baseline",
  ], { cwd: repository, windowsHide: true });
  return repository;
}

async function removeStudyTestRepository(repository: string): Promise<void> {
  const workspaceRoot = resolve(".");
  const relativePath = relative(workspaceRoot, resolve(repository));
  if (relativePath.startsWith("..") || relativePath === "") {
    throw new Error("r124_test_repository_outside_workspace");
  }
  await rm(repository, { recursive: true, force: true });
}

describe("compat_124 representative study CLI boundary", () => {
  it("builds exactly the de-identified five-role and 35-outcome partition", () => {
    const template = buildR124RepresentativeStudyTemplate(
      SOURCE_REVISION,
      "2026-08-24T14:30:00.000Z",
    );
    expect(template.participants.map(({ participantSlot }) => participantSlot)).toEqual([
      "operator-a", "operator-b", "approver", "reviewer", "keyboard-evaluator",
    ]);
    expect(template.outcomes).toHaveLength(35);
    expect(template.participants.some(({ participantSlot }) => participantSlot === "administrator"))
      .toBe(false);
    expect(evaluateR124RepresentativeStudyValue(template, SOURCE_REVISION).accepted).toBe(false);
  });

  it("accepts only completed core outcomes and rejects unsafe or administrator evidence", () => {
    const evidence = buildR124RepresentativeStudyTemplate(
      SOURCE_REVISION,
      "2026-08-24T14:30:00.000Z",
    );
    evidence.participants.forEach((participant) => { participant.experienceConfirmed = true; });
    evidence.outcomes.forEach((outcome) => {
      outcome.taskSuccess = true;
      outcome.completedUnassisted = true;
      outcome.unsafeInterpretation = false;
      outcome.topLevelActivations = 1;
      outcome.destinationActivations = 2;
    });
    expect(evaluateR124RepresentativeStudyValue(evidence, SOURCE_REVISION)).toMatchObject({
      accepted: true,
      metrics: { participantCount: 5, outcomeCount: 35, unsafeInterpretations: 0 },
    });

    evidence.participants.push({
      participantSlot: "administrator",
      role: "platform-administrator",
      experienceConfirmed: true,
    });
    evidence.outcomes[0]!.unsafeInterpretation = true;
    const rejected = evaluateR124RepresentativeStudyValue(evidence, SOURCE_REVISION);
    expect(rejected.accepted).toBe(false);
    expect(rejected.issues).toEqual(expect.arrayContaining([
      expect.stringContaining("administrator"),
      expect.stringContaining("unsafe interpretation"),
    ]));
  });

  it("rejects invalid shapes and paths outside the workspace", () => {
    expect(evaluateR124RepresentativeStudyValue(null, SOURCE_REVISION).accepted).toBe(false);
    const root = resolve("test-workspace", "RedAgent");
    expect(resolveR124StudyEvidencePath(root, ".local/validation/study.json"))
      .toBe(resolve(root, ".local", "validation", "study.json"));
    expect(() => resolveR124StudyEvidencePath(root, "../other.json"))
      .toThrow("r124_study_evidence_path_outside_workspace");
  });

  it("rejects syntactically valid evidence from a different studied checkout", () => {
    const evidence = buildR124RepresentativeStudyTemplate(
      SOURCE_REVISION,
      "2026-08-24T14:30:00.000Z",
    );
    evidence.participants.forEach((participant) => { participant.experienceConfirmed = true; });
    evidence.outcomes.forEach((outcome) => {
      outcome.taskSuccess = true;
      outcome.completedUnassisted = true;
      outcome.unsafeInterpretation = false;
      outcome.topLevelActivations = 1;
      outcome.destinationActivations = 2;
    });

    const evaluation = evaluateR124RepresentativeStudyValue(evidence, "b".repeat(40));
    expect(evaluation.accepted).toBe(false);
    expect(evaluation.issues).toContain("sourceRevision does not match the studied workspace HEAD");
  });

  it("rejects template generation when the requested source is not workspace HEAD", async () => {
    const repository = await createStudyTestRepository();
    try {
      await expect(runR124StudyCli(["--template", SOURCE_REVISION], repository))
        .rejects.toThrow("r124_study_source_revision_mismatch");
    } finally {
      await removeStudyTestRepository(repository);
    }
  });

  it("reads an immutable workspace HEAD and fails closed when the workspace is unavailable", async () => {
    const bootstrapHead = await readWorkspaceGitHead(resolve(".")).catch(() => null);
    if (bootstrapHead !== null) {
      expect(bootstrapHead).toMatch(/^[0-9a-f]{40}([0-9a-f]{24})?$/);
    }
    await expect(readWorkspaceGitHead(resolve(".tmp", "r124-study-missing-workspace")))
      .rejects.toThrow("r124_study_workspace_head_unavailable");
  });

  it("rejects malformed Git output and every dirty status except the exact untracked evidence", () => {
    expect(() => parseWorkspaceGitHead("working-tree\n"))
      .toThrow("r124_study_workspace_head_invalid");
    expect(() => assertR124StudyWorkspaceStatus(" M frontend/source.ts\0"))
      .toThrow("r124_study_workspace_dirty");
    expect(() => assertR124StudyWorkspaceStatus("M  frontend/source.ts\0"))
      .toThrow("r124_study_workspace_dirty");
    expect(() => assertR124StudyWorkspaceStatus("?? frontend/untracked.ts\0"))
      .toThrow("r124_study_workspace_dirty");
    expect(() => assertR124StudyWorkspaceStatus(
      "?? .local/validation/results.json\0",
      ".local/validation/results.json",
    )).not.toThrow();
    expect(() => assertR124StudyWorkspaceStatus(
      "?? .local/validation/results.json\0?? frontend/untracked.ts\0",
      ".local/validation/results.json",
    )).toThrow("r124_study_workspace_dirty");
  });

  it.each(["tracked", "untracked"] as const)(
    "rejects a %s dirty same-HEAD workspace before template output",
    async (dirtyKind) => {
      const repository = await createStudyTestRepository();
      const output = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      try {
        const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], {
          cwd: repository,
          windowsHide: true,
        });
        if (dirtyKind === "tracked") {
          await writeFile(join(repository, "tracked.txt"), "modified\n", "utf8");
        } else {
          await writeFile(join(repository, "untracked.txt"), "untracked\n", "utf8");
        }
        await expect(runR124StudyCli(["--template", stdout.trim()], repository))
          .rejects.toThrow("r124_study_workspace_dirty");
      } finally {
        output.mockRestore();
        await removeStudyTestRepository(repository);
      }
    },
  );

  // Keep native Git contracts separate; combining them can exhaust the 5s Windows budget.
  it.each(["exact-evidence", "other-untracked", "changed-source"] as const)(
    "enforces the %s native Git evidence contract",
    async (scenario) => {
      const repository = await createStudyTestRepository();
      const output = vi.spyOn(process.stdout, "write").mockImplementation(() => true);
      try {
        const { stdout } = await execFileAsync("git", ["rev-parse", "HEAD"], {
          cwd: repository,
          windowsHide: true,
        });
        const evidence = buildR124RepresentativeStudyTemplate(
          stdout.trim(),
          "2026-08-25T00:00:00.000Z",
        );
        evidence.participants.forEach((participant) => { participant.experienceConfirmed = true; });
        evidence.outcomes.forEach((outcome) => {
          outcome.taskSuccess = true;
          outcome.completedUnassisted = true;
          outcome.unsafeInterpretation = false;
          outcome.topLevelActivations = 1;
          outcome.destinationActivations = 2;
        });
        await mkdir(join(repository, ".local", "validation"), { recursive: true });
        await writeFile(
          join(repository, ".local", "validation", "results.json"),
          `${JSON.stringify(evidence)}\n`,
          "utf8",
        );
        if (scenario === "exact-evidence") {
          await expect(runR124StudyCli([".local/validation/results.json"], repository)).resolves.toBe(0);
        } else if (scenario === "other-untracked") {
          await writeFile(join(repository, "other-untracked.txt"), "unexpected\n", "utf8");
          await expect(runR124StudyCli([".local/validation/results.json"], repository))
            .rejects.toThrow("r124_study_workspace_dirty");
        } else {
          await writeFile(join(repository, "tracked.txt"), "next revision\n", "utf8");
          await execFileAsync("git", ["add", "tracked.txt"], { cwd: repository, windowsHide: true });
          await execFileAsync("git", [
            "-c", "user.name=compat_124 Test", "-c", "user.email=compat_124@example.invalid",
            "commit", "--quiet", "-m", "next revision",
          ], { cwd: repository, windowsHide: true });
          await expect(runR124StudyCli([".local/validation/results.json"], repository)).resolves.toBe(1);
        }
      } finally {
        output.mockRestore();
        await removeStudyTestRepository(repository);
      }
    },
  );
});
