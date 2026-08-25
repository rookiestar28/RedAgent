import { execFile } from "node:child_process";
import { readFile } from "node:fs/promises";
import { isAbsolute, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { promisify } from "node:util";

import { REPRESENTATIVE_TASK_PROTOCOL } from "../src/ui-foundation/uiFoundationContracts.js";
import { UI_FOUNDATION_CONTRACT_VERSION } from "../src/ui-foundation/uiFoundationQualification.js";
import {
  R124_REPRESENTATIVE_PARTITION,
  evaluateRepresentativeTaskStudyPartitionJson,
  type RepresentativeStudyEvidence,
  type RepresentativeStudyEvaluation,
} from "../src/ui-foundation/uiFoundationRepresentativeStudy.js";

const execFileAsync = promisify(execFile);
const IMMUTABLE_GIT_OID = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const STUDY_STATUS_ARGS = [
  "status", "--porcelain=v1", "-z", "--untracked-files=all", "--ignored=no",
] as const;

export function buildR124RepresentativeStudyTemplate(
  sourceRevision: string,
  conductedAt = new Date().toISOString(),
): RepresentativeStudyEvidence {
  const selectedSlots = new Set(R124_REPRESENTATIVE_PARTITION.participantSlots);
  const roles = REPRESENTATIVE_TASK_PROTOCOL.roles.filter(({ participantSlot }) =>
    selectedSlots.has(participantSlot));
  return {
    contractVersion: UI_FOUNDATION_CONTRACT_VERSION,
    studyId: `r124-core-study-${conductedAt.replace(/[^0-9]/g, "").slice(0, 14)}`,
    sourceRevision,
    conductedAt,
    participants: roles.map(({ participantSlot, role }) => ({
      participantSlot,
      role,
      experienceConfirmed: false,
    })),
    outcomes: roles.flatMap(({ participantSlot }) =>
      REPRESENTATIVE_TASK_PROTOCOL.tasks.map(({ id }) => ({
        participantSlot,
        taskId: id,
        taskSuccess: false,
        completedUnassisted: false,
        unsafeInterpretation: false,
        topLevelActivations: 0,
        destinationActivations: 0,
      }))),
    privacy: {
      syntheticDataConfirmed: true,
      participantIdentityRecorded: false,
      rawMediaRecorded: false,
      operationalTargetDataRecorded: false,
    },
  };
}

export function evaluateR124RepresentativeStudyValue(
  value: unknown,
  expectedSourceRevision: string,
): RepresentativeStudyEvaluation {
  const evaluation = evaluateRepresentativeTaskStudyPartitionJson(
    value,
    REPRESENTATIVE_TASK_PROTOCOL,
    R124_REPRESENTATIVE_PARTITION,
  );
  const evidenceSourceRevision = typeof value === "object" && value !== null
    && "sourceRevision" in value && typeof value.sourceRevision === "string"
    ? value.sourceRevision
    : null;
  const sourceIssues: string[] = [];
  if (!IMMUTABLE_GIT_OID.test(expectedSourceRevision)) {
    sourceIssues.push("trusted workspace HEAD is not an immutable Git object id");
  } else if (evidenceSourceRevision !== expectedSourceRevision) {
    sourceIssues.push("sourceRevision does not match the studied workspace HEAD");
  }
  if (sourceIssues.length === 0) return evaluation;
  return {
    ...evaluation,
    accepted: false,
    issues: [...evaluation.issues, ...sourceIssues],
  };
}

async function readWorkspaceGitOutput(
  workspaceRoot: string,
  args: readonly string[],
  unavailableCode: string,
): Promise<string> {
  try {
    const { stdout } = await execFileAsync("git", [...args], {
      cwd: resolve(workspaceRoot),
      windowsHide: true,
    });
    return stdout;
  } catch {
    throw new Error(unavailableCode);
  }
}

export function parseWorkspaceGitHead(stdout: string): string {
  const revision = stdout.trim();
  if (!IMMUTABLE_GIT_OID.test(revision)) {
    throw new Error("r124_study_workspace_head_invalid");
  }
  return revision;
}

export async function readWorkspaceGitHead(workspaceRoot: string): Promise<string> {
  return parseWorkspaceGitHead(await readWorkspaceGitOutput(
    workspaceRoot,
    ["rev-parse", "HEAD"],
    "r124_study_workspace_head_unavailable",
  ));
}

export function assertR124StudyWorkspaceStatus(
  statusOutput: string,
  allowedUntrackedPath?: string,
): void {
  const entries = statusOutput.split("\0").filter((entry) => entry.length > 0);
  const normalizedAllowed = allowedUntrackedPath?.split(sep).join("/");
  if (entries.length === 0) return;
  if (normalizedAllowed && entries.length === 1 && entries[0] === `?? ${normalizedAllowed}`) {
    return;
  }
  throw new Error("r124_study_workspace_dirty");
}

async function readWorkspaceStudySnapshot(
  workspaceRoot: string,
  allowedUntrackedEvidencePath?: string,
): Promise<string> {
  const root = resolve(workspaceRoot);
  const headBefore = await readWorkspaceGitHead(root);
  const statusOutput = await readWorkspaceGitOutput(
    root,
    STUDY_STATUS_ARGS,
    "r124_study_workspace_status_unavailable",
  );
  const headAfter = await readWorkspaceGitHead(root);
  if (headBefore !== headAfter) {
    throw new Error("r124_study_workspace_head_changed");
  }
  let allowedRelativePath: string | undefined;
  if (allowedUntrackedEvidencePath) {
    allowedRelativePath = relative(root, resolve(allowedUntrackedEvidencePath));
  }
  assertR124StudyWorkspaceStatus(statusOutput, allowedRelativePath);
  return headBefore;
}

export function resolveR124StudyEvidencePath(
  workspaceRoot: string,
  inputPath: string,
): string {
  const root = resolve(workspaceRoot);
  const candidate = resolve(root, inputPath);
  const relativePath = relative(root, candidate);
  if (relativePath === ".." || relativePath.startsWith(`..${sep}`) || isAbsolute(relativePath)) {
    throw new Error("r124_study_evidence_path_outside_workspace");
  }
  return candidate;
}

export async function runR124StudyCli(
  args: string[],
  workspaceRoot = process.cwd(),
): Promise<number> {
  if (args.length === 2 && args[0] === "--template") {
    // CRITICAL: bind participant evidence to a clean Git snapshot, never evidence-owned state.
    const workspaceHead = await readWorkspaceStudySnapshot(workspaceRoot);
    if (args[1] !== workspaceHead) {
      throw new Error("r124_study_source_revision_mismatch");
    }
    process.stdout.write(`${JSON.stringify(buildR124RepresentativeStudyTemplate(workspaceHead), null, 2)}\n`);
    return 0;
  }
  if (args.length !== 1 || !args[0]) {
    throw new Error("usage: r124-study --template <source-revision> | <workspace-json-path>");
  }

  const evidencePath = resolveR124StudyEvidencePath(workspaceRoot, args[0]);
  const workspaceHeadBefore = await readWorkspaceStudySnapshot(workspaceRoot, evidencePath);
  const rawEvidence = await readFile(evidencePath, "utf8");
  const workspaceHeadAfter = await readWorkspaceStudySnapshot(workspaceRoot, evidencePath);
  if (workspaceHeadBefore !== workspaceHeadAfter) {
    throw new Error("r124_study_workspace_head_changed");
  }
  const value = JSON.parse(rawEvidence.replace(/^\uFEFF/, "")) as unknown;
  const evaluation = evaluateR124RepresentativeStudyValue(value, workspaceHeadAfter);
  process.stdout.write(`${JSON.stringify(evaluation, null, 2)}\n`);
  return evaluation.accepted ? 0 : 1;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  runR124StudyCli(process.argv.slice(2)).then(
    (code) => { process.exitCode = code; },
    (error: unknown) => {
      process.stderr.write(`${error instanceof Error ? error.message : "r124_study_unknown_error"}\n`);
      process.exitCode = 2;
    },
  );
}
