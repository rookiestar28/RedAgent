import { describe, expect, it } from "vitest";

import {
  REPRESENTATIVE_TASK_PROTOCOL,
} from "./uiFoundationContracts";
import {
  type RepresentativeStudyEvidence,
  evaluateRepresentativeTaskStudy,
  evaluateRepresentativeTaskStudyJson,
} from "./uiFoundationRepresentativeStudy";
import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";

function passingStudy(): RepresentativeStudyEvidence {
  return {
    contractVersion: UI_FOUNDATION_CONTRACT_VERSION,
    studyId: "r126-study-synthetic-fixture",
    sourceRevision: "0123456789abcdef0123456789abcdef01234567", // pragma: allowlist secret -- synthetic immutable-revision fixture
    conductedAt: "2026-07-14T12:00:00.000Z",
    participants: REPRESENTATIVE_TASK_PROTOCOL.roles.map(({ participantSlot, role }) => ({
      participantSlot,
      role,
      experienceConfirmed: true,
    })),
    outcomes: REPRESENTATIVE_TASK_PROTOCOL.roles.flatMap(({ participantSlot }) => (
      REPRESENTATIVE_TASK_PROTOCOL.tasks.map(({ id }) => ({
        participantSlot,
        taskId: id,
        taskSuccess: true,
        completedUnassisted: true,
        unsafeInterpretation: false,
        topLevelActivations: 1,
        destinationActivations: 2,
      }))
    )),
    privacy: {
      syntheticDataConfirmed: true,
      participantIdentityRecorded: false,
      rawMediaRecorded: false,
      operationalTargetDataRecorded: false,
    },
  };
}

describe("compat_126 representative task study evaluation", () => {
  it("accepts one unique outcome per role/task at the frozen thresholds", () => {
    const result = evaluateRepresentativeTaskStudy(passingStudy(), REPRESENTATIVE_TASK_PROTOCOL);

    expect(result.accepted).toBe(true);
    expect(result.issues).toEqual([]);
    expect(result.metrics).toEqual({
      participantCount: 6,
      outcomeCount: 42,
      safetyCriticalSuccessRate: 1,
      overallUnassistedSuccessRate: 1,
      nonSafetyUnassistedSuccessRate: 1,
      unsafeInterpretations: 0,
      medianTopLevelActivations: 1,
      medianDestinationActivations: 2,
    });
  });

  it("rejects missing or duplicate role/task evidence", () => {
    const evidence = passingStudy();
    evidence.outcomes.pop();
    evidence.outcomes.push(structuredClone(evidence.outcomes[0]!));

    expect(evaluateRepresentativeTaskStudy(evidence, REPRESENTATIVE_TASK_PROTOCOL).issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining("duplicate"),
        expect.stringContaining("missing"),
      ]),
    );
  });

  it("fails closed on one unsafe interpretation or safety-critical failure", () => {
    const evidence = passingStudy();
    const safetyTask = REPRESENTATIVE_TASK_PROTOCOL.tasks.find(({ safetyCritical }) => safetyCritical)!;
    const outcome = evidence.outcomes.find(({ taskId }) => taskId === safetyTask.id)!;
    outcome.taskSuccess = false;
    outcome.unsafeInterpretation = true;

    expect(evaluateRepresentativeTaskStudy(evidence, REPRESENTATIVE_TASK_PROTOCOL).issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining("safety-critical"),
        expect.stringContaining("unsafe interpretation"),
      ]),
    );
  });

  it("enforces non-safety unassisted completion and navigation medians", () => {
    const evidence = passingStudy();
    const nonSafetyTaskIds = REPRESENTATIVE_TASK_PROTOCOL.tasks
      .filter(({ safetyCritical }) => !safetyCritical)
      .map(({ id }) => id);
    const failures = evidence.outcomes.filter(({ taskId }) => nonSafetyTaskIds.includes(taskId)).slice(0, 2);
    for (const outcome of failures) outcome.completedUnassisted = false;
    for (const outcome of evidence.outcomes) {
      outcome.topLevelActivations = 3;
      outcome.destinationActivations = 4;
    }

    expect(evaluateRepresentativeTaskStudy(evidence, REPRESENTATIVE_TASK_PROTOCOL).issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining("non-safety"),
        expect.stringContaining("top-level"),
        expect.stringContaining("destination"),
      ]),
    );
  });

  it("also enforces the roadmap's overall unassisted completion threshold", () => {
    const evidence = passingStudy();
    const safetyTaskIds = new Set(
      REPRESENTATIVE_TASK_PROTOCOL.tasks.filter(({ safetyCritical }) => safetyCritical).map(({ id }) => id),
    );
    for (const outcome of evidence.outcomes) {
      if (safetyTaskIds.has(outcome.taskId)) outcome.completedUnassisted = false;
    }

    expect(evaluateRepresentativeTaskStudy(evidence, REPRESENTATIVE_TASK_PROTOCOL).issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining("overall unassisted"),
      ]),
    );
  });

  it("rejects identifying fields, real data, invalid revisions, and unconfirmed experience", () => {
    const evidence = passingStudy() as RepresentativeStudyEvidence & {
      participants: Array<RepresentativeStudyEvidence["participants"][number] & { name?: string }>;
    };
    evidence.sourceRevision = "working-tree";
    evidence.participants[0]!.experienceConfirmed = false;
    evidence.participants[0]!.name = "Must not be recorded";
    evidence.privacy.syntheticDataConfirmed = false;
    evidence.privacy.participantIdentityRecorded = true;
    evidence.privacy.operationalTargetDataRecorded = true;

    expect(evaluateRepresentativeTaskStudy(evidence, REPRESENTATIVE_TASK_PROTOCOL).issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining("sourceRevision"),
        expect.stringContaining("experience"),
        expect.stringContaining("unexpected participant field"),
        expect.stringContaining("synthetic"),
        expect.stringContaining("identity"),
        expect.stringContaining("operational target"),
      ]),
    );
  });

  it("rejects unexpected schema fields and non-boolean outcome values", () => {
    const evidence = passingStudy() as RepresentativeStudyEvidence & {
      participantNames?: string[];
      privacy: RepresentativeStudyEvidence["privacy"] & { notes?: string };
    };
    evidence.participantNames = ["Must not be recorded"];
    evidence.privacy.notes = "Free-form study notes are not evidence";
    (evidence.outcomes[0] as unknown as { taskSuccess: string }).taskSuccess = "yes";

    expect(evaluateRepresentativeTaskStudy(evidence, REPRESENTATIVE_TASK_PROTOCOL).issues).toEqual(
      expect.arrayContaining([
        expect.stringContaining("unexpected study field"),
        expect.stringContaining("unexpected privacy field"),
        expect.stringContaining("boolean"),
      ]),
    );
  });

  it("fails closed without throwing for malformed JSON evidence", () => {
    for (const malformed of [null, {}, { participants: "six" }, { participants: [], outcomes: [], privacy: null }]) {
      const result = evaluateRepresentativeTaskStudyJson(malformed, REPRESENTATIVE_TASK_PROTOCOL);
      expect(result.accepted).toBe(false);
      expect(result.issues).toEqual(expect.arrayContaining([
        expect.stringContaining("JSON shape"),
      ]));
    }

    expect(evaluateRepresentativeTaskStudyJson(
      passingStudy() as unknown,
      REPRESENTATIVE_TASK_PROTOCOL,
    ).accepted).toBe(true);
  });

  it.each([
    "syntheticDataConfirmed",
    "participantIdentityRecorded",
    "rawMediaRecorded",
    "operationalTargetDataRecorded",
  ] as const)("fails closed when privacy declaration %s is omitted", (field) => {
    const evidence = passingStudy();
    delete (evidence.privacy as Partial<RepresentativeStudyEvidence["privacy"]>)[field];

    const evaluation = evaluateRepresentativeTaskStudyJson(
      evidence,
      REPRESENTATIVE_TASK_PROTOCOL,
    );

    expect(evaluation.accepted).toBe(false);
    expect(evaluation.issues).toEqual(expect.arrayContaining([
      expect.stringContaining("JSON shape"),
    ]));
  });
});
