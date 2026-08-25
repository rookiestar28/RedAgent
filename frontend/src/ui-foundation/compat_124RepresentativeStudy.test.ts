import { describe, expect, it } from "vitest";

import { REPRESENTATIVE_TASK_PROTOCOL } from "./uiFoundationContracts";
import {
  R124_REPRESENTATIVE_PARTITION,
  R128_REPRESENTATIVE_PARTITION,
  evaluateRepresentativeTaskStudyPartition,
  type RepresentativeStudyEvidence,
} from "./uiFoundationRepresentativeStudy";
import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";

function passingR124Evidence(): RepresentativeStudyEvidence {
  const roles = REPRESENTATIVE_TASK_PROTOCOL.roles.filter(({ participantSlot }) =>
    R124_REPRESENTATIVE_PARTITION.participantSlots.includes(participantSlot));
  return {
    contractVersion: UI_FOUNDATION_CONTRACT_VERSION,
    studyId: "r124-core-study-synthetic-fixture",
    sourceRevision: "0123456789abcdef0123456789abcdef01234567", // pragma: allowlist secret -- synthetic immutable-revision fixture
    conductedAt: "2026-08-24T12:00:00.000Z",
    participants: roles.map(({ participantSlot, role }) => ({
      participantSlot,
      role,
      experienceConfirmed: true,
    })),
    outcomes: roles.flatMap(({ participantSlot }) =>
      REPRESENTATIVE_TASK_PROTOCOL.tasks.map(({ id }) => ({
        participantSlot,
        taskId: id,
        taskSuccess: true,
        completedUnassisted: true,
        unsafeInterpretation: false,
        topLevelActivations: 1,
        destinationActivations: 2,
      }))),
    privacy: {
      syntheticDataConfirmed: true,
      participantIdentityRecorded: false,
      rawMediaRecorded: false,
      operationalTargetDataRecorded: false,
    },
  };
}

describe("compat_124 frozen representative-study partition", () => {
  it("splits all 42 outcomes into non-overlapping 35/7 ownership", () => {
    expect(R124_REPRESENTATIVE_PARTITION.participantSlots).toEqual([
      "operator-a", "operator-b", "approver", "reviewer", "keyboard-evaluator",
    ]);
    expect(R128_REPRESENTATIVE_PARTITION.participantSlots).toEqual(["administrator"]);
    expect(new Set([
      ...R124_REPRESENTATIVE_PARTITION.participantSlots,
      ...R128_REPRESENTATIVE_PARTITION.participantSlots,
    ]).size).toBe(6);
  });

  it("accepts exactly the immutable 35-outcome compat_124 core evidence", () => {
    const result = evaluateRepresentativeTaskStudyPartition(
      passingR124Evidence(),
      REPRESENTATIVE_TASK_PROTOCOL,
      R124_REPRESENTATIVE_PARTITION,
    );
    expect(result.accepted).toBe(true);
    expect(result.metrics.participantCount).toBe(5);
    expect(result.metrics.outcomeCount).toBe(35);
  });

  it("rejects administrator evidence, missing outcomes, and unsafe interpretation", () => {
    const evidence = passingR124Evidence();
    evidence.participants.push({
      participantSlot: "administrator",
      role: "platform-administrator",
      experienceConfirmed: true,
    });
    evidence.outcomes.pop();
    evidence.outcomes[0]!.unsafeInterpretation = true;

    const result = evaluateRepresentativeTaskStudyPartition(
      evidence,
      REPRESENTATIVE_TASK_PROTOCOL,
      R124_REPRESENTATIVE_PARTITION,
    );
    expect(result.accepted).toBe(false);
    expect(result.issues).toEqual(expect.arrayContaining([
      expect.stringContaining("administrator"),
      expect.stringContaining("missing"),
      expect.stringContaining("unsafe interpretation"),
    ]));
  });
});
