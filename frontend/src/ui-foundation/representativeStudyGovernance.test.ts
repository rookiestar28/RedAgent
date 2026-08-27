import { describe, expect, it } from "vitest";

import { REPRESENTATIVE_TASK_PROTOCOL } from "./uiFoundationContracts";
import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";
import {
  R124_REPRESENTATIVE_PARTITION,
  type RepresentativeStudyEvidence,
} from "./uiFoundationRepresentativeStudy";
import {
  PARTICIPANT_STUDY_GOVERNANCE_SCHEMA_VERSION,
  PARTICIPANT_STUDY_LIMITATIONS,
  PARTICIPANT_STUDY_PROTOCOL_REVISION,
  evaluateRepresentativeStudyGovernance,
  type ParticipantStudyExpectedBindings,
  type ParticipantStudyGovernanceEvidence,
  type ParticipantStudySlot,
} from "./representativeStudyGovernance";

const SOURCE_REVISION = "a".repeat(40);
const SOURCE_TREE_OID = "b".repeat(40);
const PROTOCOL_SHA256 = "c".repeat(64);
const FIXTURE_SHA256 = "d".repeat(64);
const EVALUATOR_SHA256 = "e".repeat(64);
const GUIDE_SHA256 = "f".repeat(64);
const POLICY_SHA256 = "1".repeat(64);
const INFORMATION_SHEET_SHA256 = "2".repeat(64);
const CONSENT_FORM_SHA256 = "3".repeat(64);

const EXPECTED_BINDINGS: ParticipantStudyExpectedBindings = {
  sourceRevision: SOURCE_REVISION,
  sourceTreeOid: SOURCE_TREE_OID,
  protocolSha256: PROTOCOL_SHA256,
  fixtureSha256: FIXTURE_SHA256,
  evaluatorSha256: EVALUATOR_SHA256,
  facilitatorGuideSha256: GUIDE_SHA256,
  retentionPolicySha256: POLICY_SHA256,
  informationSheetSha256: INFORMATION_SHEET_SHA256,
  consentFormSha256: CONSENT_FORM_SHA256,
};

const ELIGIBILITY_BY_SLOT = {
  "operator-a": "authorized-red-team-operator",
  "operator-b": "authorized-red-team-operator",
  approver: "security-approval-authority",
  reviewer: "security-evidence-reviewer",
  "keyboard-evaluator": "keyboard-accessibility-evaluator",
} as const;

function buildTaskEvidence(): RepresentativeStudyEvidence {
  const selectedSlots = new Set(R124_REPRESENTATIVE_PARTITION.participantSlots);
  const participants = REPRESENTATIVE_TASK_PROTOCOL.roles
    .filter(({ participantSlot }) => selectedSlots.has(participantSlot))
    .map(({ participantSlot, role }) => ({
      participantSlot,
      role,
      experienceConfirmed: true,
    }));
  return {
    contractVersion: UI_FOUNDATION_CONTRACT_VERSION,
    studyId: "participant-study-20260827",
    sourceRevision: SOURCE_REVISION,
    conductedAt: "2026-08-27T03:00:00.000Z",
    participants,
    outcomes: participants.flatMap(({ participantSlot }) =>
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

function buildGovernanceEvidence(): ParticipantStudyGovernanceEvidence {
  const taskEvidence = buildTaskEvidence();
  return {
    schemaVersion: PARTICIPANT_STUDY_GOVERNANCE_SCHEMA_VERSION,
    protocolRevision: PARTICIPANT_STUDY_PROTOCOL_REVISION,
    studyId: taskEvidence.studyId,
    sourceRevision: SOURCE_REVISION,
    sourceTreeOid: SOURCE_TREE_OID,
    conductedAt: taskEvidence.conductedAt,
    bindings: {
      protocolSha256: PROTOCOL_SHA256,
      fixtureSha256: FIXTURE_SHA256,
      evaluatorSha256: EVALUATOR_SHA256,
      facilitatorGuideSha256: GUIDE_SHA256,
      retentionPolicySha256: POLICY_SHA256,
    },
    practiceRun: {
      completed: true,
      completedAt: "2026-08-26T03:00:00.000Z",
      neutralGuideRevision: "neutral-facilitator-guide-v1",
    },
    participants: R124_REPRESENTATIVE_PARTITION.participantSlots.map((participantSlot) => ({
      participantSlot: participantSlot as ParticipantStudySlot,
      eligibilityCategory: ELIGIBILITY_BY_SLOT[
        participantSlot as keyof typeof ELIGIBILITY_BY_SLOT
      ],
      realPersonConfirmed: true,
      distinctPersonConfirmed: true,
      consent: {
        verified: true,
        informationSheetRevision: "participant-information-v1",
        informationSheetSha256: INFORMATION_SHEET_SHA256,
        consentFormRevision: "participant-consent-v1",
        consentFormSha256: CONSENT_FORM_SHA256,
        verifiedAt: "2026-08-26T04:00:00.000Z",
        withdrawalDeadline: "2026-09-10T00:00:00.000Z",
      },
      sessionIntegrity: {
        practiceCompleted: true,
        fixtureResetConfirmed: true,
        neutralGuideRevision: "neutral-facilitator-guide-v1",
        recordingUsed: false,
        protocolDeviation: false,
      },
      satisfaction: {
        measure: "redagent-directional-v1",
        easeOfUse: 4,
        safetyConfidence: 5,
      },
    })),
    distinctPeopleConfirmed: true,
    withdrawalExclusionCount: 0,
    administration: {
      consentRecordsLocation: "restricted-outside-git",
      accessScope: "authorized-research-and-assurance-only",
      retentionPolicyRevision: "participant-evidence-retention-v1",
      trackedEvidenceExpiresAt: "2027-08-27T00:00:00.000Z",
    },
    claims: {
      claim: "candidate-specific-formative-operator-validation",
      limitations: [...PARTICIPANT_STUDY_LIMITATIONS],
    },
    taskEvidence,
  };
}

function evaluate(value: unknown) {
  return evaluateRepresentativeStudyGovernance(value, EXPECTED_BINDINGS);
}

describe("participant study governance contract", () => {
  it("accepts exactly five deidentified governed slots and the frozen 35-outcome compat_124 contract", () => {
    const result = evaluate(buildGovernanceEvidence());
    expect(result).toMatchObject({
      accepted: true,
      issues: [],
      metrics: {
        participantCount: 5,
        outcomeCount: 35,
        safetyCriticalSuccessRate: 1,
        unsafeInterpretations: 0,
        medianEaseOfUse: 4,
        medianSafetyConfidence: 5,
      },
    });
    expect(REPRESENTATIVE_TASK_PROTOCOL.tasks).toHaveLength(7);
    expect(R124_REPRESENTATIVE_PARTITION.participantSlots).toHaveLength(5);
  });

  it("rejects missing, duplicate, extra, or falsely distinct participant slots", () => {
    const missing = buildGovernanceEvidence();
    missing.participants.pop();
    expect(evaluate(missing).issues).toContain("missing governance participant keyboard-evaluator");

    const duplicate = buildGovernanceEvidence();
    duplicate.participants[4] = structuredClone(duplicate.participants[0]!);
    expect(evaluate(duplicate).issues).toContain("duplicate governance participant operator-a");

    const extra = buildGovernanceEvidence() as unknown as { participants: unknown[] };
    extra.participants.push({ participantSlot: "administrator" });
    expect(evaluate(extra).issues).toContain("unexpected governance participant administrator");

    const notDistinct = buildGovernanceEvidence();
    notDistinct.distinctPeopleConfirmed = false;
    notDistinct.participants[0]!.distinctPersonConfirmed = false;
    expect(evaluate(notDistinct).issues).toEqual(expect.arrayContaining([
      "five distinct real people must be confirmed",
      "operator-a distinct-person attestation is required",
    ]));
  });

  it("rejects missing consent, invalid withdrawal bounds, and incoherent timestamps", () => {
    const evidence = buildGovernanceEvidence();
    evidence.participants[0]!.consent.verified = false;
    evidence.participants[1]!.consent.verifiedAt = "2026-08-28T00:00:00.000Z";
    evidence.participants[2]!.consent.withdrawalDeadline = "2026-08-26T00:00:00.000Z";
    evidence.withdrawalExclusionCount = -1;
    evidence.practiceRun.completedAt = "2026-08-28T00:00:00.000Z";
    expect(evaluate(evidence).issues).toEqual(expect.arrayContaining([
      "operator-a consent verification is required",
      "operator-b consent must be verified before the study",
      "approver withdrawal deadline must follow the study",
      "withdrawalExclusionCount must be a non-negative integer",
      "practice run must complete before the study",
    ]));
  });

  it("binds every participant to the same trusted information and consent revisions", () => {
    const evidence = buildGovernanceEvidence();
    evidence.participants[0]!.consent.informationSheetSha256 = "4".repeat(64);
    evidence.participants[1]!.consent.consentFormSha256 = "5".repeat(64);
    evidence.participants[2]!.consent.informationSheetRevision = "contains free text";
    evidence.participants[3]!.consent.consentFormRevision = "";
    expect(evaluate(evidence).issues).toEqual(expect.arrayContaining([
      "operator-a information sheet does not match the trusted digest",
      "operator-b consent form does not match the trusted digest",
      "approver informationSheetRevision must be an opaque revision token",
      "reviewer consentFormRevision must be an opaque revision token",
    ]));
  });

  it("delegates missing, duplicate, extra, and threshold-drift outcomes to the frozen compat_124 gate", () => {
    const missing = buildGovernanceEvidence();
    missing.taskEvidence.outcomes.pop();
    expect(evaluate(missing).issues).toEqual(expect.arrayContaining([
      expect.stringContaining("missing outcome"),
    ]));

    const duplicate = buildGovernanceEvidence();
    duplicate.taskEvidence.outcomes[34] = structuredClone(duplicate.taskEvidence.outcomes[0]!);
    expect(evaluate(duplicate).issues).toEqual(expect.arrayContaining([
      expect.stringContaining("duplicate outcome"),
    ]));

    const extra = buildGovernanceEvidence() as unknown as {
      taskEvidence: { outcomes: Array<Record<string, unknown>>; thresholds?: unknown };
    };
    extra.taskEvidence.outcomes.push({
      participantSlot: "administrator",
      taskId: "invented-task",
      taskSuccess: true,
      completedUnassisted: true,
      unsafeInterpretation: false,
      topLevelActivations: 0,
      destinationActivations: 0,
    });
    extra.taskEvidence.thresholds = { safetyCriticalSuccessRate: 0 };
    expect(evaluate(extra).issues).toEqual(expect.arrayContaining([
      "unexpected outcome administrator:invented-task",
      "unexpected study field thresholds",
    ]));
  });

  it("rejects recording, fixture, guide, access, retention, and opaque-token drift", () => {
    const evidence = buildGovernanceEvidence();
    evidence.studyId = "participant name or free text";
    evidence.participants[0]!.sessionIntegrity.recordingUsed = true;
    evidence.participants[1]!.sessionIntegrity.fixtureResetConfirmed = false;
    evidence.participants[2]!.sessionIntegrity.neutralGuideRevision = "other-guide";
    evidence.participants[3]!.sessionIntegrity.protocolDeviation = true;
    evidence.administration.consentRecordsLocation = "restricted-outside-git";
    evidence.administration.accessScope = "authorized-research-and-assurance-only";
    evidence.administration.retentionPolicyRevision = "contains free text";
    evidence.administration.trackedEvidenceExpiresAt = "2026-08-26T00:00:00.000Z";
    expect(evaluate(evidence).issues).toEqual(expect.arrayContaining([
      "studyId must be an opaque token",
      "operator-a recording is prohibited",
      "operator-b fixture reset is required",
      "approver neutral facilitator guide revision must match the practice run",
      "reviewer protocol deviation prevents acceptance",
      "retention policy revision must be an opaque revision token",
      "tracked evidence expiry must follow the study",
    ]));
  });

  it("rejects identity, free-text, raw-data, and other unexpected fields at every governed layer", () => {
    const evidence = buildGovernanceEvidence() as unknown as Record<string, unknown>;
    (evidence.participants as Array<Record<string, unknown>>)[0]!.name = "prohibited";
    ((evidence.participants as Array<Record<string, unknown>>)[1]!.consent as Record<string, unknown>)
      .contact = "prohibited";
    ((evidence.taskEvidence as Record<string, unknown>).outcomes as Array<Record<string, unknown>>)[0]!
      .rawEvidence = "prohibited";
    (evidence.claims as Record<string, unknown>).freeText = "prohibited";
    expect(evaluate(evidence).issues).toEqual(expect.arrayContaining([
      "unexpected governance participant field name",
      "unexpected consent field contact",
      "unexpected outcome field rawEvidence",
      "unexpected claims field freeText",
    ]));
  });

  it.each([
    ["sourceRevision", "9".repeat(40), "sourceRevision does not match the expected candidate"],
    ["sourceTreeOid", "8".repeat(40), "sourceTreeOid does not match the expected candidate tree"],
  ] as const)("rejects stale %s bindings", (field, value, issue) => {
    const evidence = buildGovernanceEvidence();
    evidence[field] = value;
    expect(evaluate(evidence).issues).toContain(issue);
  });

  it.each([
    ["protocolSha256", "protocol binding does not match the expected digest"],
    ["fixtureSha256", "fixture binding does not match the expected digest"],
    ["evaluatorSha256", "evaluator binding does not match the expected digest"],
    ["facilitatorGuideSha256", "facilitator guide binding does not match the expected digest"],
    ["retentionPolicySha256", "retention policy binding does not match the expected digest"],
  ] as const)("rejects stale %s", (field, issue) => {
    const evidence = buildGovernanceEvidence();
    evidence.bindings[field] = "9".repeat(64);
    expect(evaluate(evidence).issues).toContain(issue);
  });

  it("rejects overbroad claims, incomplete limitations, and invalid directional ratings", () => {
    const evidence = buildGovernanceEvidence();
    evidence.claims.claim = "production-qualified" as typeof evidence.claims.claim;
    evidence.claims.limitations.pop();
    evidence.participants[0]!.satisfaction.easeOfUse = 6;
    evidence.participants[1]!.satisfaction.measure = "UMUX-LITE" as "redagent-directional-v1";
    expect(evaluate(evidence).issues).toEqual(expect.arrayContaining([
      "claim must remain candidate-specific formative operator validation",
      "claim limitations must match the closed formative vocabulary",
      "operator-a directional satisfaction ratings must be integers from 1 to 5",
      "operator-b satisfaction measure must be redagent-directional-v1",
    ]));
  });

  it("never lets satisfaction override consent, privacy, or compat_124 safety/task failure", () => {
    const evidence = buildGovernanceEvidence();
    evidence.participants.forEach(({ satisfaction }) => {
      satisfaction.easeOfUse = 5;
      satisfaction.safetyConfidence = 5;
    });
    evidence.taskEvidence.outcomes[0]!.taskSuccess = false;
    evidence.taskEvidence.outcomes[0]!.unsafeInterpretation = true;
    const result = evaluate(evidence);
    expect(result.accepted).toBe(false);
    expect(result.metrics).toMatchObject({
      medianEaseOfUse: 5,
      medianSafetyConfidence: 5,
      unsafeInterpretations: 1,
    });
    expect(result.issues).toEqual(expect.arrayContaining([
      expect.stringContaining("safety-critical success rate"),
      expect.stringContaining("unsafe interpretation count"),
    ]));
  });

  it("rejects malformed governance JSON instead of throwing or accepting partial evidence", () => {
    expect(evaluate(null)).toMatchObject({ accepted: false });
    expect(evaluate({ taskEvidence: buildTaskEvidence() })).toMatchObject({ accepted: false });
    expect(evaluate([])).toMatchObject({ accepted: false });
  });
});
