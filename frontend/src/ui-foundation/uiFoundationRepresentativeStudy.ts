import type {
  RepresentativeRole,
  RepresentativeTaskProtocol,
} from "./uiFoundationContracts";
import { UI_FOUNDATION_CONTRACT_VERSION } from "./uiFoundationQualification";

export type RepresentativeStudyParticipant = {
  participantSlot: string;
  role: RepresentativeRole["role"];
  experienceConfirmed: boolean;
};

export type RepresentativeStudyOutcome = {
  participantSlot: string;
  taskId: string;
  taskSuccess: boolean;
  completedUnassisted: boolean;
  unsafeInterpretation: boolean;
  topLevelActivations: number;
  destinationActivations: number;
};

export type RepresentativeStudyEvidence = {
  contractVersion: string;
  studyId: string;
  sourceRevision: string;
  conductedAt: string;
  participants: RepresentativeStudyParticipant[];
  outcomes: RepresentativeStudyOutcome[];
  privacy: {
    syntheticDataConfirmed: boolean;
    participantIdentityRecorded: boolean;
    rawMediaRecorded: boolean;
    operationalTargetDataRecorded: boolean;
  };
};

export type RepresentativeStudyEvaluation = {
  accepted: boolean;
  issues: string[];
  metrics: {
    participantCount: number;
    outcomeCount: number;
    safetyCriticalSuccessRate: number;
    overallUnassistedSuccessRate: number;
    nonSafetyUnassistedSuccessRate: number;
    unsafeInterpretations: number;
    medianTopLevelActivations: number;
    medianDestinationActivations: number;
  };
};

export type RepresentativeStudyPartition = {
  owner: "compat_124" | "compat_128";
  participantSlots: readonly string[];
};

export const R124_REPRESENTATIVE_PARTITION: RepresentativeStudyPartition = {
  owner: "compat_124",
  participantSlots: [
    "operator-a",
    "operator-b",
    "approver",
    "reviewer",
    "keyboard-evaluator",
  ],
};

export const R128_REPRESENTATIVE_PARTITION: RepresentativeStudyPartition = {
  owner: "compat_128",
  participantSlots: ["administrator"],
};

function invalidJsonShapeEvaluation(): RepresentativeStudyEvaluation {
  return {
    accepted: false,
    issues: ["representative study JSON shape is invalid"],
    metrics: {
      participantCount: 0,
      outcomeCount: 0,
      safetyCriticalSuccessRate: 0,
      overallUnassistedSuccessRate: 0,
      nonSafetyUnassistedSuccessRate: 0,
      unsafeInterpretations: 0,
      medianTopLevelActivations: 0,
      medianDestinationActivations: 0,
    },
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

const PRIVACY_FIELDS = [
  "syntheticDataConfirmed",
  "participantIdentityRecorded",
  "rawMediaRecorded",
  "operationalTargetDataRecorded",
] as const;

export function evaluateRepresentativeTaskStudyJson(
  value: unknown,
  protocol: RepresentativeTaskProtocol,
): RepresentativeStudyEvaluation {
  if (!isRecord(value)) return invalidJsonShapeEvaluation();
  const privacy = value.privacy;
  if (typeof value.contractVersion !== "string"
    || typeof value.studyId !== "string"
    || typeof value.sourceRevision !== "string"
    || typeof value.conductedAt !== "string"
    || !Array.isArray(value.participants)
    || !value.participants.every(isRecord)
    || !Array.isArray(value.outcomes)
    || !value.outcomes.every(isRecord)
    || !isRecord(privacy)
    || !PRIVACY_FIELDS.every((field) => typeof privacy[field] === "boolean")) {
    return invalidJsonShapeEvaluation();
  }

  return evaluateRepresentativeTaskStudy(
    value as unknown as RepresentativeStudyEvidence,
    protocol,
  );
}

export function evaluateRepresentativeTaskStudyPartitionJson(
  value: unknown,
  protocol: RepresentativeTaskProtocol,
  partition: RepresentativeStudyPartition,
): RepresentativeStudyEvaluation {
  const selectedSlots = new Set(partition.participantSlots);
  const selectedProtocol: RepresentativeTaskProtocol = {
    ...protocol,
    roles: protocol.roles.filter(({ participantSlot }) => selectedSlots.has(participantSlot)),
  };
  const shapeEvaluation = evaluateRepresentativeTaskStudyJson(value, selectedProtocol);
  if (shapeEvaluation.issues.includes("representative study JSON shape is invalid")) {
    return shapeEvaluation;
  }
  return evaluateRepresentativeTaskStudyPartition(
    value as RepresentativeStudyEvidence,
    protocol,
    partition,
  );
}

export function evaluateRepresentativeTaskStudy(
  evidence: RepresentativeStudyEvidence,
  protocol: RepresentativeTaskProtocol,
): RepresentativeStudyEvaluation {
  const issues: string[] = [];
  const studyFields = [
    "contractVersion",
    "studyId",
    "sourceRevision",
    "conductedAt",
    "participants",
    "outcomes",
    "privacy",
  ];
  const participantFields = ["participantSlot", "role", "experienceConfirmed"];
  const outcomeFields = [
    "participantSlot",
    "taskId",
    "taskSuccess",
    "completedUnassisted",
    "unsafeInterpretation",
    "topLevelActivations",
    "destinationActivations",
  ];
  const privacyFields: readonly string[] = PRIVACY_FIELDS;

  for (const field of Object.keys(evidence)) {
    if (!studyFields.includes(field)) issues.push(`unexpected study field ${field}`);
  }
  for (const field of Object.keys(evidence.privacy)) {
    if (!privacyFields.includes(field)) issues.push(`unexpected privacy field ${field}`);
  }

  if (evidence.contractVersion !== UI_FOUNDATION_CONTRACT_VERSION) {
    issues.push(`contractVersion must be ${UI_FOUNDATION_CONTRACT_VERSION}`);
  }
  if (!/^[0-9a-f]{40}([0-9a-f]{24})?$/.test(evidence.sourceRevision)) {
    issues.push("sourceRevision must be an immutable 40- or 64-character lowercase Git object id");
  }
  if (!evidence.studyId || Number.isNaN(Date.parse(evidence.conductedAt))) {
    issues.push("studyId and a valid conductedAt timestamp are required");
  }

  const expectedParticipants = new Map(
    protocol.roles.map(({ participantSlot, role }) => [participantSlot, role]),
  );
  const seenParticipants = new Set<string>();
  for (const participant of evidence.participants) {
    for (const field of Object.keys(participant)) {
      if (!participantFields.includes(field)) {
        issues.push(`unexpected participant field ${field}`);
      }
    }
    if (seenParticipants.has(participant.participantSlot)) {
      issues.push(`duplicate participant slot ${participant.participantSlot}`);
    }
    seenParticipants.add(participant.participantSlot);
    const expectedRole = expectedParticipants.get(participant.participantSlot);
    if (!expectedRole) {
      issues.push(`unexpected participant slot ${participant.participantSlot}`);
    } else if (participant.role !== expectedRole) {
      issues.push(`${participant.participantSlot} role must be ${expectedRole}`);
    }
    if (!participant.experienceConfirmed) {
      issues.push(`${participant.participantSlot} required experience is not confirmed`);
    }
    if (typeof participant.experienceConfirmed !== "boolean") {
      issues.push(`${participant.participantSlot} experienceConfirmed must be boolean`);
    }
  }
  for (const participantSlot of expectedParticipants.keys()) {
    if (!seenParticipants.has(participantSlot)) {
      issues.push(`missing participant slot ${participantSlot}`);
    }
  }

  const expectedOutcomeKeys = new Set(
    protocol.roles.flatMap(({ participantSlot }) => (
      protocol.tasks.map(({ id }) => `${participantSlot}:${id}`)
    )),
  );
  const seenOutcomeKeys = new Set<string>();
  for (const outcome of evidence.outcomes) {
    for (const field of Object.keys(outcome)) {
      if (!outcomeFields.includes(field)) issues.push(`unexpected outcome field ${field}`);
    }
    const key = `${outcome.participantSlot}:${outcome.taskId}`;
    if (seenOutcomeKeys.has(key)) issues.push(`duplicate outcome ${key}`);
    seenOutcomeKeys.add(key);
    if (!expectedOutcomeKeys.has(key)) issues.push(`unexpected outcome ${key}`);
    if (!Number.isInteger(outcome.topLevelActivations) || outcome.topLevelActivations < 0
      || !Number.isInteger(outcome.destinationActivations) || outcome.destinationActivations < 0) {
      issues.push(`${key} activation counts must be non-negative integers`);
    }
    for (const [field, value] of [
      ["taskSuccess", outcome.taskSuccess],
      ["completedUnassisted", outcome.completedUnassisted],
      ["unsafeInterpretation", outcome.unsafeInterpretation],
    ] as const) {
      if (typeof value !== "boolean") issues.push(`${key} ${field} must be boolean`);
    }
  }
  for (const key of expectedOutcomeKeys) {
    if (!seenOutcomeKeys.has(key)) issues.push(`missing outcome ${key}`);
  }

  if (!evidence.privacy.syntheticDataConfirmed) {
    issues.push("study data must be confirmed synthetic");
  }
  if (evidence.privacy.participantIdentityRecorded) {
    issues.push("participant identity must not be recorded");
  }
  if (evidence.privacy.rawMediaRecorded) {
    issues.push("raw participant media must not be recorded");
  }
  if (evidence.privacy.operationalTargetDataRecorded) {
    issues.push("operational target data must not be recorded");
  }
  for (const [field, value] of Object.entries(evidence.privacy)) {
    if (typeof value !== "boolean") issues.push(`privacy ${field} must be boolean`);
  }

  const safetyTaskIds = new Set(
    protocol.tasks.filter(({ safetyCritical }) => safetyCritical).map(({ id }) => id),
  );
  const safetyOutcomes = evidence.outcomes.filter(({ taskId }) => safetyTaskIds.has(taskId));
  const nonSafetyOutcomes = evidence.outcomes.filter(({ taskId }) => !safetyTaskIds.has(taskId));
  const rate = (numerator: number, denominator: number) => (
    denominator === 0 ? 0 : numerator / denominator
  );
  const median = (values: number[]) => {
    if (values.length === 0) return 0;
    const sorted = [...values].sort((left, right) => left - right);
    const middle = Math.floor(sorted.length / 2);
    if (sorted.length % 2 === 1) return sorted[middle] ?? 0;
    return ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2;
  };
  const safetyCriticalSuccessRate = rate(
    safetyOutcomes.filter(({ taskSuccess, unsafeInterpretation }) => taskSuccess === true && unsafeInterpretation === false).length,
    safetyOutcomes.length,
  );
  const overallUnassistedSuccessRate = rate(
    evidence.outcomes.filter(({ taskSuccess, completedUnassisted }) => taskSuccess === true && completedUnassisted === true).length,
    evidence.outcomes.length,
  );
  const nonSafetyUnassistedSuccessRate = rate(
    nonSafetyOutcomes.filter(({ taskSuccess, completedUnassisted }) => taskSuccess === true && completedUnassisted === true).length,
    nonSafetyOutcomes.length,
  );
  const unsafeInterpretations = evidence.outcomes.filter(({ unsafeInterpretation }) => unsafeInterpretation === true).length;
  const medianTopLevelActivations = median(evidence.outcomes.map(({ topLevelActivations }) => topLevelActivations));
  const medianDestinationActivations = median(evidence.outcomes.map(({ destinationActivations }) => destinationActivations));

  if (safetyCriticalSuccessRate < protocol.thresholds.safetyCriticalSuccessRate) {
    issues.push(`safety-critical success rate ${safetyCriticalSuccessRate} is below ${protocol.thresholds.safetyCriticalSuccessRate}`);
  }
  if (overallUnassistedSuccessRate < protocol.thresholds.overallUnassistedSuccessRate) {
    issues.push(`overall unassisted success rate ${overallUnassistedSuccessRate} is below ${protocol.thresholds.overallUnassistedSuccessRate}`);
  }
  if (nonSafetyUnassistedSuccessRate < protocol.thresholds.nonSafetyUnassistedSuccessRate) {
    issues.push(`non-safety unassisted success rate ${nonSafetyUnassistedSuccessRate} is below ${protocol.thresholds.nonSafetyUnassistedSuccessRate}`);
  }
  if (unsafeInterpretations > protocol.thresholds.unsafeInterpretations) {
    issues.push(`unsafe interpretation count ${unsafeInterpretations} exceeds ${protocol.thresholds.unsafeInterpretations}`);
  }
  if (medianTopLevelActivations > protocol.thresholds.medianTopLevelActivations) {
    issues.push(`top-level activation median ${medianTopLevelActivations} exceeds ${protocol.thresholds.medianTopLevelActivations}`);
  }
  if (medianDestinationActivations > protocol.thresholds.medianDestinationActivations) {
    issues.push(`destination activation median ${medianDestinationActivations} exceeds ${protocol.thresholds.medianDestinationActivations}`);
  }

  const metrics = {
    participantCount: evidence.participants.length,
    outcomeCount: evidence.outcomes.length,
    safetyCriticalSuccessRate,
    overallUnassistedSuccessRate,
    nonSafetyUnassistedSuccessRate,
    unsafeInterpretations,
    medianTopLevelActivations,
    medianDestinationActivations,
  };
  return {
    accepted: issues.length === 0,
    issues,
    metrics,
  };
}

export function evaluateRepresentativeTaskStudyPartition(
  evidence: RepresentativeStudyEvidence,
  protocol: RepresentativeTaskProtocol,
  partition: RepresentativeStudyPartition,
): RepresentativeStudyEvaluation {
  const issues: string[] = [];
  const knownSlots = new Set(protocol.roles.map(({ participantSlot }) => participantSlot));
  const selectedSlots = new Set(partition.participantSlots);
  if (selectedSlots.size !== partition.participantSlots.length) {
    issues.push(`${partition.owner} partition contains duplicate participant slots`);
  }
  for (const slot of selectedSlots) {
    if (!knownSlots.has(slot)) issues.push(`${partition.owner} partition contains unknown slot ${slot}`);
  }
  const overlap = R124_REPRESENTATIVE_PARTITION.participantSlots.filter((slot) =>
    R128_REPRESENTATIVE_PARTITION.participantSlots.includes(slot));
  const owned = new Set([
    ...R124_REPRESENTATIVE_PARTITION.participantSlots,
    ...R128_REPRESENTATIVE_PARTITION.participantSlots,
  ]);
  if (overlap.length || owned.size !== knownSlots.size
    || [...knownSlots].some((slot) => !owned.has(slot))) {
    issues.push("compat_124/compat_128 representative partitions must cover the frozen roles exactly once");
  }
  const selectedProtocol: RepresentativeTaskProtocol = {
    ...protocol,
    roles: protocol.roles.filter(({ participantSlot }) => selectedSlots.has(participantSlot)),
  };
  const evaluated = evaluateRepresentativeTaskStudy(evidence, selectedProtocol);
  const combinedIssues = [...issues, ...evaluated.issues];
  return {
    ...evaluated,
    accepted: combinedIssues.length === 0,
    issues: combinedIssues,
  };
}
