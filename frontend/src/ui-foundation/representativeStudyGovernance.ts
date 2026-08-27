import { REPRESENTATIVE_TASK_PROTOCOL } from "./uiFoundationContracts";
import {
  R124_REPRESENTATIVE_PARTITION,
  evaluateRepresentativeTaskStudyPartitionJson,
  type RepresentativeStudyEvidence,
  type RepresentativeStudyEvaluation,
} from "./uiFoundationRepresentativeStudy";

export const PARTICIPANT_STUDY_GOVERNANCE_SCHEMA_VERSION =
  "participant-study-governance-v1" as const;
export const PARTICIPANT_STUDY_PROTOCOL_REVISION = "participant-study-protocol-v1" as const;

export const PARTICIPANT_STUDY_LIMITATIONS = [
  "no-population-generalization",
  "no-accessibility-conformance",
  "no-production-qualification",
  "no-release-or-ga-authority",
] as const;

const ELIGIBILITY_BY_SLOT = {
  "operator-a": "authorized-red-team-operator",
  "operator-b": "authorized-red-team-operator",
  approver: "security-approval-authority",
  reviewer: "security-evidence-reviewer",
  "keyboard-evaluator": "keyboard-accessibility-evaluator",
} as const;

export type ParticipantStudySlot = keyof typeof ELIGIBILITY_BY_SLOT;
type ParticipantSlot = ParticipantStudySlot;
type EligibilityCategory = typeof ELIGIBILITY_BY_SLOT[ParticipantSlot];
const PARTICIPANT_SLOTS = R124_REPRESENTATIVE_PARTITION.participantSlots;

export type ParticipantStudyExpectedBindings = {
  sourceRevision: string;
  sourceTreeOid: string;
  protocolSha256: string;
  fixtureSha256: string;
  evaluatorSha256: string;
  facilitatorGuideSha256: string;
  retentionPolicySha256: string;
  informationSheetSha256: string;
  consentFormSha256: string;
};

type ParticipantConsentVerification = {
  verified: boolean;
  informationSheetRevision: string;
  informationSheetSha256: string;
  consentFormRevision: string;
  consentFormSha256: string;
  verifiedAt: string;
  withdrawalDeadline: string;
};

type ParticipantSessionIntegrity = {
  practiceCompleted: boolean;
  fixtureResetConfirmed: boolean;
  neutralGuideRevision: string;
  recordingUsed: boolean;
  protocolDeviation: boolean;
};

type ParticipantDirectionalSatisfaction = {
  measure: "redagent-directional-v1";
  easeOfUse: number;
  safetyConfidence: number;
};

type ParticipantStudyGovernanceParticipant = {
  participantSlot: ParticipantSlot;
  eligibilityCategory: EligibilityCategory;
  realPersonConfirmed: boolean;
  distinctPersonConfirmed: boolean;
  consent: ParticipantConsentVerification;
  sessionIntegrity: ParticipantSessionIntegrity;
  satisfaction: ParticipantDirectionalSatisfaction;
};

export type ParticipantStudyGovernanceEvidence = {
  schemaVersion: typeof PARTICIPANT_STUDY_GOVERNANCE_SCHEMA_VERSION;
  protocolRevision: typeof PARTICIPANT_STUDY_PROTOCOL_REVISION;
  studyId: string;
  sourceRevision: string;
  sourceTreeOid: string;
  conductedAt: string;
  bindings: {
    protocolSha256: string;
    fixtureSha256: string;
    evaluatorSha256: string;
    facilitatorGuideSha256: string;
    retentionPolicySha256: string;
  };
  practiceRun: {
    completed: boolean;
    completedAt: string;
    neutralGuideRevision: string;
  };
  participants: ParticipantStudyGovernanceParticipant[];
  distinctPeopleConfirmed: boolean;
  withdrawalExclusionCount: number;
  administration: {
    consentRecordsLocation: "restricted-outside-git";
    accessScope: "authorized-research-and-assurance-only";
    retentionPolicyRevision: string;
    trackedEvidenceExpiresAt: string;
  };
  claims: {
    claim: "candidate-specific-formative-operator-validation";
    limitations: Array<typeof PARTICIPANT_STUDY_LIMITATIONS[number]>;
  };
  taskEvidence: RepresentativeStudyEvidence;
};

export type ParticipantStudyGovernanceEvaluation = {
  accepted: boolean;
  issues: string[];
  metrics: RepresentativeStudyEvaluation["metrics"] & {
    medianEaseOfUse: number;
    medianSafetyConfidence: number;
  };
};

const TOP_LEVEL_FIELDS = [
  "schemaVersion",
  "protocolRevision",
  "studyId",
  "sourceRevision",
  "sourceTreeOid",
  "conductedAt",
  "bindings",
  "practiceRun",
  "participants",
  "distinctPeopleConfirmed",
  "withdrawalExclusionCount",
  "administration",
  "claims",
  "taskEvidence",
] as const;
const BINDING_FIELDS = [
  "protocolSha256",
  "fixtureSha256",
  "evaluatorSha256",
  "facilitatorGuideSha256",
  "retentionPolicySha256",
] as const;
const PRACTICE_FIELDS = ["completed", "completedAt", "neutralGuideRevision"] as const;
const PARTICIPANT_FIELDS = [
  "participantSlot",
  "eligibilityCategory",
  "realPersonConfirmed",
  "distinctPersonConfirmed",
  "consent",
  "sessionIntegrity",
  "satisfaction",
] as const;
const CONSENT_FIELDS = [
  "verified",
  "informationSheetRevision",
  "informationSheetSha256",
  "consentFormRevision",
  "consentFormSha256",
  "verifiedAt",
  "withdrawalDeadline",
] as const;
const SESSION_FIELDS = [
  "practiceCompleted",
  "fixtureResetConfirmed",
  "neutralGuideRevision",
  "recordingUsed",
  "protocolDeviation",
] as const;
const SATISFACTION_FIELDS = ["measure", "easeOfUse", "safetyConfidence"] as const;
const ADMINISTRATION_FIELDS = [
  "consentRecordsLocation",
  "accessScope",
  "retentionPolicyRevision",
  "trackedEvidenceExpiresAt",
] as const;
const CLAIM_FIELDS = ["claim", "limitations"] as const;
const GIT_OID = /^[0-9a-f]{40}([0-9a-f]{24})?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const OPAQUE_TOKEN = /^[a-z0-9][a-z0-9._-]{0,63}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function recordUnexpectedFields(
  value: Record<string, unknown>,
  allowedFields: readonly string[],
  label: string,
  issues: string[],
): void {
  for (const field of Object.keys(value)) {
    if (!allowedFields.includes(field)) issues.push(`unexpected ${label} field ${field}`);
  }
}

function validTimestamp(value: unknown): value is string {
  return typeof value === "string" && !Number.isNaN(Date.parse(value));
}

function isParticipantSlot(value: string): value is ParticipantSlot {
  return Object.prototype.hasOwnProperty.call(ELIGIBILITY_BY_SLOT, value);
}

function median(values: number[]): number {
  if (values.length === 0) return 0;
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  if (sorted.length % 2 === 1) return sorted[middle] ?? 0;
  return ((sorted[middle - 1] ?? 0) + (sorted[middle] ?? 0)) / 2;
}

function emptyMetrics(): RepresentativeStudyEvaluation["metrics"] {
  return {
    participantCount: 0,
    outcomeCount: 0,
    safetyCriticalSuccessRate: 0,
    overallUnassistedSuccessRate: 0,
    nonSafetyUnassistedSuccessRate: 0,
    unsafeInterpretations: 0,
    medianTopLevelActivations: 0,
    medianDestinationActivations: 0,
  };
}

function malformedEvaluation(): ParticipantStudyGovernanceEvaluation {
  return {
    accepted: false,
    issues: ["participant study governance JSON shape is invalid"],
    metrics: { ...emptyMetrics(), medianEaseOfUse: 0, medianSafetyConfidence: 0 },
  };
}

function bindingIssue(field: keyof ParticipantStudyExpectedBindings): string {
  const messages: Record<keyof ParticipantStudyExpectedBindings, string> = {
    sourceRevision: "sourceRevision does not match the expected candidate",
    sourceTreeOid: "sourceTreeOid does not match the expected candidate tree",
    protocolSha256: "protocol binding does not match the expected digest",
    fixtureSha256: "fixture binding does not match the expected digest",
    evaluatorSha256: "evaluator binding does not match the expected digest",
    facilitatorGuideSha256: "facilitator guide binding does not match the expected digest",
    retentionPolicySha256: "retention policy binding does not match the expected digest",
    informationSheetSha256: "information sheet does not match the trusted digest",
    consentFormSha256: "consent form does not match the trusted digest",
  };
  return messages[field];
}

export function evaluateRepresentativeStudyGovernance(
  value: unknown,
  expectedBindings: ParticipantStudyExpectedBindings,
): ParticipantStudyGovernanceEvaluation {
  // SECURITY: keep this boundary closed-key and fail-closed; tracked study evidence must not absorb PII or raw session content.
  if (!isRecord(value)) return malformedEvaluation();
  const issues: string[] = [];
  recordUnexpectedFields(value, TOP_LEVEL_FIELDS, "governance", issues);

  if (value.schemaVersion !== PARTICIPANT_STUDY_GOVERNANCE_SCHEMA_VERSION) {
    issues.push(`schemaVersion must be ${PARTICIPANT_STUDY_GOVERNANCE_SCHEMA_VERSION}`);
  }
  if (value.protocolRevision !== PARTICIPANT_STUDY_PROTOCOL_REVISION) {
    issues.push(`protocolRevision must be ${PARTICIPANT_STUDY_PROTOCOL_REVISION}`);
  }
  if (typeof value.studyId !== "string" || !OPAQUE_TOKEN.test(value.studyId)) {
    issues.push("studyId must be an opaque token");
  }
  if (typeof value.sourceRevision !== "string" || !GIT_OID.test(value.sourceRevision)) {
    issues.push("sourceRevision must be an immutable lowercase Git object id");
  }
  if (typeof value.sourceTreeOid !== "string" || !GIT_OID.test(value.sourceTreeOid)) {
    issues.push("sourceTreeOid must be an immutable lowercase Git object id");
  }
  if (!validTimestamp(value.conductedAt)) issues.push("conductedAt must be a valid timestamp");
  if (value.sourceRevision !== expectedBindings.sourceRevision) {
    issues.push(bindingIssue("sourceRevision"));
  }
  if (value.sourceTreeOid !== expectedBindings.sourceTreeOid) {
    issues.push(bindingIssue("sourceTreeOid"));
  }

  const bindings = isRecord(value.bindings) ? value.bindings : {};
  if (!isRecord(value.bindings)) issues.push("bindings are required");
  recordUnexpectedFields(bindings, BINDING_FIELDS, "bindings", issues);
  for (const field of BINDING_FIELDS) {
    if (typeof bindings[field] !== "string" || !SHA256.test(bindings[field])) {
      issues.push(`${field} must be a lowercase SHA-256 digest`);
    }
    if (bindings[field] !== expectedBindings[field]) issues.push(bindingIssue(field));
  }

  const practiceRun = isRecord(value.practiceRun) ? value.practiceRun : {};
  if (!isRecord(value.practiceRun)) issues.push("practiceRun is required");
  recordUnexpectedFields(practiceRun, PRACTICE_FIELDS, "practiceRun", issues);
  if (practiceRun.completed !== true) issues.push("practice run must be completed");
  if (!validTimestamp(practiceRun.completedAt)) {
    issues.push("practice run completedAt must be a valid timestamp");
  } else if (validTimestamp(value.conductedAt)
    && Date.parse(practiceRun.completedAt) >= Date.parse(value.conductedAt)) {
    issues.push("practice run must complete before the study");
  }
  if (typeof practiceRun.neutralGuideRevision !== "string"
    || !OPAQUE_TOKEN.test(practiceRun.neutralGuideRevision)) {
    issues.push("neutral facilitator guide revision must be an opaque revision token");
  }

  const rawParticipants = Array.isArray(value.participants) ? value.participants : [];
  if (!Array.isArray(value.participants)) issues.push("governance participants must be an array");
  const expectedSlots = new Set<string>(PARTICIPANT_SLOTS);
  const seenSlots = new Set<string>();
  const easeOfUse: number[] = [];
  const safetyConfidence: number[] = [];
  for (const [index, rawParticipant] of rawParticipants.entries()) {
    if (!isRecord(rawParticipant)) {
      issues.push(`governance participant ${index} must be an object`);
      continue;
    }
    recordUnexpectedFields(rawParticipant, PARTICIPANT_FIELDS, "governance participant", issues);
    const slot = typeof rawParticipant.participantSlot === "string"
      ? rawParticipant.participantSlot
      : `<unknown:${index}>`;
    if (seenSlots.has(slot)) issues.push(`duplicate governance participant ${slot}`);
    seenSlots.add(slot);
    if (!expectedSlots.has(slot)) issues.push(`unexpected governance participant ${slot}`);
    const expectedEligibility = isParticipantSlot(slot) ? ELIGIBILITY_BY_SLOT[slot] : undefined;
    if (rawParticipant.eligibilityCategory !== expectedEligibility) {
      issues.push(`${slot} eligibility category must be ${expectedEligibility ?? "recognized"}`);
    }
    if (rawParticipant.realPersonConfirmed !== true) {
      issues.push(`${slot} real-person attestation is required`);
    }
    if (rawParticipant.distinctPersonConfirmed !== true) {
      issues.push(`${slot} distinct-person attestation is required`);
    }

    const consent = isRecord(rawParticipant.consent) ? rawParticipant.consent : {};
    if (!isRecord(rawParticipant.consent)) issues.push(`${slot} consent metadata is required`);
    recordUnexpectedFields(consent, CONSENT_FIELDS, "consent", issues);
    if (consent.verified !== true) issues.push(`${slot} consent verification is required`);
    for (const revision of ["informationSheetRevision", "consentFormRevision"] as const) {
      if (typeof consent[revision] !== "string" || !OPAQUE_TOKEN.test(consent[revision])) {
        issues.push(`${slot} ${revision} must be an opaque revision token`);
      }
    }
    for (const digest of ["informationSheetSha256", "consentFormSha256"] as const) {
      if (typeof consent[digest] !== "string" || !SHA256.test(consent[digest])) {
        issues.push(`${slot} ${digest} must be a lowercase SHA-256 digest`);
      }
    }
    if (consent.informationSheetSha256 !== expectedBindings.informationSheetSha256) {
      issues.push(`${slot} ${bindingIssue("informationSheetSha256")}`);
    }
    if (consent.consentFormSha256 !== expectedBindings.consentFormSha256) {
      issues.push(`${slot} ${bindingIssue("consentFormSha256")}`);
    }
    if (!validTimestamp(consent.verifiedAt)) {
      issues.push(`${slot} consent verifiedAt must be a valid timestamp`);
    } else if (validTimestamp(value.conductedAt)
      && Date.parse(consent.verifiedAt) > Date.parse(value.conductedAt)) {
      issues.push(`${slot} consent must be verified before the study`);
    }
    if (!validTimestamp(consent.withdrawalDeadline)) {
      issues.push(`${slot} withdrawalDeadline must be a valid timestamp`);
    } else if (validTimestamp(value.conductedAt)
      && Date.parse(consent.withdrawalDeadline) <= Date.parse(value.conductedAt)) {
      issues.push(`${slot} withdrawal deadline must follow the study`);
    }

    const session = isRecord(rawParticipant.sessionIntegrity)
      ? rawParticipant.sessionIntegrity
      : {};
    if (!isRecord(rawParticipant.sessionIntegrity)) {
      issues.push(`${slot} session integrity metadata is required`);
    }
    recordUnexpectedFields(session, SESSION_FIELDS, "sessionIntegrity", issues);
    if (session.practiceCompleted !== true) issues.push(`${slot} practice session is required`);
    if (session.fixtureResetConfirmed !== true) issues.push(`${slot} fixture reset is required`);
    if (session.neutralGuideRevision !== practiceRun.neutralGuideRevision) {
      issues.push(`${slot} neutral facilitator guide revision must match the practice run`);
    }
    if (session.recordingUsed !== false) issues.push(`${slot} recording is prohibited`);
    if (session.protocolDeviation !== false) {
      issues.push(`${slot} protocol deviation prevents acceptance`);
    }

    const satisfaction = isRecord(rawParticipant.satisfaction) ? rawParticipant.satisfaction : {};
    if (!isRecord(rawParticipant.satisfaction)) {
      issues.push(`${slot} directional satisfaction is required`);
    }
    recordUnexpectedFields(satisfaction, SATISFACTION_FIELDS, "satisfaction", issues);
    if (satisfaction.measure !== "redagent-directional-v1") {
      issues.push(`${slot} satisfaction measure must be redagent-directional-v1`);
    }
    const ratings = [satisfaction.easeOfUse, satisfaction.safetyConfidence];
    if (!ratings.every((rating) => Number.isInteger(rating)
      && typeof rating === "number" && rating >= 1 && rating <= 5)) {
      issues.push(`${slot} directional satisfaction ratings must be integers from 1 to 5`);
    } else {
      easeOfUse.push(satisfaction.easeOfUse as number);
      safetyConfidence.push(satisfaction.safetyConfidence as number);
    }
  }
  for (const slot of PARTICIPANT_SLOTS) {
    if (!seenSlots.has(slot)) issues.push(`missing governance participant ${slot}`);
  }
  if (value.distinctPeopleConfirmed !== true) {
    issues.push("five distinct real people must be confirmed");
  }
  if (!Number.isSafeInteger(value.withdrawalExclusionCount)
    || typeof value.withdrawalExclusionCount !== "number"
    || value.withdrawalExclusionCount < 0) {
    issues.push("withdrawalExclusionCount must be a non-negative integer");
  }

  const administration = isRecord(value.administration) ? value.administration : {};
  if (!isRecord(value.administration)) issues.push("administration metadata is required");
  recordUnexpectedFields(administration, ADMINISTRATION_FIELDS, "administration", issues);
  if (administration.consentRecordsLocation !== "restricted-outside-git") {
    issues.push("consent records must remain restricted outside Git");
  }
  if (administration.accessScope !== "authorized-research-and-assurance-only") {
    issues.push("tracked evidence access scope is invalid");
  }
  if (typeof administration.retentionPolicyRevision !== "string"
    || !OPAQUE_TOKEN.test(administration.retentionPolicyRevision)) {
    issues.push("retention policy revision must be an opaque revision token");
  }
  if (!validTimestamp(administration.trackedEvidenceExpiresAt)) {
    issues.push("tracked evidence expiry must be a valid timestamp");
  } else if (validTimestamp(value.conductedAt)
    && Date.parse(administration.trackedEvidenceExpiresAt) <= Date.parse(value.conductedAt)) {
    issues.push("tracked evidence expiry must follow the study");
  }

  const claims = isRecord(value.claims) ? value.claims : {};
  if (!isRecord(value.claims)) issues.push("claims metadata is required");
  recordUnexpectedFields(claims, CLAIM_FIELDS, "claims", issues);
  if (claims.claim !== "candidate-specific-formative-operator-validation") {
    issues.push("claim must remain candidate-specific formative operator validation");
  }
  const limitations = Array.isArray(claims.limitations) ? claims.limitations : [];
  if (!Array.isArray(claims.limitations)
    || limitations.length !== PARTICIPANT_STUDY_LIMITATIONS.length
    || !PARTICIPANT_STUDY_LIMITATIONS.every(
      (limitation, index) => limitations[index] === limitation,
    )) {
    issues.push("claim limitations must match the closed formative vocabulary");
  }

  const taskEvaluation = evaluateRepresentativeTaskStudyPartitionJson(
    value.taskEvidence,
    REPRESENTATIVE_TASK_PROTOCOL,
    R124_REPRESENTATIVE_PARTITION,
  );
  issues.push(...taskEvaluation.issues);
  if (isRecord(value.taskEvidence)) {
    if (value.taskEvidence.studyId !== value.studyId) {
      issues.push("task evidence studyId must match the governance envelope");
    }
    if (value.taskEvidence.sourceRevision !== value.sourceRevision) {
      issues.push("task evidence sourceRevision must match the governance envelope");
    }
    if (value.taskEvidence.conductedAt !== value.conductedAt) {
      issues.push("task evidence conductedAt must match the governance envelope");
    }
  }

  const metrics = {
    ...taskEvaluation.metrics,
    medianEaseOfUse: median(easeOfUse),
    medianSafetyConfidence: median(safetyConfidence),
  };
  return { accepted: issues.length === 0, issues, metrics };
}
