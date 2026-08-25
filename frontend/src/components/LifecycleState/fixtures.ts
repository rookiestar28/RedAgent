export type LifecycleStatus =
  | "queued"
  | "running"
  | "approval"
  | "denied"
  | "partial"
  | "failed"
  | "cancelled"
  | "cleanup";

export type LifecycleFixture = {
  state: LifecycleStatus;
  label: string;
  detail: string;
  nextAction: string;
};

export const lifecycleFixtures: readonly LifecycleFixture[] = [
  { state: "queued", label: "Queued", detail: "Waiting for an eligible runner.", nextAction: "Review scope and policy." },
  { state: "running", label: "Running", detail: "A future owner service reports active work.", nextAction: "Monitor evidence and safety gates." },
  { state: "approval", label: "Approval required", detail: "Independent approval is required before continuation.", nextAction: "Open the approval record." },
  { state: "denied", label: "Denied", detail: "Authorization or scope policy blocked this action.", nextAction: "Review the denial reason." },
  { state: "partial", label: "Partial", detail: "Some bounded work completed; one or more steps did not.", nextAction: "Inspect the incomplete steps." },
  { state: "failed", label: "Failed", detail: "The operation stopped without a successful outcome.", nextAction: "Review the failure and cleanup state." },
  { state: "cancelled", label: "Cancelled", detail: "Cancellation was requested and acknowledged.", nextAction: "Confirm cleanup before retrying." },
  { state: "cleanup", label: "Cleanup", detail: "Resources are being reconciled after execution.", nextAction: "Wait for a terminal cleanup result." },
] as const;
