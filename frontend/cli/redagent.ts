import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { pathToFileURL } from "node:url";
import { createInterface } from "node:readline/promises";

import { ConsoleApiError, createConsoleClient } from "../src/lib/apiClient.js";

export type CliCommand =
  | { kind: "context" }
  | { kind: "campaigns-start" }
  | { kind: "campaigns-stop" }
  | { kind: "campaigns-revoke" }
  | { kind: "engagements-list" }
  | { kind: "engagements-create"; input: string; dryRun: boolean }
  | { kind: "jobs-list" }
  | { kind: "jobs-get"; jobId: string; roeVersionId: string }
  | { kind: "jobs-containment"; jobId: string }
  | { kind: "jobs-start"; input: string; dryRun: boolean }
  | { kind: "jobs-command"; jobId: string; action: JobAction; roeVersionId: string; expectedRevision: number; reason: string }
  | { kind: "jobs-stop" }
  | { kind: "containment-list" }
  | { kind: "containment-get"; controlId: string }
  | { kind: "containment-request"; scopeKind: "job" | "campaign" | "capability" | "tenant" | "global"; scopeId: string | null; reason: string }
  | { kind: "containment-approve" }
  | { kind: "containment-recover" }
  | { kind: "quotas-status" }
  | { kind: "observability-status" }
  | { kind: "lab-status" }
  | { kind: "zap-profiles" }
  | { kind: "zap-status" }
  | { kind: "nuclei-profiles" }
  | { kind: "nuclei-status" }
  | { kind: "api-differential-profiles" }
  | { kind: "api-differential-status" }
  | { kind: "network-profiles" }
  | { kind: "network-status" }
  | { kind: "cloud-profiles" }
  | { kind: "cloud-status" }
  | { kind: "identity-profiles" }
  | { kind: "identity-status" }
  | { kind: "artifact-profiles" }
  | { kind: "artifact-status" }
  | { kind: "purple-abilities" }
  | { kind: "purple-status" }
  | { kind: "human-campaigns" }
  | { kind: "human-status" }
  | { kind: "agent-tools" }
  | { kind: "agent-status" }
  | { kind: "workbench-status" }
  | { kind: "findings-status" }
  | { kind: "observability-correlation"; correlationId: string }
  | { kind: "incidents-list" }
  | { kind: "incidents-timeline"; incidentId: string }
  | { kind: "incidents-action"; incidentId: string; action: IncidentAction; expectedVersion: number; assigneeId: string | null }
  | { kind: "runners-status" }
  | { kind: "runners-registrations" }
  | { kind: "runners-manifests" }
  | { kind: "runners-executions" }
  | { kind: "evidence-list" }
  | { kind: "evidence-get"; artifactId: string }
  | { kind: "evidence-verify"; artifactId: string }
  | { kind: "evidence-derive"; sourceArtifactId: string; artifactId: string; artifactClass: "report_safe" | "export_safe" }
  | { kind: "evidence-hold" }
  | { kind: "evidence-synthetic-dry-run"; input: string }
  | { kind: "leases-list" }
  | { kind: "leases-revoke" }
  | { kind: "policy-status" }
  | { kind: "policy-decisions" }
  | { kind: "policy-bundles" }
  | { kind: "policy-simulate"; fixture: "api-job-create" | "workflow-job-command" | "evidence-write" | "secret-lease" }
  | { kind: "policy-transition"; rollback: boolean; revision: string; expectedVersion: number; reason: string };

type JobAction = "approve" | "pause" | "resume" | "retry" | "cancel";
type IncidentAction = "assign" | "acknowledge" | "preserve_evidence" | "verify_containment" | "mark_contained" | "mark_recovered" | "complete_review" | "close";

export function parseArguments(args: string[]): CliCommand {
  const forbidden = args.find((argument) => argument !== "secret-lease" && /secret|token|password|rego|bundle[-_]?url|policy[-_]?(?:file|text|override)|decision[-_]?path/i.test(argument));
  if (forbidden) throw new CliUsageError("secret_or_policy_flags_forbidden");
  if (args[0] === "campaigns" && new Set(["start", "stop", "revoke"]).has(args[1] ?? "")) {
    if (args.length !== 2) throw new CliUsageError("raw_id_arguments_forbidden");
    return { kind: `campaigns-${args[1]}` as "campaigns-start" | "campaigns-stop" | "campaigns-revoke" };
  }
  if (args.length === 1 && args[0] === "context") return { kind: "context" };
  if (args.length === 2 && args[0] === "engagements" && args[1] === "list") {
    return { kind: "engagements-list" };
  }
  if (args[0] === "engagements" && args[1] === "create") {
    throw new CliUsageError("legacy_mutation_disabled_until_r128");
  }
  if (args.length === 2 && args[0] === "jobs" && args[1] === "list") return { kind: "jobs-list" };
  if (args.length === 5 && args[0] === "jobs" && args[1] === "get" && args[3] === "--roe") {
    return { kind: "jobs-get", jobId: identifier(args[2]), roeVersionId: identifier(args[4]) };
  }
  if (args.length === 3 && args[0] === "jobs" && args[1] === "containment") {
    return { kind: "jobs-containment", jobId: identifier(args[2]) };
  }
  if (args[0] === "jobs" && args[1] === "start") {
    throw new CliUsageError("legacy_mutation_disabled_until_r128");
  }
  if (args.length === 10 && args[0] === "jobs" && args[1] === "command" && args[4] === "--roe" && args[6] === "--revision" && args[8] === "--reason") {
    throw new CliUsageError("legacy_mutation_disabled_until_r128");
  }
  if (args[0] === "jobs" && args[1] === "stop") {
    if (args.length !== 2) throw new CliUsageError("raw_id_arguments_forbidden");
    return { kind: "jobs-stop" };
  }
  if (args.length === 2 && args[0] === "containment" && args[1] === "list") return { kind: "containment-list" };
  if (args.length === 3 && args[0] === "containment" && args[1] === "get") {
    return { kind: "containment-get", controlId: identifier(args[2]) };
  }
  if (args[0] === "containment" && args[1] === "request") {
    throw new CliUsageError("legacy_mutation_disabled_until_r128");
  }
  if (args[0] === "containment" && args[1] === "approve") {
    if (args.length !== 2) throw new CliUsageError("raw_id_arguments_forbidden");
    return { kind: "containment-approve" };
  }
  if (args[0] === "containment" && args[1] === "recover") {
    if (args.length !== 2) throw new CliUsageError("raw_id_arguments_forbidden");
    return { kind: "containment-recover" };
  }
  if (args.length === 2 && args[0] === "quotas" && args[1] === "status") return { kind: "quotas-status" };
  if (args.length === 2 && args[0] === "observability" && args[1] === "status") return { kind: "observability-status" };
  if (args.length === 2 && args[0] === "lab" && args[1] === "status") return { kind: "lab-status" };
  if (args.length === 2 && args[0] === "zap" && args[1] === "profiles") return { kind: "zap-profiles" };
  if (args.length === 2 && args[0] === "zap" && args[1] === "status") return { kind: "zap-status" };
  if (args.length === 2 && args[0] === "nuclei" && args[1] === "profiles") return { kind: "nuclei-profiles" };
  if (args.length === 2 && args[0] === "nuclei" && args[1] === "status") return { kind: "nuclei-status" };
  if (args.length === 2 && args[0] === "api-differential" && args[1] === "profiles") return { kind: "api-differential-profiles" };
  if (args.length === 2 && args[0] === "api-differential" && args[1] === "status") return { kind: "api-differential-status" };
  if (args.length === 2 && args[0] === "network" && args[1] === "profiles") return { kind: "network-profiles" };
  if (args.length === 2 && args[0] === "network" && args[1] === "status") return { kind: "network-status" };
  if (args.length === 2 && args[0] === "cloud" && args[1] === "profiles") return { kind: "cloud-profiles" };
  if (args.length === 2 && args[0] === "cloud" && args[1] === "status") return { kind: "cloud-status" };
  if (args.length === 2 && args[0] === "identity" && args[1] === "profiles") return { kind: "identity-profiles" };
  if (args.length === 2 && args[0] === "identity" && args[1] === "status") return { kind: "identity-status" };
  if (args.length === 2 && args[0] === "artifact" && args[1] === "profiles") return { kind: "artifact-profiles" };
  if (args.length === 2 && args[0] === "artifact" && args[1] === "status") return { kind: "artifact-status" };
  if (args.length === 2 && args[0] === "purple" && args[1] === "abilities") return { kind: "purple-abilities" };
  if (args.length === 2 && args[0] === "purple" && args[1] === "status") return { kind: "purple-status" };
  if (args.length === 2 && args[0] === "human-simulation" && args[1] === "campaigns") return { kind: "human-campaigns" };
  if (args.length === 2 && args[0] === "human-simulation" && args[1] === "status") return { kind: "human-status" };
  if (args.length === 2 && args[0] === "agent" && args[1] === "tools") return { kind: "agent-tools" };
  if (args.length === 2 && args[0] === "agent" && args[1] === "status") return { kind: "agent-status" };
  if (args.length === 2 && args[0] === "workbench" && args[1] === "status") return { kind: "workbench-status" };
  if (args.length === 2 && args[0] === "findings" && args[1] === "status") return { kind: "findings-status" };
  if (args.length === 3 && args[0] === "observability" && args[1] === "correlation") {
    return { kind: "observability-correlation", correlationId: identifier(args[2]) };
  }
  if (args.length === 2 && args[0] === "incidents" && args[1] === "list") return { kind: "incidents-list" };
  if (args.length === 3 && args[0] === "incidents" && args[1] === "timeline") {
    return { kind: "incidents-timeline", incidentId: identifier(args[2]) };
  }
  if (args[0] === "incidents" && args[1] === "action") {
    throw new CliUsageError("legacy_mutation_disabled_until_r128");
  }
  if (args.length === 2 && args[0] === "runners" && args[1] === "status") return { kind: "runners-status" };
  if (args.length === 2 && args[0] === "runners" && args[1] === "registrations") return { kind: "runners-registrations" };
  if (args.length === 2 && args[0] === "runners" && args[1] === "manifests") return { kind: "runners-manifests" };
  if (args.length === 2 && args[0] === "runners" && args[1] === "executions") return { kind: "runners-executions" };
  if (args.length === 2 && args[0] === "evidence" && args[1] === "list") return { kind: "evidence-list" };
  if (args.length === 3 && args[0] === "evidence" && args[1] === "get") {
    return { kind: "evidence-get", artifactId: identifier(args[2]) };
  }
  if (args.length === 3 && args[0] === "evidence" && args[1] === "verify") {
    return { kind: "evidence-verify", artifactId: identifier(args[2]) };
  }
  if (args.length === 7 && args[0] === "evidence" && args[1] === "derive" && args[3] === "--artifact" && args[5] === "--class") {
    throw new CliUsageError("legacy_mutation_disabled_until_r128");
  }
  if (args[0] === "evidence" && args[1] === "hold") {
    if (args.length !== 2) throw new CliUsageError("raw_id_arguments_forbidden");
    return { kind: "evidence-hold" };
  }
  if (args.length === 5 && args[0] === "evidence" && args[1] === "synthetic" && args[2] === "--input" && args[4] === "--dry-run") {
    return { kind: "evidence-synthetic-dry-run", input: bounded(args[3], 500) };
  }
  if (args.length === 2 && args[0] === "leases" && args[1] === "list") return { kind: "leases-list" };
  if (args[0] === "leases" && args[1] === "revoke") {
    if (args.length !== 2) throw new CliUsageError("raw_id_arguments_forbidden");
    return { kind: "leases-revoke" };
  }
  if (args.length === 2 && args[0] === "policy" && args[1] === "status") return { kind: "policy-status" };
  if (args.length === 2 && args[0] === "policy" && args[1] === "decisions") return { kind: "policy-decisions" };
  if (args.length === 2 && args[0] === "policy" && args[1] === "bundles") return { kind: "policy-bundles" };
  if (args.length === 3 && args[0] === "policy" && args[1] === "simulate") {
    const fixtures = new Set(["api-job-create", "workflow-job-command", "evidence-write", "secret-lease"] as const);
    const fixture = args[2] as "api-job-create" | "workflow-job-command" | "evidence-write" | "secret-lease";
    if (!fixtures.has(fixture)) throw new CliUsageError("invalid_policy_fixture");
    return { kind: "policy-simulate", fixture };
  }
  if (args.length === 7 && args[0] === "policy" && new Set(["promote", "rollback"]).has(args[1] ?? "") && args[3] === "--version" && args[5] === "--reason") {
    throw new CliUsageError("legacy_mutation_disabled_until_r128");
  }
  throw new CliUsageError("unsupported_command");
}

export function loadConfiguration(env: NodeJS.ProcessEnv) {
  const apiUrl = requiredEnv(env, "REDAGENT_API_URL");
  const parsed = new URL(apiUrl);
  const loopback = new Set(["127.0.0.1", "localhost", "::1"]).has(parsed.hostname);
  if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
    throw new CliUsageError("insecure_api_url_forbidden");
  }
  return {
    apiUrl: parsed.toString(),
    tenant: requiredEnv(env, "REDAGENT_SERVICE_TENANT"),
    client: requiredEnv(env, "REDAGENT_SERVICE_CLIENT"),
    secret: requiredEnv(env, "REDAGENT_SERVICE_SECRET"),
  };
}

export function exitCode(error: unknown): number {
  if (error instanceof CliUsageError) return 2;
  if (error instanceof ConsoleApiError) {
    if (error.status === 401 || error.status === 403) return 3;
    if (error.status === 409) return 4;
  }
  return 5;
}

async function run(): Promise<void> {
  const command = parseArguments(process.argv.slice(2));
  const config = loadConfiguration(process.env);
  const client = createConsoleClient({
    baseUrl: config.apiUrl,
    readCsrf: () => null,
    defaultHeaders: () => ({
      "X-RedAgent-Service-Tenant": config.tenant,
      "X-RedAgent-Service-Client": config.client,
      "X-RedAgent-Service-Secret": config.secret,
    }),
  });
  if (
    command.kind === "campaigns-start"
    || command.kind === "campaigns-stop"
    || command.kind === "campaigns-revoke"
  ) {
    return output(await runCampaignCommand(command.kind, client));
  }
  if (
    command.kind === "jobs-stop"
    || command.kind === "containment-approve"
    || command.kind === "containment-recover"
    || command.kind === "evidence-hold"
    || command.kind === "leases-revoke"
  ) {
    return output(await runEmergencySelectionCommand(command.kind, client));
  }
  if (command.kind === "context") return output(await client.getContext());
  if (command.kind === "engagements-list") return output(await client.listEngagements());
  if (command.kind === "jobs-list") return output(await client.listJobs());
  if (command.kind === "jobs-get") return output(await client.getJob(command.jobId, command.roeVersionId));
  if (command.kind === "jobs-containment") return output(await client.getJobContainment(command.jobId));
  if (command.kind === "jobs-command") return output(await client.commandJob(command.jobId, command.roeVersionId, {
    command_id: randomUUID(), action: command.action, expected_revision: command.expectedRevision, reason: command.reason,
  }));
  if (command.kind === "containment-list") return output(await client.listContainmentControls());
  if (command.kind === "containment-get") return output(await client.getContainmentControl(command.controlId));
  if (command.kind === "containment-request") return output(await client.requestContainmentControl({
    stop_id: randomUUID(), scope_kind: command.scopeKind, scope_id: command.scopeId,
    expected_version: 1, reason: command.reason,
  }));
  if (command.kind === "quotas-status") return output(await client.getQuotaStatus());
  if (command.kind === "observability-status") return output(await client.getObservabilityDashboard());
  if (command.kind === "lab-status") return output(await client.getLabDashboard());
  if (command.kind === "zap-profiles") return output(await client.listZapProfiles());
  if (command.kind === "zap-status") return output(await client.getZapDashboard());
  if (command.kind === "nuclei-profiles") return output(await client.listNucleiProfiles());
  if (command.kind === "nuclei-status") return output(await client.getNucleiDashboard());
  if (command.kind === "api-differential-profiles") return output(await client.listApiDifferentialProfiles());
  if (command.kind === "api-differential-status") return output(await client.getApiDifferentialDashboard());
  if (command.kind === "network-profiles") return output(await client.listNetworkProfiles());
  if (command.kind === "network-status") return output(await client.getNetworkDashboard());
  if (command.kind === "cloud-profiles") return output(await client.listCloudProfiles());
  if (command.kind === "cloud-status") return output(await client.getCloudDashboard());
  if (command.kind === "identity-profiles") return output(await client.listIdentitySaasProfiles());
  if (command.kind === "identity-status") return output(await client.getIdentitySaasDashboard());
  if (command.kind === "artifact-profiles") return output(await client.listArtifactProfiles());
  if (command.kind === "artifact-status") return output(await client.getArtifactDashboard());
  if (command.kind === "purple-abilities") return output(await client.listPurpleAbilities());
  if (command.kind === "purple-status") return output(await client.getPurpleDashboard());
  if (command.kind === "human-campaigns") return output(await client.listHumanSimulationCampaigns());
  if (command.kind === "human-status") return output(await client.getHumanSimulationDashboard());
  if (command.kind === "agent-tools") return output(await client.listAgentTools());
  if (command.kind === "agent-status") return output(await client.getAgentDashboard());
  if (command.kind === "workbench-status") return output(await client.getWorkbenchDashboard());
  if (command.kind === "findings-status") return output(await client.getFindingOperationsDashboard());
  if (command.kind === "observability-correlation") return output(await client.lookupCorrelation(command.correlationId));
  if (command.kind === "incidents-list") return output(await client.listIncidents());
  if (command.kind === "incidents-timeline") return output(await client.getIncidentTimeline(command.incidentId));
  if (command.kind === "incidents-action") return output(await client.applyIncidentAction(command.incidentId, {
    action_id: randomUUID(), action: command.action, expected_version: command.expectedVersion,
    assignee_id: command.assigneeId,
  }));
  if (command.kind === "runners-status") return output(await client.getRunnerStatus());
  if (command.kind === "runners-registrations") return output(await client.listRunnerRegistrations());
  if (command.kind === "runners-manifests") return output(await client.listRunnerManifests());
  if (command.kind === "runners-executions") return output(await client.listRunnerExecutions());
  if (command.kind === "evidence-list") return output(await client.listEvidence());
  if (command.kind === "evidence-get") return output(await client.getEvidence(command.artifactId));
  if (command.kind === "evidence-verify") return output(await client.verifyEvidence(command.artifactId));
  if (command.kind === "evidence-derive") return output(await client.deriveEvidence(command.sourceArtifactId, {
    artifact_id: command.artifactId,
    artifact_class: command.artifactClass,
    transform_name: "central-redaction",
    transform_version: "1",
    quality_approved: true,
  }));
  if (command.kind === "evidence-synthetic-dry-run") {
    return output({ dry_run: true, operation: "evidence.synthetic", payload: await readEvidenceSynthetic(command.input) });
  }
  if (command.kind === "leases-list") return output(await client.listSecretLeases());
  if (command.kind === "policy-status") return output(await client.getPolicyStatus());
  if (command.kind === "policy-decisions") return output(await client.listPolicyDecisions());
  if (command.kind === "policy-bundles") return output(await client.listPolicyBundles());
  if (command.kind === "policy-simulate") return output(await client.simulatePolicy({ fixture: command.fixture }));
  if (command.kind === "policy-transition") {
    const payload = { revision: command.revision, expected_version: command.expectedVersion, reason: command.reason };
    return output(command.rollback ? await client.rollbackPolicy(payload) : await client.promotePolicy(payload));
  }
  if (command.kind === "jobs-start") {
    const payload = await readJob(command.input);
    if (command.dryRun) return output({ dry_run: true, operation: "job.start", payload });
    return output(await client.createJob(payload));
  }
  const payload = await readEngagement(command.input);
  if (command.dryRun) return output({ dry_run: true, operation: "engagement.create", payload });
  output(await client.createEngagement(payload));
}

async function runCampaignCommand(
  kind: "campaigns-start" | "campaigns-stop" | "campaigns-revoke",
  client: ReturnType<typeof createConsoleClient>,
): Promise<unknown> {
  const terminal = createInterface({ input: process.stdin, output: process.stdout });
  try {
    if (kind === "campaigns-start") {
      if (process.env.REDAGENT_R124_CAMPAIGN_CORE_ENABLED === "false") {
        throw new CliUsageError("campaign_core_create_disabled");
      }
      const engagements = await client.listCampaignCoreEngagementOptions();
      const engagement = await selectOption(
        terminal,
        "Authorized engagement",
        engagements.data.filter(({ eligible }) => eligible),
      );
      const targets = await client.listCampaignCoreTargetOptions(engagement.binding);
      const target = await selectOption(
        terminal,
        "Authorized target",
        targets.data.filter(({ eligible }) => eligible),
      );
      const objectives = [
        "Assess HTTP security posture",
        "Verify X-Content-Type-Options",
        "Assess repository snapshot posture",
      ] as const;
      const objective = await selectText(terminal, "Objective", objectives);
      const risks = await client.listCampaignCoreRiskOptions(engagement.binding, target.binding);
      const risk = await selectOption(
        terminal,
        "Risk profile",
        risks.data.filter(({ eligible }) => eligible),
      );
      return client.startCampaignCore({
        engagement_binding: engagement.binding,
        target_binding: target.binding,
        objective,
        risk_profile: risk.binding,
      });
    }
    const campaigns = await client.listCampaignCoreCampaigns();
    const activeCampaigns = recoverableCampaigns(campaigns.data);
    const campaign = await selectOption(
      terminal,
      "Active campaign",
      activeCampaigns,
    );
    const aggregate = await client.getCampaignCoreCampaign(campaign.campaign_id);
    const etag = aggregate.etag;
    if (typeof etag !== "string") throw new CliUsageError("campaign_etag_unavailable");
    const reason = bounded(await terminal.question("Reason (10-500 characters): "), 500);
    if (reason.length < 10) throw new CliUsageError("campaign_recovery_reason_invalid");
    return client.recoverCampaignCore(
      kind === "campaigns-stop" ? "stop" : "revoke",
      campaign.campaign_id,
      etag,
      reason,
    );
  } finally {
    terminal.close();
  }
}

export function recoverableCampaigns<T extends { status: string }>(campaigns: T[]): T[] {
  return campaigns.filter(({ status }) =>
    status === "dispatch_pending" || status === "workflow_started"
  );
}

async function runEmergencySelectionCommand(
  kind: "jobs-stop" | "containment-approve" | "containment-recover" | "evidence-hold" | "leases-revoke",
  client: ReturnType<typeof createConsoleClient>,
): Promise<unknown> {
  const terminal = createInterface({ input: process.stdin, output: process.stdout });
  try {
    if (kind === "jobs-stop") {
      const jobs = (await client.listJobs()).filter(({ stop_requested: stopped }) => !stopped);
      const selected = await selectOption(terminal, "Active job", jobs.map((value) => ({
        label: `Job in ${value.status}: ${value.current_gate}`,
        value,
      })));
      const reason = bounded(await terminal.question("Reason (10-500 characters): "), 500);
      if (reason.length < 10) throw new CliUsageError("campaign_recovery_reason_invalid");
      return client.emergencyStopJob(
        selected.value.job_id,
        selected.value.roe_version_id,
        reason,
      );
    }
    if (kind === "containment-approve" || kind === "containment-recover") {
      const controls = (await client.listContainmentControls()).filter(({ control_state: state }) =>
        kind === "containment-approve"
          ? state === "pending_approval"
          : state === "active",
      );
      const selected = await selectOption(terminal, "Containment control", controls.map((value) => ({
        label: `${humanLabel(value.scope_kind)} control: ${humanLabel(value.control_state)}`,
        value,
      })));
      return kind === "containment-approve"
        ? client.approveContainmentControl(
          selected.value.control_id,
          selected.value.request_hash,
          selected.value.version,
        )
        : client.recoverContainmentControl(selected.value.control_id, selected.value.version);
    }
    if (kind === "evidence-hold") {
      const evidence = (await client.listEvidence()).filter(({ legal_hold: held }) => !held);
      const selected = await selectOption(terminal, "Evidence artifact", evidence.map((value) => ({
        label: `${humanLabel(value.artifact_class)} evidence · ${value.content_type}`,
        value,
      })));
      return client.placeEvidenceLegalHold(selected.value.artifact_id, selected.value.version);
    }
    const leases = (await client.listSecretLeases()).filter(({ revoked_at: revoked }) => revoked === null);
    const selected = await selectOption(terminal, "Active credential lease", leases.map((value) => ({
      label: `${humanLabel(value.capability)} · expires ${value.expires_at}`,
      value,
    })));
    return client.revokeSecretLease(selected.value.lease_id, selected.value.version);
  } finally {
    terminal.close();
  }
}

async function selectOption<T extends { label: string }>(
  terminal: ReturnType<typeof createInterface>,
  prompt: string,
  options: T[],
): Promise<T> {
  if (options.length === 0 || options.length > 50) {
    throw new CliUsageError("authorized_options_unavailable");
  }
  for (const [index, option] of options.entries()) process.stdout.write(`${index + 1}. ${option.label}\n`);
  const answer = await terminal.question(`${prompt} [1-${options.length}]: `);
  const selected = Number(answer);
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > options.length) {
    throw new CliUsageError("authorized_option_selection_invalid");
  }
  return options[selected - 1]!;
}

async function selectText<T extends string>(
  terminal: ReturnType<typeof createInterface>,
  prompt: string,
  options: readonly T[],
): Promise<T> {
  if (options.length === 0 || options.length > 50) {
    throw new CliUsageError("authorized_options_unavailable");
  }
  for (const [index, value] of options.entries()) process.stdout.write(`${index + 1}. ${value}\n`);
  const answer = await terminal.question(`${prompt} [1-${options.length}]: `);
  const selected = Number(answer);
  if (!Number.isSafeInteger(selected) || selected < 1 || selected > options.length) {
    throw new CliUsageError("authorized_option_selection_invalid");
  }
  return options[selected - 1]!;
}

async function readJob(path: string) {
  const parsed = await readJson(path);
  const allowed = new Set(["job_id", "engagement_id", "roe_version_id", "request"]);
  if (Object.keys(parsed).some((key) => !allowed.has(key)) || !isRecord(parsed.request)) {
    throw new CliUsageError("input_field_forbidden");
  }
  const request = parsed.request;
  const requestAllowed = new Set(["capability", "approval_timeout_seconds", "max_activity_attempts", "budget_reference"]);
  const timeout = integer(request.approval_timeout_seconds, 1, 604800);
  const attempts = integer(request.max_activity_attempts, 1, 5);
  if (
    Object.keys(request).some((key) => !requestAllowed.has(key))
    || !new Set(["synthetic-noop", "synthetic-conformance"]).has(String(request.capability))
  ) {
    throw new CliUsageError("input_field_forbidden");
  }
  return {
    job_id: identifier(parsed.job_id),
    engagement_id: identifier(parsed.engagement_id),
    roe_version_id: identifier(parsed.roe_version_id),
    request: {
      capability: request.capability as "synthetic-noop" | "synthetic-conformance",
      approval_timeout_seconds: timeout,
      max_activity_attempts: attempts,
      budget_reference: bounded(request.budget_reference, 100, /^[A-Za-z0-9._:-]+$/),
    },
  };
}

async function readEngagement(path: string) {
  const parsed = await readJson(path);
  const allowed = new Set(["engagement_id", "name", "owner_user_id"]);
  if (Object.keys(parsed).some((key) => !allowed.has(key))) throw new CliUsageError("input_field_forbidden");
  return {
    engagement_id: identifier(parsed.engagement_id),
    name: bounded(parsed.name, 200),
    owner_user_id: identifier(parsed.owner_user_id),
  };
}

async function readEvidenceSynthetic(path: string) {
  const parsed = await readJson(path);
  const allowed = new Set(["artifact_id", "engagement_id", "job_id", "fixture_kind", "retention_days"]);
  if (Object.keys(parsed).some((key) => !allowed.has(key))) throw new CliUsageError("input_field_forbidden");
  const fixture = parsed.fixture_kind;
  if (fixture !== "sanitized-log" && fixture !== "sanitized-json") throw new CliUsageError("input_value_invalid");
  return {
    artifact_id: identifier(parsed.artifact_id),
    engagement_id: identifier(parsed.engagement_id),
    job_id: identifier(parsed.job_id),
    fixture_kind: fixture,
    retention_days: integer(parsed.retention_days ?? 30, 1, 365),
  };
}

async function readJson(path: string): Promise<Record<string, unknown>> {
  if (!path || path.length > 500) throw new CliUsageError("input_path_invalid");
  let parsed: unknown;
  try { parsed = JSON.parse(await readFile(path, "utf8")); }
  catch { throw new CliUsageError("input_json_invalid"); }
  if (!isRecord(parsed)) throw new CliUsageError("input_shape_invalid");
  return parsed;
}

function output(value: unknown): void { process.stdout.write(`${JSON.stringify(value)}\n`); }
function humanLabel(value: string): string { return value.replaceAll("_", " "); }
function requiredEnv(env: NodeJS.ProcessEnv, name: string): string {
  const value = env[name];
  if (!value || !value.trim() || value.length > 512) throw new CliUsageError(`${name.toLowerCase()}_required`);
  return value;
}
function bounded(value: unknown, maximum: number, pattern?: RegExp): string {
  if (typeof value !== "string" || !value.trim() || value.length > maximum || (pattern && !pattern.test(value))) {
    throw new CliUsageError("input_value_invalid");
  }
  return value;
}
function identifier(value: unknown): string { return bounded(value, 64, /^[A-Za-z0-9._:-]+$/); }
function integer(value: unknown, minimum: number, maximum: number): number {
  if (!Number.isSafeInteger(value) || Number(value) < minimum || Number(value) > maximum) {
    throw new CliUsageError("input_value_invalid");
  }
  return Number(value);
}
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export class CliUsageError extends Error {}

const invokedPath = process.argv[1] ? pathToFileURL(process.argv[1]).href : "";
if (import.meta.url === invokedPath) {
  run().catch((error: unknown) => {
    const code = exitCode(error);
    const reason = error instanceof ConsoleApiError ? error.code : error instanceof Error ? error.message : "cli_failed";
    process.stderr.write(`${JSON.stringify({ error: { code: reason } })}\n`);
    process.exitCode = code;
  });
}
