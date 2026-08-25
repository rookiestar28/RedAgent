import createClient from "openapi-fetch";

import type { components, paths } from "../generated/api";

type ContextResponse = components["schemas"]["ContextResponse"];
type PageData = components["schemas"]["PageData"];
type EngagementCreate = components["schemas"]["EngagementCreateRequest"];
type EngagementData = components["schemas"]["EngagementData"];
type TargetCreate = components["schemas"]["TargetCreateRequest"];
type TargetData = components["schemas"]["TargetData"];
type RoeCreate = components["schemas"]["RoeVersionCreateRequest"];
type RoeData = components["schemas"]["RoeVersionData"];
type JitCreate = components["schemas"]["JitGrantCreateRequest"];
type JitData = components["schemas"]["JitGrantData"];
type ActivityData = components["schemas"]["ActivityData"];
type JobCreate = components["schemas"]["JobCreateRequest"];
type JobData = components["schemas"]["JobData"];
type JobCommand = components["schemas"]["JobLifecycleCommandRequest"];
type JobStopData = components["schemas"]["JobStopData"];
type JobContainmentData = components["schemas"]["JobContainmentData"];
type ContainmentControlData = components["schemas"]["ContainmentControlData"];
type ContainmentStopRequest = components["schemas"]["ContainmentStopRequest"];
type QuotaStatusData = components["schemas"]["QuotaStatusData"];
type EvidenceArtifact = components["schemas"]["EvidenceArtifactData"];
type EvidenceArtifactDetail = components["schemas"]["EvidenceArtifactDetailData"];
type EvidenceSyntheticRegister = components["schemas"]["EvidenceSyntheticRegisterRequest"];
type EvidenceDerive = components["schemas"]["EvidenceDeriveRequest"];
type EvidenceVerification = components["schemas"]["EvidenceVerificationData"];
type SecretReference = components["schemas"]["SecretReferenceData"];
type SecretLease = components["schemas"]["SecretLeaseData"];
type SecretSyntheticIssue = components["schemas"]["SecretSyntheticIssueRequest"];
type PolicyStatus = components["schemas"]["PolicyStatusData"];
type PolicyDecision = components["schemas"]["PolicyDecisionData"];
type PolicyBundle = components["schemas"]["PolicyBundleData"];
type PolicyPromotion = components["schemas"]["PolicyPromotionData"];
type PolicyPromotionRequest = components["schemas"]["PolicyPromotionRequest"];
type PolicySimulation = components["schemas"]["PolicySimulationData"];
type PolicySimulationRequest = components["schemas"]["PolicySimulationRequest"];
type RunnerStatus = components["schemas"]["RunnerStatusData"];
type RunnerRegistration = components["schemas"]["RunnerRegistrationData"];
type RunnerManifest = components["schemas"]["RunnerManifestData"];
type RunnerExecution = components["schemas"]["RunnerExecutionData"];
type ObservabilityDashboard = components["schemas"]["ObservabilityDashboardData"];
type CorrelationEvent = components["schemas"]["CorrelationEventData"];
type Incident = components["schemas"]["IncidentData"];
type IncidentActionRequest = components["schemas"]["IncidentActionRequest"];
type IncidentTimeline = components["schemas"]["IncidentTimelineData"];
type IncidentRunbook = components["schemas"]["IncidentRunbookData"];
type LabDashboard = components["schemas"]["LabDashboardData"];
type ZapProfile = components["schemas"]["ZapProfileData"];
type ZapDashboard = components["schemas"]["ZapDashboardData"];
type ZapCompile = components["schemas"]["ZapCompileRequest"];
type ZapPlan = components["schemas"]["ZapPlanData"];
type ZapRunCreate = components["schemas"]["ZapRunCreateRequest"];
type ZapRun = components["schemas"]["ZapRunData"];
type NucleiProfile = components["schemas"]["NucleiProfileData"];
type NucleiDashboard = components["schemas"]["NucleiDashboardData"];
type NucleiCompile = components["schemas"]["NucleiCompileRequest"];
type NucleiPlan = components["schemas"]["NucleiPlanData"];
type NucleiRunCreate = components["schemas"]["NucleiRunCreateRequest"];
type NucleiRun = components["schemas"]["NucleiRunData"];
type ApiDifferentialProfile = components["schemas"]["ApiDifferentialProfileData"];
type ApiDifferentialDashboard = components["schemas"]["ApiDifferentialDashboardData"];
type ApiDifferentialCompile = components["schemas"]["ApiDifferentialCompileRequest"];
type ApiDifferentialPlan = components["schemas"]["ApiDifferentialPlanData"];
type ApiDifferentialRunCreate = components["schemas"]["ApiDifferentialRunCreateRequest"];
type ApiDifferentialRun = components["schemas"]["ApiDifferentialRunData"];
type NetworkProfile = components["schemas"]["NetworkProfileData"];
type NetworkDashboard = components["schemas"]["NetworkDashboardData"];
type NetworkCompile = components["schemas"]["NetworkCompileRequest"];
type NetworkPlan = components["schemas"]["NetworkPlanData"];
type NetworkRunCreate = components["schemas"]["NetworkRunCreateRequest"];
type NetworkRun = components["schemas"]["NetworkRunData"];
type CloudProfile = components["schemas"]["CloudProfileData"];
type CloudDashboard = components["schemas"]["CloudDashboardData"];
type CloudCompile = components["schemas"]["CloudCompileRequest"];
type CloudPlan = components["schemas"]["CloudPlanData"];
type CloudRunCreate = components["schemas"]["CloudRunCreateRequest"];
type CloudRun = components["schemas"]["CloudRunData"];
type IdentitySaasProfile = components["schemas"]["IdentitySaasProfileData"];
type IdentitySaasDashboard = components["schemas"]["IdentitySaasDashboardData"];
type IdentitySaasCompile = components["schemas"]["IdentitySaasCompileRequest"];
type IdentitySaasPlan = components["schemas"]["IdentitySaasPlanData"];
type IdentitySaasRunCreate = components["schemas"]["IdentitySaasRunCreateRequest"];
type IdentitySaasRun = components["schemas"]["IdentitySaasRunData"];
type ArtifactProfile = components["schemas"]["ArtifactProfileData"];
type ArtifactDashboard = components["schemas"]["ArtifactDashboardData"];
type ArtifactCompile = components["schemas"]["ArtifactCompileRequest"];
type ArtifactPlan = components["schemas"]["ArtifactPlanData"];
type ArtifactRunCreate = components["schemas"]["ArtifactRunCreateRequest"];
type ArtifactRun = components["schemas"]["ArtifactRunData"];
type PurpleAbility = components["schemas"]["PurpleAbilityData"];
type PurpleDashboard = components["schemas"]["PurpleDashboardData"];
type PurpleCompile = components["schemas"]["PurpleCompileRequest"];
type PurplePlan = components["schemas"]["PurplePlanData"];
type PurpleRunCreate = components["schemas"]["PurpleRunCreateRequest"];
type PurpleRun = components["schemas"]["PurpleRunData"];
type HumanSimulationCampaign = components["schemas"]["HumanSimulationCampaignData"];
type HumanSimulationDashboard = components["schemas"]["HumanSimulationDashboardData"];
type HumanSimulationCompile = components["schemas"]["HumanSimulationCompileRequest"];
type HumanSimulationPlan = components["schemas"]["HumanSimulationPlanData"];
type HumanSimulationRunCreate = components["schemas"]["HumanSimulationRunCreateRequest"];
type HumanSimulationRun = components["schemas"]["HumanSimulationRunData"];
type AgentTool = components["schemas"]["AgentToolData"];
type AgentDashboard = components["schemas"]["AgentDashboardData"];
type AgentRunCreate = components["schemas"]["AgentRunCreateRequest"];
type AgentRunStart = components["schemas"]["AgentRunStartData"];
type AgentProposal = components["schemas"]["AgentProposalData"];
type AgentRun = components["schemas"]["AgentRunData"];
type WorkbenchDashboard = components["schemas"]["WorkbenchDashboardData"];
type WorkbenchDraftCreate = components["schemas"]["WorkbenchDraftCreateRequest"];
type WorkbenchDraftMutation = components["schemas"]["WorkbenchDraftMutationData"];
type WorkbenchReview = components["schemas"]["WorkbenchReviewData"];
type McpFreezeMutation = components["schemas"]["McpFreezeMutationData"];
type FindingOperationsDashboard = components["schemas"]["FindingOperationsDashboardData"];
type FindingOperationsImport = components["schemas"]["FindingOperationsImportRequest"];
type FindingOperationsImportData = components["schemas"]["FindingOperationsImportData"];
type FindingOperationsIssue = components["schemas"]["FindingOperationsIssueData"];
type FindingOperationsReport = components["schemas"]["FindingOperationsReportData"];
type FindingOperationsPublication = components["schemas"]["FindingOperationsPublicationData"];
type FindingOperationsDelivery = components["schemas"]["FindingOperationsDeliveryData"];
export type R124CampaignOption = components["schemas"]["R124OptionData"];
export type R124CampaignOptionPage = components["schemas"]["R124EngagementOptionPageResponse"];
export type R124CampaignStart = components["schemas"]["R124CampaignStartRequest"];
export type R124CampaignMutation = components["schemas"]["R124CampaignMutationData"];
export type R124CampaignSummaryPage = components["schemas"]["R124CampaignSummaryPageResponse"];
export type R124AttentionPage = components["schemas"]["R124AttentionPageResponse"];
export type R124CampaignSummary = components["schemas"]["R124CampaignSummaryData"];
export type R124Attention = components["schemas"]["R124AttentionData"];
export type R124CampaignAggregate = components["schemas"]["R124CampaignAggregateData"];
export type R124CampaignInspector = components["schemas"]["R124CampaignInspectorData"];

export type PageResult<T> = {
  readonly data: readonly T[];
  readonly page: PageData;
};

export class ConsoleApiError extends Error {
  readonly code: string;
  readonly correlationId: string | null;
  readonly status: number;

  constructor(code: string, message: string, status: number, correlationId: string | null) {
    super(message);
    this.name = "ConsoleApiError";
    this.code = code;
    this.status = status;
    this.correlationId = correlationId;
  }
}

type ClientOptions = {
  fetch?: typeof fetch;
  readCsrf?: () => string | null;
  baseUrl?: string;
  defaultHeaders?: () => HeadersInit;
};

export function createConsoleClient(options: ClientOptions = {}) {
  const fetchImplementation = options.fetch ?? globalThis.fetch.bind(globalThis);
  const readCsrf = options.readCsrf ?? readCsrfCookie;
  const secureFetch: typeof fetch = async (input, init) => {
    const method = (input instanceof Request ? input.method : init?.method ?? "GET").toUpperCase();
    const headers = new Headers(options.defaultHeaders?.());
    new Headers(input instanceof Request ? input.headers : undefined)
      .forEach((value, name) => headers.set(name, value));
    new Headers(init?.headers).forEach((value, name) => headers.set(name, value));
    if (!new Set(["GET", "HEAD", "OPTIONS"]).has(method)) {
      const csrf = readCsrf();
      if (csrf) headers.set("X-CSRF-Token", csrf);
    }
    headers.delete("Authorization");
    return fetchImplementation(input, { ...init, credentials: "include", headers });
  };
  const client = createClient<paths>({ baseUrl: resolveBaseUrl(options.baseUrl), fetch: secureFetch });

  return {
    async getWorkbenchDashboard(): Promise<WorkbenchDashboard> {
      const result = await client.GET("/api/v1/workbench/dashboard"); return unwrap(result).data;
    },

    async createWorkbenchDraft(payload: WorkbenchDraftCreate): Promise<WorkbenchDraftMutation> {
      const result = await client.POST("/api/v1/workbench/drafts", {body: payload,
        params: {header: mutationHeaders("console:r114-structured-draft:1")}}); return unwrap(result).data;
    },

    async createWorkbenchSuccessor(draftId: string, successorDraftId: string, planId: string): Promise<WorkbenchDraftMutation> {
      const result = await client.POST("/api/v1/workbench/drafts/{draft_id}/successors", {
        body: {successor_draft_id: successorDraftId, plan_id: planId,
          confirmation: "--confirm-r114-successor-invalidates-approval"},
        params: {path: {draft_id: draftId}, header: mutationHeaders("console:r114-successor:1")},
      }); return unwrap(result).data;
    },

    async reviewWorkbenchDraft(draftId: string, decisionId: string, proposalSha256: string,
                               decision: "approve_exact" | "deny"): Promise<WorkbenchReview> {
      const result = await client.POST("/api/v1/workbench/drafts/{draft_id}/review", {
        body: {decision_id: decisionId, expected_proposal_sha256: proposalSha256, decision,
          confirmation: "--confirm-r114-exact-review"},
        params: {path: {draft_id: draftId}, header: mutationHeaders("console:r114-exact-review:1")},
      }); return unwrap(result).data;
    },

    async freezeMcpServer(registrationId: string, inventorySha256: string): Promise<McpFreezeMutation> {
      const result = await client.POST("/api/v1/mcp/servers/{registration_id}/freeze", {
        body: {expected_inventory_sha256: inventorySha256, confirmation: "--confirm-r114-freeze-and-invalidate"},
        params: {path: {registration_id: registrationId}, header: mutationHeaders("console:r114-freeze:1")},
      }); return unwrap(result).data;
    },

    async getFindingOperationsDashboard(): Promise<FindingOperationsDashboard> {
      const result = await client.GET("/api/v1/finding-operations/dashboard"); return unwrap(result).data;
    },

    async importFindingFixture(payload: FindingOperationsImport): Promise<FindingOperationsImportData> {
      const result = await client.POST("/api/v1/finding-operations/imports", {
        body: payload, params: {header: mutationHeaders(`console:r115-import:${payload.import_id}`)},
      }); return unwrap(result).data;
    },

    async reviewFindingIssue(issueId: string, disposition: "confirmed" | "false_positive",
                             reasonCode: string): Promise<FindingOperationsIssue> {
      const result = await client.POST("/api/v1/finding-operations/issues/{issue_id}/review", {
        body: {operation_id: `review-${issueId}-${disposition}`, disposition, reason_code: reasonCode,
          confirmation: "--confirm-r115-reviewed-disposition"},
        params: {path: {issue_id: issueId}, header: mutationHeaders(`console:r115-review:${issueId}:${disposition}`)},
      }); return unwrap(result).data;
    },

    async createFindingReport(reportId: string, audience: "technical" | "executive" | "customer" | "internal",
                              reviewedSnapshotSha256: string, evidenceSha256: string,
                              coverageState: "complete" | "partial"): Promise<FindingOperationsReport> {
      const result = await client.POST("/api/v1/finding-operations/reports", {
        body: {report_id: reportId, audience, reviewed_snapshot_sha256: reviewedSnapshotSha256,
          evidence_sha256: evidenceSha256, coverage_state: coverageState,
          partial_coverage_disclosed: coverageState === "partial",
          confirmation: "--confirm-r115-deterministic-report"},
        params: {header: mutationHeaders(`console:r115-report:${reportId}`)},
      }); return unwrap(result).data;
    },

    async queueFindingDelivery(deliveryId: string, report: FindingOperationsReport,
                               destinationObjectId: string): Promise<FindingOperationsDelivery> {
      const result = await client.POST("/api/v1/finding-operations/deliveries", {
        body: {delivery_id: deliveryId, profile_id: "fixture-ticket-v1", report_id: report.report_id,
          report_sha256: report.report_sha256, destination_object_id: destinationObjectId,
          confirmation: "--confirm-r115-fixture-delivery"},
        params: {header: mutationHeaders(`console:r115-delivery:${deliveryId}`)},
      }); return unwrap(result).data;
    },

    async publishFindingReport(report: FindingOperationsReport): Promise<FindingOperationsPublication> {
      const publicationId = `publication-${report.report_id}`;
      const result = await client.POST("/api/v1/finding-operations/reports/{report_id}/publish", {
        body: {publication_id: publicationId, report_sha256: report.report_sha256,
          confirmation: "--confirm-r115-independent-publication"},
        params: {path: {report_id: report.report_id},
          header: mutationHeaders(`console:r115-publication:${publicationId}`)},
      }); return unwrap(result).data;
    },

    async listAgentTools(): Promise<AgentTool[]> {
      const result = await client.GET("/api/v1/agent/tools");
      return unwrap(result).data;
    },

    async getAgentDashboard(): Promise<AgentDashboard> {
      const result = await client.GET("/api/v1/agent/dashboard");
      return unwrap(result).data;
    },

    async createAgentRun(payload: AgentRunCreate): Promise<AgentRunStart> {
      const result = await client.POST("/api/v1/agent/runs", {
        body: payload,
        params: { header: mutationHeaders("console:agent-proposal-only:1") },
      });
      return unwrap(result).data;
    },

    async approveAgentProposal(proposalId: string, approvalId: string, expectedSha256: string): Promise<AgentProposal> {
      const result = await client.POST("/api/v1/agent/proposals/{proposal_id}/approve", {
        body: { approval_id: approvalId, confirmation: "--confirm-r113-exact-proposal", expected_proposal_sha256: expectedSha256 },
        params: { path: { proposal_id: proposalId }, header: mutationHeaders("console:agent-exact-approval:1") },
      });
      return unwrap(result).data;
    },

    async cancelAgentRun(runId: string, expectedVersion: number, reason: string): Promise<AgentRun> {
      const result = await client.POST("/api/v1/agent/runs/{run_id}/cancel", {
        body: { expected_version: expectedVersion, reason },
        params: { path: { run_id: runId }, header: mutationHeaders("console:agent-cancel:1") },
      });
      return unwrap(result).data;
    },

    async getContext(): Promise<ContextResponse["data"]> {
      const result = await client.GET("/api/v1/context");
      return unwrap(result).data;
    },

    async getRunnerStatus(): Promise<RunnerStatus> {
      const result = await client.GET("/api/v1/runners/status");
      return unwrap(result).data;
    },

    async listRunnerRegistrations(): Promise<RunnerRegistration[]> {
      const result = await client.GET("/api/v1/runners/registrations", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listRunnerRegistrationsPage(limit = 50, offset = 0): Promise<PageResult<RunnerRegistration>> {
      const result = await client.GET("/api/v1/runners/registrations", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async listRunnerManifests(): Promise<RunnerManifest[]> {
      const result = await client.GET("/api/v1/runner-manifests", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listRunnerManifestsPage(limit = 50, offset = 0): Promise<PageResult<RunnerManifest>> {
      const result = await client.GET("/api/v1/runner-manifests", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async listRunnerExecutions(): Promise<RunnerExecution[]> {
      const result = await client.GET("/api/v1/runner-executions", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listRunnerExecutionsPage(limit = 50, offset = 0): Promise<PageResult<RunnerExecution>> {
      const result = await client.GET("/api/v1/runner-executions", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async getPolicyStatus(): Promise<PolicyStatus> {
      const result = await client.GET("/api/v1/policy/status");
      return unwrap(result).data;
    },

    async listPolicyDecisions(): Promise<PolicyDecision[]> {
      const result = await client.GET("/api/v1/policy/decisions", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listPolicyDecisionsPage(limit = 50, offset = 0): Promise<PageResult<PolicyDecision>> {
      const result = await client.GET("/api/v1/policy/decisions", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async listPolicyBundles(): Promise<PolicyBundle[]> {
      const result = await client.GET("/api/v1/policy/bundles", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listPolicyBundlesPage(limit = 50, offset = 0): Promise<PageResult<PolicyBundle>> {
      const result = await client.GET("/api/v1/policy/bundles", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async simulatePolicy(payload: PolicySimulationRequest): Promise<PolicySimulation> {
      const result = await client.POST("/api/v1/policy/simulations", {
        body: payload,
        params: { header: mutationHeaders("console:policy-simulation:1") },
      });
      return unwrap(result).data;
    },

    async promotePolicy(payload: PolicyPromotionRequest): Promise<PolicyPromotion> {
      const result = await client.POST("/api/v1/policy/promotions", {
        body: payload,
        params: { header: mutationHeaders("console:policy-promotion:1") },
      });
      return unwrap(result).data;
    },

    async rollbackPolicy(payload: PolicyPromotionRequest): Promise<PolicyPromotion> {
      const result = await client.POST("/api/v1/policy/rollbacks", {
        body: payload,
        params: { header: mutationHeaders("console:policy-rollback:1") },
      });
      return unwrap(result).data;
    },

    async listEngagements(): Promise<EngagementData[]> {
      const result = await client.GET("/api/v1/engagements", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listEngagementsPage(limit = 50, offset = 0): Promise<PageResult<EngagementData>> {
      const result = await client.GET("/api/v1/engagements", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async listJobs(): Promise<JobData[]> {
      const result = await client.GET("/api/v1/jobs", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listJobsPage(limit = 50, offset = 0): Promise<PageResult<JobData>> {
      const result = await client.GET("/api/v1/jobs", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async getJob(jobId: string, roeVersionId: string): Promise<JobData> {
      const result = await client.GET("/api/v1/jobs/{job_id}", {
        params: {
          path: { job_id: jobId },
          header: { "X-RedAgent-ROE-Version": roeVersionId },
        },
      });
      return unwrap(result).data;
    },

    async createJob(payload: JobCreate): Promise<JobData> {
      const result = await client.POST("/api/v1/jobs", {
        body: payload,
        params: {
          header: {
            ...mutationHeaders("console:job-create:1"),
            "X-RedAgent-ROE-Version": payload.roe_version_id,
          },
        },
      });
      return unwrap(result).data;
    },

    async commandJob(jobId: string, roeVersionId: string, payload: JobCommand): Promise<JobData> {
      const result = await client.POST("/api/v1/jobs/{job_id}/commands", {
        body: payload,
        params: {
          path: { job_id: jobId },
          header: {
            ...mutationHeaders("console:job-command:1"),
            "X-RedAgent-ROE-Version": roeVersionId,
          },
        },
      });
      return unwrap(result).data;
    },

    async emergencyStopJob(jobId: string, roeVersionId: string, reason: string): Promise<JobStopData> {
      const result = await client.POST("/api/v1/jobs/{job_id}/emergency-stop", {
        body: { signal_id: createIdempotencyKey(), reason },
        params: {
          path: { job_id: jobId },
          header: {
            ...mutationHeaders("console:job-stop:1"),
            "X-RedAgent-ROE-Version": roeVersionId,
          },
        },
      });
      return unwrap(result).data;
    },

    async getJobContainment(jobId: string): Promise<JobContainmentData> {
      const result = await client.GET("/api/v1/jobs/{job_id}/containment", {
        params: { path: { job_id: jobId } },
      });
      return unwrap(result).data;
    },

    async listContainmentControls(): Promise<ContainmentControlData[]> {
      const result = await client.GET("/api/v1/containment-controls", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async getContainmentControl(controlId: string): Promise<ContainmentControlData> {
      const result = await client.GET("/api/v1/containment-controls/{control_id}", {
        params: { path: { control_id: controlId } },
      });
      return unwrap(result).data;
    },

    async requestContainmentControl(payload: ContainmentStopRequest): Promise<ContainmentControlData> {
      const result = await client.POST("/api/v1/containment-controls", {
        body: payload,
        params: { header: mutationHeaders("console:containment-stop:1") },
      });
      return unwrap(result).data;
    },

    async approveContainmentControl(
      controlId: string, requestHash: string, expectedVersion: number,
    ): Promise<ContainmentControlData> {
      const result = await client.POST("/api/v1/containment-controls/{control_id}/approve", {
        body: { approval_id: createIdempotencyKey(), request_hash: requestHash, expected_version: expectedVersion },
        params: {
          path: { control_id: controlId },
          header: mutationHeaders("console:containment-approve:1"),
        },
      });
      return unwrap(result).data;
    },

    async recoverContainmentControl(controlId: string, expectedVersion: number): Promise<ContainmentControlData> {
      const result = await client.POST("/api/v1/containment-controls/{control_id}/recover", {
        body: { review_id: createIdempotencyKey(), expected_version: expectedVersion },
        params: {
          path: { control_id: controlId },
          header: mutationHeaders("console:containment-recover:1"),
        },
      });
      return unwrap(result).data;
    },

    async getQuotaStatus(): Promise<QuotaStatusData[]> {
      const result = await client.GET("/api/v1/quotas/status");
      return unwrap(result).data;
    },

    async getObservabilityDashboard(): Promise<ObservabilityDashboard> {
      const result = await client.GET("/api/v1/observability/dashboard");
      return unwrap(result).data;
    },

    async getLabDashboard(): Promise<LabDashboard> {
      const result = await client.GET("/api/v1/lab/dashboard");
      return unwrap(result).data;
    },

    async listZapProfiles(): Promise<ZapProfile[]> {
      const result = await client.GET("/api/v1/zap/profiles");
      return unwrap(result).data;
    },

    async getZapDashboard(): Promise<ZapDashboard> {
      const result = await client.GET("/api/v1/zap/dashboard");
      return unwrap(result).data;
    },

    async compileZapPlan(payload: ZapCompile): Promise<ZapPlan> {
      const result = await client.POST("/api/v1/zap/plans", {
        body: payload,
        params: {
          header: {
            ...mutationHeaders("console:zap-plan:1"),
            "X-RedAgent-ROE-Version": payload.roe_version_id,
          },
        },
      });
      return unwrap(result).data;
    },

    async createZapRun(payload: ZapRunCreate): Promise<ZapRun> {
      const result = await client.POST("/api/v1/zap/runs", {
        body: payload,
        params: { header: mutationHeaders("console:zap-run:1") },
      });
      return unwrap(result).data;
    },

    async cancelZapRun(runId: string, expectedVersion: number, reason: string): Promise<ZapRun> {
      const result = await client.POST("/api/v1/zap/runs/{run_id}/cancel", {
        body: { expected_version: expectedVersion, reason },
        params: {
          path: { run_id: runId },
          header: mutationHeaders("console:zap-cancel:1"),
        },
      });
      return unwrap(result).data;
    },

    async listNucleiProfiles(): Promise<NucleiProfile[]> {
      const result = await client.GET("/api/v1/nuclei/profiles");
      return unwrap(result).data;
    },

    async getNucleiDashboard(): Promise<NucleiDashboard> {
      const result = await client.GET("/api/v1/nuclei/dashboard");
      return unwrap(result).data;
    },

    async compileNucleiPlan(payload: NucleiCompile): Promise<NucleiPlan> {
      const result = await client.POST("/api/v1/nuclei/plans", {
        body: payload,
        params: { header: {
          ...mutationHeaders("console:nuclei-plan:1"),
          "X-RedAgent-ROE-Version": payload.roe_version_id,
        } },
      });
      return unwrap(result).data;
    },

    async createNucleiRun(payload: NucleiRunCreate): Promise<NucleiRun> {
      const result = await client.POST("/api/v1/nuclei/runs", {
        body: payload, params: { header: mutationHeaders("console:nuclei-run:1") },
      });
      return unwrap(result).data;
    },

    async cancelNucleiRun(runId: string, expectedVersion: number, reason: string): Promise<NucleiRun> {
      const result = await client.POST("/api/v1/nuclei/runs/{run_id}/cancel", {
        body: { expected_version: expectedVersion, reason },
        params: { path: { run_id: runId }, header: mutationHeaders("console:nuclei-cancel:1") },
      });
      return unwrap(result).data;
    },

    async listApiDifferentialProfiles(): Promise<ApiDifferentialProfile[]> {
      const result = await client.GET("/api/v1/api-differential/profiles");
      return unwrap(result).data;
    },

    async getApiDifferentialDashboard(): Promise<ApiDifferentialDashboard> {
      const result = await client.GET("/api/v1/api-differential/dashboard");
      return unwrap(result).data;
    },

    async compileApiDifferentialPlan(payload: ApiDifferentialCompile): Promise<ApiDifferentialPlan> {
      const result = await client.POST("/api/v1/api-differential/plans", {
        body: payload,
        params: { header: {
          ...mutationHeaders("console:api-differential-plan:1"),
          "X-RedAgent-ROE-Version": payload.roe_version_id,
        } },
      });
      return unwrap(result).data;
    },

    async createApiDifferentialRun(payload: ApiDifferentialRunCreate): Promise<ApiDifferentialRun> {
      const result = await client.POST("/api/v1/api-differential/runs", {
        body: payload, params: { header: mutationHeaders("console:api-differential-run:1") },
      });
      return unwrap(result).data;
    },

    async cancelApiDifferentialRun(runId: string, expectedVersion: number, reason: string): Promise<ApiDifferentialRun> {
      const result = await client.POST("/api/v1/api-differential/runs/{run_id}/cancel", {
        body: { expected_version: expectedVersion, reason },
        params: { path: { run_id: runId }, header: mutationHeaders("console:api-differential-cancel:1") },
      });
      return unwrap(result).data;
    },

    async listNetworkProfiles(): Promise<NetworkProfile[]> {
      const result = await client.GET("/api/v1/network-assessment/profiles");
      return unwrap(result).data;
    },

    async getNetworkDashboard(): Promise<NetworkDashboard> {
      const result = await client.GET("/api/v1/network-assessment/dashboard");
      return unwrap(result).data;
    },

    async compileNetworkPlan(payload: NetworkCompile): Promise<NetworkPlan> {
      const result = await client.POST("/api/v1/network-assessment/plans", {
        body: payload,
        params: { header: {
          ...mutationHeaders("console:network-plan:1"),
          "X-RedAgent-ROE-Version": payload.roe_version_id,
        } },
      });
      return unwrap(result).data;
    },

    async createNetworkRun(payload: NetworkRunCreate): Promise<NetworkRun> {
      const result = await client.POST("/api/v1/network-assessment/runs", {
        body: payload, params: { header: mutationHeaders("console:network-run:1") },
      });
      return unwrap(result).data;
    },

    async cancelNetworkRun(runId: string, expectedVersion: number, reason: string): Promise<NetworkRun> {
      const result = await client.POST("/api/v1/network-assessment/runs/{run_id}/cancel", {
        body: { expected_version: expectedVersion, reason },
        params: { path: { run_id: runId }, header: mutationHeaders("console:network-cancel:1") },
      });
      return unwrap(result).data;
    },

    async listCloudProfiles(): Promise<CloudProfile[]> {
      const result = await client.GET("/api/v1/cloud-posture/profiles");
      return unwrap(result).data;
    },

    async getCloudDashboard(): Promise<CloudDashboard> {
      const result = await client.GET("/api/v1/cloud-posture/dashboard");
      return unwrap(result).data;
    },

    async compileCloudPlan(payload: CloudCompile): Promise<CloudPlan> {
      const result = await client.POST("/api/v1/cloud-posture/plans", {
        body: payload,
        params: { header: {
          ...mutationHeaders("console:cloud-plan:1"),
          "X-RedAgent-ROE-Version": payload.roe_version_id,
        } },
      });
      return unwrap(result).data;
    },

    async createCloudRun(payload: CloudRunCreate): Promise<CloudRun> {
      const result = await client.POST("/api/v1/cloud-posture/runs", {
        body: payload, params: { header: mutationHeaders("console:cloud-run:1") },
      });
      return unwrap(result).data;
    },

    async cancelCloudRun(runId: string, expectedVersion: number, reason: string): Promise<CloudRun> {
      const result = await client.POST("/api/v1/cloud-posture/runs/{run_id}/cancel", {
        body: { expected_version: expectedVersion, reason },
        params: { path: { run_id: runId }, header: mutationHeaders("console:cloud-cancel:1") },
      });
      return unwrap(result).data;
    },

    async listIdentitySaasProfiles(): Promise<IdentitySaasProfile[]> {
      const result = await client.GET("/api/v1/identity-posture/profiles");
      return unwrap(result).data;
    },

    async getIdentitySaasDashboard(): Promise<IdentitySaasDashboard> {
      const result = await client.GET("/api/v1/identity-posture/dashboard");
      return unwrap(result).data;
    },

    async compileIdentitySaasPlan(payload: IdentitySaasCompile): Promise<IdentitySaasPlan> {
      const result = await client.POST("/api/v1/identity-posture/plans", {
        body: payload,
        params: { header: {
          ...mutationHeaders("console:identity-plan:1"),
          "X-RedAgent-ROE-Version": payload.roe_version_id,
        } },
      });
      return unwrap(result).data;
    },

    async createIdentitySaasRun(payload: IdentitySaasRunCreate): Promise<IdentitySaasRun> {
      const result = await client.POST("/api/v1/identity-posture/runs", {
        body: payload, params: { header: mutationHeaders("console:identity-run:1") },
      });
      return unwrap(result).data;
    },

    async cancelIdentitySaasRun(runId: string, expectedVersion: number, reason: string): Promise<IdentitySaasRun> {
      const result = await client.POST("/api/v1/identity-posture/runs/{run_id}/cancel", {
        body: { expected_version: expectedVersion, reason },
        params: { path: { run_id: runId }, header: mutationHeaders("console:identity-cancel:1") },
      });
      return unwrap(result).data;
    },

    async listArtifactProfiles(): Promise<ArtifactProfile[]> {
      const result = await client.GET("/api/v1/artifact-posture/profiles"); return unwrap(result).data;
    },

    async getArtifactDashboard(): Promise<ArtifactDashboard> {
      const result = await client.GET("/api/v1/artifact-posture/dashboard"); return unwrap(result).data;
    },

    async compileArtifactPlan(payload: ArtifactCompile): Promise<ArtifactPlan> {
      const result = await client.POST("/api/v1/artifact-posture/plans", {body: payload, params: {header: {...mutationHeaders("console:artifact-plan:1"), "X-RedAgent-ROE-Version": payload.roe_version_id}}});
      return unwrap(result).data;
    },

    async createArtifactRun(payload: ArtifactRunCreate): Promise<ArtifactRun> {
      const result = await client.POST("/api/v1/artifact-posture/runs", {body: payload, params: {header: mutationHeaders("console:artifact-run:1")}}); return unwrap(result).data;
    },

    async cancelArtifactRun(runId: string, expectedVersion: number, reason: string): Promise<ArtifactRun> {
      const result = await client.POST("/api/v1/artifact-posture/runs/{run_id}/cancel", {body: {expected_version: expectedVersion, reason}, params: {path: {run_id: runId}, header: mutationHeaders("console:artifact-cancel:1")}}); return unwrap(result).data;
    },

    async lookupCorrelation(correlationId: string): Promise<CorrelationEvent[]> {
      const result = await client.GET("/api/v1/observability/correlations/{correlation_id}", {
        params: { path: { correlation_id: correlationId }, query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listPurpleAbilities(): Promise<PurpleAbility[]> {
      const result = await client.GET("/api/v1/purple-lab/abilities"); return unwrap(result).data;
    },

    async getPurpleDashboard(): Promise<PurpleDashboard> {
      const result = await client.GET("/api/v1/purple-lab/dashboard"); return unwrap(result).data;
    },

    async compilePurplePlan(payload: PurpleCompile): Promise<PurplePlan> {
      const result = await client.POST("/api/v1/purple-lab/plans", {body: payload, params: {header: {
        ...mutationHeaders("console:purple-plan:1"), "X-RedAgent-ROE-Version": payload.roe_version_id,
      }}}); return unwrap(result).data;
    },

    async createPurpleRun(payload: PurpleRunCreate): Promise<PurpleRun> {
      const result = await client.POST("/api/v1/purple-lab/runs", {body: payload,
        params: {header: mutationHeaders("console:purple-run:1")}}); return unwrap(result).data;
    },

    async killPurpleRun(runId: string, expectedVersion: number, reason: string): Promise<PurpleRun> {
      const result = await client.POST("/api/v1/purple-lab/runs/{run_id}/kill", {body: {expected_version: expectedVersion, reason},
        params: {path: {run_id: runId}, header: mutationHeaders("console:purple-kill:1")}}); return unwrap(result).data;
    },

    async listIncidents(): Promise<Incident[]> {
      const result = await client.GET("/api/v1/incidents", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listIncidentsPage(limit = 50, offset = 0): Promise<PageResult<Incident>> {
      const result = await client.GET("/api/v1/incidents", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async listHumanSimulationCampaigns(): Promise<HumanSimulationCampaign[]> {
      const result = await client.GET("/api/v1/human-simulation/campaigns"); return unwrap(result).data;
    },

    async getHumanSimulationDashboard(): Promise<HumanSimulationDashboard> {
      const result = await client.GET("/api/v1/human-simulation/dashboard"); return unwrap(result).data;
    },

    async compileHumanSimulationPlan(payload: HumanSimulationCompile): Promise<HumanSimulationPlan> {
      const result = await client.POST("/api/v1/human-simulation/plans", {body: payload, params: {header: {
        ...mutationHeaders("console:human-plan:1"), "X-RedAgent-ROE-Version": payload.roe_version_id,
      }}}); return unwrap(result).data;
    },

    async createHumanSimulationRun(payload: HumanSimulationRunCreate): Promise<HumanSimulationRun> {
      const result = await client.POST("/api/v1/human-simulation/runs", {body: payload,
        params: {header: mutationHeaders("console:human-run:1")}}); return unwrap(result).data;
    },

    async stopHumanSimulationRun(runId: string, expectedVersion: number, reason: string): Promise<HumanSimulationRun> {
      const result = await client.POST("/api/v1/human-simulation/runs/{run_id}/stop", {body: {expected_version: expectedVersion, reason},
        params: {path: {run_id: runId}, header: mutationHeaders("console:human-stop:1")}}); return unwrap(result).data;
    },

    async listIncidentRunbooks(): Promise<IncidentRunbook[]> {
      const result = await client.GET("/api/v1/incidents/runbooks");
      return unwrap(result).data;
    },

    async lookupCorrelationPage(
      correlationId: string, limit = 50, offset = 0,
    ): Promise<PageResult<CorrelationEvent>> {
      const result = await client.GET("/api/v1/observability/correlations/{correlation_id}", {
        params: { path: { correlation_id: correlationId }, query: { limit, offset } },
      });
      return unwrap(result);
    },

    async getIncidentTimeline(incidentId: string): Promise<IncidentTimeline[]> {
      const result = await client.GET("/api/v1/incidents/{incident_id}/timeline", {
        params: { path: { incident_id: incidentId } },
      });
      return unwrap(result).data;
    },

    async applyIncidentAction(incidentId: string, payload: IncidentActionRequest): Promise<Incident> {
      const result = await client.POST("/api/v1/incidents/{incident_id}/actions", {
        body: payload,
        params: {
          path: { incident_id: incidentId },
          header: mutationHeaders(`console:incident-${payload.action}:1`),
        },
      });
      return unwrap(result).data;
    },

    async createEngagement(payload: EngagementCreate): Promise<EngagementData> {
      const result = await client.POST("/api/v1/engagements", {
        body: payload,
        params: {
          header: {
            "Idempotency-Key": createIdempotencyKey(),
            "X-RedAgent-Policy-Reference": "console:engagement-create:1",
          },
        },
      });
      return unwrap(result).data;
    },

    async listTargets(engagementId: string): Promise<TargetData[]> {
      const result = await client.GET("/api/v1/engagements/{engagement_id}/targets", {
        params: { path: { engagement_id: engagementId }, query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async createTarget(engagementId: string, payload: TargetCreate): Promise<TargetData> {
      const result = await client.POST("/api/v1/engagements/{engagement_id}/targets", {
        body: payload,
        params: {
          path: { engagement_id: engagementId },
          header: mutationHeaders("console:target-create:1"),
        },
      });
      return unwrap(result).data;
    },

    async listRoeVersions(engagementId: string): Promise<RoeData[]> {
      const result = await client.GET("/api/v1/engagements/{engagement_id}/roe-versions", {
        params: { path: { engagement_id: engagementId }, query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async createRoeVersion(engagementId: string, payload: RoeCreate): Promise<RoeData> {
      const result = await client.POST("/api/v1/engagements/{engagement_id}/roe-versions", {
        body: payload,
        params: {
          path: { engagement_id: engagementId },
          header: mutationHeaders("console:roe-create:1"),
        },
      });
      return unwrap(result).data;
    },

    async approveRoeVersion(roeVersionId: string, expectedVersion: number): Promise<RoeData> {
      const result = await client.POST("/api/v1/roe-versions/{roe_version_id}/approve", {
        body: { approval_id: createIdempotencyKey(), expected_version: expectedVersion },
        params: {
          path: { roe_version_id: roeVersionId },
          header: {
            ...mutationHeaders("console:roe-approve:1"),
            "X-RedAgent-ROE-Version": roeVersionId,
          },
        },
      });
      return unwrap(result).data;
    },

    async listJitGrants(): Promise<JitData[]> {
      const result = await client.GET("/api/v1/jit-grants", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listJitGrantsPage(limit = 50, offset = 0): Promise<PageResult<JitData>> {
      const result = await client.GET("/api/v1/jit-grants", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async requestJitGrant(payload: JitCreate): Promise<JitData> {
      const result = await client.POST("/api/v1/jit-grants", {
        body: payload,
        params: { header: mutationHeaders("console:jit-request:1") },
      });
      return unwrap(result).data;
    },

    async approveJitGrant(grantId: string, expectedVersion: number): Promise<JitData> {
      const result = await client.POST("/api/v1/jit-grants/{grant_id}/approve", {
        body: { expected_version: expectedVersion },
        params: {
          path: { grant_id: grantId },
          header: mutationHeaders("console:jit-approve:1"),
        },
      });
      return unwrap(result).data;
    },

    async revokeJitGrant(grantId: string, expectedVersion: number, reason: string): Promise<JitData> {
      const result = await client.POST("/api/v1/jit-grants/{grant_id}/revoke", {
        body: { expected_version: expectedVersion, reason },
        params: {
          path: { grant_id: grantId },
          header: mutationHeaders("console:jit-revoke:1"),
        },
      });
      return unwrap(result).data;
    },

    async reviewJitGrant(grantId: string, expectedVersion: number): Promise<JitData> {
      const result = await client.POST("/api/v1/jit-grants/{grant_id}/review", {
        body: {
          review_id: createIdempotencyKey(),
          expected_version: expectedVersion,
          outcome: "approved",
        },
        params: {
          path: { grant_id: grantId },
          header: mutationHeaders("console:jit-review:1"),
        },
      });
      return unwrap(result).data;
    },

    async listActivity(): Promise<ActivityData[]> {
      const result = await client.GET("/api/v1/activity", {
        params: { query: { limit: 100, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listActivityPage(limit = 50, offset = 0): Promise<PageResult<ActivityData>> {
      const result = await client.GET("/api/v1/activity", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async listEvidence(): Promise<EvidenceArtifact[]> {
      const result = await client.GET("/api/v1/evidence/artifacts", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listEvidencePage(limit = 50, offset = 0): Promise<PageResult<EvidenceArtifact>> {
      const result = await client.GET("/api/v1/evidence/artifacts", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async getEvidence(artifactId: string): Promise<EvidenceArtifactDetail> {
      const result = await client.GET("/api/v1/evidence/artifacts/{artifact_id}", {
        params: { path: { artifact_id: artifactId } },
      });
      return unwrap(result).data;
    },

    async selectEvidence(artifactId: string, purpose: "review" | "report" | "export"): Promise<EvidenceArtifact> {
      const result = await client.GET("/api/v1/evidence/artifacts/{artifact_id}/selection", {
        params: { path: { artifact_id: artifactId }, query: { purpose } },
      });
      return unwrap(result).data;
    },

    async registerSyntheticEvidence(payload: EvidenceSyntheticRegister): Promise<EvidenceArtifact> {
      const result = await client.POST("/api/v1/evidence/synthetic", {
        body: payload,
        params: { header: mutationHeaders("console:evidence-synthetic:1") },
      });
      return unwrap(result).data;
    },

    async deriveEvidence(artifactId: string, payload: EvidenceDerive): Promise<EvidenceArtifact> {
      const result = await client.POST("/api/v1/evidence/artifacts/{artifact_id}/derive", {
        body: payload,
        params: {
          path: { artifact_id: artifactId },
          header: mutationHeaders("console:evidence-derive:1"),
        },
      });
      return unwrap(result).data;
    },

    async verifyEvidence(artifactId: string): Promise<EvidenceVerification> {
      const result = await client.POST("/api/v1/evidence/artifacts/{artifact_id}/verify", {
        params: {
          path: { artifact_id: artifactId },
          header: mutationHeaders("console:evidence-verify:1"),
        },
      });
      return unwrap(result).data;
    },

    async placeEvidenceLegalHold(artifactId: string, expectedVersion: number): Promise<EvidenceArtifact> {
      const result = await client.POST("/api/v1/evidence/artifacts/{artifact_id}/legal-hold", {
        body: { expected_version: expectedVersion },
        params: {
          path: { artifact_id: artifactId },
          header: mutationHeaders("console:evidence-retention:1"),
        },
      });
      return unwrap(result).data;
    },

    async listSecretReferences(): Promise<SecretReference[]> {
      const result = await client.GET("/api/v1/secret-references", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listSecretReferencesPage(limit = 50, offset = 0): Promise<PageResult<SecretReference>> {
      const result = await client.GET("/api/v1/secret-references", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async listSecretLeases(): Promise<SecretLease[]> {
      const result = await client.GET("/api/v1/secret-leases", {
        params: { query: { limit: 50, offset: 0 } },
      });
      return unwrap(result).data;
    },

    async listSecretLeasesPage(limit = 50, offset = 0): Promise<PageResult<SecretLease>> {
      const result = await client.GET("/api/v1/secret-leases", {
        params: { query: { limit, offset } },
      });
      return unwrap(result);
    },

    async issueSyntheticSecretLease(payload: SecretSyntheticIssue, roeVersionId: string): Promise<SecretLease> {
      const result = await client.POST("/api/v1/secret-leases/synthetic", {
        body: payload,
        params: {
          header: {
            ...mutationHeaders("console:secret-synthetic:1"),
            "X-RedAgent-ROE-Version": roeVersionId,
          },
        },
      });
      return unwrap(result).data;
    },

    async revokeSecretLease(leaseId: string, expectedVersion: number): Promise<SecretLease> {
      const result = await client.POST("/api/v1/secret-leases/{lease_id}/revoke", {
        body: { expected_version: expectedVersion },
        params: {
          path: { lease_id: leaseId },
          header: mutationHeaders("console:secret-revoke:1"),
        },
      });
      return unwrap(result).data;
    },

    async listCampaignCoreEngagementOptions(limit = 50, cursor?: string): Promise<R124CampaignOptionPage> {
      const result = await client.GET("/api/v1/campaign-core/options/engagements", {
        params: { query: { limit, cursor: cursor ?? null } },
      });
      return unwrap(result);
    },

    async listCampaignCoreTargetOptions(
      engagementBinding: string,
      limit = 50,
      cursor?: string,
    ): Promise<R124CampaignOptionPage> {
      const result = await client.GET("/api/v1/campaign-core/options/targets", {
        params: { query: { engagement_binding: engagementBinding, limit, cursor: cursor ?? null } },
      });
      return unwrap(result);
    },

    async listCampaignCoreRiskOptions(
      engagementBinding: string,
      targetBinding: string,
      limit = 50,
      cursor?: string,
    ): Promise<R124CampaignOptionPage> {
      const result = await client.GET("/api/v1/campaign-core/options/risk-profiles", {
        params: { query: {
          engagement_binding: engagementBinding,
          target_binding: targetBinding,
          limit,
          cursor: cursor ?? null,
        } },
      });
      return unwrap(result);
    },

    async startCampaignCore(
      payload: R124CampaignStart,
      idempotencyKey?: string,
    ): Promise<R124CampaignMutation> {
      const result = await client.POST("/api/v1/campaign-core/campaigns", {
        body: payload,
        params: { header: mutationHeaders("console:r124-campaign-start:1", idempotencyKey) },
      });
      return unwrap(result).data;
    },

    async listCampaignCoreCampaigns(limit = 50, cursor?: string): Promise<R124CampaignSummaryPage> {
      const result = await client.GET("/api/v1/campaign-core/campaigns", {
        params: { query: { limit, cursor: cursor ?? null } },
      });
      return unwrap(result);
    },

    async getCampaignCoreCampaign(campaignId: string): Promise<R124CampaignAggregate> {
      const result = await client.GET("/api/v1/campaign-core/campaigns/{campaign_id}", {
        params: { path: { campaign_id: campaignId } },
      });
      return unwrap(result).data;
    },

    async inspectCampaignCoreCampaign(campaignId: string): Promise<R124CampaignInspector> {
      const result = await client.GET("/api/v1/campaign-core/campaigns/{campaign_id}/inspector", {
        params: { path: { campaign_id: campaignId } },
      });
      return unwrap(result).data;
    },

    async listCampaignCoreAttention(limit = 50, cursor?: string): Promise<R124AttentionPage> {
      const result = await client.GET("/api/v1/campaign-core/attention", {
        params: { query: { limit, cursor: cursor ?? null } },
      });
      return unwrap(result);
    },

    async recoverCampaignCore(
      action: "stop" | "revoke",
      campaignId: string,
      etag: string,
      reason: string,
    ): Promise<R124CampaignMutation> {
      const headers = { ...mutationHeaders(`console:r124-campaign-${action}:1`), "If-Match": etag };
      const result = action === "stop"
        ? await client.POST("/api/v1/campaign-core/campaigns/{campaign_id}/stop", {
          body: { reason }, params: { path: { campaign_id: campaignId }, header: headers },
        })
        : await client.POST("/api/v1/campaign-core/campaigns/{campaign_id}/revoke", {
          body: { reason }, params: { path: { campaign_id: campaignId }, header: headers },
        });
      return unwrap(result).data;
    },
  };
}

function resolveBaseUrl(configured?: string): string {
  if (configured) return new URL("/", configured).toString();
  const origin = typeof window === "undefined" ? "http://localhost" : window.location.origin;
  return new URL("/", origin).toString();
}

function mutationHeaders(policyReference: string, idempotencyKey?: string) {
  return {
    "Idempotency-Key": idempotencyKey ?? createIdempotencyKey(),
    "X-RedAgent-Policy-Reference": policyReference,
  };
}

type FetchResult<T> = {
  data?: T;
  error?: unknown;
  response: Response;
};

function unwrap<T>(result: FetchResult<T>): T {
  if (result.data !== undefined) return result.data;
  const error = asRecord(result.error);
  const envelope = asRecord(error.error ?? error);
  const code = text(envelope.code) ?? "request_failed";
  const message = text(envelope.message) ?? "The control-plane request failed.";
  const correlationId = text(envelope.correlation_id);
  throw new ConsoleApiError(code, message, result.response.status, correlationId);
}

function asRecord(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function text(value: unknown): string | null {
  return typeof value === "string" && value.length <= 500 ? value : null;
}

function createIdempotencyKey(): string {
  return typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `console-${Date.now().toString(36)}`;
}

export function readCsrfCookie(): string | null {
  const prefix = "__Host-redagent_csrf=";
  const cookie = document.cookie.split(";").map((part) => part.trim()).find((part) => part.startsWith(prefix));
  return cookie ? decodeURIComponent(cookie.slice(prefix.length)) : null;
}
