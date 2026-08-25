import { useCallback, useEffect, useState, type ReactNode } from "react";

import { LifecycleState } from "../components/LifecycleState/LifecycleState";
import { CampaignAttentionFeature, CampaignCoreFeature, CampaignStatusFeature } from "../features/campaigns/CampaignCoreFeature";
import { AccessPage } from "../features/residual/command/AccessPage";
import { EngagementsPage } from "../features/residual/command/EngagementsPage";
import { JobsPage } from "../features/residual/command/JobsPage";
import { PolicyPage } from "../features/residual/command/PolicyPage";
import { ActivityPage } from "../features/residual/trust/ActivityPage";
import { EvidencePage } from "../features/residual/trust/EvidencePage";
import { FindingOperationsPage } from "../features/residual/trust/FindingOperationsPage";
import { LabPage } from "../features/residual/trust/LabPage";
import { ObservabilityPage } from "../features/residual/trust/ObservabilityPage";
import { RunnersPage } from "../features/residual/trust/RunnersPage";
import { SecretsPage } from "../features/residual/trust/SecretsPage";
import { ZapPage } from "../features/residual/assessment/ZapPage";
import { NucleiPage } from "../features/residual/assessment/NucleiPage";
import { ApiDifferentialPage } from "../features/residual/assessment/ApiDifferentialPage";
import { NetworkAssessmentPage } from "../features/residual/assessment/NetworkAssessmentPage";
import { CloudPosturePage } from "../features/residual/assessment/CloudPosturePage";
import { IdentityPosturePage } from "../features/residual/assessment/IdentityPosturePage";
import { ArtifactPosturePage } from "../features/residual/assessment/ArtifactPosturePage";
import { PurpleLabPage } from "../features/residual/assessment/PurpleLabPage";
import { HumanSimulationPage } from "../features/residual/assessment/HumanSimulationPage";
import { AgentKernelPage } from "../features/residual/supervision/AgentKernelPage";
import { WorkbenchPage } from "../features/residual/supervision/WorkbenchPage";
import { ConsoleApiError } from "../lib/apiClient";
import { RouteLink } from "./RouteLink";
import { useShellRuntime, type ConsoleClient } from "./shellRuntime";


type EngagementRows = Awaited<ReturnType<ConsoleClient["listEngagements"]>>;
type RouteDataState =
  | { readonly kind: "loading" }
  | { readonly kind: "error"; readonly error: ConsoleApiError }
  | { readonly kind: "ready"; readonly engagements: EngagementRows };

export function OverviewRoute() {
  return <EngagementData>{(engagements) => <Overview engagements={engagements} />}</EngagementData>;
}

export function EngagementsRoute() {
  const { client, context } = useShellRuntime();
  return <EngagementsPage client={client} context={context} />;
}

export function CampaignsRoute() {
  const { client } = useShellRuntime();
  return <CampaignStatusFeature client={client} />;
}

export function CampaignAttentionRoute() {
  const { client } = useShellRuntime();
  return <CampaignAttentionFeature client={client} />;
}

export function CampaignNewRoute() {
  const { campaignCreateEnabled, client } = useShellRuntime();
  return <CampaignCoreFeature client={client} createEnabled={campaignCreateEnabled} />;
}

export function JobsRoute() {
  const { client, context } = useShellRuntime();
  return <JobsPage client={client} context={context} />;
}

export function EvidenceRoute() {
  const { client, context } = useShellRuntime();
  return <EvidencePage client={client} context={context} />;
}

export function SecretsRoute() {
  const { client, context } = useShellRuntime();
  return <SecretsPage client={client} context={context} />;
}

export function AccessRoute() {
  const { client, context } = useShellRuntime();
  return <AccessPage client={client} context={context} />;
}

export function RunnersRoute() {
  const { client, context } = useShellRuntime();
  return <RunnersPage client={client} context={context} />;
}

export function ActivityRoute() {
  const { client, context } = useShellRuntime();
  return <ActivityPage client={client} context={context} />;
}

export function PolicyRoute() {
  const { client, context } = useShellRuntime();
  return <PolicyPage client={client} context={context} />;
}

export function ObservabilityRoute() {
  const { client, context } = useShellRuntime();
  return <ObservabilityPage client={client} context={context} />;
}

export function LabRoute() {
  const { client, context } = useShellRuntime();
  return <LabPage client={client} context={context} />;
}

export function ZapRoute() {
  const { client, context } = useShellRuntime();
  return <ZapPage client={client} context={context} />;
}

export function NucleiRoute() {
  const { client, context } = useShellRuntime();
  return <NucleiPage client={client} context={context} />;
}

export function ApiDifferentialRoute() {
  const { client, context } = useShellRuntime();
  return <ApiDifferentialPage client={client} context={context} />;
}

export function NetworkAssessmentRoute() {
  const { client, context } = useShellRuntime();
  return <NetworkAssessmentPage client={client} context={context} />;
}

export function CloudPostureRoute() {
  const { client, context } = useShellRuntime();
  return <CloudPosturePage client={client} context={context} />;
}

export function IdentityPostureRoute() {
  const { client, context } = useShellRuntime();
  return <IdentityPosturePage client={client} context={context} />;
}

export function ArtifactPostureRoute() {
  const { client, context } = useShellRuntime();
  return <ArtifactPosturePage client={client} context={context} />;
}

export function PurpleLabRoute() {
  const { client, context } = useShellRuntime();
  return <PurpleLabPage client={client} context={context} />;
}

export function HumanSimulationRoute() {
  const { client, context } = useShellRuntime();
  return <HumanSimulationPage client={client} context={context} />;
}

export function AgentKernelRoute() {
  const { client, context } = useShellRuntime();
  return <AgentKernelPage client={client} context={context} />;
}

export function WorkbenchRoute() {
  const { client, context } = useShellRuntime();
  return <WorkbenchPage client={client} context={context} />;
}

export function FindingOperationsRoute() {
  const { client, context } = useShellRuntime();
  return <FindingOperationsPage client={client} context={context} />;
}

function EngagementData({ children }: {
  readonly children: (engagements: EngagementRows) => ReactNode;
}) {
  const { client } = useShellRuntime();
  const [state, setState] = useState<RouteDataState>({ kind: "loading" });
  const load = useCallback(async () => {
    setState({ kind: "loading" });
    try {
      setState({ kind: "ready", engagements: await client.listEngagements() });
    } catch (error) {
      setState({
        kind: "error",
        error: error instanceof ConsoleApiError
          ? error
          : new ConsoleApiError("api_unavailable", "Route data unavailable", 0, null),
      });
    }
  }, [client]);

  useEffect(() => {
    let active = true;
    void client.listEngagements().then((engagements) => {
      if (active) setState({ kind: "ready", engagements });
    }).catch((error: unknown) => {
      if (!active) return;
      setState({
        kind: "error",
        error: error instanceof ConsoleApiError
          ? error
          : new ConsoleApiError("api_unavailable", "Route data unavailable", 0, null),
      });
    });
    return () => { active = false; };
  }, [client]);

  if (state.kind === "loading") return <section className="route-state" role="status">Loading route data</section>;
  if (state.kind === "error") {
    const denied = isRouteAccessDenied(state.error);
    return <section aria-label={denied ? "Route access denied" : "Route data unavailable"} className="route-state route-state--error" role="alert">
      <strong>{denied ? "Access denied" : "Route data unavailable"}</strong>
      <p>{denied
        ? "The authenticated session is not permitted to load this route. Choose a permitted destination or reauthenticate after access changes."
        : "The page data could not be loaded. Global safety context remains authoritative."}</p>
      {state.error.correlationId && <p className="correlation">Correlation: {state.error.correlationId}</p>}
      <button type="button" onClick={() => { void load(); }}>Retry route data</button>
    </section>;
  }
  return children(state.engagements);
}

function isRouteAccessDenied(error: ConsoleApiError): boolean {
  return error.status === 401
    || error.status === 403
    || error.code.includes("permission")
    || error.code.includes("tenant")
    || error.code.includes("csrf");
}

function Overview({ engagements }: { readonly engagements: EngagementRows }) {
  const { navigate } = useShellRuntime();
  return (
    <div className="overview-layout">
      <section className="work-panel" aria-labelledby="engagements-title">
        <div className="section-heading">
          <div><span className="eyebrow">Active context</span><h2 id="engagements-title">Engagements</h2></div>
          <RouteLink className="button-link" onNavigate={navigate} path="/engagements">
            Manage engagements
          </RouteLink>
        </div>
        {engagements.length === 0 ? (
          <div className="empty-state">
            <span className="empty-state__index" aria-hidden="true">01</span>
            <div><h3>No engagements yet</h3><p>Create a bounded engagement before defining targets or rules of engagement.</p></div>
          </div>
        ) : <ul className="engagement-list">{engagements.map((item) => <li key={item.engagement_id}><strong>{item.name}</strong><span>{item.engagement_id}</span></li>)}</ul>}
      </section>
      <aside className="decision-panel" aria-labelledby="decision-title">
        <span className="eyebrow">Next safe decision</span>
        <h2 id="decision-title">Establish engagement scope</h2>
        <p>Targets, ROE approval, and policy context are required before any future execution workflow.</p>
        <dl><dt>Runtime</dt><dd>Disabled</dd><dt>Evidence</dt><dd>Not started</dd><dt>Policy</dt><dd>Required</dd></dl>
      </aside>
      <section className="preview-strip" aria-labelledby="preview-title">
        <div><span className="eyebrow">Component preview</span><h2 id="preview-title">Operational states</h2></div>
        <LifecycleState state="approval" />
        <LifecycleState state="denied" />
      </section>
    </div>
  );
}
