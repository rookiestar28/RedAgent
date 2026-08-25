import {
  Component,
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useRef,
  useState,
  type KeyboardEvent,
  type ReactNode,
} from "react";

import { ConsoleApiError, createConsoleClient } from "../lib/apiClient";
import {
  APPLICATION_ROUTES,
  commandRoutesForPermissions,
  orientationRoutesForPermissions,
  ROUTE_GROUP_LABELS,
  type ApplicationRoute,
  type RouteGroup,
} from "./routeRegistry";
import { ShellRuntimeContext, type ConsoleContext } from "./shellRuntime";
import { RouteLink } from "./RouteLink";
import { useBoundedRouter } from "./useBoundedRouter";


type ContextState =
  | { readonly kind: "loading" }
  | { readonly kind: "error"; readonly error: ConsoleApiError }
  | { readonly kind: "ready"; readonly context: ConsoleContext };

const GROUPS = Object.keys(ROUTE_GROUP_LABELS) as RouteGroup[];

export function OperationalShell() {
  const client = useMemo(
    () => createConsoleClient({ fetch: (input, init) => globalThis.fetch(input, init) }),
    [],
  );
  const [contextState, setContextState] = useState<ContextState>({ kind: "loading" });
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [safetyOpen, setSafetyOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const drawerTrigger = useRef<HTMLButtonElement>(null);
  const drawerPanel = useRef<HTMLElement>(null);
  const safetyTrigger = useRef<HTMLButtonElement>(null);
  const safetyCancel = useRef<HTMLButtonElement>(null);
  const routeHeading = useRef<HTMLHeadingElement>(null);
  const shellFrame = useRef<HTMLDivElement>(null);
  const [routeLoadAttempt, setRouteLoadAttempt] = useState(0);
  const { navigate, path, route } = useBoundedRouter();
  const campaignCreateEnabled = import.meta.env.VITE_R124_CAMPAIGN_CORE_ENABLED !== "false";

  const loadContext = useCallback(async () => {
    setContextState({ kind: "loading" });
    try {
      const context = await client.getContext() as ConsoleContext;
      setContextState({ kind: "ready", context });
    } catch (error) {
      setContextState({
        kind: "error",
        error: error instanceof ConsoleApiError
          ? error
          : new ConsoleApiError("api_unavailable", "Control plane unavailable", 0, null),
      });
    }
  }, [client]);

  useEffect(() => {
    let active = true;
    void client.getContext().then((context) => {
      if (active) setContextState({ kind: "ready", context });
    }).catch((error: unknown) => {
      if (!active) return;
      setContextState({
        kind: "error",
        error: error instanceof ConsoleApiError
          ? error
          : new ConsoleApiError("api_unavailable", "Control plane unavailable", 0, null),
      });
    });
    return () => { active = false; };
  }, [client]);
  useEffect(() => {
    document.title = `${route?.title ?? "Page not found"} · RedAgent`;
  }, [route]);
  useEffect(() => {
    if (shellFrame.current) shellFrame.current.inert = drawerOpen || safetyOpen;
  }, [drawerOpen, safetyOpen]);
  useEffect(() => {
    routeHeading.current?.focus();
  }, [path]);
  useEffect(() => {
    if (!drawerOpen) return;
    queueMicrotask(() => drawerPanel.current?.querySelector<HTMLElement>("button, a[href]")?.focus());
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setDrawerOpen(false);
        queueMicrotask(() => drawerTrigger.current?.focus());
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [drawerOpen]);
  useEffect(() => {
    if (!safetyOpen) return;
    queueMicrotask(() => safetyCancel.current?.focus());
    const onKeyDown = (event: globalThis.KeyboardEvent) => {
      if (event.key === "Escape") {
        event.preventDefault();
        setSafetyOpen(false);
        queueMicrotask(() => safetyTrigger.current?.focus());
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [safetyOpen]);

  const context = contextState.kind === "ready" ? contextState.context : null;
  const routeAvailability = { campaignCreateEnabled } as const;
  const permissions = context?.permissions ?? [];
  const searchResults = context === null
    ? []
    : commandRoutesForPermissions(APPLICATION_ROUTES, permissions, searchQuery, 12, routeAvailability);
  const orientationRoutes = orientationRoutesForPermissions(
    APPLICATION_ROUTES,
    permissions,
    routeAvailability,
  );
  const activateRoute = (destination: string) => {
    const activated = navigate(destination);
    if (activated) {
      setDrawerOpen(false);
      setSearchQuery("");
    }
    return activated;
  };
  const routeComponent = useMemo(() => {
    if (route === null) return null;
    const attempt = routeLoadAttempt;
    return lazy(async () => {
      // IMPORTANT: retry must create a new React.lazy promise after a rejected route chunk.
      void attempt;
      return route.load();
    });
  }, [route, routeLoadAttempt]);

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">Skip to main content</a>
      <div ref={shellFrame} className="shell-frame">
        <UtilityHeader
          contextState={contextState}
          drawerTrigger={drawerTrigger}
          onOpenDrawer={() => setDrawerOpen(true)}
          onOpenSafety={() => setSafetyOpen(true)}
          onNavigate={activateRoute}
          query={searchQuery}
          results={searchResults}
          safetyTrigger={safetyTrigger}
          setQuery={setSearchQuery}
        />
        <div className="shell-body">
          {!drawerOpen && (
            <aside className="navigation-rail">
              <PrimaryNavigation currentPath={path} onNavigate={activateRoute} routes={orientationRoutes} />
            </aside>
          )}
          <main id="main-content" className="route-workspace" tabIndex={-1}>
            <RouteHeading headingRef={routeHeading} route={route} />
            {contextState.kind === "loading" && <ShellLoading />}
            {contextState.kind === "error" && (
              <ContextError error={contextState.error} onRetry={loadContext} />
            )}
            {contextState.kind === "ready" && route === null && <NotFound onNavigate={activateRoute} />}
            {contextState.kind === "ready" && route !== null && routeComponent !== null && (
              <ShellRuntimeContext.Provider value={{
                campaignCreateEnabled,
                client,
                context: contextState.context,
                navigate: activateRoute,
                path,
              }}>
                <RouteErrorBoundary
                  key={`${path}:${routeLoadAttempt}`}
                  onRetry={() => setRouteLoadAttempt((attempt) => attempt + 1)}
                >
                  <Suspense fallback={<RouteLoading />}>
                    {(() => {
                      const RouteComponent = routeComponent;
                      return <RouteComponent key={path} />;
                    })()}
                  </Suspense>
                </RouteErrorBoundary>
              </ShellRuntimeContext.Provider>
            )}
          </main>
          <aside className="context-inspector" aria-label="Context inspector">
            <span className="eyebrow">Current boundary</span>
            <strong>{route?.title ?? "Unknown route"}</strong>
            <p>Navigation is orientation only. Server authorization remains authoritative.</p>
          </aside>
        </div>
      </div>
      {drawerOpen && (
        <div className="navigation-drawer-backdrop">
          <section
            ref={drawerPanel}
            aria-label="Primary navigation"
            aria-modal="true"
            className="navigation-drawer"
            onKeyDown={containModalFocus}
            role="dialog"
          >
            <div className="navigation-drawer__header">
              <strong>Navigate</strong>
              <button type="button" onClick={() => {
                setDrawerOpen(false);
                queueMicrotask(() => drawerTrigger.current?.focus());
              }}>Close navigation</button>
            </div>
            <PrimaryNavigation currentPath={path} onNavigate={activateRoute} routes={orientationRoutes} />
          </section>
        </div>
      )}
      {safetyOpen && (
        <div className="navigation-drawer-backdrop">
          <section
            aria-label="Stop and revoke controls"
            aria-modal="true"
            className="safety-dialog"
            onKeyDown={containModalFocus}
            role="dialog"
          >
            <span className="eyebrow">Fail-closed safety control</span>
            <h2>Stop and revoke</h2>
            <p>Select the governed job workspace to inspect current authority, request containment, and verify cleanup. This shell control does not dispatch or grant authority.</p>
            <div className="dialog-actions">
              <button ref={safetyCancel} type="button" onClick={() => {
                setSafetyOpen(false);
                queueMicrotask(() => safetyTrigger.current?.focus());
              }}>Cancel</button>
              <RouteLink className="button-link danger-action" onNavigate={(destination) => {
                setSafetyOpen(false);
                return activateRoute(destination);
              }} path="/jobs">Open governed job controls</RouteLink>
            </div>
          </section>
        </div>
      )}
    </div>
  );
}

function UtilityHeader({
  contextState,
  drawerTrigger,
  onNavigate,
  onOpenDrawer,
  onOpenSafety,
  query,
  results,
  safetyTrigger,
  setQuery,
}: {
  readonly contextState: ContextState;
  readonly drawerTrigger: React.RefObject<HTMLButtonElement | null>;
  readonly onNavigate: (path: string) => boolean;
  readonly onOpenDrawer: () => void;
  readonly onOpenSafety: () => void;
  readonly query: string;
  readonly results: readonly ApplicationRoute[];
  readonly safetyTrigger: React.RefObject<HTMLButtonElement | null>;
  readonly setQuery: (value: string) => void;
}) {
  const context = contextState.kind === "ready" ? contextState.context : null;
  return (
    <header className="utility-header">
      <button ref={drawerTrigger} className="drawer-trigger" type="button" onClick={onOpenDrawer}>
        Open navigation
      </button>
      <RouteLink className="brand" current={false} label="RedAgent operator console home" onNavigate={onNavigate} path="/">
        <span className="brand-mark" aria-hidden="true">RA</span>
        <span><strong>RedAgent</strong><small>Operator console</small></span>
      </RouteLink>
      <div className="safety-boundary">Execution remains disabled until policy-approved</div>
      <CommandSearch
        available={context !== null}
        onNavigate={onNavigate}
        query={query}
        results={results}
        setQuery={setQuery}
      />
      <SafetyContext context={context} loading={contextState.kind === "loading"} />
      <button type="button" className="notification-control" aria-label="Notifications">0</button>
      <button ref={safetyTrigger} type="button" className="danger-action" onClick={onOpenSafety}>Stop &amp; revoke</button>
      {context !== null && (
        <div className="identity-context" aria-label="Current identity">
          <span>{context.tenant_id}</span>
          <strong>{titleCase(context.roles[0] ?? "authenticated")}</strong>
        </div>
      )}
    </header>
  );
}

function SafetyContext({ context, loading }: { readonly context: ConsoleContext | null; readonly loading: boolean }) {
  const shell = context?.operator_shell;
  if (loading) return <span className="environment-chip" role="status">Context loading</span>;
  if (shell?.status !== "ready") {
    return (
      <span aria-label="Safety context unavailable" className="environment-chip environment-chip--unsafe" role="status">
        Safety context unavailable
      </span>
    );
  }
  const label = shell.environment === "local" && shell.safety_profile === "synthetic-local"
    ? "Synthetic local"
    : shell.environment === "local" && shell.safety_profile === "local-conformance"
      ? "Local conformance"
      : shell.environment === "production" && shell.safety_profile === "production"
        ? "Production restricted"
        : null;
  if (label === null) {
    return <span aria-label="Safety context unavailable" className="environment-chip environment-chip--unsafe" role="status">Safety context unavailable</span>;
  }
  return <span aria-label="Authoritative safety context" className="environment-chip" role="status">{label}</span>;
}

function CommandSearch({
  available,
  onNavigate,
  query,
  results,
  setQuery,
}: {
  readonly available: boolean;
  readonly onNavigate: (path: string) => boolean;
  readonly query: string;
  readonly results: readonly ApplicationRoute[];
  readonly setQuery: (value: string) => void;
}) {
  const [activeIndex, setActiveIndex] = useState(-1);
  const input = useRef<HTMLInputElement>(null);
  const popupOpen = available && query.length > 0;
  const normalizedActiveIndex = popupOpen && activeIndex >= 0 && activeIndex < results.length
    ? activeIndex
    : -1;
  const activeResult = normalizedActiveIndex >= 0 ? results[normalizedActiveIndex] : undefined;

  return (
    <div className="command-search">
      <label htmlFor="route-command-search">Find destination</label>
      <input
        id="route-command-search"
        ref={input}
        aria-activedescendant={activeResult ? `route-command-option-${activeResult.id}` : undefined}
        aria-autocomplete="list"
        aria-controls="route-command-results"
        aria-expanded={popupOpen}
        autoComplete="off"
        disabled={!available}
        onChange={(event) => {
          setActiveIndex(-1);
          setQuery(event.currentTarget.value);
        }}
        onKeyDown={(event) => {
          if (event.key === "Escape") {
            event.preventDefault();
            setActiveIndex(-1);
            setQuery("");
            input.current?.focus();
          } else if (event.key === "ArrowDown" && results.length > 0) {
            event.preventDefault();
            setActiveIndex((current) => current < 0 ? 0 : (current + 1) % results.length);
          } else if (event.key === "ArrowUp" && results.length > 0) {
            event.preventDefault();
            setActiveIndex((current) => current < 0 ? results.length - 1 : (current - 1 + results.length) % results.length);
          } else if (event.key === "Enter" && activeResult !== undefined) {
            event.preventDefault();
            if (onNavigate(activeResult.path)) {
              setActiveIndex(-1);
              setQuery("");
            }
          }
        }}
        placeholder={available ? "Search destinations" : "Search unavailable"}
        role="combobox"
        value={query}
      />
      <span aria-label="Command search results" className="visually-hidden" role="status" aria-live="polite">
        {!available
          ? "Command search unavailable"
          : !query
            ? "Type to search permitted destinations"
            : results.length === 0
              ? "No permitted destinations found"
              : `${results.length} permitted destinations found`}
      </span>
      {popupOpen && (
        <ul id="route-command-results" className="command-results" role="listbox">
          {results.length === 0 && <li className="command-empty" role="option" aria-disabled="true">No destinations found</li>}
          {results.map((item, index) => (
            <li
              id={`route-command-option-${item.id}`}
              aria-selected={index === normalizedActiveIndex}
              key={item.id}
              role="option"
            >
              <RouteLink onNavigate={onNavigate} path={item.path}>{item.title}</RouteLink>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

function PrimaryNavigation({ currentPath, onNavigate, routes: visibleRoutes }: {
  readonly currentPath: string;
  readonly onNavigate: (path: string) => boolean;
  readonly routes: readonly ApplicationRoute[];
}) {
  return (
    <nav className="primary-navigation" aria-label="Primary navigation">
      {GROUPS.map((group) => {
        const routes = visibleRoutes.filter((item) => item.group === group);
        if (routes.length === 0) return null;
        return (
          <section key={group} className="navigation-group" aria-labelledby={`nav-group-${group}`}>
            <h2 id={`nav-group-${group}`}>{ROUTE_GROUP_LABELS[group]}</h2>
            <ul>
              {routes.map((item) => (
                <li key={item.id}>
                  <RouteLink current={currentPath === item.path} onNavigate={onNavigate} path={item.path}>
                    <span className="navigation-initial" aria-hidden="true">{item.navigationLabel.slice(0, 2)}</span>
                    <span className="navigation-label">{item.navigationLabel}</span>
                  </RouteLink>
                </li>
              ))}
            </ul>
          </section>
        );
      })}
    </nav>
  );
}

function RouteHeading({ headingRef, route }: {
  readonly headingRef: React.RefObject<HTMLHeadingElement | null>;
  readonly route: ApplicationRoute | null;
}) {
  const breadcrumb = route?.breadcrumb ?? ["Unknown route"];
  return (
    <div className="route-heading">
      <nav aria-label="Breadcrumb">
        <ol>{breadcrumb.map((item, index) => <li key={`${index}:${item}`}>{item}</li>)}</ol>
      </nav>
      <h1 ref={headingRef} tabIndex={-1}>{route?.title ?? "Page not found"}</h1>
    </div>
  );
}

function NotFound({ onNavigate }: { readonly onNavigate: (path: string) => boolean }) {
  return (
    <section className="route-state route-state--error">
      <p>The requested route is not part of this operator console.</p>
      <RouteLink onNavigate={onNavigate} path="/">Return to Overview</RouteLink>
    </section>
  );
}

function ShellLoading() {
  return <section className="route-state" role="status"><strong>Loading authenticated context</strong></section>;
}

function RouteLoading() {
  return <section className="route-state" role="status"><strong>Loading route</strong></section>;
}

function ContextError({ error, onRetry }: { readonly error: ConsoleApiError; readonly onRetry: () => Promise<void> }) {
  const needsSignIn = error.status === 401 || error.code === "production_identity_not_configured";
  return (
    <section className="route-state route-state--error" role="alert">
      <strong>{needsSignIn ? "Authentication required" : "Control plane unavailable"}</strong>
      <p>{error.message}</p>
      {error.status > 0 && <p>Request failed with status {error.status}.</p>}
      {error.correlationId && <p className="correlation">Correlation: {error.correlationId}</p>}
      {needsSignIn && <TenantSignIn />}
      <button type="button" onClick={() => { void onRetry(); }}>Retry</button>
    </section>
  );
}

class RouteErrorBoundary extends Component<{
  readonly children: ReactNode;
  readonly onRetry: () => void;
}, { readonly failed: boolean }> {
  state = { failed: false };

  static getDerivedStateFromError() {
    return { failed: true };
  }

  componentDidCatch() {
    // IMPORTANT: route failures stay inside the shell; no error detail or authority data is exposed.
  }

  render() {
    if (this.state.failed) {
      return <section aria-label="Route rendering failed" className="route-state route-state--error" role="alert">
        <strong>Route rendering failed</strong>
        <p>The route could not be displayed. Global safety context remains available.</p>
        <button type="button" onClick={this.props.onRetry}>Retry route</button>
      </section>;
    }
    return this.props.children;
  }
}

function TenantSignIn() {
  function submit(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const tenant = new FormData(event.currentTarget).get("tenant_id");
    if (typeof tenant === "string" && /^[A-Za-z0-9._:-]{1,64}$/.test(tenant)) {
      window.location.assign(`/auth/login?tenant_id=${encodeURIComponent(tenant)}`);
    }
  }
  return <form className="tenant-sign-in" onSubmit={submit}>
    <label>Tenant ID<input name="tenant_id" required pattern="[A-Za-z0-9._:-]+" maxLength={64} /></label>
    <button type="submit">Sign in with SSO</button>
  </form>;
}

function containModalFocus(event: KeyboardEvent<HTMLElement>) {
  if (event.key !== "Tab") return;
  const controls = [...event.currentTarget.querySelectorAll<HTMLElement>(
    'a[href], button:not([disabled]), input:not([disabled]), [tabindex]:not([tabindex="-1"])',
  )];
  const first = controls[0];
  const last = controls.at(-1);
  if (!first || !last) return;
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function titleCase(value: string): string {
  return value.replace(/(^|[-_\s])([a-z])/g, (_, prefix: string, letter: string) => `${prefix}${letter.toUpperCase()}`);
}
