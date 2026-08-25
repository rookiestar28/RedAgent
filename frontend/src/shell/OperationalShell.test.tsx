import { fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { App } from "../App";
import { APPLICATION_ROUTES } from "./routeRegistry";


describe("compat_127 operational shell", () => {
  afterEach(() => vi.unstubAllEnvs());

  it("renders a real 404 rather than silently falling back to Overview", async () => {
    window.history.replaceState({}, "", "/missing-route");
    installContextFetch();

    render(<App />);

    expect(await screen.findByRole("heading", { name: "Page not found" })).toBeVisible();
    expect(screen.queryByRole("heading", { name: "No engagements yet" })).toBeNull();
  });

  it("keeps module navigation out of the utility header and exposes one primary landmark", async () => {
    installContextFetch();
    render(<App />);

    expect(await screen.findByText("tenant-r127")).toBeVisible();
    const banner = screen.getByRole("banner");
    expect(within(banner).queryByRole("navigation")).toBeNull();
    expect(within(banner).queryByRole("link", { name: "Engagements" })).toBeNull();
    expect(screen.getAllByRole("navigation", { name: "Primary navigation" })).toHaveLength(1);
  });

  it("keeps authoritative shell context visible when route data fails", async () => {
    window.history.replaceState({}, "", "/");
    installContextFetch({ engagementsFail: true });
    render(<App />);

    expect(await screen.findByText("tenant-r127")).toBeVisible();
    expect(screen.getByText("Synthetic local")).toBeVisible();
    expect(await screen.findByRole("alert", { name: "Route data unavailable" })).toBeVisible();
    expect(screen.getByRole("navigation", { name: "Primary navigation" })).toBeVisible();
  });

  it("uses client-side route navigation and focuses the destination heading", async () => {
    const user = userEvent.setup();
    installContextFetch();
    render(<App />);

    const link = await screen.findByRole("link", { name: "Engagements" });
    await user.click(link);

    const heading = await screen.findByRole("heading", { level: 1, name: "Engagements" });
    await waitFor(() => expect(heading).toHaveFocus());
    expect(window.location.pathname).toBe("/engagements");
    expect(link).toHaveAttribute("aria-current", "page");
  });

  it("implements modal drawer Escape and focus restoration", async () => {
    const user = userEvent.setup();
    installContextFetch();
    render(<App />);

    const trigger = await screen.findByRole("button", { name: "Open navigation" });
    trigger.focus();
    await user.click(trigger);
    const drawer = screen.getByRole("dialog", { name: "Primary navigation" });
    expect(drawer).toBeVisible();
    await waitFor(() => expect(within(drawer).getByRole("button", { name: "Close navigation" })).toHaveFocus());

    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Primary navigation" })).toBeNull());
    expect(trigger).toHaveFocus();
  });

  it("filters command search by permissions and supports keyboard entry", async () => {
    const user = userEvent.setup();
    installContextFetch({ permissions: ["campaign:read"] });
    render(<App />);

    const search = await screen.findByRole("combobox", { name: "Find destination" });
    await user.type(search, "campaign");
    const results = screen.getByRole("listbox");
    expect(within(results).getAllByRole("option")).toHaveLength(3);
    fireEvent.keyDown(search, { key: "ArrowDown" });
    expect(search).toHaveAttribute("aria-activedescendant", "route-command-option-campaigns");
    fireEvent.keyDown(search, { key: "ArrowDown" });
    expect(search).toHaveAttribute("aria-activedescendant", "route-command-option-campaign-attention");
    fireEvent.keyDown(search, { key: "ArrowUp" });
    expect(search).toHaveAttribute("aria-activedescendant", "route-command-option-campaigns");
    fireEvent.keyDown(search, { key: "Enter" });
    expect(await screen.findByRole("heading", { level: 1, name: "Campaigns" })).toHaveFocus();

    await user.type(search, "no such destination");
    expect(screen.getByRole("status", { name: "Command search results" })).toHaveTextContent("No permitted destinations found");
    fireEvent.keyDown(search, { key: "Escape" });
    expect(screen.queryByRole("listbox")).toBeNull();
    expect(search).toHaveFocus();
  });

  it("uses one feature-aware permission filter for desktop and drawer navigation", async () => {
    const user = userEvent.setup();
    installContextFetch({ permissions: ["campaign:read"] });
    render(<App />);

    await screen.findByText("tenant-r127");
    const primary = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(within(primary).getByRole("link", { name: "Campaigns" })).toBeVisible();
    expect(within(primary).queryByRole("link", { name: "Jobs" })).toBeNull();
    expect(within(primary).queryByRole("link", { name: "Engagements" })).toBeNull();

    await user.click(screen.getByRole("button", { name: "Open navigation" }));
    const drawer = screen.getByRole("dialog", { name: "Primary navigation" });
    expect(within(drawer).getByRole("link", { name: "Campaigns" })).toBeVisible();
    expect(within(drawer).queryByRole("link", { name: "Jobs" })).toBeNull();
  });

  it("hides normal campaign creation from navigation and search when rollback is active", async () => {
    vi.stubEnv("VITE_R124_CAMPAIGN_CORE_ENABLED", "false");
    const user = userEvent.setup();
    installContextFetch({ permissions: ["campaign:read"] });
    render(<App />);

    await screen.findByText("tenant-r127");
    const primary = screen.getByRole("navigation", { name: "Primary navigation" });
    expect(within(primary).queryByRole("link", { name: "New campaign" })).toBeNull();
    const search = screen.getByRole("combobox", { name: "Find destination" });
    await user.type(search, "campaign");
    expect(within(screen.getByRole("listbox")).queryByRole("link", { name: "New campaign" })).toBeNull();
  });

  it("responds to browser popstate without a reload", async () => {
    installContextFetch();
    render(<App />);
    await screen.findByText("tenant-r127");

    window.history.replaceState({}, "", "/jobs");
    window.dispatchEvent(new PopStateEvent("popstate"));

    expect(await screen.findByRole("heading", { level: 1, name: "Jobs" })).toHaveFocus();
  });

  it("keeps a persistent non-authorizing stop and revoke entry point", async () => {
    const user = userEvent.setup();
    installContextFetch();
    render(<App />);

    const trigger = await screen.findByRole("button", { name: "Stop & revoke" });
    await user.click(trigger);
    const dialog = screen.getByRole("dialog", { name: "Stop and revoke controls" });
    expect(within(dialog).getByText(/does not dispatch or grant authority/i)).toBeVisible();
    const cancel = within(dialog).getByRole("button", { name: "Cancel" });
    const governedControls = within(dialog).getByRole("link", { name: "Open governed job controls" });
    await waitFor(() => expect(cancel).toHaveFocus());
    await user.tab({ shift: true });
    expect(governedControls).toHaveFocus();
    await user.tab();
    expect(cancel).toHaveFocus();
    fireEvent.keyDown(document, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Stop and revoke controls" })).toBeNull());
    expect(trigger).toHaveFocus();
  });

  it("renders route authorization failures as an explicit denial", async () => {
    window.history.replaceState({}, "", "/jobs");
    installContextFetch({ engagementsStatus: 403 });
    render(<App />);

    const denied = await screen.findByRole("alert", { name: "Route access denied" });
    expect(denied).toHaveTextContent("Access denied");
    expect(denied).toHaveTextContent(/authenticated session is not permitted/i);
    expect(screen.getByText("Synthetic local")).toBeVisible();
  });

  it("recreates a rejected lazy route import before retrying", async () => {
    window.history.replaceState({}, "", "/jobs");
    installContextFetch();
    const jobsRoute = APPLICATION_ROUTES.find(({ path }) => path === "/jobs");
    expect(jobsRoute).toBeDefined();
    if (!jobsRoute) return;
    vi.spyOn(console, "error").mockImplementation(() => undefined);
    vi.spyOn(jobsRoute, "load")
      .mockRejectedValueOnce(new Error("chunk unavailable"))
      .mockResolvedValueOnce({ default: () => <section>Recovered route adapter</section> });
    const user = userEvent.setup();
    render(<App />);

    expect(await screen.findByRole("alert", { name: "Route rendering failed" })).toBeVisible();
    await user.click(screen.getByRole("button", { name: "Retry route" }));
    expect(await screen.findByText("Recovered route adapter")).toBeVisible();
  });

  it("shows unknown server context as unsafe rather than inventing a safe label", async () => {
    installContextFetch({ shell: {
      schema_version: "1",
      environment: "unknown",
      safety_profile: "unknown",
      status: "unavailable",
    } });
    render(<App />);

    expect(await screen.findByRole("status", { name: "Safety context unavailable" })).toBeVisible();
    expect(screen.queryByText("Synthetic local")).toBeNull();
  });
});


function installContextFetch(options: {
  engagementsFail?: boolean;
  engagementsStatus?: number;
  permissions?: string[];
  shell?: {
    schema_version: "1";
    environment: "local" | "production" | "unknown";
    safety_profile: "synthetic-local" | "local-conformance" | "production" | "unknown";
    status: "ready" | "unknown" | "unavailable";
  };
} = {}) {
  const shell = options.shell ?? {
    schema_version: "1" as const,
    environment: "local" as const,
    safety_profile: "synthetic-local" as const,
    status: "ready" as const,
  };
  vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockImplementation((input) => {
    const path = input instanceof Request ? input.url : String(input);
    if (path.includes("/api/v1/context")) {
      return Promise.resolve(json({ data: {
        subject: "operator-r127",
        tenant_id: "tenant-r127",
        permissions: options.permissions ?? ["*", "campaign:read", "engagement:read", "engagement:create"],
        roles: ["operator"],
        operator_shell: shell,
      } }));
    }
    if (path.includes("/api/v1/engagements")) {
      if (options.engagementsFail) return Promise.reject(new TypeError("route data failed"));
      if (options.engagementsStatus) {
        return Promise.resolve(json({ error: {
          code: "permission_denied",
          message: "The route data is not permitted for this operator.",
        } }, options.engagementsStatus));
      }
      return Promise.resolve(json({ data: [], page: { limit: 50, offset: 0, returned: 0 } }));
    }
    if (path.includes("/api/v1/jobs") || path.includes("/api/v1/containment-controls")) {
      return Promise.resolve(json({ data: [], page: { limit: 50, offset: 0, returned: 0 } }));
    }
    if (path.includes("/api/v1/quotas/status")) {
      return Promise.resolve(json({ data: [] }));
    }
    return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
  }));
}


function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
