import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";

describe("App shell", () => {
  it("prioritizes authenticated tenant, engagement context, and the next safe action", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn<typeof fetch>().mockImplementation((input) => {
        const path = input instanceof Request ? input.url : String(input);
        if (path.includes("/api/v1/context")) {
          return Promise.resolve(new Response(
            JSON.stringify({
              data: {
                subject: "operator-1",
                tenant_id: "tenant-1",
                permissions: ["engagement:read", "engagement:create"],
                roles: ["operator"],
              },
            }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ));
        }
        if (path.includes("/api/v1/engagements")) {
          return Promise.resolve(new Response(
            JSON.stringify({ data: [], page: { limit: 50, offset: 0, returned: 0 } }),
            { status: 200, headers: { "Content-Type": "application/json" } },
          ));
        }
        return Promise.resolve(new Response(null, { status: 404 }));
      }),
    );

    render(<App />);

    expect(await screen.findByRole("heading", { level: 1, name: "Overview" })).toBeVisible();
    expect(await screen.findByText("tenant-1")).toBeVisible();
    expect(screen.getByText("Operator")).toBeVisible();
    expect(screen.getByRole("link", { name: "Engagements" })).toBeVisible();
    expect(await screen.findByRole("heading", { name: "No engagements yet" })).toBeVisible();
    expect(screen.getByRole("link", { name: "Manage engagements" })).toBeVisible();
    expect(screen.getByText(/execution remains disabled until policy-approved/i)).toBeVisible();
  });

  it("renders an actionable API-unavailable state", async () => {
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockRejectedValue(new TypeError("connection failed")));
    render(<App />);

    expect(await screen.findByRole("alert")).toHaveTextContent("Control plane unavailable");
    expect(screen.getByRole("button", { name: "Retry" })).toBeEnabled();
  });
});
