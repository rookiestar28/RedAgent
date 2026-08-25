import { render, screen } from "@testing-library/react";
import { describe, expect, it, vi } from "vitest";

import { App } from "./App";


describe("compat_124 campaign route adapter", () => {
  it("mounts the portable create feature on the current shell", async () => {
    window.history.replaceState({}, "", "/campaigns/new");
    vi.stubGlobal("fetch", vi.fn<typeof fetch>().mockImplementation((input, init) => {
      const request = input instanceof Request ? input : new Request(input, init);
      if (request.url.includes("/api/v1/context")) {
        return Promise.resolve(json({ data: {
          subject: "operator-r124",
          tenant_id: "tenant-r124",
          permissions: ["campaign:read", "campaign:create", "engagement:read"],
          roles: ["operator"],
        } }));
      }
      if (request.url.includes("/api/v1/engagements")) {
        return Promise.resolve(json({ data: [], page: { limit: 50, offset: 0, returned: 0 } }));
      }
      if (request.url.includes("/api/v1/campaign-core/options/engagements")) {
        return Promise.resolve(json({
          data: [{
            binding: "opaque-engagement",
            label: "Owned loopback engagement",
            revision: "1",
            freshness: "current",
            eligible: true,
            unavailable_reason: null,
          }],
          page: { limit: 50, next_cursor: null },
        }));
      }
      return Promise.resolve(json({ error: { code: "not_found", message: "Not found" } }, 404));
    }));

    render(<App />);

    expect(await screen.findByRole("heading", { name: "Start an authorized campaign" })).toBeVisible();
    expect(screen.getByRole("link", { name: "New campaign" })).toHaveAttribute("aria-current", "page");
    expect(screen.queryByLabelText(/internal id/i)).toBeNull();
  });
});

function json(body: object, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}
