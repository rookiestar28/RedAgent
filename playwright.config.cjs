const { defineConfig } = require("@playwright/test");

const requestedPort = process.env.REDAGENT_E2E_PORT ?? "4173";
if (!/^\d{4,5}$/.test(requestedPort) || Number(requestedPort) < 1024 || Number(requestedPort) > 65535) {
  throw new Error("REDAGENT_E2E_PORT must be an unprivileged numeric port");
}
// CRITICAL: Windows can reserve 4173; the server and browser must share the
// validated loopback override, never an arbitrary URL or a silent port fallback.
const e2ePort = Number(requestedPort);
const e2eUrl = `http://127.0.0.1:${e2ePort}`;

module.exports = defineConfig({
  testDir: "tests/e2e",
  timeout: 30_000,
  use: {
    baseURL: e2eUrl,
    trace: "retain-on-failure",
    screenshot: "only-on-failure"
  },
  webServer: {
    command: `npm run dev -- --port ${e2ePort}`,
    url: e2eUrl,
    reuseExistingServer: !process.env.CI,
    timeout: 30_000
  }
});
