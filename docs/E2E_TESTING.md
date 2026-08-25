# Frontend E2E Testing

Run Playwright only after confirming Node.js 18 or newer and installing the locked frontend dependencies:

```powershell
node -v
npm install
npx playwright install chromium
npm test
```

Use the repository root as the working directory. E2E must verify interaction outcomes, policy denials, evidence and audit visibility, and useful failure feedback. Target-facing actions must remain blocked when authorization, scope, or policy is absent.

On WSL, use a repository-local temporary directory and provide a `python` shim if the environment exposes only `python3`. Do not mix Windows and WSL dependency folders.
