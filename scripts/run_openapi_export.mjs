import { existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";

const root = process.cwd();
const candidates = process.platform === "win32"
  ? [path.join(root, ".venv", "Scripts", "python.exe")]
  : [path.join(root, ".venv-wsl", "bin", "python"), path.join(root, ".venv", "bin", "python")];
const python = candidates.find((candidate) => existsSync(candidate));

if (!python) {
  process.stderr.write("project_local_python_missing\n");
  process.exit(2);
}

const result = spawnSync(python, [path.join(root, "scripts", "export_openapi.py"), ...process.argv.slice(2)], {
  cwd: root,
  stdio: "inherit",
  shell: false,
});
process.exit(result.status ?? 1);
