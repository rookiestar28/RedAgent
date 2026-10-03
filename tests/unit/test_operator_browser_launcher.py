"""Exercise the actual browser fixture hooks before frontend packages are installed."""

import json
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
HARNESS = r"""
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { EventEmitter, once } = require('node:events');
const platform = process.argv[1];
const scenario = process.argv[2];
const root = path.resolve('fixture-project');
const hooks = {};
const calls = [];
let reads = 0;
let stops = 0;
let child;
const test = () => {};
test.describe = { configure() {} };
test.beforeAll = fn => { hooks.start = fn; };
test.afterAll = fn => { hooks.stop = fn; };
const expect = value => ({
  toBe: expected => assert.equal(value, expected),
  toBeTruthy: () => assert.ok(value),
  toPass: async () => { await value(); },
});
const spawn = (executable, args, options) => {
  calls.push({ executable, args, options });
  child = new EventEmitter();
  child.stderr = new EventEmitter();
  child.exitCode = null;
  child.pid = scenario === 'spawn-error' ? undefined : 123;
  process.nextTick(() => {
    if (scenario === 'spawn-error') {
      child.emit('error', Object.assign(new Error('fixture spawn ENOENT'), { code: 'ENOENT' }));
    } else {
      child.emit('spawn');
    }
  });
  return child;
};
const request = {
  get: async url => {
    reads++;
    assert.equal(url, 'http://127.0.0.1:4311/__test_fixture__');
    return { ok: () => true, json: async () => ({ scope: 'synthetic-plan-only-native-postgres' }) };
  },
  post: async url => {
    stops++;
    assert.equal(url, 'http://127.0.0.1:4311/__test_fixture__/stop');
    const exit = () => { child.exitCode = 0; child.emit('exit', 0); };
    if (scenario === 'fast-exit') exit(); // Can finish before the HTTP promise resolves.
    else setImmediate(exit);
  },
};
const source = fs.readFileSync('tests/e2e/autonomous-campaign-operator.spec.js', 'utf8')
  .replace(/^import .*;\r?\n/gm, '');
vm.runInNewContext(source, {
  test, expect, spawn, once, path,
  existsSync: () => scenario !== 'missing',
  process: { platform, cwd: () => root, env: { TEST_ONLY: 'retained' } },
}, { filename: 'autonomous-campaign-operator.spec.js' });
(async () => {
  let error = null;
  try { await hooks.start({ request }); } catch (caught) { error = caught.message; }
  // Bound the probe: a lost exit event must fail, never hang the backend suite.
  let timer;
  try {
    await Promise.race([
      hooks.stop({ request }),
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error('lost child exit')), 100); }),
    ]);
  } finally { clearTimeout(timer); }
  process.stdout.write(JSON.stringify({ root, calls, reads, stops, error }));
})().catch(error => { process.stderr.write(error.stack); process.exitCode = 1; });
"""


def _hooks(platform, scenario="success"):
    result = subprocess.run(
        ["node", "-e", HARNESS, platform, scenario],
        cwd=ROOT, capture_output=True, text=True, check=False, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    return json.loads(result.stdout)


@pytest.mark.parametrize("platform,layout", (
    ("win32", (".venv", "Scripts", "python.exe")),
    ("linux", (".venv-wsl", "bin", "python")),
    ("darwin", (".venv-wsl", "bin", "python")),
))
def test_fixture_uses_gate_interpreter_and_stops_child(platform, layout):
    result = _hooks(platform)
    call, = result["calls"]
    assert call["executable"] == str(Path(result["root"]).joinpath(*layout))
    assert call["args"] == ["-m", "tests.integration.operator_browser_server"]
    assert call["options"]["cwd"] == result["root"]
    assert call["options"]["shell"] is False
    assert call["options"]["env"] == {
        "TEST_ONLY": "retained", "REDAGENT_OPERATOR_BROWSER_TEST": "plan-only-v1",
    }
    assert result["error"] is None
    assert (result["reads"], result["stops"]) == (1, 1)


@pytest.mark.parametrize("platform", ("win32", "linux"))
def test_missing_local_interpreter_denies_before_spawn_or_http(platform):
    result = _hooks(platform, "missing")
    assert "project_local_python_missing" in result["error"]
    assert result["calls"] == []
    assert (result["reads"], result["stops"]) == (0, 0)


def test_spawn_error_rejects_setup_without_readiness_or_stop():
    result = _hooks("linux", "spawn-error")
    assert result["error"] == "fixture spawn ENOENT"
    assert len(result["calls"]) == 1
    assert (result["reads"], result["stops"]) == (0, 0)


def test_stop_does_not_lose_exit_before_http_response():
    result = _hooks("linux", "fast-exit")
    assert result["error"] is None
    assert (result["reads"], result["stops"]) == (1, 1)
