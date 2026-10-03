"""The acceptance browser and server share one bounded loopback endpoint."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from redagent_platform.validation import Stage, StageRunner


ROOT = Path(__file__).resolve().parents[2]


def _config(port, *, packages_installed=True):
    environment = {**os.environ}
    if port is None:
        environment.pop("REDAGENT_E2E_PORT", None)
    else:
        environment["REDAGENT_E2E_PORT"] = port
    script = "process.stdout.write(JSON.stringify(require('./playwright.config.cjs')))"
    if not packages_installed:
        # Use the real Node resolver with no package search paths, even on a warmed checkout.
        script = (
            "const fs = require('node:fs'); const vm = require('node:vm');"
            "const module = {exports: {}};"
            "const isolatedRequire = name => require(require.resolve(name, {paths: []}));"
            "vm.runInNewContext(fs.readFileSync('playwright.config.cjs', 'utf8'),"
            "{module, process, require: isolatedRequire}, {filename: 'playwright.config.cjs'});"
            "process.stdout.write(JSON.stringify(module.exports));"
        )
    return subprocess.run(
        ["node", "-e", script],
        cwd=ROOT,
        env=environment,
        capture_output=True, text=True, check=False,
    )


def test_valid_port_override_binds_browser_and_owned_server():
    result = _config("4310")
    assert result.returncode == 0, result.stderr
    config = json.loads(result.stdout)
    assert config["use"]["baseURL"] == "http://127.0.0.1:4310"
    assert config["webServer"]["url"] == config["use"]["baseURL"]
    assert config["webServer"]["command"] == "npm run dev -- --port 4310"


@pytest.mark.parametrize("port", ("80", "65536", "abc", "4310 --host 0.0.0.0", "https://outside.invalid"))
@pytest.mark.parametrize("packages_installed", (True, False))
def test_invalid_port_denies_before_server_spawn(port, packages_installed):
    result = _config(port, packages_installed=packages_installed)
    assert result.returncode != 0
    assert "REDAGENT_E2E_PORT must be an unprivileged numeric port" in result.stderr


@pytest.mark.parametrize("port,expected", ((None, 4173), ("4310", 4310), ("1024", 1024), ("65535", 65535)))
def test_configuration_contract_loads_before_frontend_dependencies(port, expected):
    cold = _config(port, packages_installed=False)
    normal = _config(port)
    assert cold.returncode == 0, cold.stderr
    assert normal.returncode == 0, normal.stderr
    config = json.loads(cold.stdout)
    assert config == json.loads(normal.stdout)
    assert config["use"]["baseURL"] == f"http://127.0.0.1:{expected}"
    assert config["webServer"]["url"] == config["use"]["baseURL"]
    assert config["webServer"]["command"] == f"npm run dev -- --port {expected}"
    assert config["webServer"]["reuseExistingServer"] == (not bool(os.environ.get("CI")))


def test_stage_contract_binds_port_override_and_ignores_external_cache_override():
    stage = Stage("frontend-e2e", ("npm", "test"), ("G2",), 60)
    first = StageRunner(ROOT, {"REDAGENT_E2E_PORT": "4310", "npm_config_cache": "outside-cache"})
    second = StageRunner(ROOT, {"REDAGENT_E2E_PORT": "4311"})
    assert first._environment["npm_config_cache"] == str(ROOT / ".tmp" / "npm-cache")
    assert first._environment["REDAGENT_E2E_PORT"] == "4310"
    assert first.execution_contract(stage, source_oid="a" * 40)["environment_sha256"] != second.execution_contract(stage, source_oid="a" * 40)["environment_sha256"]
