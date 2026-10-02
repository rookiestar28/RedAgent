"""The acceptance browser and server share one bounded loopback endpoint."""

import json
import os
from pathlib import Path
import subprocess

import pytest

from redagent_platform.validation import Stage, StageRunner


ROOT = Path(__file__).resolve().parents[2]


def _config(port):
    return subprocess.run(
        ["node", "-e", "process.stdout.write(JSON.stringify(require('./playwright.config.cjs')))"],
        cwd=ROOT,
        env={**os.environ, "REDAGENT_E2E_PORT": port},
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
def test_invalid_port_denies_before_server_spawn(port):
    result = _config(port)
    assert result.returncode != 0
    assert "REDAGENT_E2E_PORT must be an unprivileged numeric port" in result.stderr


def test_stage_contract_binds_port_override_and_ignores_external_cache_override():
    stage = Stage("frontend-e2e", ("npm", "test"), ("G2",), 60)
    first = StageRunner(ROOT, {"REDAGENT_E2E_PORT": "4310", "npm_config_cache": "outside-cache"})
    second = StageRunner(ROOT, {"REDAGENT_E2E_PORT": "4311"})
    assert first._environment["npm_config_cache"] == str(ROOT / ".tmp" / "npm-cache")
    assert first._environment["REDAGENT_E2E_PORT"] == "4310"
    assert first.execution_contract(stage, source_oid="a" * 40)["environment_sha256"] != second.execution_contract(stage, source_oid="a" * 40)["environment_sha256"]
