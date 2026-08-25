import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
from datetime import datetime, timedelta, timezone

import pytest

from scripts import authorized_web_assessment_runner as assessment


ROOT = Path(__file__).resolve().parents[2]
POWERSHELL_WRAPPER = ROOT / "scripts" / "run_authorized_web_assessment.ps1"
PYTHON_RUNNER = ROOT / "scripts" / "authorized_web_assessment_runner.py"
SOP = ROOT / "docs" / "sop" / "AUTHORIZED_WEB_ASSESSMENT_SOP.md"


def test_assessment_sop_covers_full_workflow() -> None:
    text = SOP.read_text(encoding="utf-8")
    required = [
        "engagement authorization review",
        "local log-console startup",
        "controlled execution",
        "log and artifact capture",
        "result analysis",
        "improvement recommendation report drafting",
        "closeout and validation",
    ]
    for phrase in required:
        assert phrase in text


def test_wrapper_does_not_expose_arbitrary_command_execution() -> None:
    text = POWERSHELL_WRAPPER.read_text(encoding="utf-8").lower()
    forbidden = [
        "invoke-expression",
        "iex ",
        " -command $",
        "scriptblock::create",
        "-argumentlist $",
    ]
    for phrase in forbidden:
        assert phrase not in text
    assert "windowstyle hidden" in text
    assert '@("run", "dev")' in POWERSHELL_WRAPPER.read_text(encoding="utf-8")
    assert "authorized_web_assessment_runner.py" in text


def test_runner_keeps_scanner_and_payload_tools_out() -> None:
    text = PYTHON_RUNNER.read_text(encoding="utf-8").lower()
    forbidden = [
        "nmap",
        "sqlmap",
        "nikto",
        "nuclei",
        "zap",
        "ffuf",
        "gobuster",
        "wfuzz",
        "subprocess",
        "os.system",
        "eval(",
        "exec(",
    ]
    for phrase in forbidden:
        assert phrase not in text


def test_runner_contains_core_safety_controls() -> None:
    text = PYTHON_RUNNER.read_text(encoding="utf-8")
    required = [
        "def check_window",
        "def assert_allowed_url",
        "def interaction",
        "max_interactions",
        "min_delay_seconds",
        "blocked out-of-scope",
        "GET",
        "HEAD",
    ]
    for phrase in required:
        assert phrase in text


def test_wrapper_supports_dry_run_and_ui_log() -> None:
    text = POWERSHELL_WRAPPER.read_text(encoding="utf-8")
    assert "[switch]$DryRun" in text
    assert ".tmp\\ui-terminal.log" in text
    assert "reports\\assessments" in text
    assert ".local\\validation\\automated-runs" in text


def test_wrapper_stage2_contract_is_array_safe_and_dry_run_validates_config() -> None:
    text = POWERSHELL_WRAPPER.read_text(encoding="utf-8")
    required = [
        "[switch]$DisableDirectoryProbes",
        "--validate-only",
        "--expected-config-sha256",
        "authorization_label must use the approved identifier grammar",
        "Targets must contain between 1 and 10 unique hostnames",
        "WindowStart and WindowEnd must be ISO-8601 values with explicit offsets",
        "WindowEnd must be later than WindowStart",
        "Directory probes disabled:",
        "Directory probe count:",
        "runner.log",
        "-Targets @(",
        "-DisableDirectoryProbes",
        "Run ID: $RunId",
        "Config SHA-256: $ConfigSha256",
        "~~~powershell",
        "Add-Content -LiteralPath $RunLogPath -Value $line -Encoding UTF8",
        "function Assert-RepoContainedPath",
        "[System.IO.FileAttributes]::ReparsePoint",
        "$NoUi = $true",
        "Get-Command wsl.exe -CommandType Application -ErrorAction Stop",
        "$ExitCode = $null",
        "native runner invocation did not provide a valid exit code",
        "Config verification observed:",
        "Config verification was not confirmed; this run is failed and inadmissible.",
    ]
    for phrase in required:
        assert phrase in text
    assert "Tee-Object" not in text
    assert "````powershell" not in text
    assert "read_bytes()" not in PYTHON_RUNNER.read_text(encoding="utf-8")


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell wrapper test")
def test_wrapper_missing_wsl_fails_before_creating_run_directory() -> None:
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    run_root = ROOT / ".tmp" / "assessments"
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    before = {item.name for item in run_root.iterdir() if item.is_dir()} if run_root.exists() else set()
    start = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
    end = (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
    with tempfile.TemporaryDirectory(prefix="assessment-empty-path-", dir=local) as empty_path:
        script = (
            f"$env:PATH='{empty_path}'; "
            "try { "
            f"& '{POWERSHELL_WRAPPER}' -Mode passive -Targets @('agentique.io') "
            f"-WindowStart '{start}' -WindowEnd '{end}' "
            "-AuthorizationLabel 'r117-missing-wsl-test' -DisableDirectoryProbes -DryRun; "
            "exit 0 } catch { Write-Output $_.Exception.Message; exit 17 }"
        )
        completed = subprocess.run(
            [str(powershell), "-NoProfile", "-Command", script],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    after = {item.name for item in run_root.iterdir() if item.is_dir()} if run_root.exists() else set()

    assert completed.returncode == 17
    assert "wsl.exe" in completed.stdout
    assert after == before


@pytest.mark.skipif(os.name != "nt", reason="Windows PowerShell wrapper test")
def test_wrapper_rejects_dictionary_dot_segments_before_other_preflight() -> None:
    powershell = (
        Path(os.environ["SystemRoot"])
        / "System32"
        / "WindowsPowerShell"
        / "v1.0"
        / "powershell.exe"
    )
    script = (
        "try { "
        f"& '{POWERSHELL_WRAPPER}' -Mode passive -Targets @('agentique.io') "
        "-WindowStart 'invalid' -WindowEnd 'invalid' "
        "-AuthorizationLabel 'r117-dot-segment-test' "
        "-DirectoryDictionary @('/safe/./hidden') -DryRun; "
        "exit 0 } catch { Write-Output $_.Exception.Message; exit 19 }"
    )
    completed = subprocess.run(
        [str(powershell), "-NoProfile", "-Command", script],
        check=False,
        capture_output=True,
        text=True,
        timeout=30,
    )

    assert completed.returncode == 19
    assert "dot segments" in completed.stdout


def runner_for(directory: Path) -> assessment.Runner:
    return assessment.Runner(
        config={
            "run_id": "fixture-run",
            "mode": "passive",
            "execution_intent": "execute",
            "authorization_label": "fixture-authorization",
            "window_start": "2000-01-01T00:00:00+00:00",
            "window_end": "2100-01-01T00:00:00+00:00",
            "max_interactions": 30,
            "min_delay_seconds": 1,
            "summary_path": str(directory / "summary.json"),
            "report_path": str(directory / "report.md"),
        },
        allowed_hosts={"agentique.io"},
        output_dir=directory,
        artifacts_dir=directory / "artifacts",
        observations={
            "tls": [],
            "http": [],
            "robots": {},
            "security_txt": {},
            "sitemaps": [],
            "crawl": [],
            "directory": [],
            "fingerprint": [],
            "review_notes": [],
        },
    )


def test_runner_accepts_only_exact_https_default_port_without_userinfo() -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-url-", dir=local) as directory:
        runner = runner_for(Path(directory))
        assert runner.assert_allowed_url("https://agentique.io/path") == "agentique.io"
        assert runner.assert_allowed_url("https://agentique.io:443/path") == "agentique.io"
        for url in (
            "http://agentique.io/path",
            "https://agentique.io:8443/path",
            "https://user@agentique.io/path",
            "https://" + "user" + ":" + "password" + "@agentique.io/path",
            "https://agentique.io:not-a-port/path",
            "https://other.example/path",
        ):
            with pytest.raises(assessment.SafetyError):
                runner.assert_allowed_url(url)


def test_direct_config_rejects_budget_header_and_path_bypass_before_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-config-", dir=local) as directory:
        temp = Path(directory)
        approved_runs = temp / "approved-runs"
        approved_reports = temp / "approved-reports"
        monkeypatch.setattr(assessment, "RUN_ROOT", approved_runs, raising=False)
        monkeypatch.setattr(assessment, "REPORT_ROOT", approved_reports, raising=False)
        base = {
            "run_id": "run-1",
            "mode": "progressive",
            "execution_intent": "execute",
            "targets": ["agentique.io"],
            "window_start": "2026-07-12T00:00:00+00:00",
            "window_end": "2026-07-13T00:00:00+00:00",
            "authorization_label": "r117-test-authorization",
            "output_dir": str(approved_runs / "run-1"),
            "summary_path": str(approved_runs / "run-1" / "summary.json"),
            "report_path": str(approved_reports / "run-1-report.md"),
            "max_interactions": 30,
            "min_delay_seconds": 2,
            "directory_dictionary": [],
            "user_agent": "RedAgentAuthorizedAutomation/0.1",
        }

        runner = assessment.Runner.from_config(base)
        assert runner.output_dir == (approved_runs / "run-1").resolve()

        invalid = dict(base, output_dir=str(temp / "outside"), summary_path=str(temp / "outside" / "summary.json"))
        with pytest.raises(assessment.SafetyError):
            assessment.Runner.from_config(invalid)
        assert not (temp / "outside").exists()

        for mutation in (
            {"max_interactions": 501},
            {"max_interactions": True},
            {"min_delay_seconds": 0},
            {"min_delay_seconds": float("nan")},
            {"min_delay_seconds": float("inf")},
            {"min_delay_seconds": True},
            {"user_agent": "valid\r\ninjected: true"},
            {"summary_path": str(approved_runs / "other.json")},
            {"report_path": str(temp / "outside-report.md")},
            {"mode": "active"},
            {"execution_intent": "maybe"},
            {"authorization_label": "invalid label"},
            {"targets": ["https://agentique.io"]},
            {"window_end": "2026-07-11T00:00:00+00:00"},
            {"window_start": "2026-07-12T00:00:00"},
            {"directory_dictionary": [True]},
            {"directory_dictionary": ["/safe/./hidden"]},
        ):
            with pytest.raises(assessment.SafetyError):
                assessment.Runner.from_config(dict(base, **mutation))


def test_direct_config_rejects_reparse_components_before_creation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-reparse-", dir=local) as directory:
        temp = Path(directory)
        approved_runs = temp / "approved-runs"
        approved_reports = temp / "approved-reports"
        approved_runs.mkdir()
        approved_reports.mkdir()
        monkeypatch.setattr(assessment, "RUN_ROOT", approved_runs)
        monkeypatch.setattr(assessment, "REPORT_ROOT", approved_reports)
        original_check = assessment.is_reparse_path
        monkeypatch.setattr(
            assessment,
            "is_reparse_path",
            lambda path: path == approved_runs or original_check(path),
        )
        config = {
            "run_id": "run-reparse",
            "mode": "passive",
            "execution_intent": "execute",
            "targets": ["agentique.io"],
            "window_start": "2026-07-12T00:00:00+00:00",
            "window_end": "2026-07-13T00:00:00+00:00",
            "authorization_label": "r117-test-authorization",
            "max_interactions": 30,
            "min_delay_seconds": 2,
            "directory_dictionary": [],
            "output_dir": str(approved_runs / "run-reparse"),
            "report_path": str(approved_reports / "run-reparse-report.md"),
            "summary_path": str(approved_runs / "run-reparse" / "summary.json"),
            "user_agent": "RedAgentAuthorizedAutomation/0.1",
        }

        with pytest.raises(assessment.SafetyError, match="symlink or reparse"):
            assessment.Runner.from_config(config)
        assert not (approved_runs / "run-reparse").exists()


def test_repo_root_reparse_is_rejected_before_descendant_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-root-reparse-", dir=local) as directory:
        fake_repo = Path(directory)
        original_check = assessment.is_reparse_path
        monkeypatch.setattr(assessment, "REPO_ROOT", fake_repo)
        monkeypatch.setattr(assessment, "LEXICAL_REPO_ROOT", fake_repo)
        monkeypatch.setattr(
            assessment,
            "is_reparse_path",
            lambda path: path == fake_repo or original_check(path),
        )
        with pytest.raises(assessment.SafetyError, match="repository root"):
            assessment.ensure_repo_path(fake_repo / "child", "child")


def test_direct_config_rejects_real_directory_symlink_when_supported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-symlink-", dir=local) as directory:
        temp = Path(directory)
        approved_runs = temp / "approved-runs"
        approved_reports = temp / "approved-reports"
        outside = temp / "outside"
        approved_runs.mkdir()
        approved_reports.mkdir()
        outside.mkdir()
        run_link = approved_runs / "run-link"
        try:
            run_link.symlink_to(outside, target_is_directory=True)
        except OSError as error:
            pytest.skip(f"directory symlink creation is unavailable: {error}")
        monkeypatch.setattr(assessment, "RUN_ROOT", approved_runs)
        monkeypatch.setattr(assessment, "REPORT_ROOT", approved_reports)
        config = {
            "run_id": "run-link",
            "mode": "passive",
            "execution_intent": "execute",
            "targets": ["agentique.io"],
            "window_start": "2026-07-12T00:00:00+00:00",
            "window_end": "2026-07-13T00:00:00+00:00",
            "authorization_label": "r117-test-authorization",
            "max_interactions": 30,
            "min_delay_seconds": 2,
            "directory_dictionary": [],
            "output_dir": str(run_link),
            "report_path": str(approved_reports / "run-link-report.md"),
            "summary_path": str(run_link / "summary.json"),
            "user_agent": "RedAgentAuthorizedAutomation/0.1",
        }

        with pytest.raises(assessment.SafetyError, match="symlink or reparse"):
            assessment.Runner.from_config(config)
        assert not (outside / "artifacts").exists()


def test_cli_config_loader_is_bounded_bom_aware_and_rejects_ambiguous_json(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-loader-", dir=local) as directory:
        temp = Path(directory)
        approved_runs = temp / "approved-runs"
        approved_reports = temp / "approved-reports"
        monkeypatch.setattr(assessment, "RUN_ROOT", approved_runs, raising=False)
        monkeypatch.setattr(assessment, "REPORT_ROOT", approved_reports, raising=False)
        run_dir = approved_runs / "run-1"
        run_dir.mkdir(parents=True)
        config = {
            "run_id": "run-1",
            "mode": "passive",
            "execution_intent": "validate_only",
            "targets": ["agentique.io"],
            "window_start": "2026-07-12T00:00:00+00:00",
            "window_end": "2026-07-13T00:00:00+00:00",
            "authorization_label": "r117-test-authorization",
            "max_interactions": 30,
            "min_delay_seconds": 2,
            "directory_dictionary": [],
            "output_dir": str(run_dir),
            "report_path": str(approved_reports / "run-1-report.md"),
            "summary_path": str(run_dir / "summary.json"),
            "user_agent": "RedAgentAuthorizedAutomation/0.1",
        }
        config_path = run_dir / "config.json"
        config_path.write_bytes(b"\xef\xbb\xbf" + json.dumps(config).encode("utf-8"))

        config_digest = hashlib.sha256(config_path.read_bytes()).hexdigest()
        runner = assessment.Runner.from_config_path(
            config_path,
            config_digest,
            "validate_only",
        )
        assert runner.output_dir == run_dir.resolve()

        with pytest.raises(assessment.SafetyError, match="digest"):
            assessment.Runner.from_config_path(config_path, "0" * 64, "validate_only")

        outside_path = temp / "outside.json"
        outside_path.write_text(json.dumps(config), encoding="utf-8")
        with pytest.raises(assessment.SafetyError):
            assessment.Runner.from_config_path(
                outside_path,
                hashlib.sha256(outside_path.read_bytes()).hexdigest(),
                "validate_only",
            )

        config_path.write_text('{"run_id":"run-1","run_id":"shadow"}', encoding="utf-8")
        with pytest.raises(assessment.SafetyError, match="duplicate"):
            assessment.Runner.from_config_path(
                config_path,
                hashlib.sha256(config_path.read_bytes()).hexdigest(),
                "validate_only",
            )

        config_path.write_text('{"max_interactions":NaN}', encoding="utf-8")
        with pytest.raises(assessment.SafetyError, match="non-finite"):
            assessment.Runner.from_config_path(
                config_path,
                hashlib.sha256(config_path.read_bytes()).hexdigest(),
                "validate_only",
            )

        config_path.write_text("[]", encoding="utf-8")
        with pytest.raises(assessment.SafetyError, match="JSON object"):
            assessment.Runner.from_config_path(
                config_path,
                hashlib.sha256(config_path.read_bytes()).hexdigest(),
                "validate_only",
            )

        config_path.write_bytes(b"{" + (b" " * 70_000) + b"}")
        with pytest.raises(assessment.SafetyError, match="size"):
            assessment.Runner.from_config_path(
                config_path,
                hashlib.sha256(config_path.read_bytes()).hexdigest(),
                "validate_only",
            )

        mismatch_dir = approved_runs / "run-mismatch-config"
        mismatch_dir.mkdir()
        mismatch_config = dict(
            config,
            run_id="run-mismatch-output",
            output_dir=str(approved_runs / "run-mismatch-output"),
            summary_path=str(approved_runs / "run-mismatch-output" / "summary.json"),
            report_path=str(approved_reports / "run-mismatch-output-report.md"),
        )
        mismatch_path = mismatch_dir / "config.json"
        mismatch_path.write_text(json.dumps(mismatch_config), encoding="utf-8")
        with pytest.raises(assessment.SafetyError, match="config path"):
            assessment.Runner.from_config_path(
                mismatch_path,
                hashlib.sha256(mismatch_path.read_bytes()).hexdigest(),
                "validate_only",
            )
        assert not (approved_runs / "run-mismatch-output").exists()


def test_validate_only_cli_loads_config_without_running_network_work(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-validate-", dir=local) as directory:
        temp = Path(directory)
        approved_runs = temp / "approved-runs"
        approved_reports = temp / "approved-reports"
        monkeypatch.setattr(assessment, "RUN_ROOT", approved_runs)
        monkeypatch.setattr(assessment, "REPORT_ROOT", approved_reports)
        run_dir = approved_runs / "run-validate"
        run_dir.mkdir(parents=True)
        config = {
            "run_id": "run-validate",
            "mode": "passive",
            "execution_intent": "validate_only",
            "targets": ["agentique.io"],
            "window_start": "2026-07-12T00:00:00+00:00",
            "window_end": "2026-07-13T00:00:00+00:00",
            "authorization_label": "r117-test-authorization",
            "max_interactions": 30,
            "min_delay_seconds": 2,
            "directory_dictionary": [],
            "output_dir": str(run_dir),
            "report_path": str(approved_reports / "run-validate-report.md"),
            "summary_path": str(run_dir / "summary.json"),
            "user_agent": "RedAgentAuthorizedAutomation/0.1",
        }
        config_path = run_dir / "config.json"
        config_path.write_text(json.dumps(config), encoding="utf-8")
        config_digest = hashlib.sha256(config_path.read_bytes()).hexdigest()

        def fail_if_run(_runner: assessment.Runner) -> None:
            raise AssertionError("validate-only must not enter network run")

        monkeypatch.setattr(assessment.Runner, "run", fail_if_run)
        result = assessment.main(
            [
                "runner",
                "--validate-only",
                "--expected-config-sha256",
                config_digest,
                str(config_path),
            ]
        )
        execute_result = assessment.main(
            [
                "runner",
                "--expected-config-sha256",
                config_digest,
                str(config_path),
            ]
        )

    assert result == 0
    assert execute_result == 10


class FakeResponse:
    def __init__(
        self,
        body: bytes = b"body",
        headers: list[tuple[str, str]] | None = None,
        status: int = 200,
        reason: str = "OK",
    ) -> None:
        self.status = status
        self.reason = reason
        self.body = body
        self.read_amounts: list[int | None] = []
        self.headers = (
            headers
            if headers is not None
            else [
                ("Content-Type", "text/plain"),
                ("Set-Cookie", "session=secret-value; Secure; HttpOnly; SameSite=Lax"),
                ("WWW-Authenticate", "Bearer secret-challenge"),
                ("Location", "https://agentique.io/next?token=secret-value#fragment"),
                ("X-Secret-Token", "secret-header-value"),
            ]
        )

    def read(self, amount: int | None = None) -> bytes:
        self.read_amounts.append(amount)
        return self.body if amount is None else self.body[:amount]

    def getheaders(self) -> list[tuple[str, str]]:
        return self.headers


class FakeConnection:
    response = FakeResponse()
    request_target = ""
    created = 0

    def __init__(self, host: str, timeout: int) -> None:
        type(self).created += 1
        self.host = host
        self.timeout = timeout

    def request(self, method: str, path: str, headers: dict[str, str]) -> None:
        type(self).request_target = path

    def getresponse(self) -> FakeResponse:
        return type(self).response

    def close(self) -> None:
        return None


def test_request_redacts_headers_and_evidence_url_without_changing_request(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-redaction-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)
        monkeypatch.setattr(runner, "delay", lambda: None)
        FakeConnection.response = FakeResponse(reason="secret-token ![pixel](https://third-party.example)")

        observation = runner.request(
            "GET",
            "https://agentique.io/path?token=secret-value#fragment",
            "redaction",
            100,
        )
        output = capsys.readouterr().out
        artifact = (root / observation.artifact).read_text(encoding="utf-8")
        runner.write_summary("2026-07-12T00:00:00+00:00", "2026-07-12T00:00:01+00:00")
        summary = (root / "summary.json").read_text(encoding="utf-8")
        report = (root / "report.md").read_text(encoding="utf-8")

    assert FakeConnection.request_target == "/path?token=secret-value"
    assert observation.url == "https://agentique.io/{path-redacted}"
    assert observation.headers["set-cookie"] == "<redacted>"
    assert observation.headers["www-authenticate"] == "<redacted>"
    assert observation.headers["location"] == "https://agentique.io/{path-redacted}"
    assert "x-secret-token" not in observation.headers
    assert observation.body_artifact is None
    assert observation.body_sha256 == hashlib.sha256(b"body").hexdigest()
    body_artifacts = list((root / "artifacts").glob("*.body"))
    assert all(amount is not None for amount in FakeConnection.response.read_amounts)
    assert "secret-value" not in output
    assert "secret-value" not in artifact
    assert "secret-challenge" not in artifact
    assert "secret-value" not in summary
    assert "secret-challenge" not in summary
    assert "secret-value" not in report
    assert "secret-token" not in output
    assert "secret-token" not in artifact
    assert "secret-token" not in summary
    assert "third-party.example" not in report
    assert "secret-header-value" not in summary
    assert str(root) not in summary
    assert str(root) not in report
    assert body_artifacts == []


def test_redirect_scope_is_validated_before_any_artifact_is_written(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-redirect-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)
        FakeConnection.response = FakeResponse(
            headers=[("Location", "http://agentique.io/next?token=secret-value")],
            status=302,
        )

        with pytest.raises(assessment.SafetyError):
            runner.request("HEAD", "https://agentique.io/", "blocked-redirect")
        assert not list((root / "artifacts").iterdir())
        assert FakeConnection.response.read_amounts == []


def test_each_interaction_rechecks_the_authorization_window() -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-window-", dir=local) as directory:
        runner = runner_for(Path(directory))
        runner.config["window_start"] = "2000-01-01T00:00:00+00:00"
        runner.config["window_end"] = "2000-01-02T00:00:00+00:00"
        with pytest.raises(assessment.SafetyError, match="outside approved window"):
            runner.interaction("GET https://agentique.io/")
        assert runner.count == 0


def test_request_rejects_oversized_body_without_persisting_partial_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-cap-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)
        monkeypatch.setattr(runner, "delay", lambda: None)
        FakeConnection.response = FakeResponse(b"123456")

        with pytest.raises(assessment.SafetyError, match="body exceeds approved cap"):
            runner.request("GET", "https://agentique.io/", "oversized", 5)
        assert not list((root / "artifacts").iterdir())
        assert runner.observations["http"] == []

        for invalid_cap in (-1, 2_097_153, True):
            with pytest.raises(assessment.SafetyError):
                runner.request("GET", "https://agentique.io/", "invalid-cap", invalid_cap)
        assert all(amount is not None for amount in FakeConnection.response.read_amounts)


def test_request_cap_is_checked_before_connection_construction(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-request-cap-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        runner.count = runner.max_interactions
        FakeConnection.created = 0
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)

        with pytest.raises(assessment.SafetyError, match="request cap"):
            runner.request("HEAD", "https://agentique.io/", "over-cap")
        assert FakeConnection.created == 0
        assert not list((root / "artifacts").iterdir())


def test_validate_only_intent_blocks_direct_request_before_connection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-intent-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        runner.config["execution_intent"] = "validate_only"
        FakeConnection.created = 0
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)

        with pytest.raises(assessment.SafetyError, match="validate-only"):
            runner.request("HEAD", "https://agentique.io/", "intent-block")
        assert FakeConnection.created == 0
        assert runner.count == 0


def test_body_derived_observations_never_persist_query_or_contact_values() -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-derived-", dir=local) as directory:
        runner = runner_for(Path(directory))
        sitemaps = runner.extract_robots(
            "agentique.io",
            "Disallow: /private?token=secret-value\n"
            "Sitemap: https://agentique.io/sitemap.xml?token=secret-value#fragment\n",
        )
        runner.extract_security_txt_fields(
            "agentique.io",
            "Contact: https://agentique.io/contact?token=secret-value\n"
            "Policy: https://agentique.io/policy?token=secret-value\n"
            "Secret-Token: secret-value\n",
        )
        runner.extract_sitemap_count(
            "https://agentique.io/sitemap.xml?token=secret-value",
            "<loc>https://agentique.io/page?token=secret-value#fragment</loc>",
        )
        persisted = json.dumps(runner.observations)

    assert sitemaps == []
    assert "secret-value" not in persisted
    assert "?" not in persisted
    assert "#fragment" not in persisted


def test_robots_rules_block_disallowed_crawl_paths_without_persisting_rules() -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-robots-", dir=local) as directory:
        runner = runner_for(Path(directory))
        runtime_sitemaps = runner.extract_robots(
            "agentique.io",
            "User-agent: *\n"
            "Disallow: /private # owner note\n"
            "Disallow: /login$\n"
            "Sitemap: https://agentique.io/private-sitemap-token.xml\n",
        )
        links = runner.extract_links(
            "https://agentique.io/",
            '<a href="/private/account">private</a>'
            '<a href="/login">login</a>'
            '<a href="/public%2Fencoded-secret">encoded</a>'
            '<a href="\\private">backslash</a>'
            '<a href="//agentique.io//private">double slash</a>'
            '<a href="/public path">space</a>'
            '<a href="/café">unicode</a>'
            '<a href="/logout?confirm=1">query</a>'
            '<a href="/public">public</a>',
        )
        persisted = json.dumps(runner.observations)

    assert links == ["https://agentique.io/public"]
    assert runtime_sitemaps == ["https://agentique.io/private-sitemap-token.xml"]
    assert "/private" not in persisted
    assert "/login" not in persisted
    assert "private-sitemap-token" not in persisted


def test_malformed_robots_disallow_rules_fail_closed() -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-robots-malformed-", dir=local) as directory:
        runner = runner_for(Path(directory))
        for rule in (
            "relative-path",
            "/safe/./hidden",
            "/safe/../hidden",
            "/café",
        ):
            runner.extract_robots("agentique.io", f"User-agent: *\nDisallow: {rule}\n")
            assert runner.robots_disallow["agentique.io"] == ["/"]


def test_passive_mode_loads_robots_before_discretionary_head_requests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-passive-robots-", dir=local) as directory:
        runner = runner_for(Path(directory))
        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(runner, "tls_probe", lambda _host: None)

        def fake_request(
            method: str,
            url: str,
            _name: str,
            _max_body_bytes: int = 0,
        ) -> assessment.HttpObservation:
            calls.append((method, url))
            return assessment.HttpObservation(
                method=method,
                url=url,
                status=200,
                reason="OK",
                artifact="artifacts/fake.headers.txt",
                body=b"User-agent: *\nDisallow: /\n",
            )

        monkeypatch.setattr(runner, "request", fake_request)
        runner.passive()

    assert calls == [("GET", "https://agentique.io/robots.txt")]


def test_non_success_robots_response_blocks_all_discretionary_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-robots-status-", dir=local) as directory:
        runner = runner_for(Path(directory))
        calls: list[tuple[str, str]] = []
        monkeypatch.setattr(runner, "tls_probe", lambda _host: None)

        def fake_request(
            method: str,
            url: str,
            _name: str,
            _max_body_bytes: int = 0,
        ) -> assessment.HttpObservation:
            calls.append((method, url))
            return assessment.HttpObservation(
                method=method,
                url=assessment.sanitized_evidence_url(url),
                status=302,
                reason="Found",
                artifact="artifacts/fake.headers.txt",
                body=b"",
            )

        monkeypatch.setattr(runner, "request", fake_request)
        runner.passive()

    assert calls == [("GET", "https://agentique.io/robots.txt")]
    assert runner.robots_disallow["agentique.io"] == ["/"]


def test_progressive_crawl_persists_only_redacted_dynamic_paths(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-progressive-redaction-", dir=local) as directory:
        runner = runner_for(Path(directory))
        monkeypatch.setattr(runner, "tls_probe", lambda _host: None)

        def fake_request(
            method: str,
            url: str,
            _name: str,
            _max_body_bytes: int = 0,
        ) -> assessment.HttpObservation:
            bodies = {
                "https://agentique.io/robots.txt": b"User-agent: *\n",
                "https://agentique.io/.well-known/security.txt": b"",
                "https://agentique.io/sitemap.xml": b"<urlset></urlset>",
                "https://agentique.io/": (
                    b'<a href="/reset/private-path-token">reset</a>'
                ),
            }
            return assessment.HttpObservation(
                method=method,
                url=assessment.sanitized_evidence_url(url),
                status=200,
                reason="OK",
                artifact="artifacts/fake.headers.txt",
                body=bodies.get(url, b""),
            )

        monkeypatch.setattr(runner, "request", fake_request)
        runner.progressive()
        persisted = json.dumps(runner.observations)

    assert "private-path-token" not in persisted
    assert runner.observations["crawl"] == [
        {"url": "https://agentique.io/{path-redacted}", "status": 200}
    ]


@pytest.mark.parametrize("status", [401, 403, 429])
def test_access_denial_and_rate_limit_stop_after_first_response(
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-stop-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)
        monkeypatch.setattr(runner, "delay", lambda: None)
        FakeConnection.response = FakeResponse(headers=[], status=status)

        with pytest.raises(assessment.SafetyError, match="stop condition"):
            runner.request("GET", "https://agentique.io/", f"status-{status}", 100)
        assert runner.count == 1


def test_waf_challenge_and_second_5xx_stop_progression(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-waf-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)
        monkeypatch.setattr(runner, "delay", lambda: None)
        FakeConnection.response = FakeResponse(
            body=b"challenge",
            headers=[("cf-mitigated", "challenge")],
        )
        with pytest.raises(assessment.SafetyError, match="stop condition"):
            runner.request("GET", "https://agentique.io/", "waf", 100)

    with tempfile.TemporaryDirectory(prefix="assessment-5xx-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)
        monkeypatch.setattr(runner, "delay", lambda: None)
        FakeConnection.response = FakeResponse(headers=[], status=500)
        runner.request("GET", "https://agentique.io/", "first-5xx", 100)
        with pytest.raises(assessment.SafetyError, match="stop condition"):
            runner.request("GET", "https://agentique.io/", "second-5xx", 100)
        assert runner.count == 2


def test_high_confidence_sensitive_body_stops_before_artifact_or_observation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-sensitive-stop-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)
        FakeConnection.response = FakeResponse(
            body=b"-----BEGIN " + b"PRIVATE KEY-----\nnot-retained\n",
            headers=[],
        )

        with pytest.raises(assessment.SafetyError, match="sensitive material"):
            runner.request("GET", "https://agentique.io/", "sensitive", 100)
        assert not list((root / "artifacts").iterdir())
        assert runner.observations["http"] == []


def test_material_request_latency_is_an_automatic_stop_condition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-latency-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        monkeypatch.setattr(assessment.http.client, "HTTPSConnection", FakeConnection)
        monkeypatch.setattr(runner, "delay", lambda: None)
        ticks = iter([10.0, 20.1])
        monkeypatch.setattr(assessment.time, "monotonic", lambda: next(ticks))
        FakeConnection.response = FakeResponse(headers=[])

        with pytest.raises(assessment.SafetyError, match="stop condition"):
            runner.request("GET", "https://agentique.io/", "latency", 100)


def test_material_tls_latency_is_an_automatic_stop_condition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FakeSocket:
        def __enter__(self) -> "FakeSocket":
            return self

        def __exit__(self, *_args: object) -> None:
            return None

    class FakeTls(FakeSocket):
        def getpeercert(self) -> dict[str, object]:
            return {
                "subject": ((('commonName', 'agentique.io'),),),
                "issuer": ((('commonName', 'Test CA'),),),
                "subjectAltName": (("DNS", "agentique.io"),),
            }

    class FakeContext:
        def wrap_socket(self, _socket: FakeSocket, server_hostname: str) -> FakeTls:
            assert server_hostname == "agentique.io"
            return FakeTls()

    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-tls-latency-", dir=local) as directory:
        root = Path(directory)
        (root / "artifacts").mkdir()
        runner = runner_for(root)
        ticks = iter([10.0, 20.1])
        monkeypatch.setattr(assessment.time, "monotonic", lambda: next(ticks))
        monkeypatch.setattr(assessment.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
        monkeypatch.setattr(assessment.ssl, "create_default_context", lambda: FakeContext())

        with pytest.raises(assessment.SafetyError, match="material TLS latency"):
            runner.tls_probe("agentique.io")


def test_fingerprint_and_http_reason_never_persist_target_controlled_prose() -> None:
    local = ROOT / ".local"
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="assessment-prose-", dir=local) as directory:
        runner = runner_for(Path(directory))
        runner.fingerprint(
            "<title>![pixel](https://third-party.example/secret-token)</title>"
        )
        persisted = json.dumps(runner.observations)

    assert "third-party" not in persisted
    assert "secret-token" not in persisted
    assert "![pixel]" not in persisted
    assert "title element present" in persisted
