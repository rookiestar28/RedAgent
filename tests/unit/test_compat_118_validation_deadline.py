from __future__ import annotations

from pathlib import Path
import time
from types import SimpleNamespace

import pytest


def test_authoritative_gate_budgets_are_closed_and_fit_the_ci_timeout() -> None:
    from redagent_platform.gate_deadline import (
        GATE_EXECUTION_BUDGET_SECONDS,
        GateDeadlineError,
        budget_seconds,
    )

    assert GATE_EXECUTION_BUDGET_SECONDS == {"G0": 600, "G1": 1_500, "G2": 2_700}
    assert budget_seconds("G0") <= 600
    assert budget_seconds("G1") <= 1_500
    # Preserve five minutes for the outer job's venv preparation, evidence
    # verification, artifact publication, and process cleanup.
    assert budget_seconds("G2") <= 3_300
    with pytest.raises(GateDeadlineError, match="unknown"):
        budget_seconds("G3")


def test_deadline_timeout_never_rounds_a_child_past_the_remaining_budget(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import redagent_platform.gate_deadline as gate_deadline

    monkeypatch.setattr(gate_deadline.time, "monotonic", lambda: 100.4)
    assert gate_deadline.bounded_timeout(105.9, 900) == 5
    assert gate_deadline.bounded_timeout(100.4, 900) == 0
    assert gate_deadline.bounded_timeout(99.9, 900) == 0


def test_receipt_binding_refuses_an_expired_deadline_before_a_fresh_git_query(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import run_validation_gate

    monkeypatch.setattr(
        run_validation_gate,
        "run_bounded_stdout",
        lambda *_args, **_kwargs: pytest.fail("Git work must not start after the campaign deadline"),
    )

    with pytest.raises(RuntimeError, match="deadline exhausted"):
        run_validation_gate._changed_paths("a" * 40, "b" * 40, deadline=0.0)


def test_authoritative_selection_forwards_its_outer_deadline_to_git_request_building(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Classification must not create an unbounded Git prefix inside the writer lease."""

    from scripts import run_validation_gate

    observed: dict[str, object] = {}
    request = SimpleNamespace()
    decision = SimpleNamespace(selected_gate="G0")
    monkeypatch.setattr(
        run_validation_gate,
        "_request",
        lambda *_args, **kwargs: observed.update(kwargs) or request,
    )
    monkeypatch.setattr(run_validation_gate, "classify_change", lambda _request: decision)

    assert run_validation_gate._authoritative_selection(
        SimpleNamespace(gate=None, force_full=False),
        deadline=123.0,
    ) == (request, decision, "G0")
    assert observed == {"authoritative": True, "deadline": 123.0}


def test_current_gate_stage_runner_inherits_the_shared_deadline_and_fixed_git_environment(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from redagent_platform.validation.stages import Stage, StageResult
    from scripts import run_validation_gate

    stage = Stage("only", ("python", "-V"), ("G0",), 60)
    captured: dict[str, object] = {}

    class Registry:
        def plan_ids(self, _ids: object) -> tuple[Stage, ...]:
            return (stage,)

    class Runner:
        def __init__(self, *_args: object, **kwargs: object) -> None:
            captured["fixed_environment"] = kwargs.get("fixed_environment")

        def run(self, received: Stage, *, deadline_monotonic: float | None = None) -> StageResult:
            captured["deadline"] = deadline_monotonic
            return StageResult(received.id, "passed", 0, 1, received.argv)

    monkeypatch.setattr(run_validation_gate, "build_default_registry", lambda _root: Registry())
    monkeypatch.setattr(run_validation_gate, "StageRunner", Runner)
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: True)
    monkeypatch.setattr(run_validation_gate, "_revision", lambda *_args, **_kwargs: "a" * 40)
    monkeypatch.setattr(run_validation_gate, "collect_artifact_digests", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(run_validation_gate, "build_verification_receipt", lambda **_kwargs: {})
    monkeypatch.setattr(
        run_validation_gate,
        "_validated_authoritative_receipt_path",
        lambda _value, **_kwargs: tmp_path / "receipt.json",
    )
    monkeypatch.setattr(run_validation_gate, "_write_json", lambda *_args, **_kwargs: None)

    request = SimpleNamespace(base_revision=None, head_revision="a" * 40, force_full=False, ci_context="test")
    decision = SimpleNamespace(required_stage_ids=("only",), normalized_paths=("docs/example.md",))
    deadline = time.monotonic() + 120
    assert run_validation_gate._run_command_locked(
        SimpleNamespace(receipt="ignored"),
        tmp_path / "receipt.json",
        request=request,
        decision=decision,
        selected_gate="G0",
        deadline=deadline,
    ) == 0
    assert captured == {
        "fixed_environment": run_validation_gate._GIT_ENVIRONMENT,
        "deadline": deadline,
    }


def test_configuration_hashing_refuses_an_expired_campaign_deadline() -> None:
    from redagent_platform.validation.receipt import (
        ReceiptVerificationError,
        current_configuration_digests,
    )

    with pytest.raises(ReceiptVerificationError, match="deadline exhausted"):
        current_configuration_digests(deadline_monotonic=0.0)


def test_current_gate_records_timeout_then_skips_remaining_stages_without_launching_them(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    from redagent_platform.validation.stages import Stage
    from scripts import run_validation_gate

    stages = (
        Stage("first", ("python", "-V"), ("G0",), 60),
        Stage("second", ("python", "-V"), ("G0",), 60),
    )
    captured: dict[str, object] = {}

    class Registry:
        def plan_ids(self, _ids: object) -> tuple[Stage, ...]:
            return stages

    def receipt(**kwargs: object) -> dict[str, object]:
        captured["results"] = kwargs["stage_results"]
        return {}

    monkeypatch.setattr(run_validation_gate, "build_default_registry", lambda _root: Registry())
    monkeypatch.setattr(run_validation_gate, "StageRunner", lambda *_args, **_kwargs: pytest.fail("must not launch"))
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", lambda **_kwargs: True)
    monkeypatch.setattr(run_validation_gate, "_revision", lambda *_args, **_kwargs: "a" * 40)
    monkeypatch.setattr(run_validation_gate, "collect_artifact_digests", lambda *_args, **_kwargs: {})
    monkeypatch.setattr(run_validation_gate, "current_configuration_digests", lambda **_kwargs: {})
    monkeypatch.setattr(run_validation_gate, "build_verification_receipt", receipt)
    monkeypatch.setattr(
        run_validation_gate,
        "_validated_authoritative_receipt_path",
        lambda _value, **_kwargs: tmp_path / "receipt.json",
    )
    monkeypatch.setattr(run_validation_gate, "_write_json", lambda *_args, **_kwargs: None)

    request = SimpleNamespace(base_revision=None, head_revision="a" * 40, force_full=False, ci_context="test")
    decision = SimpleNamespace(required_stage_ids=("first", "second"), normalized_paths=("docs/example.md",))

    assert run_validation_gate._run_command_locked(
        SimpleNamespace(receipt="ignored"),
        tmp_path / "receipt.json",
        request=request,
        decision=decision,
        selected_gate="G0",
        deadline=0.0,
    ) == 1
    results = captured["results"]
    assert [result.status for result in results] == ["timed_out", "skipped"]


def test_public_receipt_verifier_uses_one_absolute_deadline_for_every_replay_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Public receipt replay must not restart a fresh timeout for each preflight."""

    from scripts import run_validation_gate

    source = "a" * 40
    expected_deadline = 1_060.0
    observed: dict[str, object] = {"worktree": [], "revision": []}
    monkeypatch.setattr(run_validation_gate.time, "monotonic", lambda: 1_000.0)

    def load(_path: Path, *, deadline: float) -> dict[str, str]:
        observed["load"] = deadline
        return {"aggregate_result": "passed"}

    def clean(*, deadline: float) -> bool:
        observed["worktree"].append(deadline)
        return True

    def revision(
        _value: str | None,
        _fallback: str | None = None,
        *,
        allow_zero: bool = False,
        deadline: float,
    ) -> str:
        observed["revision"].append(deadline)
        return source

    def artifacts(*_args: object, deadline: float, **_kwargs: object) -> dict[str, str]:
        observed["artifacts"] = deadline
        return {}

    def configuration(*, deadline_monotonic: float) -> dict[str, str]:
        observed["configuration"] = deadline_monotonic
        return {}

    def changed_paths(_base: str | None, _head: str, *, deadline: float) -> tuple[str, ...]:
        observed["changed_paths"] = deadline
        return ()

    def node(*, deadline: float) -> str:
        observed["node"] = deadline
        return "v22.0.0"

    monkeypatch.setattr(run_validation_gate, "_load_bounded_json", load)
    monkeypatch.setattr(run_validation_gate, "_worktree_is_clean", clean)
    monkeypatch.setattr(run_validation_gate, "_revision", revision)
    monkeypatch.setattr(run_validation_gate, "collect_artifact_digests", artifacts)
    monkeypatch.setattr(run_validation_gate, "current_configuration_digests", configuration)
    monkeypatch.setattr(run_validation_gate, "_changed_paths", changed_paths)
    monkeypatch.setattr(run_validation_gate, "_node_version", node)
    monkeypatch.setattr(
        run_validation_gate,
        "verify_verification_receipt",
        lambda *_args, **_kwargs: observed.setdefault("receipt_verified", True),
    )

    assert run_validation_gate.verify_command(
        SimpleNamespace(
            receipt="ignored.json",
            source_revision=source,
            base_revision="none",
            expected_gate="G2",
            expected_force_full="false",
            expected_ci_context="local",
            expected_mode="risk_proportional",
            max_execution_seconds=60,
        )
    ) == 0

    assert observed == {
        "load": expected_deadline,
        "worktree": [expected_deadline, expected_deadline],
        "revision": [expected_deadline, expected_deadline, expected_deadline],
        "artifacts": expected_deadline,
        "configuration": expected_deadline,
        "changed_paths": expected_deadline,
        "node": expected_deadline,
        "receipt_verified": True,
    }


def test_public_receipt_verifier_stops_before_git_after_its_budget_expires(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from scripts import run_validation_gate

    now = 1_000.0
    monkeypatch.setattr(run_validation_gate.time, "monotonic", lambda: now)

    def load(_path: Path, *, deadline: float) -> dict[str, str]:
        nonlocal now
        assert deadline == 1_060.0
        now = deadline
        return {"aggregate_result": "passed"}

    monkeypatch.setattr(run_validation_gate, "_load_bounded_json", load)
    monkeypatch.setattr(
        run_validation_gate,
        "_worktree_is_clean",
        lambda **_kwargs: pytest.fail("Git work must not start after the verifier deadline"),
    )

    with pytest.raises(RuntimeError, match="deadline exhausted"):
        run_validation_gate.verify_command(
            SimpleNamespace(
                receipt="ignored.json",
                source_revision="a" * 40,
                base_revision="none",
                expected_gate="G0",
                expected_force_full="false",
                expected_ci_context="local",
                expected_mode="risk_proportional",
                max_execution_seconds=60,
            )
        )


def test_public_receipt_verifier_cli_rejects_unbounded_execution_budget() -> None:
    from scripts import run_validation_gate

    parser = run_validation_gate.build_parser()
    common = (
        "verify",
        "--receipt",
        "receipt.json",
        "--source-revision",
        "a" * 40,
        "--base-revision",
        "none",
        "--expected-gate",
        "G0",
        "--expected-force-full",
        "false",
        "--expected-ci-context",
        "local",
        "--expected-mode",
        "risk_proportional",
    )

    parsed = parser.parse_args((*common, "--max-execution-seconds", "60"))
    assert parsed.max_execution_seconds == 60
    with pytest.raises(SystemExit):
        parser.parse_args((*common, "--max-execution-seconds", "59"))
