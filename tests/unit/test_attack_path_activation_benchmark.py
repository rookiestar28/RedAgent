from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys

import pytest

from redagent_platform.campaign_service.contracts import StrategyObjectiveKind
from redagent_platform.campaign_service.registry import closed_execution_registry
from redagent_platform.validation.attack_path_benchmark import (
    ACTIVATE_BOUNDED_ATTACK_PATH_PLANNING,
    INSUFFICIENT_CURRENT_NEED,
    BenchmarkError,
    canonical_sha256,
    decide_activation,
    load_corpus,
    parse_corpus,
    run_benchmark,
    validate_plan,
)


ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = ROOT / "config/validation/attack-path-activation-benchmark-v1.json"
CLI_PATH = ROOT / "scripts/attack_path_activation_benchmark.py"
RECEIPT_PATH = ROOT / ".tmp/attack-path-activation-benchmark/receipt.json"


def _payload() -> dict[str, object]:
    return json.loads(CORPUS_PATH.read_text(encoding="utf-8"))


def _rehash(payload: dict[str, object]) -> dict[str, object]:
    body = {key: value for key, value in payload.items() if key != "corpus_sha256"}
    payload["corpus_sha256"] = canonical_sha256(body)
    return payload


def test_frozen_corpus_covers_exact_current_objective_and_capability_contract() -> None:
    corpus = load_corpus(CORPUS_PATH)

    assert corpus.capability_ids == (
        "artifact-posture",
        "nuclei-trusted-runtime",
        "zap-controlled-runtime",
    )
    assert corpus.objective_kinds == (
        "http_posture",
        "repository_snapshot_posture",
        "security_header_assertion",
    )
    assert corpus.capability_ids == tuple(
        sorted(item.capability_id for item in closed_execution_registry().values())
    )
    assert corpus.objective_kinds == tuple(sorted(item.value for item in StrategyObjectiveKind))
    assert len(corpus.operators) == 5
    assert len(corpus.cases) == 12
    assert {case.provenance for case in corpus.cases} == {
        "synthetic_owned_loopback"
    }


def test_current_depth_two_bound_is_sufficient_and_receipt_is_canonical() -> None:
    corpus = load_corpus(CORPUS_PATH)

    first = run_benchmark(corpus)
    second = run_benchmark(corpus)

    assert first == second
    assert first["decision"] == INSUFFICIENT_CURRENT_NEED
    assert first["coverage_case_count"] == 0
    assert first["coverage_fraction_basis_points"] == 0
    assert first["quality_gap_case_count"] == 0
    assert first["quality_mean_basis_points"] == 10_000
    assert first["realism_gate_passed"] is False
    assert first["provenance_profile"] == "synthetic_owned_loopback_only"
    assert first["provenance_counts"] == {
        "authorized_history_derived": 0,
        "synthetic_owned_loopback": 12,
    }
    assert first["execution_authority"] is False
    assert first["release_approval"] is False
    assert first["production_release_authority"] is False
    assert first["go_authority"] is False
    assert first["ga_authority"] is False
    assert first["receipt_sha256"] == canonical_sha256(
        {key: value for key, value in first.items() if key != "receipt_sha256"}
    )


def test_every_oracle_and_depth_two_plan_is_independently_certified() -> None:
    corpus = load_corpus(CORPUS_PATH)
    receipt = run_benchmark(corpus)

    assert len(receipt["case_certifications"]) == len(corpus.cases)
    for result in receipt["case_certifications"]:
        case = next(item for item in corpus.cases if item.case_id == result["case_id"])
        optimal = validate_plan(corpus, case, tuple(result["optimal_length_plan"]))
        depth_two = validate_plan(corpus, case, tuple(result["depth_two_plan"]))
        assert optimal.length == result["optimal_length"]
        assert optimal.certification_sha256 == result["optimal_length_certification_sha256"]
        assert depth_two.cost == result["depth_two_cost"]
        assert depth_two.certification_sha256 == result["depth_two_certification_sha256"]


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda value: value.update({"unexpected": True}), "corpus fields invalid"),
        (lambda value: value.update({"schema_version": "wrong"}), "schema invalid"),
        (
            lambda value: value["thresholds"].update(  # type: ignore[union-attr]
                {"coverage_fraction_min_basis_points": 999}
            ),
            "threshold contract invalid",
        ),
        (
            lambda value: value["capability_ids"].append("arbitrary-command"),  # type: ignore[union-attr]
            "capability contract invalid",
        ),
        (
            lambda value: value["operators"][0].update(  # type: ignore[index,union-attr]
                {"objective_kind": "unknown"}
            ),
            "operator objective invalid",
        ),
        (
            lambda value: value["cases"][0].update(  # type: ignore[index,union-attr]
                {"target": "https://example.invalid"}
            ),
            "case fields invalid",
        ),
    ),
)
def test_corpus_schema_and_frozen_contract_fail_closed(mutation, message: str) -> None:
    payload = _payload()
    mutation(payload)
    _rehash(payload)

    with pytest.raises(BenchmarkError, match=message):
        parse_corpus(payload)


def test_corpus_digest_tamper_fails_before_evaluation() -> None:
    payload = _payload()
    payload["cases"][0]["goal_facts"].append("tampered")  # type: ignore[index,union-attr]

    with pytest.raises(BenchmarkError, match="corpus digest mismatch"):
        parse_corpus(payload)


@pytest.mark.parametrize(
    ("operator_ids", "message"),
    (
        (
            ("artifact-posture:repository-snapshot-posture",),
            "plan operator objective mismatch",
        ),
        (("zap-controlled-runtime:http-posture",), "plan goal unsatisfied"),
        (
            (
                "zap-controlled-runtime:http-posture",
                "zap-controlled-runtime:http-posture",
            ),
            "plan operator repeated",
        ),
    ),
)
def test_independent_validator_rejects_invalid_or_self_certifying_plans(
    operator_ids: tuple[str, ...], message: str
) -> None:
    corpus = load_corpus(CORPUS_PATH)
    case = next(
        item for item in corpus.cases if item.case_id == "http-posture-two-source"
    )

    with pytest.raises(BenchmarkError, match=message):
        validate_plan(corpus, case, operator_ids)


def test_synthetic_positive_signal_cannot_activate_high_risk_successor() -> None:
    assert (
        decide_activation(
            coverage_signal=True,
            quality_signal=False,
            positive_case_provenances=("synthetic_owned_loopback",),
        )
        == INSUFFICIENT_CURRENT_NEED
    )
    assert (
        decide_activation(
            coverage_signal=True,
            quality_signal=False,
            positive_case_provenances=("authorized_history_derived",),
        )
        == ACTIVATE_BOUNDED_ATTACK_PATH_PLANNING
    )


def test_case_order_does_not_change_canonical_decision() -> None:
    payload = _payload()
    expected = run_benchmark(parse_corpus(payload))
    payload["cases"] = list(reversed(payload["cases"]))  # type: ignore[arg-type]
    _rehash(payload)

    with pytest.raises(BenchmarkError, match="cases must be sorted"):
        parse_corpus(payload)

    payload["cases"] = sorted(payload["cases"], key=lambda item: item["case_id"])  # type: ignore[arg-type,index]
    _rehash(payload)
    assert run_benchmark(parse_corpus(payload)) == expected


def _cli(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(CLI_PATH), *arguments],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_cli_runs_and_verifies_only_the_fixed_repository_receipt() -> None:
    run = _cli("run")
    verify = _cli("verify")
    escaped = _cli("run", "--output", str(ROOT.parent / "forbidden.json"))

    assert run.returncode == verify.returncode == 0
    assert json.loads(run.stdout)["decision"] == INSUFFICIENT_CURRENT_NEED
    assert json.loads(verify.stdout)["receipt_sha256"] == json.loads(run.stdout)[
        "receipt_sha256"
    ]
    assert RECEIPT_PATH.is_file()
    assert escaped.returncode == 2
    assert not (ROOT.parent / "forbidden.json").exists()


def test_cli_rejects_duplicate_receipt_keys_even_when_values_are_coherent() -> None:
    assert _cli("run").returncode == 0
    original = RECEIPT_PATH.read_text(encoding="utf-8")
    duplicated = original.replace(
        "{\n", '{\n  "decision": "INSUFFICIENT_CURRENT_NEED",\n', 1
    )
    RECEIPT_PATH.write_text(duplicated, encoding="utf-8", newline="\n")
    try:
        verify = _cli("verify")
        assert verify.returncode == 2
        assert "duplicate JSON field" in verify.stderr
    finally:
        assert _cli("run").returncode == 0
