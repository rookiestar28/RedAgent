from __future__ import annotations

from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from redagent_platform.validation.autonomous_planner_qualification import (
    ABORTED,
    AUTONOMOUS_PLANNER_QUALIFIED,
    EXPECTED_FORMAL_ENVIRONMENT,
    NOT_QUALIFIED,
    PINS_SCHEMA,
    PROJECTION_SCHEMA,
    QualificationError,
    build_bundle,
    build_event_chain,
    canonical_bytes,
    canonical_sha256,
    compute_disposition,
    create_stage_result,
    decode_json_bytes,
    load_matrix,
    parse_matrix,
    parse_projection,
    verify_bundle,
    verify_preflight,
)


ROOT = Path(__file__).resolve().parents[2]
MATRIX_PATH = ROOT / "config/validation/autonomous-planner-qualification-v1.json"
ZERO_SHA = "0" * 64


def _projection_payload(matrix) -> dict[str, object]:
    body: dict[str, object] = {
        "schema_version": PROJECTION_SCHEMA,
        "attempt_id": "r163-formal-attempt-1",
        "candidate_commit": "1" * 40,
        "candidate_tree": "2" * 40,
        "candidate_parent_commit": matrix.candidate_parent_commit,
        "matrix_sha256": matrix.matrix_sha256,
        "source_sha256": {path: hashlib.sha256(path.encode("utf-8")).hexdigest() for path in matrix.source_paths},
        "environment": {
            "platform": "windows",
            "architecture": "amd64",
            "python_version": "3.11.9",
            "node_version": "22.14.0",
        },
        "private_manifest_sha256": "3" * 64,
        "operator_identity_sha256": "4" * 64,
        "reviewer_identity_sha256": "5" * 64,
        "trust_anchor_sha256": "6" * 64,
        "runner_ids": [stage.runner_id for stage in matrix.stages],
        "target_hosts": list(matrix.allowed_target_hosts),
        "formal_environment": dict(matrix.formal_environment),
        "max_concurrency": 1,
        "scorer_sha256": matrix.scorer_sha256,
        "retained_artifacts": list(matrix.retained_artifacts),
        "residual_ports": [43161, 43162, 43163, 43164],
        "residual_process_markers": ["redagent-opa", "redagent-openbao", "redagent-stack"],
    }
    return {**body, "projection_sha256": canonical_sha256(body)}


def _projection(matrix):
    return parse_projection(_projection_payload(matrix), matrix)


def _preflight(matrix, projection) -> dict[str, object]:
    return verify_preflight(
        matrix,
        projection,
        observed_commit=projection.candidate_commit,
        observed_tree=projection.candidate_tree,
        observed_parent=projection.candidate_parent_commit,
        observed_branch="dev",
        worktree_clean=True,
        observed_source_sha256=projection.source_sha256,
        observed_environment={
            "platform": projection.platform,
            "architecture": projection.architecture,
            "python_version": projection.python_version,
            "node_version": projection.node_version,
        },
    )


def _stage_log_payloads(matrix) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for stage in matrix.stages:
        payloads[f"stages/{stage.stage_id}.stdout.log"] = f"{stage.stage_id}: passed\n".encode()
        payloads[f"stages/{stage.stage_id}.stderr.log"] = b""
    payloads["forced-g2-verification.json"] = b'{"aggregate_result":"passed"}\n'
    return payloads


def _passed_stage_results(matrix, payloads: dict[str, bytes]) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for stage in matrix.stages:
        stdout_path = f"stages/{stage.stage_id}.stdout.log"
        stderr_path = f"stages/{stage.stage_id}.stderr.log"
        results.append(
            create_stage_result(
                stage,
                status="passed",
                exit_code=0,
                passed_count=stage.expected_pass_count,
                skipped_count=stage.allowed_skip_count,
                stdout_sha256=hashlib.sha256(payloads[stdout_path]).hexdigest(),
                stderr_sha256=hashlib.sha256(payloads[stderr_path]).hexdigest(),
                artifact_sha256={path: hashlib.sha256(payloads[path]).hexdigest() for path in stage.expected_artifacts},
                unapproved_assessment_contacts=0,
                cleanup_complete=True,
                detail="all_fixed_runner_contracts_passed",
            )
        )
    return results


def _events(matrix, projection, preflight, stage_results, result):
    inputs = [
        ("preflight_passed", {"preflight_sha256": preflight["preflight_sha256"]}),
        ("attempt_started", {"attempt_id": projection.attempt_id}),
    ]
    inputs.extend(
        (
            "stage_completed",
            {
                "stage_id": stage.stage_id,
                "stage_result_sha256": stage_result["stage_result_sha256"],
            },
        )
        for stage, stage_result in zip(matrix.stages, stage_results, strict=True)
    )
    inputs.append(("attempt_terminal", {"result_sha256": result["result_sha256"]}))
    return build_event_chain(inputs)


def _accepted_ceremony():
    matrix = load_matrix(MATRIX_PATH)
    projection = _projection(matrix)
    preflight = _preflight(matrix, projection)
    payloads = _stage_log_payloads(matrix)
    stage_results = _passed_stage_results(matrix, payloads)
    result = compute_disposition(matrix, stage_results, protocol_drift=False, artifacts_complete=True)
    events = _events(matrix, projection, preflight, stage_results, result)
    payloads.update(
        {
            "preflight.json": canonical_bytes(preflight) + b"\n",
            "stage-results.json": canonical_bytes(stage_results) + b"\n",
            "events.jsonl": b"".join(canonical_bytes(event) + b"\n" for event in events),
        }
    )
    artifact_sha256 = {path: hashlib.sha256(payload).hexdigest() for path, payload in sorted(payloads.items())}
    bundle = build_bundle(
        matrix,
        projection,
        preflight,
        stage_results,
        artifact_sha256,
        events,
        protocol_drift=False,
    )
    pin_body = {
        "schema_version": PINS_SCHEMA,
        "matrix_sha256": matrix.matrix_sha256,
        "projection_sha256": projection.projection_sha256,
        "candidate_commit": projection.candidate_commit,
        "candidate_tree": projection.candidate_tree,
        "private_manifest_sha256": projection.private_manifest_sha256,
        "trust_anchor_sha256": projection.trust_anchor_sha256,
    }
    pins = {**pin_body, "pins_sha256": canonical_sha256(pin_body)}
    return matrix, projection, preflight, payloads, stage_results, events, bundle, pins


def _rehash_projection(payload: dict[str, object]) -> None:
    body = {key: value for key, value in payload.items() if key != "projection_sha256"}
    payload["projection_sha256"] = canonical_sha256(body)


def test_matrix_is_source_pinned_closed_and_complete() -> None:
    matrix = load_matrix(MATRIX_PATH)

    assert matrix.max_concurrency == 1
    assert matrix.required_score_basis_points == 10_000
    assert matrix.conditional_allowlist == ()
    assert matrix.allowed_target_hosts == ("127.0.0.1", "::1", "localhost")
    assert dict(matrix.formal_environment) == EXPECTED_FORMAL_ENVIRONMENT
    assert matrix.validation_dependency_runner_ids == ("windows-full-gate",)
    assert len(matrix.accepted_predecessors) == 8
    assert len(matrix.stages) == 7
    assert matrix.retained_artifacts == tuple(sorted(matrix.retained_artifacts))


def test_coherently_rehashed_matrix_drift_still_fails_the_trusted_digest() -> None:
    payload = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    payload["max_concurrency"] = 2
    body = {key: value for key, value in payload.items() if key != "matrix_sha256"}
    payload["matrix_sha256"] = canonical_sha256(body)

    with pytest.raises(QualificationError, match="trusted matrix digest mismatch"):
        parse_matrix(payload)


def test_json_decoder_rejects_duplicates_bom_empty_and_unbounded_nesting() -> None:
    with pytest.raises(QualificationError, match="duplicate JSON field"):
        decode_json_bytes(b'{"field":1,"field":2}', label="fixture", maximum_bytes=100)
    with pytest.raises(QualificationError, match="byte contract"):
        decode_json_bytes(b"", label="fixture", maximum_bytes=100)
    with pytest.raises(QualificationError, match="byte contract"):
        decode_json_bytes(b"\xef\xbb\xbf{}", label="fixture", maximum_bytes=100)
    nested = b"[" * 18 + b"0" + b"]" * 18
    with pytest.raises(QualificationError, match="nesting"):
        decode_json_bytes(nested, label="fixture", maximum_bytes=100)


def test_projection_denies_target_runner_identity_and_candidate_lineage_drift() -> None:
    matrix = load_matrix(MATRIX_PATH)
    payload = _projection_payload(matrix)

    cases = (
        ("target_hosts", ["example.com"]),
        ("runner_ids", [stage.runner_id for stage in reversed(matrix.stages)]),
        ("candidate_parent_commit", "f" * 40),
        ("reviewer_identity_sha256", payload["operator_identity_sha256"]),
        (
            "formal_environment",
            {**dict(matrix.formal_environment), "REDAGENT_OPA_HOST_PORT": "9999"},
        ),
    )
    for field, value in cases:
        mutated = deepcopy(payload)
        mutated[field] = value
        _rehash_projection(mutated)
        with pytest.raises(QualificationError):
            parse_projection(mutated, matrix)


def test_preflight_requires_exact_clean_direct_successor_on_windows_dev() -> None:
    matrix = load_matrix(MATRIX_PATH)
    projection = _projection(matrix)
    preflight = _preflight(matrix, projection)

    assert preflight["branch"] == "dev"
    assert preflight["worktree_clean"] is True
    assert preflight["formal_run_authority"] is False
    assert preflight["remote_authority"] is False
    with pytest.raises(QualificationError, match="exact clean candidate preflight failed"):
        verify_preflight(
            matrix,
            projection,
            observed_commit=projection.candidate_commit,
            observed_tree=projection.candidate_tree,
            observed_parent=projection.candidate_parent_commit,
            observed_branch="main",
            worktree_clean=True,
            observed_source_sha256=projection.source_sha256,
            observed_environment={
                "platform": projection.platform,
                "architecture": projection.architecture,
                "python_version": projection.python_version,
                "node_version": projection.node_version,
            },
        )


def test_disposition_is_all_or_nothing_and_never_grants_authority() -> None:
    matrix, _projection_value, _preflight_value, payloads, stage_results, *_rest = _accepted_ceremony()
    accepted = compute_disposition(matrix, stage_results, protocol_drift=False)

    assert accepted["disposition"] == AUTONOMOUS_PLANNER_QUALIFIED
    assert accepted["score_basis_points"] == 10_000
    assert accepted["execution_authority"] is False
    assert accepted["remote_authority"] is False
    failed_results = deepcopy(stage_results)
    stage = matrix.stages[0]
    stdout_path = f"stages/{stage.stage_id}.stdout.log"
    stderr_path = f"stages/{stage.stage_id}.stderr.log"
    failed_results[0] = create_stage_result(
        stage,
        status="failed",
        exit_code=1,
        passed_count=stage.expected_pass_count,
        skipped_count=0,
        stdout_sha256=hashlib.sha256(payloads[stdout_path]).hexdigest(),
        stderr_sha256=hashlib.sha256(payloads[stderr_path]).hexdigest(),
        artifact_sha256={},
        unapproved_assessment_contacts=0,
        cleanup_complete=False,
        detail="mandatory_fixed_runner_or_result_contract_failed",
    )
    assert compute_disposition(matrix, failed_results, protocol_drift=False)["disposition"] == NOT_QUALIFIED
    assert compute_disposition(matrix, [], protocol_drift=True)["disposition"] == ABORTED


def test_accepted_bundle_verifies_offline_against_exact_payloads_and_pins() -> None:
    matrix, projection, _preflight_value, payloads, _stage_results, _events_value, bundle, pins = _accepted_ceremony()

    verified = verify_bundle(matrix, projection, bundle, pins, payloads)

    assert verified["verified"] is True
    assert verified["disposition"] == AUTONOMOUS_PLANNER_QUALIFIED
    assert verified["execution_authority"] is False
    assert verified["release_authority"] is False
    assert verified["ga_authority"] is False


def test_offline_verifier_rejects_artifact_bytes_or_pin_tamper() -> None:
    matrix, projection, _preflight_value, payloads, _stage_results, _events_value, bundle, pins = _accepted_ceremony()
    tampered_payloads = dict(payloads)
    tampered_payloads["preflight.json"] += b" "
    with pytest.raises(QualificationError, match="offline artifact digest mismatch"):
        verify_bundle(matrix, projection, bundle, pins, tampered_payloads)

    tampered_pins = dict(pins)
    tampered_pins["candidate_tree"] = "f" * 40
    with pytest.raises(QualificationError, match="pins digest mismatch"):
        verify_bundle(matrix, projection, bundle, tampered_pins, payloads)


def test_bundle_builder_rejects_cross_attempt_log_event_and_preflight_splicing() -> None:
    matrix, projection, preflight, payloads, stage_results, events, _bundle, _pins = _accepted_ceremony()
    artifact_sha256 = {path: hashlib.sha256(payload).hexdigest() for path, payload in sorted(payloads.items())}

    spliced_results = deepcopy(stage_results)
    body = {key: value for key, value in spliced_results[0].items() if key != "stage_result_sha256"}
    body["stdout_sha256"] = ZERO_SHA
    spliced_results[0] = {**body, "stage_result_sha256": canonical_sha256(body)}
    result = compute_disposition(matrix, spliced_results, protocol_drift=False)
    spliced_events = _events(matrix, projection, preflight, spliced_results, result)
    spliced_payloads = dict(payloads)
    spliced_payloads["stage-results.json"] = canonical_bytes(spliced_results) + b"\n"
    spliced_payloads["events.jsonl"] = b"".join(canonical_bytes(event) + b"\n" for event in spliced_events)
    spliced_digests = {path: hashlib.sha256(payload).hexdigest() for path, payload in sorted(spliced_payloads.items())}
    with pytest.raises(QualificationError, match="stdout binding mismatch"):
        build_bundle(
            matrix,
            projection,
            preflight,
            spliced_results,
            spliced_digests,
            spliced_events,
            protocol_drift=False,
        )

    wrong_events = build_event_chain(
        [
            ("preflight_passed", {"preflight_sha256": preflight["preflight_sha256"]}),
            ("attempt_started", {"attempt_id": "another-attempt"}),
            *(
                (
                    "stage_completed",
                    {
                        "stage_id": stage.stage_id,
                        "stage_result_sha256": stage_result["stage_result_sha256"],
                    },
                )
                for stage, stage_result in zip(matrix.stages, stage_results, strict=True)
            ),
            (
                "attempt_terminal",
                {"result_sha256": compute_disposition(matrix, stage_results, protocol_drift=False)["result_sha256"]},
            ),
        ]
    )
    wrong_payloads = dict(payloads)
    wrong_payloads["events.jsonl"] = b"".join(canonical_bytes(event) + b"\n" for event in wrong_events)
    wrong_digests = {path: hashlib.sha256(payload).hexdigest() for path, payload in sorted(wrong_payloads.items())}
    with pytest.raises(QualificationError, match="event payload binding mismatch"):
        build_bundle(
            matrix,
            projection,
            preflight,
            stage_results,
            wrong_digests,
            wrong_events,
            protocol_drift=False,
        )

    spliced_preflight = dict(preflight)
    preflight_body = {key: value for key, value in spliced_preflight.items() if key != "preflight_sha256"}
    preflight_body["remote_authority"] = True
    spliced_preflight = {**preflight_body, "preflight_sha256": canonical_sha256(preflight_body)}
    with pytest.raises(QualificationError, match="authority binding mismatch"):
        build_bundle(
            matrix,
            projection,
            spliced_preflight,
            stage_results,
            artifact_sha256,
            events,
            protocol_drift=False,
        )


def test_event_chain_rejects_missing_reordered_or_tampered_lifecycle() -> None:
    matrix, projection, preflight, _payloads, stage_results, events, _bundle, _pins = _accepted_ceremony()
    result = compute_disposition(matrix, stage_results, protocol_drift=False)
    with pytest.raises(QualificationError, match="formal event lifecycle invalid"):
        build_event_chain(
            [
                ("attempt_started", {"attempt_id": projection.attempt_id}),
                ("preflight_passed", {"preflight_sha256": preflight["preflight_sha256"]}),
                *((events[index]["kind"], events[index]["payload"]) for index in range(2, len(events) - 1)),
                ("attempt_terminal", {"result_sha256": result["result_sha256"]}),
            ]
        )


def test_cli_surface_has_only_fixed_commands_and_no_operator_target_input() -> None:
    from scripts import autonomous_planner_qualification as cli

    assert cli.build_parser().parse_args(["preflight"]).command == "preflight"
    assert cli.build_parser().parse_args(["run"]).command == "run"
    assert cli.build_parser().parse_args(["verify"]).command == "verify"
    with pytest.raises(SystemExit):
        cli.build_parser().parse_args(["run", "--target", "https://example.com"])
    commands = cli._runner_commands("pytest-authority-to-terminal", "1" * 40, "2" * 40)
    assert commands[0][1:3] == ("-m", "pytest")
    assert all("http://" not in argument and "https://" not in argument for command in commands for argument in command)
    with pytest.raises(QualificationError, match="unknown qualification runner"):
        cli._runner_commands("operator-selected", "1" * 40, "2" * 40)

    cleanup = cli._runner_commands("owned-runtime-cleanup", "1" * 40, "2" * 40)
    assert [Path(command[1]).name for command in cleanup] == [
        "openbao_conformance.py",
        "opa_conformance.py",
        "redagent_local_stack.py",
    ]


def test_formal_children_receive_only_the_source_pinned_redagent_environment(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_PATH)
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "STAGE_LOG_ROOT", tmp_path / "stages")
    monkeypatch.setenv("REDAGENT_COMPOSE_PROJECT_NAME", "ambient-project-must-not-survive")
    monkeypatch.setenv("RedAgent_Unexpected_Override", "must-not-survive")
    captured: dict[str, object] = {}

    def fixed_run(command, **kwargs):
        captured["command"] = command
        captured["environment"] = kwargs["env"]
        return cli.subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(cli.subprocess, "run", fixed_run)
    completed_count, launch_aborted = cli._run_processes(
        (("fixed-tool", "fixed-argument"),),
        matrix.stages[0],
        matrix.formal_environment,
    )

    assert completed_count == 1
    assert launch_aborted is False
    environment = captured["environment"]
    assert isinstance(environment, dict)
    observed = {key: value for key, value in environment.items() if key.upper().startswith("REDAGENT_")}
    assert observed == EXPECTED_FORMAL_ENVIRONMENT


def test_cli_atomic_writer_never_replaces_a_named_artifact(tmp_path: Path, monkeypatch) -> None:
    from scripts import autonomous_planner_qualification as cli

    monkeypatch.setattr(cli, "ROOT", tmp_path)
    artifact = tmp_path / ".tmp/autonomous-planner-qualification/preflight.json"

    cli._atomic_write(artifact, b"first\n")

    with pytest.raises(QualificationError, match="output already exists"):
        cli._atomic_write(artifact, b"replacement\n")
    assert artifact.read_bytes() == b"first\n"


def test_declared_item_runtime_paths_are_removed_without_touching_other_outputs(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_PATH)
    output_root = tmp_path / ".tmp/autonomous-planner-qualification"
    monkeypatch.setattr(cli, "ROOT", tmp_path)
    monkeypatch.setattr(cli, "OUTPUT_ROOT", output_root)
    monkeypatch.setattr(cli, "RUNTIME_ROOT", output_root / "runtime")
    monkeypatch.setattr(cli, "STAGE_LOG_ROOT", output_root / "stages")
    for relative in matrix.cleanup_paths:
        owned_path = tmp_path / Path(relative)
        owned_path.mkdir(parents=True, exist_ok=True)
        (owned_path / "item-owned.txt").write_text("fixture", encoding="utf-8")
    unrelated = output_root / "preflight.json"
    unrelated.parent.mkdir(parents=True, exist_ok=True)
    unrelated.write_text("retained", encoding="utf-8")
    cli._remove_item_runtime_paths(matrix)
    assert all(not (tmp_path / Path(relative)).exists() for relative in matrix.cleanup_paths)
    assert unrelated.read_text(encoding="utf-8") == "retained"


def test_formal_stage_environment_failure_is_retained_as_terminal_aborted_evidence(
    tmp_path: Path,
    monkeypatch,
) -> None:
    from scripts import autonomous_planner_qualification as cli

    matrix = load_matrix(MATRIX_PATH)
    projection = _projection(matrix)
    preflight = _preflight(matrix, projection)
    output_root = tmp_path / ".tmp/autonomous-planner-qualification"
    replacements = {
        "ROOT": tmp_path,
        "OUTPUT_ROOT": output_root,
        "RUNTIME_ROOT": output_root / "runtime",
        "STAGE_LOG_ROOT": output_root / "stages",
        "PREFLIGHT_PATH": output_root / "preflight.json",
        "STAGE_RESULTS_PATH": output_root / "stage-results.json",
        "EVENTS_PATH": output_root / "events.jsonl",
        "BUNDLE_PATH": output_root / "qualification-bundle.json",
        "FORCED_G2_RETAINED": output_root / "forced-g2-verification.json",
    }
    for name, value in replacements.items():
        monkeypatch.setattr(cli, name, value)
    cli._atomic_write(cli.PREFLIGHT_PATH, canonical_bytes(preflight) + b"\n")
    monkeypatch.setattr(cli, "_load_inputs", lambda: (matrix, projection, {}))
    monkeypatch.setattr(cli, "_observe_preflight", lambda *_args: preflight)

    def unavailable(*_args):
        raise QualificationError("required fixed tool unavailable")

    monkeypatch.setattr(cli, "_execute_stage", unavailable)

    assert cli.run_command() == 1
    stage_results = json.loads(cli.STAGE_RESULTS_PATH.read_text(encoding="utf-8"))
    bundle = json.loads(cli.BUNDLE_PATH.read_text(encoding="utf-8"))
    assert len(stage_results) == len(matrix.stages)
    assert all(result["status"] == "aborted" for result in stage_results)
    assert bundle["result"]["disposition"] == ABORTED
    assert bundle["result"]["protocol_drift"] is True
    assert len(bundle["events"]) == len(matrix.stages) + 3
