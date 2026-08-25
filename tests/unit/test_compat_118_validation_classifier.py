from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from redagent_platform.validation import (
    ChangeRequest,
    classify_change,
)
from redagent_platform.validation import classifier as classifier_module
from redagent_platform.validation.config import PathMappingConfig, PathRule
from redagent_platform.validation.stages import ValidationConfigError


ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "tests/fixtures/compat_118_validation_corpus.json"
BASE = "a" * 40
HEAD = "b" * 40

# Frozen pre-R118 full-gate intent. This list is deliberately independent of
# the production stage registry so deleting a mandatory stage cannot weaken
# both the implementation and its oracle in the same change.
LEGACY_FULL_STAGE_IDS = {
    "local-stack",
    "database-upgrade",
    "openbao-conformance",
    "opa-validate",
    "opa-build",
    "opa-build-rollback",
    "opa-provision",
    "secure-sdlc",
    "agent-skills",
    "pre-commit-all-files",
    "backend-tests",
    "frontend-install",
    "frontend-audit",
    "frontend-api-check",
    "frontend-typecheck",
    "frontend-lint",
    "frontend-unit",
    "frontend-build",
    "playwright-install",
    "frontend-e2e",
}


def _request(*paths: str, base: str | None = BASE, force_full: bool = False) -> ChangeRequest:
    return ChangeRequest(
        base_revision=base,
        head_revision=HEAD,
        changed_paths=paths,
        force_full=force_full,
    )


def test_frozen_corpus_contains_100_deterministic_selection_cases() -> None:
    payload = json.loads(CORPUS.read_text(encoding="utf-8"))
    cases = payload["cases"]
    assert payload["shadow_comparison"] == {
        "decision": "retired",
        "decision_date": "2026-08-24",
        "active_comparisons": 0,
    }
    legacy_required = {
        "hooks": {"changed-file-hooks"},
        "backend": {"secure-sdlc", "agent-skills", "changed-file-hooks", "backend-tests"},
        "frontend": {
            "secure-sdlc",
            "agent-skills",
            "changed-file-hooks",
            "frontend-install",
            "frontend-typecheck",
            "frontend-lint",
            "frontend-unit",
            "frontend-build",
        },
        "full": LEGACY_FULL_STAGE_IDS,
    }

    assert payload["schema_version"] == "5"
    assert len(cases) == 100
    assert len({case["id"] for case in cases}) == 100
    assert len({case["path"] for case in cases}) == 100
    observed_change_kinds: set[str] = set()
    tracked = set(
        subprocess.run(
            ("git", "ls-files"),
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            shell=False,
        ).stdout.splitlines()
    )
    if not tracked:
        pytest.skip("public bootstrap has no committed file inventory yet")
    for case in cases:
        case_id = case["id"]
        path = case["path"]
        case_paths = (path, *case.get("additional_paths", ()))
        first = classify_change(_request(*case_paths))
        second = classify_change(_request(*case_paths))
        assert all(case_path in tracked for case_path in case_paths), case_id
        assert first.selected_gate == case["expected_gate"], case_id
        assert first == second, case_id
        assert len(first.decision_digest) == 64, case_id
        assert legacy_required[case["legacy_profile"]] <= set(first.required_stage_ids), case_id
        change_kind = case.get("change_kind", "modify")
        observed_change_kinds.add(change_kind)
    assert {"modify", "delete", "rename", "mixed"} <= observed_change_kinds


@pytest.mark.parametrize(
    ("change_request", "reason"),
    [
        (_request("../PUBLIC_RELEASE.md"), "invalid_path"),
        (_request("C:/outside.txt"), "invalid_path"),
        (_request("docs/guide.md", base=None), "missing_base_revision"),
        (_request("unknown/file.bin"), "unknown_path"),
        (_request("docs/guide.md", force_full=True), "force_full"),
        (_request(*[f"docs/{index}.md" for index in range(501)]), "changed_path_limit_exceeded"),
        (_request(".github/workflows/validation.yml"), "protected_validation_change"),
    ],
)
def test_ambiguous_or_unsafe_inputs_fail_closed_to_g2(
    change_request: ChangeRequest,
    reason: str,
) -> None:
    decision = classify_change(change_request)

    assert decision.selected_gate == "G2"
    assert reason in decision.reasons


def test_normalization_rejects_duplicates_after_separator_and_case_folding() -> None:
    decision = classify_change(_request("docs/Guide.md", "docs\\guide.md"))

    assert decision.selected_gate == "G2"
    assert "duplicate_normalized_path" in decision.reasons


@pytest.mark.parametrize(
    "path",
    [
        "redagent_platform/finding_operations/promotion.py",
        "redagent_platform/finding_operations/qualification.py",
        "redagent_platform/future/release.py",
        "redagent_platform/future/provenance.py",
        "redagent_platform/future/secret_scan.py",
    ],
)
def test_nested_authority_names_are_code_owned_g2_boundaries(path: str) -> None:
    decision = classify_change(_request(path))

    assert decision.selected_gate == "G2"
    assert "protected_validation_change" in decision.reasons


def test_authoritative_validation_lease_is_a_validator_test_g2_boundary() -> None:
    decision = classify_change(_request("redagent_platform/gate_lease.py"))

    assert decision.selected_gate == "G2"
    assert decision.planes == ("validator_test",)
    assert "protected_validation_change" in decision.reasons


@pytest.mark.parametrize(
    "path",
    [
        "docs/AWS_SECRET_ACCESS_KEY=leaked.txt",  # pragma: allowlist secret
        "docs/AWS_ACCESS_KEY_ID=leaked.txt",  # pragma: allowlist secret
        "docs/PRIVATE_KEY=leaked.txt",  # pragma: allowlist secret
        "docs/AUTHORIZATION=Bearer-leaked.txt",  # pragma: allowlist secret
    ],
)
def test_secret_like_path_assignments_cannot_enter_selective_argv(path: str) -> None:
    decision = classify_change(_request(path))

    assert decision.selected_gate == "G2"
    assert "secret_like_path" in decision.reasons


def test_mixed_planes_escalate_and_digest_is_order_independent() -> None:
    first = classify_change(_request("frontend/src/App.tsx", "redagent_platform/artifact_pipeline/analysis.py"))
    second = classify_change(_request("redagent_platform/artifact_pipeline/analysis.py", "frontend/src/App.tsx"))

    assert first.selected_gate == "G2"
    assert first.normalized_paths == second.normalized_paths
    assert first.decision_digest == second.decision_digest
    assert first.planes == ("infrastructure_release",)


def test_g1_required_stages_are_plane_specific_without_under_selection() -> None:
    backend = classify_change(_request("redagent_platform/artifact_pipeline/analysis.py"))
    frontend = classify_change(_request("frontend/src/App.tsx"))

    assert backend.selected_gate == "G2"
    assert "backend-tests" in backend.required_stage_ids
    assert "frontend-unit" in backend.required_stage_ids
    assert frontend.selected_gate == "G1"
    assert "frontend-typecheck" in frontend.required_stage_ids
    assert "frontend-unit" in frontend.required_stage_ids
    assert "backend-tests" not in frontend.required_stage_ids


@pytest.mark.parametrize(
    "path",
    [
        "redagent_platform/runner_service/dispatch.py",
        "redagent_platform/policy_service/decision.py",
        "redagent_platform/secret_service/leases.py",
        "redagent_platform/containment_service/kill.py",
        "redagent_platform/lab_service/execution.py",
        "redagent_platform/nuclei_service/adapter.py",
        "redagent_platform/zap_service/adapter.py",
        "redagent_platform/deployment_release/provenance.py",
        "redagent_platform/ga_qualification/decision.py",
        "redagent_platform/ga_qualification/security_review.py",
        "redagent_platform/artifact_pipeline/promotion.py",
        "redagent_platform/artifact_pipeline/secret_scan.py",
        "redagent_platform/identity_saas/session.py",
        "redagent_platform/mcp_broker/gateway.py",
        "redagent_platform/active_policy.py",
        "redagent_platform/credentials.py",
        "redagent_platform/kill_switch.py",
        "redagent_platform/runner_isolation.py",
    ],
)
def test_actual_authority_bearing_repository_paths_always_select_g2(path: str) -> None:
    decision = classify_change(_request(path))

    assert decision.selected_gate == "G2", path


def test_every_tracked_root_python_module_conservatively_selects_g2() -> None:
    tracked_root_modules = sorted(
        path.relative_to(ROOT).as_posix()
        for path in (ROOT / "redagent_platform").glob("*.py")
        if path.is_file()
    )

    assert len(tracked_root_modules) >= 50
    for path in tracked_root_modules:
        assert classify_change(_request(path)).selected_gate == "G2", path


def test_selective_command_budget_escalates_before_receipt_argv_overflow() -> None:
    decision = classify_change(_request(*[f"docs/change-{index}.md" for index in range(60)]))

    assert decision.selected_gate == "G2"
    assert "selective_command_budget_exceeded" in decision.reasons


def test_code_owned_protected_paths_cannot_be_downgraded_by_candidate_mapping() -> None:
    malicious_mapping = PathMappingConfig(
        schema_version="1",
        classifier_revision="malicious",
        max_changed_paths=500,
        rules=(PathRule(plane="documentation", prefixes=("config/validation/",)),),
    )

    decision = classify_change(
        _request("config/validation/r118-path-mapping.json"),
        mapping=malicious_mapping,
    )

    assert decision.selected_gate == "G2"
    assert "protected_validation_change" in decision.reasons


def test_classifier_configuration_failure_returns_stable_g2_fallback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def fail_mapping() -> PathMappingConfig:
        raise ValidationConfigError("malformed mapping")

    monkeypatch.setattr(classifier_module, "_default_mapping", fail_mapping)

    first = classify_change(_request("docs/guide.md"))
    second = classify_change(_request("docs/guide.md"))

    assert first == second
    assert first.selected_gate == "G2"
    assert first.reasons == ("classifier_config_error",)
