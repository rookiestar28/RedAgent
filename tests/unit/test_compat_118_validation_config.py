from __future__ import annotations

import json
from pathlib import Path
import tomllib

import pytest

from redagent_platform.validation import (
    ChangeRequest,
    ValidationConfigError,
    classify_change,
    load_path_mapping,
    load_stage_registry,
)


ROOT = Path(__file__).resolve().parents[2]
PATH_MAPPING = ROOT / "config/validation/r118-path-mapping.json"
STAGE_REGISTRY = ROOT / "config/validation/r118-stage-registry.json"


def test_default_versioned_configuration_loads_with_closed_schema() -> None:
    mapping = load_path_mapping(PATH_MAPPING)
    registry = load_stage_registry(STAGE_REGISTRY)

    assert mapping.schema_version == "1"
    assert mapping.classifier_revision == "r118-classifier-v1"
    assert mapping.max_changed_paths == 500
    assert len(mapping.rules) >= 10
    assert len(registry.plan("G2")) >= 20
    backend = next(stage for stage in registry.plan("G2") if stage.id == "backend-tests")
    assert backend.argv == ("python", "-m", "pytest", "tests")


def test_mapping_rejects_unknown_and_duplicate_json_keys(tmp_path: Path) -> None:
    payload = json.loads(PATH_MAPPING.read_text(encoding="utf-8"))
    payload["unexpected"] = True
    unknown = tmp_path / "unknown.json"
    unknown.write_text(json.dumps(payload), encoding="utf-8")
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(
        '{"schema_version":"1","schema_version":"1","classifier_revision":"x",'
        '"max_changed_paths":1,"rules":[]}',
        encoding="utf-8",
    )

    with pytest.raises(ValidationConfigError, match="unknown"):
        load_path_mapping(unknown)
    with pytest.raises(ValidationConfigError, match="duplicate"):
        load_path_mapping(duplicate)


def test_stage_config_rejects_unapproved_executable_and_duplicate_ids(tmp_path: Path) -> None:
    payload = json.loads(STAGE_REGISTRY.read_text(encoding="utf-8"))
    payload["stages"][0]["argv"] = ["curl", "https://example.invalid"]
    unsafe = tmp_path / "unsafe.json"
    unsafe.write_text(json.dumps(payload), encoding="utf-8")
    payload = json.loads(STAGE_REGISTRY.read_text(encoding="utf-8"))
    payload["stages"].append(payload["stages"][0])
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValidationConfigError, match="exact stage contract"):
        load_stage_registry(unsafe)
    with pytest.raises(ValidationConfigError, match="duplicate stage id"):
        load_stage_registry(duplicate)


@pytest.mark.parametrize(
    ("stage_id", "weakened_argv"),
    [
        ("backend-tests", ["python", "-m", "pytest", "--version"]),
        ("pre-commit-all-files", ["python", "-m", "pre_commit", "--version"]),
        ("database-upgrade", ["python", "-m", "alembic", "--help"]),
        ("frontend-audit", ["npm", "audit", "--help"]),
    ],
)
def test_stage_config_rejects_allowlisted_but_semantically_weakened_commands(
    tmp_path: Path,
    stage_id: str,
    weakened_argv: list[str],
) -> None:
    payload = json.loads(STAGE_REGISTRY.read_text(encoding="utf-8"))
    next(stage for stage in payload["stages"] if stage["id"] == stage_id)["argv"] = weakened_argv
    path = tmp_path / f"{stage_id}.json"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(ValidationConfigError, match="exact stage contract"):
        load_stage_registry(path)


def test_classifier_decision_is_driven_by_the_loaded_mapping(tmp_path: Path) -> None:
    payload = json.loads(PATH_MAPPING.read_text(encoding="utf-8"))
    documentation_rule = next(
        rule for rule in payload["rules"] if rule["plane"] == "documentation"
    )
    documentation_rule["plane"] = "public_api"
    custom_path = tmp_path / "mapping.json"
    custom_path.write_text(json.dumps(payload), encoding="utf-8")
    mapping = load_path_mapping(custom_path)

    decision = classify_change(
        ChangeRequest(
            base_revision="a" * 40,
            head_revision="b" * 40,
            changed_paths=("docs/config-driven.md",),
        ),
        mapping=mapping,
    )

    assert decision.selected_gate == "G2"
    assert decision.planes == ("public_api",)


def test_pytest_acceptance_metadata_is_strict_and_non_selective() -> None:
    pytest_config = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))[
        "tool"
    ]["pytest"]["ini_options"]
    addopts = pytest_config["addopts"].split()

    assert "--strict-config" in addopts
    assert "--strict-markers" in addopts
    assert not {"--testmon", "--only-changed", "-n", "--dist"} & set(addopts)
