from datetime import datetime, timedelta, timezone

import pytest

from redagent_platform.artifact_pipeline.analysis import (
    ComponentInput, PipelineFixture, PromotedDatabase, PromotedRules, WorkflowInput, MobileInput, analyze_fixture,
)
from redagent_platform.artifact_pipeline.vex import VexAnnotation, VulnerabilityObservation, apply_vex


NOW = datetime(2026, 7, 11, 13, 0, tzinfo=timezone.utc)


def _fixture(*, complete=True):
    return PipelineFixture(artifact_sha256="a" * 64, manifest_sha256="b" * 64,
        components=(ComponentInput(component_id="component-1", component_type="npm", name="example", version="1.0.0", purl="pkg:npm/example@1.0.0", license_expression="MIT"),),
        workflows=(WorkflowInput(workflow_id="ci", trigger="pull_request_target", checks_out_untrusted_ref=True,
            interpolates_untrusted_context=True, action_refs=("owner/action@main",), token_permissions=("contents:write",)),),
        mobile=(MobileInput(platform="android", application_id="io.redagent.synthetic", debuggable=True,
            cleartext_traffic=True, exported_components=2, signing_state="debug"),),
        complete=complete, partial_reasons=() if complete else ("unsupported-component-metadata",))


def test_pinned_pipeline_is_deterministic_and_partial_never_clean():
    rules = PromotedRules(bundle_id="r110-rules-v1", bundle_sha256="c" * 64, schema_sha256="d" * 64)
    database = PromotedDatabase(database_id="r110-db-v1", database_sha256="e" * 64, schema_sha256="f" * 64,
        advisories={"pkg:npm/example@1.0.0": ("R110-ADVISORY-1", "high")})
    first = analyze_fixture(fixture=_fixture(), rules=rules, database=database, analyzed_at=NOW)
    second = analyze_fixture(fixture=_fixture(), rules=rules, database=database, analyzed_at=NOW)
    assert first == second and first.clean is False
    assert first.untrusted_execution_count == 0 and first.external_contact_count == 0
    assert {item.rule_id for item in first.static_findings} >= {"ci-dangerous-checkout", "ci-context-injection", "ci-unpinned-action", "ci-token-write", "mobile-debuggable", "mobile-cleartext", "mobile-exported", "mobile-debug-signing"}
    partial = analyze_fixture(fixture=_fixture(complete=False), rules=rules, database=database, analyzed_at=NOW)
    assert partial.complete is False and partial.clean is False


def test_component_identity_and_database_schema_fail_closed():
    rules = PromotedRules(bundle_id="r110-rules-v1", bundle_sha256="c" * 64, schema_sha256="d" * 64)
    database = PromotedDatabase(database_id="r110-db-v1", database_sha256="e" * 64, schema_sha256="f" * 64, advisories={})
    invalid = _fixture().__class__(**(_fixture().__dict__ | {"components": (ComponentInput(component_id="bad", component_type="npm", name="example", version="1.0.0", purl=None, license_expression="UNKNOWN"),)}))
    result = analyze_fixture(fixture=invalid, rules=rules, database=database, analyzed_at=NOW)
    assert result.complete is False and "component-identity-incomplete" in result.partial_reasons
    with pytest.raises(ValueError, match="artifact_database_invalid"):
        PromotedDatabase(database_id="bad", database_sha256="not-a-digest", schema_sha256="f" * 64, advisories={})


def test_vex_is_independent_expiring_annotation_and_never_changes_observation():
    observation = VulnerabilityObservation(observation_id="observation-r110", component_id="component-1", advisory_id="R110-ADVISORY-1", passed=False, observation_sha256="a" * 64)
    annotation = VexAnnotation(annotation_id="vex-r110", observation_id=observation.observation_id, status="not_affected",
        justification="Synthetic component cannot reach the affected behavior.", requested_by="requester-r110", approved_by="approver-r110",
        effective_at=NOW - timedelta(minutes=1), expires_at=NOW + timedelta(days=1), supersedes_annotation_id=None)
    result = apply_vex(observation=observation, annotation=annotation, now=NOW)
    assert result.observation is observation and result.observation.passed is False and result.risk_state == "vex-not-affected"
    with pytest.raises(ValueError, match="artifact_vex_separation_required"):
        apply_vex(observation=observation, annotation=annotation.__class__(**(annotation.__dict__ | {"approved_by": annotation.requested_by})), now=NOW)
