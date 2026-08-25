"""compat_110 canonical data-only repository, artifact, CI, and mobile qualification."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path: sys.path.insert(0, str(ROOT))

from redagent_platform.artifact_pipeline.analysis import ComponentInput, MobileInput, PipelineFixture, PromotedDatabase, PromotedRules, WorkflowInput, analyze_fixture
from redagent_platform.artifact_pipeline.manifest import ManifestEntry, validate_manifest
from redagent_platform.artifact_pipeline.profiles import certified_profiles
from redagent_platform.artifact_pipeline.secret_scan import match_redacted_finding


OUTPUT = ROOT / "runtime-assets/attestations/260711-R110_ARTIFACT_PIPELINE_QUALIFICATION.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("command", choices=("qualify",)); parser.add_argument("--confirm-r110-canonical-fixtures", action="store_true"); args = parser.parse_args()
    if not args.confirm_r110_canonical_fixtures: raise SystemExit("r110_canonical_fixture_confirmation_required")
    receipt = qualify(); OUTPUT.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n")
    print(json.dumps({"status": receipt["status"], "receipt": str(OUTPUT), "sha256": receipt["receipt_sha256"]})); return 0


def qualify() -> dict[str, object]:
    now = datetime.now(timezone.utc).replace(microsecond=0); manifest = validate_manifest(entries=(ManifestEntry(path="fixtures/manifest.json", kind="file", size=128, sha256="1" * 64, compressed_size=64),), max_files=8, max_bytes=4096, max_depth=4, max_expansion_ratio=20)
    fixture = PipelineFixture(artifact_sha256="2" * 64, manifest_sha256=manifest.manifest_sha256,
        components=(ComponentInput(component_id="component-r110", component_type="npm", name="synthetic", version="1.0.0", purl="pkg:npm/synthetic@1.0.0", license_expression="MIT"),),
        workflows=(WorkflowInput(workflow_id="workflow-r110", trigger="pull_request_target", checks_out_untrusted_ref=True, interpolates_untrusted_context=True, action_refs=("owner/action@main",), token_permissions=("contents:write",)),),
        mobile=(MobileInput(platform="android", application_id="io.redagent.synthetic", debuggable=True, cleartext_traffic=True, exported_components=1, signing_state="debug"),), complete=True, partial_reasons=())
    rules = PromotedRules(bundle_id="r110-rules-v1", bundle_sha256="3" * 64, schema_sha256="4" * 64)
    database = PromotedDatabase(database_id="r110-database-v1", database_sha256="5" * 64, schema_sha256="6" * 64, advisories={"pkg:npm/synthetic@1.0.0": ("R110-ADVISORY-1", "high")})
    first = analyze_fixture(fixture=fixture, rules=rules, database=database, analyzed_at=now); replay = analyze_fixture(fixture=fixture, rules=rules, database=database, analyzed_at=now)
    raw_match = "r110" + "-qualification-canary-material"; finding = match_redacted_finding(artifact_sha256=fixture.artifact_sha256, path="fixtures/example.env", line=1, rule_id="synthetic-token", classification="credential-like", raw_match=raw_match, fingerprint_key=b"r110-qualification-key")
    negatives = {}
    for name, entry, reason in (("traversal_denied", ManifestEntry(path="../escape", kind="file", size=1, sha256="7" * 64, compressed_size=1), "artifact_path_traversal"),
        ("link_denied", ManifestEntry(path="link", kind="symlink", size=1, sha256="7" * 64, compressed_size=1), "artifact_entry_kind_denied"),
        ("bomb_denied", ManifestEntry(path="bomb", kind="file", size=1000, sha256="7" * 64, compressed_size=1), "artifact_expansion_ratio_exceeded")):
        try: validate_manifest(entries=(entry,), max_files=8, max_bytes=2048, max_depth=4, max_expansion_ratio=20)
        except ValueError as exc: negatives[name] = str(exc) == reason
    encoded_finding = json.dumps(finding.__dict__, sort_keys=True)
    body: dict[str, object] = {"schema": "redagent.r110-qualification/v1", "qualified_at": now.isoformat(), "status": "passed",
        "scope": "repo-owned-canonical-data-only-fixtures", "source_sha256": _source_digest(), "profiles": list(sorted(certified_profiles())),
        "manifest_sha256": manifest.manifest_sha256, "result_sha256": first.result_sha256, "replay_sha256": replay.result_sha256,
        "component_count": len(first.components), "vulnerability_count": len(first.vulnerabilities), "static_finding_count": len(first.static_findings),
        "credential_finding": {"artifact_sha256": finding.artifact_sha256, "path": finding.path, "line": finding.line,
            "rule_id": finding.rule_id, "classification": finding.classification, "redacted_fragment": finding.redacted_fragment,
            "fingerprint_bytes": list(bytes.fromhex(finding.fingerprint))},
        "negative": negatives | {"replay_deterministic": first == replay, "raw_match_absent": raw_match not in encoded_finding},
        "safety": {"untrusted_execution_count": first.untrusted_execution_count, "external_contact_count": first.external_contact_count,
            "real_repository_contact_count": 0, "real_mobile_contact_count": 0, "external_reference_execution_count": 0, "production_qualified": False}}
    if not all(body["negative"].values()) or any(body["safety"][key] != 0 for key in ("untrusted_execution_count", "external_contact_count", "real_repository_contact_count", "real_mobile_contact_count", "external_reference_execution_count")): raise RuntimeError("r110_qualification_failed")  # type: ignore[union-attr,index]
    body["receipt_sha256"] = hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":")).encode()).hexdigest(); return body


def _source_digest() -> str:
    digest = hashlib.sha256()
    for path in sorted((ROOT / "redagent_platform/artifact_pipeline").glob("*.py")): digest.update(path.name.encode()); digest.update(path.read_bytes())
    return digest.hexdigest()


if __name__ == "__main__": raise SystemExit(main())
