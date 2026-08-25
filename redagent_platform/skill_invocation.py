"""Skill invocation artifact recording for approved command-contract decisions."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from redagent_platform.domain import EvidenceKind
from redagent_platform.evidence_chain import (
    AuditAction,
    EvidenceAccessPolicy,
    EvidenceChain,
    EvidenceRecord,
    RedactionStatus,
    RetentionClass,
    verify_evidence_record,
)
from redagent_platform.reporting import (
    RedactionReview,
    RedactionReviewStatus,
    ReportAudience,
    ReportInput,
    ReportPackage,
    ReportScope,
    generate_report_package,
    render_report_markdown,
)
from redagent_platform.redaction import RedactionArtifactClass, assert_no_sensitive_output, sanitize_text
from redagent_platform.skill_command_contract import CONTRACT_VERSION


class SkillInvocationRecordingError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, kw_only=True)
class SkillInvocationArtifacts:
    request_id: str
    skill_client: str
    command_log_path: str
    evidence_dir: str
    report_path: str
    ui_log_path: str | None
    evidence_record: EvidenceRecord
    evidence_metadata: Mapping[str, object]
    report_package: ReportPackage
    audit_chain: EvidenceChain
    artifact_hashes: Mapping[str, str]

    def to_jsonable(self) -> dict[str, object]:
        return {
            "status": "recorded",
            "request_id": self.request_id,
            "skill_client": self.skill_client,
            "command_contract_version": CONTRACT_VERSION,
            "paths": {
                "command_log_path": self.command_log_path,
                "evidence_dir": self.evidence_dir,
                "report_path": self.report_path,
                "ui_log_path": self.ui_log_path,
            },
            "evidence_record": _evidence_record_to_dict(self.evidence_record),
            "evidence_metadata": dict(self.evidence_metadata),
            "report": {
                "report_id": self.report_package.report_id,
                "report_hash": self.report_package.report_hash,
                "evidence_lock_hash": self.report_package.evidence_lock_hash,
                "redaction_review": self.report_package.redaction_review.status.value,
            },
            "audit_event_hashes": [event.event_hash for event in self.audit_chain.audit_events],
            "artifact_hashes": dict(self.artifact_hashes),
        }


def record_skill_invocation_artifacts(
    request: Mapping[str, Any],
    decision_output: Mapping[str, Any],
    *,
    repo_root: str | Path,
    ui_log_path: str | None = None,
) -> SkillInvocationArtifacts:
    """Write sanitized local artifacts for an already allowed skill decision."""

    if str(decision_output.get("decision")) != "allow":
        raise SkillInvocationRecordingError("decision_not_allowed")

    root = Path(repo_root).resolve()
    output_paths = _mapping(request.get("output_paths"), "output_paths")
    command_log_path = _resolve_repo_path(root, output_paths.get("command_log_path"), (".local", ".tmp"))
    evidence_dir = _resolve_repo_path(root, output_paths.get("evidence_dir"), (".tmp", "reports"))
    report_path = _resolve_repo_path(root, output_paths.get("report_path"), ("reports", ".tmp"))
    resolved_ui_log = _resolve_repo_path(root, ui_log_path, (".tmp",)) if ui_log_path else None

    requested_at = _parse_datetime(str(request["requested_at"]))
    request_id = str(request["request_id"])
    skill_client = str(request["skill_client"])
    evidence_dir.mkdir(parents=True, exist_ok=True)
    command_log_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    if resolved_ui_log:
        resolved_ui_log.parent.mkdir(parents=True, exist_ok=True)

    summary = _sanitized_summary(request, decision_output)
    evidence_content = _json_text(summary)
    _ensure_secret_free_text(evidence_content)

    chain = EvidenceChain().append_audit_event(
        event_id=f"{request_id}:skill-policy-decision",
        organization_id=str(request["organization_id"]),
        actor_user_id=str(request["operator_label"]),
        action=AuditAction.POLICY_DECISION,
        subject_type="skill_command_contract",
        subject_id=request_id,
        occurred_at=requested_at,
        details={
            "skill_client": skill_client,
            "command_contract_version": CONTRACT_VERSION,
            "decision": decision_output.get("decision"),
            "reason": decision_output.get("reason"),
            "delegated": decision_output.get("delegated"),
        },
    )
    chain = chain.append_evidence_record(
        evidence_id=f"{request_id}:skill-command-log",
        organization_id=str(request["organization_id"]),
        source_job_id=f"skill:{request_id}",
        kind=EvidenceKind.COMMAND_LOG,
        created_at=requested_at,
        redaction_status=RedactionStatus.REDACTED,
        retention_class=RetentionClass.STANDARD,
        access_policy=EvidenceAccessPolicy.REVIEWERS_ONLY,
        content=evidence_content.encode("utf-8"),
        contains_sensitive_capture=True,
        metadata=_evidence_metadata(request, decision_output, summary),
    )
    evidence_record = chain.evidence_records[0]
    if not verify_evidence_record(evidence_record):
        raise SkillInvocationRecordingError("invalid_evidence_integrity")

    evidence_metadata = _evidence_metadata(request, decision_output, summary)
    chain = chain.append_audit_event(
        event_id=f"{request_id}:skill-evidence-created",
        organization_id=str(request["organization_id"]),
        actor_user_id=str(request["operator_label"]),
        action=AuditAction.EVIDENCE_CREATION,
        subject_type="evidence",
        subject_id=evidence_record.id,
        occurred_at=requested_at,
        details={
            "evidence_id": evidence_record.id,
            "integrity_hash": evidence_record.integrity_hash,
            "command_log_path": _repo_relative(root, command_log_path),
            "report_path": _repo_relative(root, report_path),
        },
    )

    report_result = generate_report_package(_report_input(request, decision_output, evidence_record), chain)
    report_markdown = render_report_markdown(report_result.package, external_share=False)
    _ensure_secret_free_text(report_markdown)

    decision_json = _json_text(dict(decision_output))
    evidence_record_json = _json_text(
        {
            "evidence_record": _evidence_record_to_dict(evidence_record),
            "evidence_metadata": evidence_metadata,
        }
    )
    report_package_json = _json_text(_report_package_to_dict(report_result.package))
    audit_chain_json = _json_text(_audit_chain_to_dict(report_result.audit_chain))
    command_log_text = _render_command_log(
        summary=summary,
        evidence_record=evidence_record,
        report_package=report_result.package,
        artifact_paths={
            "decision_json": _repo_relative(root, evidence_dir / "decision.json"),
            "evidence_record_json": _repo_relative(root, evidence_dir / "evidence-record.json"),
            "report_package_json": _repo_relative(root, evidence_dir / "report-package.json"),
            "audit_chain_json": _repo_relative(root, evidence_dir / "audit-chain.json"),
        },
    )
    ui_preview_text = _render_ui_preview(summary, command_log_path, report_path)
    command_log_text = sanitize_text(command_log_text, RedactionArtifactClass.COMMAND_LOG).sanitized_text
    ui_preview_text = sanitize_text(ui_preview_text, RedactionArtifactClass.UI_LOG_PREVIEW).sanitized_text
    _ensure_secret_free_text(command_log_text)
    _ensure_secret_free_text(ui_preview_text)

    files = {
        "command_log": (command_log_path, command_log_text),
        "decision_json": (evidence_dir / "decision.json", decision_json),
        "evidence_record_json": (evidence_dir / "evidence-record.json", evidence_record_json),
        "report_package_json": (evidence_dir / "report-package.json", report_package_json),
        "audit_chain_json": (evidence_dir / "audit-chain.json", audit_chain_json),
        "report_markdown": (report_path, report_markdown),
    }
    if resolved_ui_log:
        files["ui_log"] = (resolved_ui_log, ui_preview_text)

    artifact_hashes: dict[str, str] = {}
    for name, (path, content) in files.items():
        _write_text(path, content)
        artifact_hashes[name] = _sha256_text(content)

    artifact_index = _json_text(
        {
            "request_id": request_id,
            "skill_client": skill_client,
            "command_contract_version": CONTRACT_VERSION,
            "artifact_hashes": artifact_hashes,
            "paths": {name: _repo_relative(root, path) for name, (path, _) in files.items()},
        }
    )
    _write_text(evidence_dir / "artifact-index.json", artifact_index)
    artifact_hashes["artifact_index"] = _sha256_text(artifact_index)

    return SkillInvocationArtifacts(
        request_id=request_id,
        skill_client=skill_client,
        command_log_path=_repo_relative(root, command_log_path),
        evidence_dir=_repo_relative(root, evidence_dir),
        report_path=_repo_relative(root, report_path),
        ui_log_path=_repo_relative(root, resolved_ui_log) if resolved_ui_log else None,
        evidence_record=evidence_record,
        evidence_metadata=evidence_metadata,
        report_package=report_result.package,
        audit_chain=report_result.audit_chain,
        artifact_hashes=artifact_hashes,
    )


def _sanitized_summary(request: Mapping[str, Any], decision_output: Mapping[str, Any]) -> dict[str, object]:
    output_paths = _mapping(request.get("output_paths"), "output_paths")
    return {
        "request_id": str(request["request_id"]),
        "skill_client": str(request["skill_client"]),
        "skill_version": str(request.get("skill_version", "unknown")),
        "command_contract_version": CONTRACT_VERSION,
        "assessment_type": str(request["assessment_type"]),
        "mode": str(decision_output.get("mode", request.get("mode", "dry_run"))),
        "requested_at": str(decision_output.get("requested_at", request["requested_at"])),
        "organization_id": str(request["organization_id"]),
        "engagement_id": str(request["engagement_id"]),
        "operator_label": str(request["operator_label"]),
        "policy_decision": dict(_mapping(decision_output.get("policy_decision"), "policy_decision")),
        "refusal_reason": decision_output.get("refusal_reason"),
        "decision_reason": str(decision_output.get("reason")),
        "next_action": str(decision_output.get("next_action")),
        "delegated": bool(decision_output.get("delegated", False)),
        "target_scope": {
            "requested_targets": list(decision_output.get("requested_targets", [])),
            "excluded_targets": list(request.get("excluded_targets", [])),
        },
        "limits": dict(_mapping(decision_output.get("request_counts"), "request_counts")),
        "evidence_paths": {
            "command_log_path": str(output_paths["command_log_path"]),
            "evidence_dir": str(output_paths["evidence_dir"]),
            "report_path": str(output_paths["report_path"]),
        },
        "redaction": {
            "required": bool(_mapping(request.get("data_handling"), "data_handling").get("redaction_required")),
            "status": RedactionStatus.REDACTED.value,
        },
        "specification_fingerprint": str(decision_output.get("specification_fingerprint")),
        "execution_boundary": "no target interaction or real assessment wrapper invocation",
    }


def _evidence_metadata(
    request: Mapping[str, Any],
    decision_output: Mapping[str, Any],
    summary: Mapping[str, object],
) -> dict[str, object]:
    return {
        "operator_label": str(request["operator_label"]),
        "skill_client": str(request["skill_client"]),
        "skill_version": str(request.get("skill_version", "unknown")),
        "command_contract_version": CONTRACT_VERSION,
        "policy_decision": dict(_mapping(decision_output.get("policy_decision"), "policy_decision")),
        "target_scope": dict(_mapping(summary.get("target_scope"), "target_scope")),
        "requested_at": str(summary["requested_at"]),
        "redaction_status": RedactionStatus.REDACTED.value,
        "specification_fingerprint": str(summary["specification_fingerprint"]),
    }


def _report_input(
    request: Mapping[str, Any],
    decision_output: Mapping[str, Any],
    evidence_record: EvidenceRecord,
) -> ReportInput:
    requested_at = _parse_datetime(str(request["requested_at"]))
    requested_targets = tuple(
        str(target.get("value", "unknown")) for target in decision_output.get("requested_targets", [])
        if isinstance(target, Mapping)
    )
    target_summary = ", ".join(requested_targets) if requested_targets else "No requested targets recorded"
    window = _mapping(request.get("window"), "window")
    testing_window = f"{window.get('start')} to {window.get('end')}"
    return ReportInput(
        report_id=f"{request['request_id']}:skill-report",
        organization_id=str(request["organization_id"]),
        title=f"Skill Invocation Evidence Report - {request['request_id']}",
        audience=ReportAudience.TECHNICAL,
        generated_by_user_id=str(request["operator_label"]),
        generated_at=requested_at,
        scope=ReportScope(
            engagement_id=str(request["engagement_id"]),
            target_summary=target_summary,
            testing_window=testing_window,
            allowed_modes=tuple(str(category) for category in request.get("allowed_categories", ())),
        ),
        findings=(),
        evidence_records=(evidence_record,),
        methodology=(
            "Evaluated the structured skill command-contract request.",
            "Recorded sanitized stdout JSON decision metadata as command-log evidence.",
        ),
        limitations=(
            "No target-facing assessment, scanner, exploit, payload, fuzzing, brute-force, WSL/Kali tool, or browser execution was performed by this artifact recorder.",
            "Report claims are limited to repo-local skill invocation evidence.",
        ),
        redaction_review=RedactionReview(
            review_id=f"{request['request_id']}:skill-redaction-review",
            status=RedactionReviewStatus.PENDING,
            reviewer_user_id=None,
            reviewed_at=None,
            notes="Generated for internal evidence review; external sharing requires approval.",
        ),
    )


def _render_command_log(
    *,
    summary: Mapping[str, object],
    evidence_record: EvidenceRecord,
    report_package: ReportPackage,
    artifact_paths: Mapping[str, str],
) -> str:
    targets = _mapping(summary["target_scope"], "target_scope").get("requested_targets", [])
    target_text = ", ".join(str(target) for target in targets) if targets else "none"
    lines = [
        "# Skill Invocation Command Log",
        "",
        f"- Request ID: {summary['request_id']}",
        f"- Skill client: {summary['skill_client']}",
        f"- Skill version: {summary['skill_version']}",
        f"- Command contract version: {CONTRACT_VERSION}",
        f"- Assessment type: {summary['assessment_type']}",
        f"- Mode: {summary['mode']}",
        f"- Decision reason: {summary['decision_reason']}",
        f"- Next action: {summary['next_action']}",
        f"- Delegated: {str(summary['delegated']).lower()}",
        f"- Requested targets: {target_text}",
        f"- Evidence record: {evidence_record.id}",
        f"- Evidence integrity hash: {evidence_record.integrity_hash}",
        f"- Report hash: {report_package.report_hash}",
        "",
        "## Artifact Paths",
        "",
    ]
    for name, path in sorted(artifact_paths.items()):
        lines.append(f"- {name}: `{path}`")
    lines.extend(
        [
            "",
            "## Safety Boundary",
            "",
            "- No target interaction occurred.",
            "- No scanner, exploit, payload, brute-force, fuzzing, cloud mutation, endpoint agent, WSL/Kali tool, or browser execution was invoked.",
            "- Browser UI output, when enabled, is log preview only.",
            "",
        ]
    )
    return "\n".join(lines)


def _render_ui_preview(summary: Mapping[str, object], command_log_path: Path, report_path: Path) -> str:
    lines = [
        "=== RedAgent skill invocation artifact recording ===",
        f"request_id: {summary['request_id']}",
        f"skill_client: {summary['skill_client']}",
        f"mode: {summary['mode']}",
        "decision: allow",
        f"next_action: {summary['next_action']}",
        f"command_log: {command_log_path.as_posix()}",
        f"report: {report_path.as_posix()}",
        "boundary: no browser execution; no target interaction",
        "",
    ]
    return "\n".join(lines)


def _resolve_repo_path(repo_root: Path, value: object, allowed_roots: tuple[str, ...]) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise SkillInvocationRecordingError("invalid_artifact_path")
    normalized = value.replace("\\", "/")
    posix = PurePosixPath(normalized)
    if posix.is_absolute() or ".." in posix.parts or not posix.parts:
        raise SkillInvocationRecordingError("invalid_artifact_path")
    if posix.parts[0] not in allowed_roots:
        raise SkillInvocationRecordingError("artifact_path_root_not_allowed")
    return (repo_root / Path(*posix.parts)).resolve()


def _repo_relative(repo_root: Path, path: Path | None) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(repo_root).as_posix()
    except ValueError as exc:
        raise SkillInvocationRecordingError("artifact_path_outside_repo") from exc


def _mapping(value: object, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise SkillInvocationRecordingError(f"missing_{field_name}")
    return value


def _parse_datetime(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SkillInvocationRecordingError("timezone_required")
    return parsed


def _json_text(payload: Mapping[str, object]) -> str:
    text = json.dumps(payload, indent=2, sort_keys=True, default=str)
    return text + "\n"


def _write_text(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _evidence_record_to_dict(record: EvidenceRecord) -> dict[str, object]:
    return {
        "id": record.id,
        "organization_id": record.organization_id,
        "source_job_id": record.source_job_id,
        "kind": record.kind.value,
        "created_at": record.created_at.isoformat(),
        "redaction_status": record.redaction_status.value,
        "retention_class": record.retention_class.value,
        "access_policy": record.access_policy.value,
        "content_hash": record.content_hash,
        "metadata_hash": record.metadata_hash,
        "previous_hash": record.previous_hash,
        "integrity_hash": record.integrity_hash,
    }


def _report_package_to_dict(package: ReportPackage) -> dict[str, object]:
    return {
        "report_id": package.report_id,
        "organization_id": package.organization_id,
        "title": package.title,
        "audience": package.audience.value,
        "generated_at": package.generated_at.isoformat(),
        "generated_by_user_id": package.generated_by_user_id,
        "evidence_lock_hash": package.evidence_lock_hash,
        "report_hash": package.report_hash,
        "redaction_review": package.redaction_review.status.value,
        "section_count": len(package.sections),
    }


def _audit_chain_to_dict(chain: EvidenceChain) -> dict[str, object]:
    return {
        "audit_events": [
            {
                "id": event.id,
                "action": event.action.value,
                "subject_type": event.subject_type,
                "subject_id": event.subject_id,
                "occurred_at": event.occurred_at.isoformat(),
                "details_hash": event.details_hash,
                "previous_hash": event.previous_hash,
                "event_hash": event.event_hash,
            }
            for event in chain.audit_events
        ],
        "evidence_records": [_evidence_record_to_dict(record) for record in chain.evidence_records],
    }


def _ensure_secret_free_text(value: str) -> None:
    try:
        assert_no_sensitive_output(value, RedactionArtifactClass.COMMAND_LOG)
    except ValueError as exc:
        raise SkillInvocationRecordingError("artifact_text_not_secret_free") from exc
