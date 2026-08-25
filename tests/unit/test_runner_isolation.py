from redagent_platform import runner_isolation


def kali_policy(**overrides: object) -> runner_isolation.KaliLabNodePolicy:
    values = {
        "allowed_as_controlled_lab_node": True,
        "primary_development_root": False,
        "may_run_against_project_tree": False,
        "artifact_exchange": ("json", "sarif", "text_report", "approved_lab_output"),
        "requires_runner_policy_gate": True,
    }
    values.update(overrides)
    return runner_isolation.KaliLabNodePolicy(**values)  # type: ignore[arg-type]


def design(**overrides: object) -> runner_isolation.RunnerIsolationDesign:
    values = {
        "design_id": "runner-isolation-v1",
        "selected_model": runner_isolation.RunnerExecutionModel.EPHEMERAL_RUNNER,
        "trust_boundaries": "control-plane dispatches to short-lived runner with scoped policy token.",
        "registration": "runner registration requires organization, runner id, scope, and expiry.",
        "authentication": "runner uses short-lived policy token reference, not raw token storage.",
        "command_authorization": "commands require policy grant, target scope, mode, and timeout.",
        "telemetry": "runner emits heartbeat, result, cleanup, and terminal callbacks.",
        "payload_storage": "payloads are disabled by default and must be integrity checked if later enabled.",
        "revocation": "runner token and queued jobs can be revoked by scheduler control.",
        "uninstall": "ephemeral runner has no persistent uninstall; persistent model would require uninstall proof.",
        "abuse_cases": tuple(runner_isolation.RunnerAbuseCase),
        "kali_lab_node_policy": kali_policy(),
        "threat_model_review_id": None,
        "persistent_agent_code_shipped": False,
    }
    values.update(overrides)
    return runner_isolation.RunnerIsolationDesign(**values)  # type: ignore[arg-type]


def test_adr_model_comparison_includes_agentless_ephemeral_and_persistent_agent_models() -> None:
    assessments = runner_isolation.compare_runner_models()

    assert {assessment.model for assessment in assessments} == {
        runner_isolation.RunnerExecutionModel.AGENTLESS,
        runner_isolation.RunnerExecutionModel.EPHEMERAL_RUNNER,
        runner_isolation.RunnerExecutionModel.PERSISTENT_AGENT,
    }
    persistent = next(item for item in assessments if item.model is runner_isolation.RunnerExecutionModel.PERSISTENT_AGENT)
    ephemeral = next(item for item in assessments if item.model is runner_isolation.RunnerExecutionModel.EPHEMERAL_RUNNER)
    assert persistent.recommendation is runner_isolation.RunnerRecommendation.BLOCKED_PENDING_THREAT_MODEL
    assert ephemeral.recommendation is runner_isolation.RunnerRecommendation.RECOMMENDED


def test_design_requires_all_runner_boundary_controls() -> None:
    validation = runner_isolation.validate_runner_isolation_design(
        design(authentication="", payload_storage="", uninstall="")
    )

    assert not validation.accepted
    assert validation.reason == "runner_isolation_design_incomplete"
    assert "authentication" in validation.gaps
    assert "payload_storage" in validation.gaps
    assert "uninstall" in validation.gaps


def test_kali_wsl2_can_be_lab_node_only_with_project_tree_and_primary_root_guardrails() -> None:
    primary_root = runner_isolation.validate_runner_isolation_design(
        design(kali_lab_node_policy=kali_policy(primary_development_root=True))
    )
    project_tree = runner_isolation.validate_runner_isolation_design(
        design(kali_lab_node_policy=kali_policy(may_run_against_project_tree=True))
    )
    missing_gate = runner_isolation.validate_runner_isolation_design(
        design(kali_lab_node_policy=kali_policy(requires_runner_policy_gate=False))
    )

    assert "kali_must_not_be_primary_development_root" in primary_root.gaps
    assert "kali_must_not_run_against_project_tree" in project_tree.gaps
    assert "kali_runner_policy_gate_required" in missing_gate.gaps


def test_persistent_agent_code_is_blocked_until_threat_model_review() -> None:
    no_review = runner_isolation.evaluate_persistent_agent_gate(
        design(selected_model=runner_isolation.RunnerExecutionModel.PERSISTENT_AGENT)
    )
    code_shipped = runner_isolation.evaluate_persistent_agent_gate(
        design(persistent_agent_code_shipped=True, threat_model_review_id="tm-1")
    )
    reviewed = runner_isolation.evaluate_persistent_agent_gate(
        design(
            selected_model=runner_isolation.RunnerExecutionModel.PERSISTENT_AGENT,
            threat_model_review_id="tm-1",
        )
    )

    assert not no_review.accepted
    assert no_review.reason == "persistent_agent_threat_model_required"
    assert not code_shipped.accepted
    assert code_shipped.reason == "persistent_agent_code_forbidden_before_review"
    assert reviewed.accepted
    assert not hasattr(runner_isolation, "PersistentAgent")
    assert not hasattr(runner_isolation, "install_agent")


def test_abuse_case_coverage_requires_rogue_runner_token_theft_command_injection_and_lateral_movement() -> None:
    validation = runner_isolation.validate_runner_isolation_design(
        design(
            abuse_cases=(
                runner_isolation.RunnerAbuseCase.ROGUE_RUNNER,
                runner_isolation.RunnerAbuseCase.STOLEN_RUNNER_TOKEN,
            )
        )
    )

    assert not validation.accepted
    assert "missing_abuse_case:command_injection" in validation.gaps
    assert "missing_abuse_case:lateral_movement" in validation.gaps


def test_complete_ephemeral_runner_design_is_accepted_without_shipping_persistent_agent() -> None:
    validation = runner_isolation.validate_runner_isolation_design(design())

    assert validation.accepted
    assert validation.reason == "runner_isolation_design_accepted"
    assert not design().persistent_agent_code_shipped
