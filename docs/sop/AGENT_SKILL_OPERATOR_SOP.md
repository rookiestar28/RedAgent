# Agent Skill Operator SOP

This SOP covers repository-local operation of the Codex and Claude RedAgent operator skills. The skills guide specification collection, dry-run checks, artifact recording, evidence review, and report drafting. A skill is not an authorization record and cannot approve its own actions.

## Supported clients

| Client | Repository path | Activation |
| --- | --- | --- |
| Codex | `skills/codex/redagent-operator/` | `$redagent-operator` |
| Claude Code | `skills/claude/redagent-operator/` | `/redagent-operator` |

Do not install or update global user-directory skill copies from this repository unless a separately reviewed distribution process authorizes that path.

## Preconditions for target-facing work

Before active testing can be prepared, the operator must have approved rules of engagement, a current testing window, an explicit target allowlist and exclusions, an allow policy decision, bounded rate and timeout limits, repo-local evidence paths, an emergency stop method, accountable owner labels, forbidden-action boundaries, redaction and retention requirements, and explicit confirmation of the final specification summary.

Missing preconditions require the skill to remain in planning or dry-run mode.

## Operation workflow

1. Activate the repository-local skill for the selected client.
2. Collect and summarize only the missing specification fields.
3. Require explicit confirmation before execute-mode preparation.
4. Run dry-run validation through `scripts/redagent_skill_assess.py`.
5. Use `--record-artifacts` only after the command contract returns `allow`.
6. Treat execute-mode `delegate_not_invoked` as a handoff state, not proof that testing ran.
7. Read and write evidence only through the approved repo-local `.local`, `.tmp`, and `reports` paths.
8. Draft reports from locked evidence and distinguish assumptions from confirmed observations.

## Update validation

1. Review both skill packages and their shared references.
2. Run `scripts/validate_agent_skills.py --json`.
3. Run the skill package and evaluation-fixture tests.
4. Inspect the release manifest with `scripts/build_agent_skill_release.py --json`.
5. Run the public repository validation procedure described in `docs/TESTING.md`.

## Trust and safety review

Verify that skill changes do not introduce arbitrary shell construction, scanner or payload execution, direct target interaction, hidden tool grants, or non-repository evidence paths. Evaluation fixtures must continue to cover missing specifications, denial, ambiguity, safe planning, dry-run behavior, approved wrapper preparation, log retrieval, and report drafting.
