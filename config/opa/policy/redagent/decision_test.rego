package redagent_test

import data.redagent.decision
import rego.v1

test_api_allow if {
	decision.allowed with input as fixture("api", "job.create", ["job:create"], {})
}

test_workflow_allow if {
	decision.allowed with input as fixture("workflow", "job.command", ["workflow:command"], {"dispatch_blocked": false, "roe_status": "current"})
}

test_evidence_allow if {
	decision.allowed with input as fixture("evidence", "evidence.write", ["evidence:write"], {"classification": "restricted"})
}

test_secret_allow if {
	result := decision with input as fixture("secret", "secret.lease", ["secret:lease"], {"reference_status": "active", "revoke_pending": false})
	result.allowed
	result.obligations == ["audit", "exact_revoke"]
}

test_runner_allow_only_with_current_certified_facts if {
	result := decision with input as fixture("runner", "runner.execute", ["runner:execute"], {
		"artifact_status": "verified",
		"capability_status": "certified",
		"cleanup_required": true,
		"identity_generation": 2,
		"lease_state": "claimed",
		"manifest_state": "claimed",
		"registration_state": "active",
		"runner_generation": 2,
		"sandbox_status": "verified",
	})
	result.allowed
	result.obligations == ["audit", "require_expected_version"]
}

test_runner_denies_stale_generation if {
	not decision.allowed with input as fixture("runner", "runner.execute", ["runner:execute"], {
		"artifact_status": "verified",
		"capability_status": "certified",
		"cleanup_required": true,
		"identity_generation": 1,
		"lease_state": "claimed",
		"manifest_state": "claimed",
		"registration_state": "active",
		"runner_generation": 2,
		"sandbox_status": "verified",
	})
}

test_default_deny_unknown_boundary if {
	not decision.allowed with input as fixture("unknown", "job.execute", ["job:execute"], {})
}

test_default_deny_missing_permission if {
	not decision.allowed with input as fixture("api", "job.create", ["job:read"], {})
}

test_default_deny_stale_revision if {
	value := object.union(fixture("api", "job.create", ["job:create"], {}), {"required_revision": "r099-stale"})
	not decision.allowed with input as value
}

fixture(boundary, action, permissions, attributes) := {
	"action": action,
	"attributes": attributes,
	"boundary": boundary,
	"correlation_id": "correlation-1",
	"decision_valid_until": "2026-07-10T14:00:30+00:00",
	"input_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"permissions": permissions,
	"policy_reference": "policy:r099:1",
	"requested_at": "2026-07-10T14:00:00+00:00",
	"required_revision": "r099-v1",
	"resource_id": "resource-1",
	"resource_type": "job",
	"roe_version_id": "roe-1",
	"roles": ["operator"],
	"schema_version": "1.0",
	"subject_id": "operator-1",
	"tenant_id": "tenant-1",
}
