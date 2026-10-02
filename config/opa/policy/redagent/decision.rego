package redagent

import rego.v1

default decision := {
	"allowed": false,
	"bundle_revision": "r099-v1",
	"input_hash": "",
	"issued_at": "1970-01-01T00:00:00+00:00",
	"obligations": ["audit"],
	"reason_code": "policy_denied",
	"valid_until": "1970-01-01T00:00:01+00:00",
}

decision := {
	"allowed": true,
	"bundle_revision": data.redagent.bundle.revision,
	"input_hash": input.input_hash,
	"issued_at": input.requested_at,
	"obligations": obligations,
	"reason_code": "boundary_authorized",
	"valid_until": input.decision_valid_until,
} if {
	valid_envelope
	boundary_allowed
	obligations := boundary_obligations
}

decision := {
	"allowed": false,
	"bundle_revision": data.redagent.bundle.revision,
	"input_hash": input.input_hash,
	"issued_at": input.requested_at,
	"obligations": ["audit"],
	"reason_code": "boundary_denied",
	"valid_until": input.decision_valid_until,
} if {
	valid_envelope
	not boundary_allowed
}

valid_envelope if {
	input.schema_version == "1.0"
	input.required_revision == data.redagent.bundle.revision
	input.input_hash != ""
	input.tenant_id != ""
	input.subject_id != ""
	input.resource_id != ""
}

boundary_allowed if {
	input.boundary == "api"
	input.action in input.permissions
}

boundary_allowed if {
	input.boundary == "api"
	input.action == "job.create"
	"job:create" in input.permissions
}

boundary_allowed if {
	input.boundary == "workflow"
	input.action in {"job.start", "job.command", "job.stop"}
	"workflow:command" in input.permissions
	object.get(input.attributes, "roe_status", "missing") == "current"
}

boundary_allowed if {
	input.boundary == "workflow"
	input.action == "campaign.plan.admit"
	"campaign:admit" in input.permissions
	admission_metadata_current
}

admission_metadata_current if {
	sha256_attribute("campaign_authority_sha256")
	sha256_attribute("campaign_policy_bundle_sha256")
	sha256_attribute("campaign_domain_sha256")
	sha256_attribute("campaign_plan_sha256")
	sha256_attribute("campaign_certificate_sha256")
	sha256_attribute("campaign_subset_proof_sha256")
	sha256_attribute("campaign_residual_budget_sha256")
	object.get(input.attributes, "campaign_lifecycle_epoch", -1) >= 0
	object.get(input.attributes, "campaign_policy_revocation_epoch", -1) >= 0
	object.get(input.attributes, "campaign_roe_revocation_epoch", -1) >= 0
	object.get(input.attributes, "campaign_kill_switch_epoch", -1) >= 0
}

# CRITICAL: admission is not effect authority. This closed branch rechecks the live
# lease and counters for the two fixed owned-loopback profiles before each dispatch.
boundary_allowed if {
	input.boundary == "workflow"
	input.action == "campaign.node.execute"
	"campaign:execute" in input.permissions
	admission_metadata_current
	input.attributes.campaign_environment_class == "synthetic_loopback"
	input.attributes.campaign_capability_id in {"zap-controlled-runtime", "nuclei-trusted-runtime"}
	input.attributes.campaign_effect_class == "read_only_observation"
	input.attributes.campaign_data_access_class == "metadata_only"
	input.attributes.campaign_credential_class == "none"
	input.attributes.campaign_lifecycle_state == "active"
	input.attributes.campaign_reservation_state in {"reserved", "held"}
	sha256_attribute("campaign_admission_receipt_sha256")
	sha256_attribute("campaign_reserved_budget_sha256")
	sha256_attribute("campaign_node_sha256")
	sha256_attribute("campaign_effect_intent_sha256")
	sha256_attribute("campaign_runner_binding_sha256")
	input.attributes.campaign_execution_run_id != ""
	input.attributes.campaign_target_id != ""
	input.attributes.campaign_rate_limit > 0
	input.attributes.campaign_rate_limit <= 60
	input.attributes.campaign_rate_claimed_requests >= 0
	input.attributes.campaign_rate_claimed_requests < input.attributes.campaign_rate_limit
	input.attributes.campaign_concurrency_limit == 1
	input.attributes.campaign_active_concurrency == 0
	time.parse_rfc3339_ns(input.attributes.campaign_reservation_lease_expires_at) > time.parse_rfc3339_ns(input.requested_at)
}

sha256_attribute(name) if {
	regex.match("^[0-9a-f]{64}$", object.get(input.attributes, name, ""))
}

boundary_allowed if {
	input.boundary == "evidence"
	input.action == "evidence.write"
	"evidence:write" in input.permissions
	object.get(input.attributes, "classification", "missing") in {"internal", "confidential", "restricted"}
}

boundary_allowed if {
	input.boundary == "secret"
	input.action == "secret.lease"
	"secret:lease" in input.permissions
	object.get(input.attributes, "reference_status", "missing") == "active"
	object.get(input.attributes, "revoke_pending", true) == false
}

boundary_allowed if {
	input.boundary == "runner"
	input.action == "runner.manifest.issue"
	"runner:issue" in input.permissions
	runner_current("draft", "absent", "certified")
}

boundary_allowed if {
	input.boundary == "runner"
	input.action == "runner.manifest.claim"
	"runner:claim" in input.permissions
	runner_current("issued", "absent", "certified")
}

boundary_allowed if {
	input.boundary == "runner"
	input.action == "runner.secret.resolve"
	"runner:secret" in input.permissions
	runner_current("claimed", "claimed", "verified")
}

boundary_allowed if {
	input.boundary == "runner"
	input.action == "runner.execute"
	"runner:execute" in input.permissions
	runner_current("claimed", "claimed", "verified")
}

boundary_allowed if {
	input.boundary == "runner"
	input.action == "runner.evidence.submit"
	"runner:evidence" in input.permissions
	runner_current("running", "claimed", "verified")
}

runner_current(manifest_state, lease_state, sandbox_status) if {
	object.get(input.attributes, "registration_state", "missing") == "active"
	object.get(input.attributes, "capability_status", "missing") == "certified"
	object.get(input.attributes, "artifact_status", "missing") == "verified"
	object.get(input.attributes, "manifest_state", "missing") == manifest_state
	object.get(input.attributes, "lease_state", "missing") == lease_state
	object.get(input.attributes, "sandbox_status", "missing") == sandbox_status
	object.get(input.attributes, "cleanup_required", false) == true
	object.get(input.attributes, "runner_generation", 0) > 0
	object.get(input.attributes, "identity_generation", -1) == object.get(input.attributes, "runner_generation", -2)
}

boundary_obligations := ["audit", "require_expected_version"] if {
	input.boundary in {"api", "workflow", "evidence", "runner"}
}

boundary_obligations := ["audit", "exact_revoke"] if {
	input.boundary == "secret"
}
