package redagent_detection_correlation_test

import data.redagent.detection_correlation.correlated
import rego.v1

test_confirmed_medium_in_window_correlates if {
	correlated with input as fixture("confirmed", "medium", 300)
}

test_unconfirmed_does_not_correlate if {
	not correlated with input as fixture("unconfirmed", "high", 300)
}

test_low_confidence_does_not_correlate if {
	not correlated with input as fixture("confirmed", "low", 300)
}

test_expired_observation_does_not_correlate if {
	not correlated with input as fixture("confirmed", "high", 301)
}

fixture(disposition, confidence, age_seconds) := {
	"attack_technique_id": "T1595.002",
	"tenant_id": "tenant-a",
	"engagement_id": "engagement-a",
	"correlation_key": "run-a:zap-invocation",
	"max_age_seconds": 300,
	"observations": [{
		"age_seconds": age_seconds,
		"tenant_id": "tenant-a",
		"engagement_id": "engagement-a",
		"attack_technique_id": "T1595.002",
		"confidence": confidence,
		"correlation_key": "run-a:zap-invocation",
		"disposition": disposition,
		"current": true,
		"future_evidence": false,
		"observation_id": "observation-1",
	}],
}
