package redagent.detection_correlation

import rego.v1

default correlated := false

correlated if {
	count(qualified_observations) >= 1
}

qualified_observations contains item.observation_id if {
	some item in input.observations
	item.tenant_id == input.tenant_id
	item.engagement_id == input.engagement_id
	item.correlation_key == input.correlation_key
	item.attack_technique_id == input.attack_technique_id
	item.disposition == "confirmed"
	item.confidence in {"medium", "high"}
	item.current == true
	item.future_evidence == false
	item.age_seconds >= 0
	item.age_seconds <= input.max_age_seconds
}
