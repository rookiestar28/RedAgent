package system.authz

import rego.v1

default allow := false

allow if {
	input.identity == "redagent-r099-app"
	input.method == "POST"
	input.path == ["v1", "data", "redagent", "decision"]
}

allow if {
	input.identity == "redagent-r099-app"
	input.method == "GET"
	input.path in {["health"], ["v1", "status"]}
}
