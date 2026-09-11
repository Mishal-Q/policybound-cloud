package sentinel.network.net_db_001

# --- policy metadata (informational) ---
# policy_id: NET-DB-001
# version: 1.0
# severity: critical
# title: Database must not be publicly accessible
#
# Input contract: this rule evaluates CANONICAL resources (see
# drift/detector/schema.py), never raw Terraform plan JSON or raw AWS
# Config configuration items directly. Both the CI pipeline and the
# runtime drift Lambda normalize into this schema first, so the exact
# same rule fires in both places (see doc4 finding #2).
#
# input.resources: list of canonical resource dicts

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "db_instance"
	resource.attributes.publicly_accessible == true
	msg := sprintf(
		"NET-DB-001 [CRITICAL]: %s has publicly_accessible=true; databases must not be internet-reachable",
		[resource.resource_urn],
	)
}
