package azure_sentinel.identity.azure_identity_001

# --- policy metadata (informational) ---
# policy_id: AZURE-IDENTITY-001
# version: 1.0
# severity: high
# title: RBAC role assignment scope must not exceed the resource group
#
# Same governance INTENT as IAM-BOUNDARY-001 (cap what a privileged
# identity can reach), completely different MECHANISM -- Azure has no
# permission-boundary concept. This checks the SCOPE a role assignment
# is granted at: subscription-level scope is broader than resource-
# group-level scope, which is broader than a single-resource scope.
# This policy denies subscription-scoped assignments for anything other
# than the Owner role (a deliberate, narrow exemption mirroring how
# IAM-BOUNDARY-001 exempts privilege=admin roles -- see ADR 0005).
#
# Do not read this as "the Azure version of IAM-BOUNDARY-001." It
# addresses the same governance intent by the only mechanism Azure
# actually offers, and the ADR for this (see
# docs/decisions/0011-azure-identity-not-a-boundary-port.md) says so
# explicitly rather than implying an equivalence that doesn't exist.

subscription_scope_pattern := "^/subscriptions/[^/]+$"

deny[msg] {
	some r
	assignment := input.resources[r]
	assignment.resource_type == "azure_role_assignment"
	assignment.attributes.role_definition_name != "Owner"
	regex.match(subscription_scope_pattern, assignment.attributes.scope)
	msg := sprintf(
		"AZURE-IDENTITY-001 [HIGH]: %s grants %q at subscription scope (%s); only Owner may be assigned at subscription scope",
		[assignment.resource_urn, assignment.attributes.role_definition_name, assignment.attributes.scope],
	)
}
