package sentinel.identity.iam_boundary_001

# --- policy metadata (informational) ---
# policy_id: IAM-BOUNDARY-001
# version: 1.0
# severity: high
# title: Non-administrative IAM roles must reference the approved permission boundary
#
# NOTE: this deliberately replaces an earlier draft policy that tried to
# set-compare an identity policy's allowed actions against its boundary's
# allowed actions and DENY on any excess. That's wrong: permission
# boundaries are designed to be a *superset* that the identity policy
# narrows via intersection (EffectivePermissions = IdentityPolicy ∩
# Boundary), so an identity policy granting fewer actions than its
# boundary allows is completely normal and must not be flagged.
# The actual invariant worth enforcing is boundary ATTACHMENT + ARN
# correctness, not boundary/identity-policy set arithmetic.

approved_boundary_arn := "arn:aws:iam::ACCOUNT_ID:policy/SentinelWorkloadBoundary"

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "iam_role"
	resource.attributes.privilege_tag != "admin"
	resource.attributes.permissions_boundary_arn == null
	msg := sprintf(
		"IAM-BOUNDARY-001 [HIGH]: %s is a non-admin role with no permissions boundary attached",
		[resource.resource_urn],
	)
}

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "iam_role"
	resource.attributes.privilege_tag != "admin"
	resource.attributes.permissions_boundary_arn != approved_boundary_arn
	resource.attributes.permissions_boundary_arn != null
	msg := sprintf(
		"IAM-BOUNDARY-001 [HIGH]: %s references boundary %q, expected %q",
		[resource.resource_urn, resource.attributes.permissions_boundary_arn, approved_boundary_arn],
	)
}
