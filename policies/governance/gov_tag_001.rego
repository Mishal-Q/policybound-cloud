package sentinel.governance.gov_tag_001

# --- policy metadata (informational) ---
# policy_id: GOV-TAG-001
# version: 1.0
# severity: medium
# title: Governed resources must carry required metadata tags
#
# Required tag set audited from actual repository convention, not
# invented: environments/dev/main.tf's local.common_tags applies
# ManagedBy, environment, owner, and cost-center to every resource via
# var.tags. "data-classification" is NOT part of common_tags -- it only
# appears as a literal tag on the RDS instance in
# modules/database/main.tf. Rather than require it everywhere (which
# would flag every security group and IAM role in the reference
# environment, none of which hold customer data), this policy requires
# it only on the resource types that actually hold data at rest:
# db_instance and s3_bucket. Requiring it universally would have been
# the "easier" rule to write; it would also have been checking something
# the project's own Terraform never actually promised to do.
#
# Tag keys are matched case-sensitively, exact string match, matching
# how AWS itself treats tag keys ("ManagedBy" and "managedby" are two
# different tags in AWS, not the same tag with different casing). This
# is a deliberate decision, not an oversight -- documented here so it
# isn't ambiguous.
#
# Like GOV-REGION-001, this rule doesn't check resource_type for the
# base tag set, so it evaluates any canonical resource -- AWS or Azure
# -- that has a `tags` attribute, which every type in schema.py's
# ATTRIBUTE_CONTRACTS now carries.
#
# object.get(...) with a sentinel default is used throughout instead of
# `not resource.attributes.tags.something`, specifically because `not`
# on a possibly-null value was the exact bug documented in ADR 0005 and
# found again in DATA-ENC-001 during the project recheck -- this policy
# is written to structurally avoid that whole bug class rather than
# rely on remembering to write `== null` correctly every time.

base_required_tags := {"ManagedBy", "owner", "cost-center"}

data_classification_required_types := {"db_instance", "s3_bucket"}

deny[msg] {
	some r
	resource := input.resources[r]
	tags := object.get(resource.attributes, "tags", {})
	some required_tag
	base_required_tags[required_tag]
	value := object.get(tags, required_tag, "__MISSING__")
	value == "__MISSING__"
	msg := sprintf("GOV-TAG-001 [MEDIUM]: %s is missing required tag %q", [resource.resource_urn, required_tag])
}

deny[msg] {
	some r
	resource := input.resources[r]
	tags := object.get(resource.attributes, "tags", {})
	some required_tag
	base_required_tags[required_tag]
	value := object.get(tags, required_tag, "__MISSING__")
	value != "__MISSING__"
	value == ""
	msg := sprintf(
		"GOV-TAG-001 [MEDIUM]: %s has required tag %q present but empty",
		[resource.resource_urn, required_tag],
	)
}

deny[msg] {
	some r
	resource := input.resources[r]
	data_classification_required_types[resource.resource_type]
	tags := object.get(resource.attributes, "tags", {})
	value := object.get(tags, "data-classification", "__MISSING__")
	value == "__MISSING__"
	msg := sprintf(
		"GOV-TAG-001 [MEDIUM]: %s is a data-holding resource missing required tag \"data-classification\"",
		[resource.resource_urn],
	)
}
