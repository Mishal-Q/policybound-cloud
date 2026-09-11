package sentinel.governance.gov_region_001

import data.sentinel.governance.config

# --- policy metadata (informational) ---
# policy_id: GOV-REGION-001
# version: 1.0
# severity: medium
# title: Resources must be deployed only in approved regions
#
# Evaluates the canonical `region` field populated by both normalizers
# (drift/detector/desired_state.py and aws_normalizer.py -- see the
# comment on schema.ATTRIBUTE_CONTRACTS for why region lives there
# rather than being parsed out of the resource_urn string inside this
# policy). This rule does not check resource_type at all, which is
# deliberate: it applies uniformly to every governed resource, AWS or
# Azure, as long as the normalizer populated `attributes.region`.
#
# Do not confuse this with:
#   - the Terraform provider's configured region (a deployment default,
#     not a per-resource fact -- see environments/dev/providers.tf)
#   - the AWS account's home region (accounts don't have one)
#   - a region parsed from the resource_urn (fragile string-splitting;
#     this rule reads the real field instead)

deny[msg] {
	some r
	resource := input.resources[r]
	region := object.get(resource.attributes, "region", "__MISSING__")
	region == "__MISSING__"
	msg := sprintf(
		"GOV-REGION-001 [MEDIUM]: %s has no region recorded in its canonical attributes",
		[resource.resource_urn],
	)
}

deny[msg] {
	some r
	resource := input.resources[r]
	region := object.get(resource.attributes, "region", "__MISSING__")
	region != "__MISSING__"
	not config.approved_regions[region]
	msg := sprintf(
		"GOV-REGION-001 [MEDIUM]: %s is deployed in %q, which is not in the approved region set",
		[resource.resource_urn, region],
	)
}
