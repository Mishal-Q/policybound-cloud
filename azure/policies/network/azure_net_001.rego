package azure_sentinel.network.azure_net_001

# --- policy metadata (informational) ---
# policy_id: AZURE-NET-001
# version: 1.0
# severity: critical
# title: Data-tier NSG must not allow inbound internet access
#
# This is deliberately NOT a port of NET-DB-002. AWS's default network
# posture requires an explicit route before anything can reach the
# internet, so NET-DB-002 checks for the PRESENCE of a forbidden IGW
# route. Azure's default posture is the opposite -- traffic is allowed
# unless something blocks it -- so the equivalent invariant here checks
# for the ABSENCE of a rule that would be required to actually stop
# inbound internet traffic from reaching a data-tier NSG. A data-tier
# NSG passes this check only if it has an explicit Deny rule for
# Inbound traffic from the Internet at a priority that would actually
# take effect (lower priority number = evaluated first in Azure NSGs).
#
# This is the concrete evidence for the "same governance intent,
# structurally different mechanism" finding from the cross-cloud mapping
# -- not asserted in a doc, demonstrated by two policies whose logic is
# inverted relative to each other.

deny[msg] {
	some r
	nsg := input.resources[r]
	nsg.resource_type == "azure_network_security_group"
	nsg.attributes.tags.Tier == "data"
	not has_effective_internet_deny_rule(nsg.attributes.rules)
	msg := sprintf(
		"AZURE-NET-001 [CRITICAL]: %s is a data-tier NSG with no effective rule denying inbound internet traffic",
		[nsg.resource_urn],
	)
}

# An NSG rule is "effective" here if it's the lowest-priority (first
# evaluated) rule matching Inbound + source Internet -- Azure NSGs
# evaluate rules in priority order and stop at the first match, so a
# Deny rule sitting behind an earlier Allow rule for the same traffic
# would never actually apply. This function checks that no Allow rule
# for Inbound+Internet traffic exists at a lower priority number than
# the Deny rule, i.e. the Deny genuinely wins.
has_effective_internet_deny_rule(rules) {
	some d
	deny_rule := rules[d]
	deny_rule.direction == "Inbound"
	deny_rule.access == "Deny"
	deny_rule.source_address_prefix == "Internet"

	not exists_lower_priority_allow(rules, deny_rule.priority)
}

exists_lower_priority_allow(rules, deny_priority) {
	some a
	allow_rule := rules[a]
	allow_rule.direction == "Inbound"
	allow_rule.access == "Allow"
	allow_rule.source_address_prefix == "Internet"
	allow_rule.priority < deny_priority
}
