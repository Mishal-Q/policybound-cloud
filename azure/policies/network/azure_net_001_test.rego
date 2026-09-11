package azure_sentinel.network.azure_net_001

test_pass_data_tier_nsg_has_effective_deny {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_network_security_group/nsg-data",
		"resource_type": "azure_network_security_group",
		"attributes": {
			"tags": {"Tier": "data"},
			"rules": [{
				"direction": "Inbound",
				"access": "Deny",
				"protocol": "*",
				"destination_port_range": "*",
				"source_address_prefix": "Internet",
				"priority": 100,
			}],
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_data_tier_nsg_no_rules_at_all {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_network_security_group/nsg-data",
		"resource_type": "azure_network_security_group",
		"attributes": {"tags": {"Tier": "data"}, "rules": []},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_deny_rule_present_but_shadowed_by_earlier_allow {
	# The Deny rule exists, but an Allow rule at a LOWER priority number
	# (evaluated first) matches the same traffic first -- Azure NSGs stop
	# at first match, so the Deny never actually takes effect. This is
	# exactly the kind of subtle real-world misconfiguration a naive
	# "does a Deny rule exist anywhere" check would miss.
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_network_security_group/nsg-data",
		"resource_type": "azure_network_security_group",
		"attributes": {
			"tags": {"Tier": "data"},
			"rules": [
				{
					"direction": "Inbound", "access": "Allow", "protocol": "*",
					"destination_port_range": "*", "source_address_prefix": "Internet", "priority": 90,
				},
				{
					"direction": "Inbound", "access": "Deny", "protocol": "*",
					"destination_port_range": "*", "source_address_prefix": "Internet", "priority": 100,
				},
			],
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_pass_non_data_tier_nsg_not_checked {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_network_security_group/nsg-app",
		"resource_type": "azure_network_security_group",
		"attributes": {"tags": {"Tier": "app"}, "rules": []},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}
