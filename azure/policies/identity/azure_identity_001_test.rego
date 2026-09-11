package azure_sentinel.identity.azure_identity_001

test_pass_resource_group_scoped_contributor {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_role_assignment/ra-1",
		"resource_type": "azure_role_assignment",
		"attributes": {
			"scope": "/subscriptions/sub-123/resourceGroups/sentinel-iac-demo",
			"role_definition_name": "Contributor",
			"principal_type": "User",
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_subscription_scoped_contributor {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_role_assignment/ra-2",
		"resource_type": "azure_role_assignment",
		"attributes": {
			"scope": "/subscriptions/sub-123",
			"role_definition_name": "Contributor",
			"principal_type": "User",
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_pass_subscription_scoped_owner_is_exempt {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_role_assignment/ra-3",
		"resource_type": "azure_role_assignment",
		"attributes": {
			"scope": "/subscriptions/sub-123",
			"role_definition_name": "Owner",
			"principal_type": "User",
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_pass_single_resource_scoped_reader {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_role_assignment/ra-4",
		"resource_type": "azure_role_assignment",
		"attributes": {
			"scope": "/subscriptions/sub-123/resourceGroups/sentinel-iac-demo/providers/Microsoft.Storage/storageAccounts/sentineldata",
			"role_definition_name": "Reader",
			"principal_type": "User",
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}
