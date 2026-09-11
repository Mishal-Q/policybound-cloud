package azure_sentinel.data.azure_public_001

test_pass_public_access_disabled {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_storage_account/sentineldata",
		"resource_type": "azure_storage_account",
		"attributes": {"public_network_access_enabled": false, "encryption_key_ref": "https://kv.vault.azure.net/keys/k/1"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_public_access_enabled {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_storage_account/leaky",
		"resource_type": "azure_storage_account",
		"attributes": {"public_network_access_enabled": true, "encryption_key_ref": "https://kv.vault.azure.net/keys/k/1"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_ignores_non_storage_resources {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_role_assignment/x",
		"resource_type": "azure_role_assignment",
		"attributes": {"scope": "x", "role_definition_name": "Reader", "principal_type": "User"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}
