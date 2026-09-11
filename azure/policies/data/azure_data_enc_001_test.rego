package azure_sentinel.data.azure_data_enc_001

test_pass_customer_managed_key_present {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_storage_account/sentineldata",
		"resource_type": "azure_storage_account",
		"attributes": {"public_network_access_enabled": false, "encryption_key_ref": "https://kv-sentinel.vault.azure.net/keys/storage-key/abc"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_microsoft_managed_key_only {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_storage_account/defaultenc",
		"resource_type": "azure_storage_account",
		"attributes": {"public_network_access_enabled": false, "encryption_key_ref": null},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_field_entirely_absent {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "azure:eastus:sub-123:azure_storage_account/malformed",
		"resource_type": "azure_storage_account",
		"attributes": {"public_network_access_enabled": false},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}
