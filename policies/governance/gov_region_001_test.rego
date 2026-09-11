package sentinel.governance.gov_region_001

test_pass_approved_region {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:db_instance/app_db",
		"resource_type": "db_instance",
		"attributes": {"region": "us-east-1"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_pass_second_approved_region {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "aws:us-west-2:111111111111:db_instance/app_db",
		"resource_type": "db_instance",
		"attributes": {"region": "us-west-2"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_disallowed_region {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:eu-west-1:111111111111:db_instance/app_db",
		"resource_type": "db_instance",
		"attributes": {"region": "eu-west-1"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_missing_region_field {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:db_instance/app_db",
		"resource_type": "db_instance",
		"attributes": {},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

# Applies regardless of resource_type -- proving the cross-cloud claim
# with a real test rather than just an architecture diagram. An Azure
# resource type with the same "region" attribute is evaluated by the
# exact same rule, unmodified.
test_fail_azure_resource_disallowed_region {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "azure:westeurope:sub-123:azure_storage_account/mystore",
		"resource_type": "azure_storage_account",
		"attributes": {"region": "westeurope"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}
