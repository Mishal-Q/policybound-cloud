package sentinel.governance.gov_tag_001

test_pass_all_base_tags_present_non_data_resource {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:security_group/sg-app",
		"resource_type": "security_group",
		"attributes": {"tags": {"ManagedBy": "sentinel-iac", "owner": "platform-team", "cost-center": "eng-infra"}},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_missing_one_base_tag {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:security_group/sg-app",
		"resource_type": "security_group",
		"attributes": {"tags": {"ManagedBy": "sentinel-iac", "owner": "platform-team"}},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_empty_tag_value_distinct_from_missing {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:security_group/sg-app",
		"resource_type": "security_group",
		"attributes": {"tags": {"ManagedBy": "sentinel-iac", "owner": "", "cost-center": "eng-infra"}},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_no_tags_at_all_reports_all_three_base_tags {
	count(deny) == 3 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:security_group/sg-app",
		"resource_type": "security_group",
		"attributes": {},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_pass_db_instance_with_data_classification {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:db_instance/app_db",
		"resource_type": "db_instance",
		"attributes": {"tags": {
			"ManagedBy": "sentinel-iac",
			"owner": "platform-team",
			"cost-center": "eng-infra",
			"data-classification": "confidential",
		}},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_db_instance_missing_data_classification {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:db_instance/app_db",
		"resource_type": "db_instance",
		"attributes": {"tags": {
			"ManagedBy": "sentinel-iac",
			"owner": "platform-team",
			"cost-center": "eng-infra",
		}},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_pass_security_group_does_not_need_data_classification {
	# Confirms the scoping decision actually works: a non-data resource
	# type is never asked for data-classification, even though it's
	# required on db_instance/s3_bucket.
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:security_group/sg-app",
		"resource_type": "security_group",
		"attributes": {"tags": {"ManagedBy": "sentinel-iac", "owner": "platform-team", "cost-center": "eng-infra"}},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_case_sensitive_tag_key_not_matched {
	# "managedby" (lowercase) must NOT satisfy the "ManagedBy" requirement
	# -- proves the case-sensitivity decision is actually implemented,
	# not just documented in a comment.
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:security_group/sg-app",
		"resource_type": "security_group",
		"attributes": {"tags": {"managedby": "sentinel-iac", "owner": "platform-team", "cost-center": "eng-infra"}},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}
