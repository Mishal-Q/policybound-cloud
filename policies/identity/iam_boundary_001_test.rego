package sentinel.identity.iam_boundary_001

test_pass_role_has_correct_boundary {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:iam_role/app-role",
		"resource_type": "iam_role",
		"attributes": {
			"permissions_boundary_arn": "arn:aws:iam::ACCOUNT_ID:policy/SentinelWorkloadBoundary",
			"privilege_tag": "standard",
			"trust_policy_has_mfa_condition": false,
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_role_missing_boundary {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:iam_role/app-role",
		"resource_type": "iam_role",
		"attributes": {"permissions_boundary_arn": null, "privilege_tag": "standard", "trust_policy_has_mfa_condition": false},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_role_wrong_boundary_arn {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:iam_role/app-role",
		"resource_type": "iam_role",
		"attributes": {
			"permissions_boundary_arn": "arn:aws:iam::ACCOUNT_ID:policy/SomeOtherBoundary",
			"privilege_tag": "standard",
			"trust_policy_has_mfa_condition": false,
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_pass_admin_role_exempt_without_boundary {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:iam_role/break-glass",
		"resource_type": "iam_role",
		"attributes": {"permissions_boundary_arn": null, "privilege_tag": "admin", "trust_policy_has_mfa_condition": true},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}
