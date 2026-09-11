package sentinel.network.net_db_001

test_pass_private_db {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:db_instance/app_db",
		"resource_type": "db_instance",
		"attributes": {"publicly_accessible": false, "storage_encrypted": true, "kms_key_arn": "arn:x", "subnet_group": "data"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_public_db {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:db_instance/app_db",
		"resource_type": "db_instance",
		"attributes": {"publicly_accessible": true, "storage_encrypted": true, "kms_key_arn": "arn:x", "subnet_group": "data"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_ignores_non_db_resources {
	count(deny) == 0 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:s3_bucket/exports",
		"resource_type": "s3_bucket",
		"attributes": {"encryption_algorithm": "aws:kms"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}
