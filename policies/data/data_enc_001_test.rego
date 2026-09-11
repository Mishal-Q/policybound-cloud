package sentinel.data.data_enc_001

test_pass_encrypted_db_and_bucket {
	count(deny) == 0 with input as {"resources": [
		{
			"resource_urn": "aws:us-east-1:111111111111:db_instance/app_db",
			"resource_type": "db_instance",
			"attributes": {"storage_encrypted": true, "kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/abc", "publicly_accessible": false, "subnet_group": "data"},
			"metadata": {"managed_by": "sentinel-iac"},
		},
		{
			"resource_urn": "aws:us-east-1:111111111111:s3_bucket/exports",
			"resource_type": "s3_bucket",
			"attributes": {
				"encryption_algorithm": "aws:kms",
				"kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/def",
				"public_access_block": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true},
			},
			"metadata": {"managed_by": "sentinel-iac"},
		},
	]}
}

test_fail_unencrypted_db {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:db_instance/app_db",
		"resource_type": "db_instance",
		"attributes": {"storage_encrypted": false, "kms_key_arn": null, "publicly_accessible": false, "subnet_group": "data"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

# Regression test for a real bug: "storage_encrypted == true" combined
# with "not resource.attributes.kms_key_arn" never fired when
# kms_key_arn was explicitly null, because null is a defined Rego value
# and `not null` is false, not true -- the exact same mistake as
# IAM-BOUNDARY-001 (see ADR 0005), just not caught here the first time
# because no test isolated this specific combination on its own. Caught
# during a full-project recheck, not during the original build.
test_fail_encrypted_db_but_no_customer_kms_key {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:db_instance/suspect",
		"resource_type": "db_instance",
		"attributes": {"storage_encrypted": true, "kms_key_arn": null, "publicly_accessible": false, "subnet_group": "data"},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_bucket_wrong_algorithm {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:s3_bucket/exports",
		"resource_type": "s3_bucket",
		"attributes": {
			"encryption_algorithm": "AES256",
			"kms_key_arn": null,
			"public_access_block": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true},
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

# Same class of bug, checked for the S3 side too since the fix above
# added this rule specifically to close it.
test_fail_bucket_aws_kms_but_no_specific_key {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:s3_bucket/exports",
		"resource_type": "s3_bucket",
		"attributes": {
			"encryption_algorithm": "aws:kms",
			"kms_key_arn": null,
			"public_access_block": {"block_public_acls": true, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true},
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}

test_fail_bucket_public_acls_not_blocked {
	count(deny) == 1 with input as {"resources": [{
		"resource_urn": "aws:us-east-1:111111111111:s3_bucket/exports",
		"resource_type": "s3_bucket",
		"attributes": {
			"encryption_algorithm": "aws:kms",
			"kms_key_arn": "arn:aws:kms:us-east-1:111111111111:key/def",
			"public_access_block": {"block_public_acls": false, "block_public_policy": true, "ignore_public_acls": true, "restrict_public_buckets": true},
		},
		"metadata": {"managed_by": "sentinel-iac"},
	}]}
}
