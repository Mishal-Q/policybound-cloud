package sentinel.data.data_enc_001

# --- policy metadata (informational) ---
# policy_id: DATA-ENC-001
# version: 1.0
# severity: critical
# title: Persistent storage must use customer-managed KMS encryption

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "db_instance"
	resource.attributes.storage_encrypted != true
	msg := sprintf("DATA-ENC-001 [CRITICAL]: %s has storage_encrypted != true", [resource.resource_urn])
}

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "db_instance"
	resource.attributes.storage_encrypted == true
	resource.attributes.kms_key_arn == null
	msg := sprintf(
		"DATA-ENC-001 [CRITICAL]: %s is encrypted but has no customer-managed KMS key ARN (default AWS-managed key is not sufficient)",
		[resource.resource_urn],
	)
}

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "s3_bucket"
	resource.attributes.encryption_algorithm != "aws:kms"
	msg := sprintf(
		"DATA-ENC-001 [CRITICAL]: %s uses encryption_algorithm=%q, expected customer-managed aws:kms",
		[resource.resource_urn, resource.attributes.encryption_algorithm],
	)
}

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "s3_bucket"
	resource.attributes.encryption_algorithm == "aws:kms"
	resource.attributes.kms_key_arn == null
	msg := sprintf(
		"DATA-ENC-001 [CRITICAL]: %s uses aws:kms encryption but no specific customer key ARN is set (defaults to the AWS-managed aws/s3 key, which this Control doesn't accept -- same requirement as db_instance above, added after finding the db_instance version of this check missed the same null case)",
		[resource.resource_urn],
	)
}

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "s3_bucket"
	pab := resource.attributes.public_access_block
	pab.block_public_acls != true
	msg := sprintf("DATA-ENC-001 [CRITICAL]: %s does not block public ACLs", [resource.resource_urn])
}
