package azure_sentinel.data.azure_data_enc_001

# --- policy metadata (informational) ---
# policy_id: AZURE-DATA-ENC-001
# version: 1.0
# severity: critical
# title: Azure Storage Account must use a customer-managed encryption key
#
# Uses the cloud-neutral encryption_key_ref field, not kms_key_arn --
# Azure has no KMS, it has Key Vault, and a field literally named
# kms_key_arn holding a Key Vault key URI would be dishonest naming.
# DATA-ENC-001 (AWS, policies/data/data_enc_001.rego) is completely
# untouched by this file existing -- separate package, separate file,
# separate test suite.

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "azure_storage_account"
	value := object.get(resource.attributes, "encryption_key_ref", "__MISSING__")
	value == "__MISSING__"
	msg := sprintf(
		"AZURE-DATA-ENC-001 [CRITICAL]: %s has no encryption_key_ref recorded",
		[resource.resource_urn],
	)
}

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "azure_storage_account"
	resource.attributes.encryption_key_ref == null
	msg := sprintf(
		"AZURE-DATA-ENC-001 [CRITICAL]: %s relies on Microsoft-managed encryption; a customer-managed Key Vault key is required",
		[resource.resource_urn],
	)
}
