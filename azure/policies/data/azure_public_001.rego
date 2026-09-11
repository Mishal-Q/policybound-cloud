package azure_sentinel.data.azure_public_001

# --- policy metadata (informational) ---
# policy_id: AZURE-PUBLIC-001
# version: 1.0
# severity: critical
# title: Azure Storage Account must not allow public network access
#
# Azure equivalent of NET-DB-001's intent (public exposure), NOT a port
# of the file itself -- different resource type, different provider
# field (public_network_access_enabled vs. publicly_accessible), same
# canonical-schema pattern from drift/detector/schema.py. Package name
# is azure_sentinel.* (not sentinel.*) to keep AWS and Azure policy
# namespaces visibly separate, matching the project's file-level
# separation (policies/ vs azure/policies/).

deny[msg] {
	some r
	resource := input.resources[r]
	resource.resource_type == "azure_storage_account"
	resource.attributes.public_network_access_enabled == true
	msg := sprintf(
		"AZURE-PUBLIC-001 [CRITICAL]: %s has public_network_access_enabled=true; storage accounts must not be internet-reachable",
		[resource.resource_urn],
	)
}
