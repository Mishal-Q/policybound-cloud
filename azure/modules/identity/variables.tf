variable "name_prefix" {
  type = string
}

variable "location" {
  type = string
}

variable "resource_group_name" {
  type = string
}

variable "resource_group_id" {
  type = string
}

variable "tenant_id" {
  type = string
}

variable "operator_principal_id" {
  type        = string
  description = "Object ID of the user/service principal to grant Contributor at resource-group scope. Must be a real Entra ID object ID from an actual tenant -- cannot be a placeholder default."
}

variable "key_vault_name" {
  type        = string
  description = "Globally unique Azure Key Vault name (across ALL Azure tenants, not just this subscription). Must be chosen by the caller, not derived from name_prefix -- a fixed derived name like \"$${name_prefix}-kv\" would collide across every deployment of this demo. See terraform.tfvars.example for the format requirements and a placeholder to replace."

  validation {
    # Format-only check: 3-24 chars, starts with a letter, alphanumeric
    # and hyphens only, ends with a letter or digit, no consecutive
    # hyphens. This is everything Terraform CAN check locally -- actual
    # global uniqueness is an Azure API-side check at apply time and
    # cannot be validated offline.
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.key_vault_name)) && !can(regex("--", var.key_vault_name))
    error_message = "key_vault_name must be 3-24 characters, start with a letter, contain only letters/digits/hyphens, not contain consecutive hyphens, and not end with a hyphen. Azure also requires the name to be globally unique across all Azure tenants -- this validation cannot check that part; if `terraform apply` fails with a name-already-taken error, pick a different value."
  }
}

variable "purge_protection_enabled" {
  type        = bool
  default     = false
  description = "Whether Key Vault purge protection is enabled. The student demo enables it because Azure Storage customer-managed keys require the backing Key Vault to use both soft delete and purge protection."
}

variable "tags" {
  type    = map(string)
  default = {}
}
