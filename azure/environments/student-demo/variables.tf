variable "location" {
  type    = string
  default = "eastus"
}

variable "tenant_id" {
  type = string
}

variable "operator_principal_id" {
  type = string
}

variable "key_vault_name" {
  type        = string
  description = "Globally unique Azure Key Vault name (across ALL Azure tenants, not just this subscription -- Key Vault names share a single global DNS-like namespace). Choose your own value; do not reuse the placeholder in terraform.tfvars.example as-is, since it (or any other user's literal copy of it) will collide. See modules/identity/variables.tf for the exact format validation applied to this value."

  validation {
    # Same format check as modules/identity/variables.tf -- duplicated
    # here so a bad value fails at the environment's own `terraform
    # plan`/`validate` step rather than only inside the module.
    condition     = can(regex("^[a-zA-Z][a-zA-Z0-9-]{1,22}[a-zA-Z0-9]$", var.key_vault_name)) && !can(regex("--", var.key_vault_name))
    error_message = "key_vault_name must be 3-24 characters, start with a letter, contain only letters/digits/hyphens, not contain consecutive hyphens, and not end with a hyphen. Azure also requires the name to be globally unique across all Azure tenants -- this validation cannot check that part; if `terraform apply` fails with a name-already-taken error, pick a different value."
  }
}

variable "key_vault_purge_protection_enabled" {
  type        = bool
  default     = true
  description = "Enables Key Vault purge protection. Azure Storage customer-managed keys require the backing Key Vault to have both soft delete and purge protection enabled."
}

variable "storage_account_name" {
  type = string
}

variable "owner_tag" {
  type    = string
  default = "student-demo"
}

variable "cost_center_tag" {
  type    = string
  default = "learning"
}
