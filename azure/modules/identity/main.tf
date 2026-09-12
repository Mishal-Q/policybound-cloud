# Azure identity module.
#
# This module passes local Terraform validation. Live Azure deployment and
# runtime behavior remain unverified.
#
# Deliberately does not attempt to reproduce AWS's permission-boundary
# model, because Azure has no permission-boundary concept -- see
# docs/decisions/0011-azure-identity-not-a-boundary-port.md. This module
# demonstrates RBAC scope instead: a role assignment scoped to the
# resource group, which is what AZURE-IDENTITY-001 checks for.
#
# ASSUMPTION: var.operator_principal_id is used both for the RBAC role
# assignment below AND as the deploying/Terraform identity granted Key
# Vault key-management permissions further down. That's correct for the
# common student-demo case where the human/service-principal running
# `terraform apply` is the same "operator" the RBAC assignment names.
# If a real deployment ever splits those into two different identities
# (e.g. a CI service principal running Terraform, and a separate human
# operator granted Contributor for day-2 access), this module would
# need a distinct deployer_principal_id input -- not added here since
# that's a real design decision, not a bug fix, and nothing in this
# repo currently requires it.

resource "azurerm_role_assignment" "operator" {
  scope                = var.resource_group_id
  role_definition_name = "Contributor"
  principal_id         = var.operator_principal_id

  # No permissions_boundary equivalent to set here -- the scope itself
  # (resource-group, not subscription) IS the ceiling. That's the whole
  # point of this module existing separately from a boundary-based one.
}

resource "azurerm_key_vault" "this" {
  name                       = var.key_vault_name
  location                   = var.location
  resource_group_name        = var.resource_group_name
  tenant_id                  = var.tenant_id
  sku_name                   = "standard"
  purge_protection_enabled   = var.purge_protection_enabled
  soft_delete_retention_days = 7

  # Azure Storage customer-managed keys require the backing Key Vault to have
  # both soft delete and purge protection enabled. The student-demo therefore
  # keeps purge protection on even though that means a deleted vault cannot be
  # purged immediately during the retention window.

  tags = var.tags
}

# Grants the deploying Terraform identity the minimum Key Vault key
# permissions needed to create and manage the CMK below. This Key
# Vault does not set enable_rbac_authorization, so it uses the
# access-policy model -- the azurerm_role_assignment above (Contributor
# at resource-group scope) is an ARM control-plane grant and does NOT
# cover Key Vault data-plane operations like key create/get/delete.
# Without this policy, azurerm_key_vault_key.storage_cmk below would
# fail to apply on a fresh deployment.
#
# Permission set is deliberately the minimum needed for Terraform to
# own the key's full lifecycle, not a broad grant:
#   - Get, List:  read the key / confirm current state
#   - Create, Update: create the key and change its attributes
#   - Delete: allow `terraform destroy` / key replacement
#   - Recover, Purge: included for key lifecycle operations; early purge is blocked while purge protection is enabled
#     The demo provider can recover a soft-deleted vault if needed, but does not
#     try to purge it during destroy because purge protection prevents early purge.
#     Purge permission is still kept as part of the key lifecycle permissions.
#   - GetRotationPolicy: azurerm reads this attribute on every plan/
#     refresh of an azurerm_key_vault_key resource even when rotation
#     isn't configured.
# Explicitly NOT granted: any secret_permissions, certificate_permissions,
# storage_permissions, or wrapKey/unwrapKey/decrypt/encrypt/sign/verify
# key permissions -- this identity manages the key's lifecycle, it does
# not need to use the key cryptographically. Only the storage account's
# own managed identity (granted separately, at the environment level)
# gets wrapKey/unwrapKey.
resource "azurerm_key_vault_access_policy" "deployer" {
  key_vault_id = azurerm_key_vault.this.id
  tenant_id    = var.tenant_id
  object_id    = var.operator_principal_id

  key_permissions = [
    "Get",
    "List",
    "Create",
    "Update",
    "Delete",
    "Recover",
    "Purge",
    "GetRotationPolicy",
  ]
}

resource "azurerm_key_vault_key" "storage_cmk" {
  name         = "${var.name_prefix}-storage-key"
  key_vault_id = azurerm_key_vault.this.id
  key_type     = "RSA"
  key_size     = 2048
  key_opts     = ["decrypt", "encrypt", "wrapKey", "unwrapKey"]

  # Depends on the deployer having key-management permissions on this
  # Key Vault -- see azurerm_key_vault_access_policy.deployer above.
  # No implicit dependency exists (this resource doesn't reference any
  # of that policy's attributes), so it's stated explicitly.
  depends_on = [azurerm_key_vault_access_policy.deployer]
}
