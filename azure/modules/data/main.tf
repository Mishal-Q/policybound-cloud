# Azure data module.
#
# This module passes local Terraform validation. Live Azure deployment and
# runtime behavior remain unverified.
#
# public_network_access_enabled hardcoded false, same pattern as the AWS
# database module hardcoding publicly_accessible = false -- a
# policy-enforced invariant, not a toggle someone can flip in tfvars.
#
# This module intentionally creates ONLY the storage account (with its
# system-assigned identity) and stops there. The CMK association
# (azurerm_storage_account_customer_managed_key) used to live here, but
# that created a genuine circular dependency: the Key Vault access
# policy granting this storage account's identity permission to use the
# CMK needs storage_account_principal_id, which only exists once the
# storage account is created -- while the CMK association resource
# needs that same access policy to exist first. Bundling both resources
# in one module forced the access policy (an environment-level concern)
# to be sequenced before the module could finish, which is not
# expressible as a single acyclic graph.
#
# The fix: this module only ever produces the storage account + its
# principal_id output. The CMK association is created at the
# environment level (see azure/environments/student-demo/main.tf),
# explicitly sequenced *after* the access policy that depends on this
# module's output. That keeps the dependency graph a straight line:
# storage account -> access policy -> CMK association, with no cycle.

resource "azurerm_storage_account" "data" {
  name                     = var.storage_account_name
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS" # cheapest replication tier -- this is a small demo, not prod-like

  public_network_access_enabled = false

  identity {
    type = "SystemAssigned"
  }

  tags = merge(var.tags, { "data-classification" = "confidential" })
}
