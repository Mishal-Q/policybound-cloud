# Azure student-demo environment.
#
# Local Terraform formatting, initialization, and validation have completed
# successfully. Live Azure planning, deployment, and runtime behavior remain
# unverified until the student-demo environment is exercised in Azure.
#
# Deliberately small and student-sandbox appropriate: one resource
# group, one VNet with two subnets, two NSGs, one Storage Account with a
# customer-managed key, one Key Vault, one role assignment, one Log
# Analytics workspace. Nothing here is enterprise-scale, and nothing
# here has been deployed -- see the final report for exact verification
# status of every claim in this file.

terraform {
  required_version = ">= 1.7"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.90"
    }
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy    = false
      recover_soft_deleted_key_vaults = true
    }
  }
}

locals {
  name_prefix = "sentinel-iac-demo"
  common_tags = {
    ManagedBy     = "sentinel-iac"
    environment   = "student-demo"
    owner         = var.owner_tag
    "cost-center" = var.cost_center_tag
  }
}

resource "azurerm_resource_group" "this" {
  name     = "${local.name_prefix}-rg"
  location = var.location
  tags     = local.common_tags
}

module "network" {
  source = "../../modules/network"

  name_prefix         = local.name_prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  tags                = local.common_tags
}

module "identity" {
  source = "../../modules/identity"

  name_prefix              = local.name_prefix
  location                 = var.location
  resource_group_name      = azurerm_resource_group.this.name
  resource_group_id        = azurerm_resource_group.this.id
  tenant_id                = var.tenant_id
  operator_principal_id    = var.operator_principal_id
  key_vault_name           = var.key_vault_name
  purge_protection_enabled = var.key_vault_purge_protection_enabled
  tags                     = local.common_tags
}

module "data" {
  source = "../../modules/data"

  storage_account_name = var.storage_account_name
  resource_group_name  = azurerm_resource_group.this.name
  location             = var.location
  tags                 = local.common_tags

  # No key_vault_id / cmk_key_name here, and no depends_on module.identity
  # or the access policy below: this module now only creates the storage
  # account + its system-assigned identity. That's what breaks the cycle
  # -- see the CMK dependency-cycle note below.
}

# FIXED: this used to be a genuine circular Terraform dependency. This
# access policy needs module.data.storage_account_principal_id (only
# available once the storage account exists), while the CMK association
# used to live *inside* module.data and required this same access
# policy to exist first -- so module.data would have to finish before
# this policy, and this policy would have to finish before module.data
# could finish. Neither order is satisfiable in one apply.
#
# The fix: azurerm_storage_account_customer_managed_key was moved out of
# modules/data entirely (see that module's main.tf) and now lives below,
# at this environment level, sequenced explicitly after this access
# policy. That makes the graph a straight line with no back-edge:
#
#   module.data (storage account)
#     -> storage_account_principal_id
#   azurerm_key_vault_access_policy.storage_cmk_access
#     (needs storage_account_principal_id)
#   azurerm_storage_account_customer_managed_key.data
#     (needs storage_account_principal_id already able to use the key,
#      i.e. needs the access policy above to exist first --
#      via explicit depends_on)
#
# module.data no longer depends on this policy, or on module.identity,
# at all -- it only needs the resource group. This access policy is the
# only thing waiting on module.data's output, and the CMK association is
# the only thing waiting on this policy. This supports a clean first
# deployment from zero, in a single `terraform apply`.
resource "azurerm_key_vault_access_policy" "storage_cmk_access" {
  key_vault_id = module.identity.key_vault_id
  tenant_id    = var.tenant_id
  object_id    = module.data.storage_account_principal_id

  key_permissions = ["Get", "WrapKey", "UnwrapKey"]
}

# The CMK association itself. Split out of modules/data (see that
# module's main.tf header) specifically so it can be sequenced after
# the access policy above without forcing module.data as a whole to
# wait on a resource that itself waits on module.data's own output.
resource "azurerm_storage_account_customer_managed_key" "data" {
  storage_account_id = module.data.storage_account_id
  key_vault_id       = module.identity.key_vault_id
  key_name           = "sentinel-iac-demo-storage-key"

  # Explicit, not implicit: this resource's arguments don't reference
  # the access policy's attributes, but the access policy must exist
  # before Azure will let this storage account use the key.
  depends_on = [azurerm_key_vault_access_policy.storage_cmk_access]
}

module "monitoring" {
  source = "../../modules/monitoring"

  name_prefix         = local.name_prefix
  location            = var.location
  resource_group_name = azurerm_resource_group.this.name
  storage_account_id  = module.data.storage_account_id
  tags                = local.common_tags
}
