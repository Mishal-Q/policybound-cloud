# Azure monitoring module.
#
# This module passes local Terraform validation. Live Azure deployment and
# runtime behavior remain unverified.
#
# Deliberately minimal -- one Log Analytics workspace, one diagnostic
# setting on the data-tier storage account. This is NOT an attempt to
# reproduce CloudTrail + AWS Config's scope; it exists to give the
# student-demo environment somewhere to send activity logs so the
# concept of "logging exists" has a real Azure resource behind it, same
# spirit as modules/logging on the AWS side but far smaller, since
# logging-per-resource was explicitly deferred out of the six selected
# invariants (see docs/cross-cloud-governance-model.md).

resource "azurerm_log_analytics_workspace" "this" {
  name                = "${var.name_prefix}-logs"
  location            = var.location
  resource_group_name = var.resource_group_name
  sku                 = "PerGB2018"
  retention_in_days   = 30

  tags = var.tags
}

# StorageRead/StorageWrite (and StorageDelete) are blob-data-plane log
# categories. They do not exist on the storage account resource itself
# -- azurerm_storage_account is just the management-plane parent. Azure
# Storage exposes those categories on each per-service sub-resource
# (blobServices/default, queueServices/default, tableServices/default,
# fileServices/default). Pointing target_resource_id at the storage
# account directly (the original code here) targets an invalid parent
# resource: Azure rejects StorageRead/StorageWrite diagnostic
# categories on that ID at apply time. This module only cares about
# blob activity, so the fix targets the blob service sub-resource.
resource "azurerm_monitor_diagnostic_setting" "storage" {
  name                       = "${var.name_prefix}-storage-diagnostics"
  target_resource_id         = "${var.storage_account_id}/blobServices/default"
  log_analytics_workspace_id = azurerm_log_analytics_workspace.this.id

  enabled_log {
    category = "StorageRead"
  }
  enabled_log {
    category = "StorageWrite"
  }

  metric {
    category = "Transaction"
  }
}
